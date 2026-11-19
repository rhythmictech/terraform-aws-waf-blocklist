"""Reconcile a DynamoDB blocklist table into WAFv2 IP sets and Cloudflare IP lists.

Every run computes the full desired address list from the table (entries whose
expires_at is unset or in the future) and replaces the contents of each target
when they differ. The same handler runs from the table's DynamoDB stream
(fast path after an edit) and from an EventBridge schedule (expiry sweep and
drift repair); the event payload is ignored.

WAFv2 targets are IP set ARNs, optionally paired with an IAM role to assume in
the owning account. The ARN carries region, scope, name and id.

Cloudflare targets are custom IP lists (account ID, list ID) plus a Secrets
Manager secret holding an API token with Account Filter Lists Edit. IPv4 and
IPv6 rows go in the same list, and each item's comment carries the row's ticket
and reason, since Cloudflare list items have no expiry of their own. Replacing a
list's items is an asynchronous bulk operation, so the reconciler polls it to
completion before moving on (Cloudflare allows one pending bulk operation per
account).

Each target is reconciled independently so one failing target does not block
the rest; the run raises at the end if any target failed so the invocation
shows as an error.

Safety: a target is never written when the table read fails (the scan raises
first), when an address list would exceed the target's size limit, or when the
desired list already matches. Rows with unparseable CIDRs are logged and
skipped, never silently dropped from the set they were already in. A
Cloudflare target that is not an IP list is never written.
"""

import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["TABLE_NAME"]
TARGETS = json.loads(os.environ["TARGETS"])
CLOUDFLARE_TARGETS = json.loads(os.environ.get("CLOUDFLARE_TARGETS", "[]"))
# Default WAFv2 quota for addresses in a single IP set.
MAX_IP_SET_ENTRIES = int(os.environ.get("MAX_IP_SET_ENTRIES", "10000"))
# Cloudflare's item allowance is per account across all custom lists (10,000 on
# Pro, Business and Enterprise without an add-on).
MAX_CLOUDFLARE_LIST_ITEMS = int(os.environ.get("MAX_CLOUDFLARE_LIST_ITEMS", "10000"))
CLOUDFLARE_API_BASE = os.environ.get("CLOUDFLARE_API_BASE", "https://api.cloudflare.com/client/v4")
CLOUDFLARE_OPERATION_TIMEOUT = int(os.environ.get("CLOUDFLARE_OPERATION_TIMEOUT", "60"))
CLOUDFLARE_POLL_SECONDS = 2
CLOUDFLARE_BUSY_RETRIES = 3
CLOUDFLARE_COMMENT_MAX = 500
# Shortest prefixes Cloudflare IP lists accept.
CLOUDFLARE_MIN_PREFIX = {4: 8, 6: 12}
LOCK_RETRIES = 3

IP_SET_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):wafv2:(?P<region>[^:]+):(?P<account>\d{12}):"
    r"(?P<scope>regional|global)/ipset/(?P<name>[^/]+)/(?P<id>[0-9a-f-]+)$"
)

dynamodb = boto3.resource("dynamodb")
sts = boto3.client("sts")


def parse_ip_set_arn(arn):
    match = IP_SET_ARN_RE.match(arn)
    if not match:
        raise ValueError(f"not a WAFv2 IP set ARN: {arn}")
    parts = match.groupdict()
    parts["scope"] = "CLOUDFRONT" if parts["scope"] == "global" else "REGIONAL"
    return parts


def normalize_cidr(raw):
    """Return the canonical CIDR for an address or network, or None.

    WAFv2 rejects non-canonical networks (host bits set), so '10.1.2.3/24'
    becomes '10.1.2.0/24' and a bare address becomes a /32 or /128.
    """
    try:
        network = ipaddress.ip_network(raw.strip(), strict=False)
    except (ValueError, AttributeError):
        return None
    return str(network)


def _parse_timestamp(value):
    if not value:
        return None
    ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def item_comment(item):
    """Comment for a Cloudflare list item: 'TICKET: reason', or whichever is set."""
    ticket = str(item.get("ticket") or "").strip()
    reason = str(item.get("reason") or "").strip()
    return ": ".join(part for part in (ticket, reason) if part)


def load_desired(now):
    """Scan the table for active rows.

    Returns ({4: set_of_cidrs, 6: set_of_cidrs}, {cidr: comment}). The comment
    map feeds Cloudflare targets; rows that canonicalize to the same CIDR have
    their comments joined.
    """
    table = dynamodb.Table(TABLE_NAME)
    desired = {4: set(), 6: set()}
    comments = {}
    rows = active = 0
    scan_kwargs = {
        "ProjectionExpression": "cidr, expires_at, #reason, #ticket",
        "ExpressionAttributeNames": {"#reason": "reason", "#ticket": "ticket"},
    }
    while True:
        page = table.scan(**scan_kwargs)
        for item in page.get("Items", []):
            rows += 1
            cidr = normalize_cidr(item.get("cidr", ""))
            if cidr is None:
                logger.warning("skipping row with unparseable cidr %r", item.get("cidr"))
                continue
            try:
                expires_at = _parse_timestamp(item.get("expires_at"))
            except ValueError:
                logger.warning("skipping %s: unparseable expires_at %r", cidr, item.get("expires_at"))
                continue
            if expires_at is not None and expires_at <= now:
                continue
            active += 1
            desired[ipaddress.ip_network(cidr).version].add(cidr)
            comment = item_comment(item)
            if comment and comment not in comments.get(cidr, "").split(" | "):
                comments[cidr] = f"{comments[cidr]} | {comment}" if comments.get(cidr) else comment
        if "LastEvaluatedKey" not in page:
            break
        scan_kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    logger.info(
        "table %s: %d rows, %d active (%d IPv4, %d IPv6)",
        TABLE_NAME, rows, active, len(desired[4]), len(desired[6]),
    )
    return desired, comments


def wafv2_client_for(target, parsed):
    region = parsed["region"]
    role_arn = target.get("role_arn")
    if not role_arn:
        return boto3.client("wafv2", region_name=region)
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="waf-blocklist-reconcile",
        DurationSeconds=900,
    )["Credentials"]
    return boto3.client(
        "wafv2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def reconcile_target(target, desired):
    parsed = parse_ip_set_arn(target["ip_set_arn"])
    client = wafv2_client_for(target, parsed)
    lookup = {"Name": parsed["name"], "Scope": parsed["scope"], "Id": parsed["id"]}

    for attempt in range(1, LOCK_RETRIES + 1):
        current = client.get_ip_set(**lookup)
        version = 4 if current["IPSet"]["IPAddressVersion"] == "IPV4" else 6
        wanted = desired[version]
        existing = set(current["IPSet"]["Addresses"])

        result = {
            "ip_set_arn": target["ip_set_arn"],
            "ip_address_version": f"IPV{version}",
            "previous_count": len(existing),
            "desired_count": len(wanted),
            "added": sorted(wanted - existing),
            "removed": sorted(existing - wanted),
            "updated": False,
        }

        if wanted == existing:
            return result
        if len(wanted) > MAX_IP_SET_ENTRIES:
            raise RuntimeError(
                f"{len(wanted)} IPv{version} entries exceeds the IP set quota "
                f"{MAX_IP_SET_ENTRIES}; {target['ip_set_arn']} left unchanged"
            )
        # UpdateIPSet replaces the whole IP set, so an omitted Description is cleared. Send the
        # current one back, or Terraform sees the description drift after every reconcile.
        update = {"Addresses": sorted(wanted), "LockToken": current["LockToken"], **lookup}
        if current["IPSet"].get("Description"):
            update["Description"] = current["IPSet"]["Description"]
        try:
            client.update_ip_set(**update)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "WAFOptimisticLockException"
                and attempt < LOCK_RETRIES
            ):
                logger.info("lock token stale for %s, retrying", target["ip_set_arn"])
                continue
            raise
        result["updated"] = True
        return result
    raise RuntimeError(f"gave up on {target['ip_set_arn']} after {LOCK_RETRIES} lock conflicts")


class CloudflareError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def cloudflare_list_name(target):
    return f"cloudflare:{target.get('account_id')}/{target.get('list_id')}"


def cloudflare_token(secret_arn, cache):
    """Read the API token from Secrets Manager (plain SecretString), once per run."""
    if secret_arn not in cache:
        region = secret_arn.split(":")[3]
        client = boto3.client("secretsmanager", region_name=region)
        token = client.get_secret_value(SecretId=secret_arn)["SecretString"].strip()
        if not token:
            raise ValueError(f"secret {secret_arn} is empty")
        cache[secret_arn] = token
    return cache[secret_arn]


def cloudflare_request(token, method, path, params=None, body=None):
    """Call the Cloudflare API and return the decoded envelope; raise on failure."""
    url = f"{CLOUDFLARE_API_BASE}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read() or b"{}")
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {}
    if status >= 400 or not payload.get("success", False):
        errors = payload.get("errors") or [{"message": f"HTTP {status}"}]
        detail = "; ".join(f"{e.get('code', '')} {e.get('message', '')}".strip() for e in errors)
        raise CloudflareError(f"{method} {path}: HTTP {status}: {detail}", status=status)
    return payload


def cloudflare_list_items(token, base):
    """Return {cidr: comment} for every item in the list, following cursors."""
    items = {}
    params = {"per_page": 500}
    while True:
        page = cloudflare_request(token, "GET", f"{base}/items", params=params)
        for item in page.get("result") or []:
            cidr = normalize_cidr(item.get("ip", ""))
            if cidr is None:
                # Cannot compare it, so force a rewrite that drops it.
                items[f"unparseable:{item.get('ip')}"] = item.get("comment", "")
                continue
            items[cidr] = item.get("comment", "") or ""
        cursor = ((page.get("result_info") or {}).get("cursors") or {}).get("after")
        if not cursor:
            return items
        params = {"per_page": 500, "cursor": cursor}


def cloudflare_replace_items(token, account_id, base, items):
    """Replace all items in the list and wait for the bulk operation to finish."""
    for attempt in range(1, CLOUDFLARE_BUSY_RETRIES + 1):
        try:
            response = cloudflare_request(token, "PUT", f"{base}/items", body=items)
            break
        except CloudflareError as exc:
            # 429: another bulk operation is pending in this account.
            if exc.status == 429 and attempt < CLOUDFLARE_BUSY_RETRIES:
                logger.info("cloudflare account %s busy, retrying", account_id)
                time.sleep(5 * attempt)
                continue
            raise
    operation_id = response["result"]["operation_id"]
    deadline = time.monotonic() + CLOUDFLARE_OPERATION_TIMEOUT
    path = f"/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}"
    while True:
        result = cloudflare_request(token, "GET", path)["result"]
        status = result.get("status")
        if status == "completed":
            return operation_id
        if status == "failed":
            raise RuntimeError(f"bulk operation {operation_id} failed: {result.get('error')}")
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"bulk operation {operation_id} still {status} after "
                f"{CLOUDFLARE_OPERATION_TIMEOUT}s; the next run re-checks the list"
            )
        time.sleep(CLOUDFLARE_POLL_SECONDS)


def reconcile_cloudflare_target(target, desired, comments, token_cache):
    name = cloudflare_list_name(target)
    account_id = target["account_id"]
    base = f"/accounts/{account_id}/rules/lists/{target['list_id']}"
    token = cloudflare_token(target["api_token_secret_arn"], token_cache)

    kind = cloudflare_request(token, "GET", base)["result"].get("kind")
    if kind != "ip":
        raise RuntimeError(f"{name} is a {kind!r} list, not an IP list; left unchanged")

    # Cloudflare rejects prefixes shorter than /8 (IPv4) or /12 (IPv6), and one
    # bad item fails the whole bulk operation. Leave those out, write the rest,
    # and fail the target afterwards so the alarm still fires.
    unsupported = sorted(
        cidr
        for version in (4, 6)
        for cidr in desired[version]
        if ipaddress.ip_network(cidr).prefixlen < CLOUDFLARE_MIN_PREFIX[version]
    )
    wanted = {
        cidr: comments.get(cidr, "")[:CLOUDFLARE_COMMENT_MAX]
        for version in (4, 6)
        for cidr in desired[version]
        if cidr not in unsupported
    }
    existing = cloudflare_list_items(token, base)

    result = {
        "cloudflare_list": name,
        "previous_count": len(existing),
        "desired_count": len(wanted),
        "added": sorted(set(wanted) - set(existing)),
        "removed": sorted(set(existing) - set(wanted)),
        "comments_changed": sorted(c for c in set(wanted) & set(existing) if wanted[c] != existing[c]),
        "unsupported": unsupported,
        "updated": False,
    }

    if wanted != existing:
        if len(wanted) > MAX_CLOUDFLARE_LIST_ITEMS:
            raise RuntimeError(
                f"{len(wanted)} entries exceeds the Cloudflare list item limit "
                f"{MAX_CLOUDFLARE_LIST_ITEMS}; {name} left unchanged"
            )
        items = [
            {"ip": cidr, "comment": comment} if comment else {"ip": cidr}
            for cidr, comment in sorted(wanted.items())
        ]
        result["operation_id"] = cloudflare_replace_items(token, account_id, base, items)
        result["updated"] = True

    if unsupported:
        logger.info("target result: %s", json.dumps(result))
        raise RuntimeError(
            f"{len(unsupported)} entries are broader than Cloudflare IP lists accept "
            f"(IPv4 /8, IPv6 /12) and were left out of {name}: {', '.join(unsupported)}"
        )
    return result


def lambda_handler(event, context):
    now = datetime.now(timezone.utc)
    desired, comments = load_desired(now)

    results = []
    failures = []
    for target in TARGETS:
        try:
            result = reconcile_target(target, desired)
        except Exception as exc:  # noqa: BLE001 - one bad target must not abort the rest
            logger.exception("target %s failed", target.get("ip_set_arn"))
            failures.append({"ip_set_arn": target.get("ip_set_arn"), "error": str(exc)})
            continue
        logger.info("target result: %s", json.dumps(result))
        results.append(result)

    token_cache = {}
    for target in CLOUDFLARE_TARGETS:
        name = cloudflare_list_name(target)
        try:
            result = reconcile_cloudflare_target(target, desired, comments, token_cache)
        except Exception as exc:  # noqa: BLE001 - one bad target must not abort the rest
            logger.exception("target %s failed", name)
            failures.append({"cloudflare_list": name, "error": str(exc)})
            continue
        logger.info("target result: %s", json.dumps(result))
        results.append(result)

    total = len(TARGETS) + len(CLOUDFLARE_TARGETS)
    summary = {
        "active_entries": len(desired[4]) + len(desired[6]),
        "targets": total,
        "updated": sum(1 for r in results if r["updated"]),
        "failed": failures,
    }
    logger.info("run summary: %s", json.dumps(summary))
    if failures:
        raise RuntimeError(f"{len(failures)} of {total} targets failed: {json.dumps(failures)}")
    return summary
