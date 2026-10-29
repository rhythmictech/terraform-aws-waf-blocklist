"""Reconcile a DynamoDB blocklist table into one or more WAFv2 IP sets.

Every run computes the full desired address list from the table (entries whose
expires_at is unset or in the future) and replaces the contents of each target
IP set when they differ. The same handler runs from the table's DynamoDB stream
(fast path after an edit) and from an EventBridge schedule (expiry sweep and
drift repair); the event payload is ignored.

Targets are WAFv2 IP set ARNs, optionally paired with an IAM role to assume in
the owning account. The ARN carries region, scope, name and id. Each target is
reconciled independently so one failing account does not block the rest; the
run raises at the end if any target failed so the invocation shows as an error.

Safety: a target is never written when the table read fails (the scan raises
first), when an address list would exceed the WAFv2 per-set quota, or when the
desired list already matches. Rows with unparseable CIDRs are logged and
skipped, never silently dropped from the set they were already in.
"""

import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["TABLE_NAME"]
TARGETS = json.loads(os.environ["TARGETS"])
# Default WAFv2 quota for addresses in a single IP set.
MAX_IP_SET_ENTRIES = int(os.environ.get("MAX_IP_SET_ENTRIES", "10000"))
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


def load_desired(now):
    """Scan the table and return {4: set_of_cidrs, 6: set_of_cidrs} for active rows."""
    table = dynamodb.Table(TABLE_NAME)
    desired = {4: set(), 6: set()}
    rows = active = 0
    scan_kwargs = {"ProjectionExpression": "cidr, expires_at"}
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
        if "LastEvaluatedKey" not in page:
            break
        scan_kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    logger.info(
        "table %s: %d rows, %d active (%d IPv4, %d IPv6)",
        TABLE_NAME, rows, active, len(desired[4]), len(desired[6]),
    )
    return desired


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
        try:
            client.update_ip_set(
                Addresses=sorted(wanted), LockToken=current["LockToken"], **lookup
            )
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


def lambda_handler(event, context):
    now = datetime.now(timezone.utc)
    desired = load_desired(now)

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

    summary = {
        "active_entries": len(desired[4]) + len(desired[6]),
        "targets": len(TARGETS),
        "updated": sum(1 for r in results if r["updated"]),
        "failed": failures,
    }
    logger.info("run summary: %s", json.dumps(summary))
    if failures:
        raise RuntimeError(f"{len(failures)} of {len(TARGETS)} targets failed: {json.dumps(failures)}")
    return summary
