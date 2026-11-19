"""Sync the current Tor exit-node list into one or more WAFv2 IP sets.

Runs on an EventBridge schedule. Pulls the exit list from two independent Tor
Project sources, unions them, and replaces the contents of each IP set (one
per address version) when they differ.

Safety: an IP set is never emptied on a bad run. If every source fails, or the
merged IPv4 list is under MIN_EXIT_COUNT, the function raises before any write
and the sets keep their last good contents. A single failed source is logged
and the other is used alone. An IP set is also left alone when its list would
be empty or would exceed the WAFv2 per-set quota.
"""

import ipaddress
import json
import logging
import os
import re
import urllib.request

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

IP_SET_ARNS = json.loads(os.environ["IP_SET_ARNS"])
MIN_EXIT_COUNT = int(os.environ.get("MIN_EXIT_COUNT", "500"))
# Default WAFv2 quota for addresses in a single IP set.
MAX_IP_SET_ENTRIES = int(os.environ.get("MAX_IP_SET_ENTRIES", "10000"))
FETCH_TIMEOUT_SECONDS = 20
LOCK_RETRIES = 3
USER_AGENT = "terraform-aws-waf-blocklist-tor-exit-sync/1.0 (+https://github.com/rhythmictech/terraform-aws-waf-blocklist)"

# TorDNSEL bulk exit list: exits seen in the last 16 hours, one IPv4 per line.
TORBULKEXITLIST_URL = "https://check.torproject.org/torbulkexitlist"
# Onionoo: relays currently carrying the Exit flag. Includes relays the bulk
# list has not observed yet, and is the only source of IPv6 addresses.
ONIONOO_URL = "https://onionoo.torproject.org/summary?type=relay&flag=Exit&running=true"

IP_SET_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):wafv2:(?P<region>[^:]+):(?P<account>\d{12}):"
    r"(?P<scope>regional|global)/ipset/(?P<name>[^/]+)/(?P<id>[0-9a-f-]+)$"
)


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:  # nosec B310 - fixed https URLs
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} from {url}")
        return resp.read().decode("utf-8")


def _parse_bulk_list(body):
    return [line.strip() for line in body.splitlines() if line.strip()]


def _parse_onionoo(body):
    addrs = []
    for relay in json.loads(body).get("relays", []):
        for addr in relay.get("a", []):
            # IPv6 entries are bracketed, e.g. "[2620:7:6003::141]".
            addrs.append(addr.strip("[]"))
    return addrs


SOURCES = (
    ("torbulkexitlist", TORBULKEXITLIST_URL, _parse_bulk_list),
    ("onionoo", ONIONOO_URL, _parse_onionoo),
)


def to_cidrs(candidates):
    """Return {4: set, 6: set} of host CIDRs for the globally routable addresses."""
    cidrs = {4: set(), 6: set()}
    unparseable = 0
    for raw in candidates:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            unparseable += 1
            continue
        if not ip.is_global:
            continue
        cidrs[ip.version].add(f"{ip}/{ip.max_prefixlen}")
    # Counted rather than logged per line: an HTML error or filtering page
    # served with a 200 is hundreds of lines that are not addresses.
    if unparseable:
        logger.warning("skipped %d entries that are not IP addresses", unparseable)
    return cidrs


def collect_exit_cidrs():
    merged = {4: set(), 6: set()}
    succeeded = []
    for name, url, parse in SOURCES:
        try:
            cidrs = to_cidrs(parse(_fetch(url)))
        except Exception:  # noqa: BLE001 - one bad source must not abort the run
            logger.exception("source %s failed", name)
            continue
        logger.info("source %s returned %d IPv4 and %d IPv6 exits", name, len(cidrs[4]), len(cidrs[6]))
        merged[4] |= cidrs[4]
        merged[6] |= cidrs[6]
        succeeded.append(name)

    if not succeeded:
        raise RuntimeError("every Tor exit source failed; IP sets left unchanged")
    # Both sources always carry IPv4, so a short IPv4 list means a truncated or
    # malformed response rather than a smaller Tor network.
    if len(merged[4]) < MIN_EXIT_COUNT:
        raise RuntimeError(
            f"merged exit list has {len(merged[4])} IPv4 entries, below floor {MIN_EXIT_COUNT}; "
            "IP sets left unchanged"
        )
    return merged, succeeded


def _canonical(cidr):
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return cidr


def sync_ip_set(arn, desired):
    match = IP_SET_ARN_RE.match(arn)
    if not match:
        raise ValueError(f"not a WAFv2 IP set ARN: {arn}")
    client = boto3.client("wafv2", region_name=match["region"])
    lookup = {
        "Name": match["name"],
        "Scope": "CLOUDFRONT" if match["scope"] == "global" else "REGIONAL",
        "Id": match["id"],
    }

    for attempt in range(1, LOCK_RETRIES + 1):
        current = client.get_ip_set(**lookup)
        version = 4 if current["IPSet"]["IPAddressVersion"] == "IPV4" else 6
        wanted = desired[version]
        # WAF returns IPv6 addresses fully expanded (2001:0db8:0000:...), so compare
        # canonical forms or the IPv6 set looks changed and is rewritten every sync.
        existing = {_canonical(a) for a in current["IPSet"]["Addresses"]}

        result = {
            "ip_set_arn": arn,
            "ip_address_version": f"IPV{version}",
            "previous_count": len(existing),
            "desired_count": len(wanted),
            "added": len(wanted - existing),
            "removed": len(existing - wanted),
            "updated": False,
        }
        if wanted == existing:
            return result
        if not wanted:
            raise RuntimeError(f"no IPv{version} exits returned; {arn} left unchanged")
        if len(wanted) > MAX_IP_SET_ENTRIES:
            raise RuntimeError(
                f"{len(wanted)} IPv{version} exits exceeds the IP set quota {MAX_IP_SET_ENTRIES}; {arn} left unchanged"
            )

        # UpdateIPSet replaces the whole IP set, so an omitted Description is cleared. Send the
        # current one back, or Terraform sees the description drift after every sync.
        update = {"Addresses": sorted(wanted), "LockToken": current["LockToken"], **lookup}
        if current["IPSet"].get("Description"):
            update["Description"] = current["IPSet"]["Description"]
        try:
            client.update_ip_set(**update)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "WAFOptimisticLockException" and attempt < LOCK_RETRIES:
                logger.info("lock token stale for %s, retrying", arn)
                continue
            raise
        result["updated"] = True
        return result

    raise RuntimeError(f"gave up on {arn} after {LOCK_RETRIES} lock conflicts")


def lambda_handler(event, context):
    desired, sources = collect_exit_cidrs()

    results = []
    failures = []
    for arn in IP_SET_ARNS:
        try:
            result = sync_ip_set(arn, desired)
        except Exception as exc:  # noqa: BLE001 - one bad IP set must not abort the rest
            logger.exception("IP set %s failed", arn)
            failures.append({"ip_set_arn": arn, "error": str(exc)})
            continue
        logger.info("IP set result: %s", json.dumps(result))
        results.append(result)

    summary = {
        "sources": sources,
        "ip_sets": len(IP_SET_ARNS),
        "updated": sum(1 for r in results if r["updated"]),
        "failed": failures,
    }
    logger.info("run summary: %s", json.dumps(summary))
    if failures:
        raise RuntimeError(f"{len(failures)} of {len(IP_SET_ARNS)} IP sets failed: {json.dumps(failures)}")
    return summary
