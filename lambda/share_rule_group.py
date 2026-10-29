"""Apply or remove the sharing permission policy on a WAFv2 rule group.

Invoked by Terraform through aws_lambda_invocation with lifecycle_scope CRUD,
so the payload carries a "tf" block naming the action. create and update put
the policy; delete removes it. There is no Terraform resource for this API,
and running the CLI from a provisioner would use the operator's credentials
rather than the provider's.
"""

import json
import logging
import re
import time

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARN_REGION_RE = re.compile(r"^arn:[^:]+:wafv2:(?P<region>[^:]+):")
# When the rule group is replaced, the role policy scoped to its ARN is
# updated in the same apply and IAM takes a few seconds to honor it.
ACCESS_DENIED_RETRIES = 8
ACCESS_DENIED_DELAY_SECONDS = 5


def _put_with_retry(wafv2, arn, policy):
    for attempt in range(1, ACCESS_DENIED_RETRIES + 1):
        try:
            wafv2.put_permission_policy(ResourceArn=arn, Policy=policy)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or attempt == ACCESS_DENIED_RETRIES:
                raise
            logger.info("access denied on attempt %d, waiting for IAM propagation", attempt)
            time.sleep(ACCESS_DENIED_DELAY_SECONDS)


def lambda_handler(event, context):
    action = event.get("tf", {}).get("action", "create")
    arn = event["rule_group_arn"]
    region = ARN_REGION_RE.match(arn).group("region")
    wafv2 = boto3.client("wafv2", region_name=region)

    if action == "delete":
        try:
            wafv2.delete_permission_policy(ResourceArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
            logger.info("rule group %s already gone", arn)
        logger.info("removed permission policy from %s", arn)
        return {"rule_group_arn": arn, "action": action, "shared": False}

    # WAF validates the policy against a pattern whose "." does not match
    # newlines, so a pretty-printed document is rejected; always send it
    # compact.
    policy = event["policy"]
    if isinstance(policy, str):
        policy = json.loads(policy)
    policy = json.dumps(policy, separators=(",", ":"))
    _put_with_retry(wafv2, arn, policy)
    logger.info("applied permission policy to %s: %s", arn, policy)
    return {"rule_group_arn": arn, "action": action, "shared": True}
