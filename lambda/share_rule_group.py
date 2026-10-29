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

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARN_REGION_RE = re.compile(r"^arn:[^:]+:wafv2:(?P<region>[^:]+):")


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

    policy = event["policy"]
    if not isinstance(policy, str):
        policy = json.dumps(policy)
    wafv2.put_permission_policy(ResourceArn=arn, Policy=policy)
    logger.info("applied permission policy to %s: %s", arn, policy)
    return {"rule_group_arn": arn, "action": action, "shared": True}
