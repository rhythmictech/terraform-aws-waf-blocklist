# Shared rule group mode. The hub owns the IP sets and a rule group that
# blocks on them; the rule group is shared with other accounts through a WAF
# permission policy, and each consuming web ACL references it with a
# rule_group_reference_statement. One IP set write reaches every web ACL at
# once, with no cross-account roles.

locals {
  ip_set_versions = var.create_rule_group ? toset(var.ip_address_versions) : toset([])

  # One source-IP rule per address version, plus one rule per forwarded-IP
  # header. A missing header falls back to no match, so the header rules are
  # inert on web ACLs that see clients directly.
  rule_group_rules = [
    for i, r in flatten([
      for v in var.ip_address_versions : concat(
        [{ name = "block-source-${lower(v)}", version = v, header = null }],
        [for h in var.forwarded_ip_headers : {
          name    = "block-forwarded-${lower(v)}-${lower(replace(h, "/[^A-Za-z0-9]+/", "-"))}"
          version = v
          header  = h
        }]
      )
    ]) : merge(r, { priority = i })
  ]

  share_rule_group = var.create_rule_group && (length(var.share_with_account_ids) > 0 || var.share_with_organization_id != null)
}

# Terraform owns the IP set resources; the reconciler owns their contents.
resource "aws_wafv2_ip_set" "this" {
  for_each = local.ip_set_versions

  name               = "${var.name}-${lower(each.value)}"
  description        = "Populated from the ${var.name} table by the reconciler, do not edit by hand"
  scope              = var.scope
  ip_address_version = each.value
  addresses          = []
  tags               = local.tags

  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_rule_group" "this" {
  count = var.create_rule_group ? 1 : 0

  name        = var.name
  description = "Blocks addresses in the ${var.name} blocklist. Reference from a web ACL with rule_group_reference_statement"
  scope       = var.scope
  capacity    = var.rule_group_capacity
  tags        = local.tags

  dynamic "rule" {
    for_each = local.rule_group_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.this[rule.value.version].arn

          dynamic "ip_set_forwarded_ip_config" {
            for_each = rule.value.header == null ? [] : [rule.value.header]

            content {
              header_name       = ip_set_forwarded_ip_config.value
              fallback_behavior = "NO_MATCH"
              position          = var.forwarded_ip_position
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }
}

# WAF's PutPermissionPolicy accepts exactly these actions, no Resource element,
# and principals as account root ARNs or an organization condition.
data "aws_iam_policy_document" "share" {
  count = local.share_rule_group ? 1 : 0

  statement {
    effect = "Allow"

    actions = [
      "wafv2:CreateWebACL",
      "wafv2:UpdateWebACL",
      "wafv2:PutFirewallManagerRuleGroups",
      "wafv2:GetRuleGroup"
    ]

    principals {
      type        = "AWS"
      identifiers = var.share_with_organization_id != null ? ["*"] : [for id in var.share_with_account_ids : "arn:${local.partition}:iam::${id}:root"]
    }

    dynamic "condition" {
      for_each = var.share_with_organization_id != null ? [var.share_with_organization_id] : []

      content {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [condition.value]
      }
    }
  }
}

# No Terraform resource exists for the WAF permission policy, and a local-exec
# would run with the operator's ambient credentials rather than the provider's
# (often an assumed role). A one-shot Lambda invoked with the provider's
# credentials applies the policy on create/update and removes it on destroy.
resource "aws_iam_role" "share" {
  count = local.share_rule_group ? 1 : 0

  name               = "${var.name}-share-rule-group"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "share_lambda" {
  count = local.share_rule_group ? 1 : 0

  statement {
    effect    = "Allow"
    resources = ["${aws_cloudwatch_log_group.share[0].arn}:*"]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }

  statement {
    effect    = "Allow"
    resources = [aws_wafv2_rule_group.this[0].arn]

    actions = [
      "wafv2:PutPermissionPolicy",
      "wafv2:DeletePermissionPolicy"
    ]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []

    content {
      effect    = "Allow"
      resources = [var.kms_key_arn]
      actions   = ["kms:Decrypt"]
    }
  }
}

resource "aws_iam_role_policy" "share" {
  count = local.share_rule_group ? 1 : 0

  name   = "share-rule-group"
  role   = aws_iam_role.share[0].id
  policy = data.aws_iam_policy_document.share_lambda[0].json
}

data "archive_file" "share" {
  type        = "zip"
  source_file = "${path.module}/lambda/share_rule_group.py"
  output_path = "${path.module}/lambda/share_rule_group.zip"
}

resource "aws_cloudwatch_log_group" "share" {
  count = local.share_rule_group ? 1 : 0

  name              = "/aws/lambda/${var.name}-share-rule-group"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

# X-Ray tracing adds nothing for a one-call helper.
#trivy:ignore:AVD-AWS-0066
resource "aws_lambda_function" "share" {
  count = local.share_rule_group ? 1 : 0

  function_name    = "${var.name}-share-rule-group"
  description      = "Applies the sharing permission policy to the ${var.name} rule group"
  handler          = "share_rule_group.lambda_handler"
  role             = aws_iam_role.share[0].arn
  runtime          = var.lambda_runtime
  filename         = data.archive_file.share.output_path
  source_code_hash = data.archive_file.share.output_base64sha256
  timeout          = 60
  memory_size      = 128
  tags             = local.tags

  depends_on = [aws_iam_role_policy.share]
}

resource "aws_lambda_invocation" "share" {
  count = local.share_rule_group ? 1 : 0

  function_name   = aws_lambda_function.share[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    rule_group_arn = aws_wafv2_rule_group.this[0].arn
    policy         = data.aws_iam_policy_document.share[0].json
  })

  # The role policy is scoped to the rule group ARN, so a replacement rule
  # group updates the policy in the same apply; the invocation must run after
  # it (and the Lambda retries while IAM catches up).
  depends_on = [aws_iam_role_policy.share]
}
