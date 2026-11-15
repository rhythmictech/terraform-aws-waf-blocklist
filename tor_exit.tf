# Tor exit-node feed. A second list alongside the hand-curated one: its own IP
# sets, kept current from the Tor Project's published exit lists, and its own
# rules in the shared rule group so each web ACL can count or block Tor
# independently of the blocklist.
#
# The feed stays out of the DynamoDB table on purpose. A thousand addresses
# that churn hourly would bury the reason/expiry audit trail and share the
# curated list's IP set quota. It also runs in its own function: the
# reconciler can assume roles in other accounts and should not be the thing
# making outbound requests to third parties, and a Tor Project outage should
# not read as "the blocklist is out of sync".

locals {
  tor_exit_enabled  = var.create_rule_group && var.tor_exit_enabled
  tor_exit_versions = local.tor_exit_enabled ? toset(var.ip_address_versions) : toset([])
}

# Terraform owns the IP set resources; the sync function owns their contents.
resource "aws_wafv2_ip_set" "tor_exit" {
  for_each = local.tor_exit_versions

  name               = "${var.name}-tor-exit-${lower(each.value)}"
  description        = "Current Tor exit nodes, synced by the ${var.name}-tor-exit-sync Lambda, do not edit by hand"
  scope              = var.scope
  ip_address_version = each.value
  addresses          = []
  tags               = local.tags

  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_iam_role" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  name               = "${var.name}-tor-exit-sync"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  statement {
    effect    = "Allow"
    resources = ["${aws_cloudwatch_log_group.tor_exit[0].arn}:*"]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }

  statement {
    effect    = "Allow"
    resources = [for s in aws_wafv2_ip_set.tor_exit : s.arn]

    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
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

resource "aws_iam_role_policy" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  name   = "sync-tor-exit"
  role   = aws_iam_role.tor_exit[0].id
  policy = data.aws_iam_policy_document.tor_exit[0].json
}

data "archive_file" "tor_exit" {
  type        = "zip"
  source_file = "${path.module}/lambda/tor_exit_sync.py"
  output_path = "${path.module}/lambda/tor_exit_sync.zip"
}

resource "aws_cloudwatch_log_group" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  name              = "/aws/lambda/${var.name}-tor-exit-sync"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

# X-Ray tracing adds nothing for a two-fetch batch job.
#trivy:ignore:AVD-AWS-0066
resource "aws_lambda_function" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  function_name    = "${var.name}-tor-exit-sync"
  description      = "Syncs the Tor exit-node list into the ${var.name}-tor-exit WAFv2 IP set(s)"
  handler          = "tor_exit_sync.lambda_handler"
  role             = aws_iam_role.tor_exit[0].arn
  runtime          = var.lambda_runtime
  filename         = data.archive_file.tor_exit.output_path
  source_code_hash = data.archive_file.tor_exit.output_base64sha256
  timeout          = 60
  memory_size      = 256
  tags             = local.tags

  environment {
    variables = {
      IP_SET_ARNS        = jsonencode([for s in aws_wafv2_ip_set.tor_exit : s.arn])
      MIN_EXIT_COUNT     = var.tor_exit_min_count
      MAX_IP_SET_ENTRIES = var.max_ip_set_entries
    }
  }

  depends_on = [aws_iam_role_policy.tor_exit]
}

resource "aws_cloudwatch_event_rule" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  name                = "${var.name}-tor-exit-sync"
  description         = "Scheduled refresh of the ${var.name} Tor exit-node IP set(s)"
  schedule_expression = var.tor_exit_schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  rule      = aws_cloudwatch_event_rule.tor_exit[0].name
  target_id = "tor-exit-sync"
  arn       = aws_lambda_function.tor_exit[0].arn
}

resource "aws_lambda_permission" "tor_exit" {
  count = local.tor_exit_enabled ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tor_exit[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tor_exit[0].arn
}

# A failed run leaves the IP sets at their last good contents, so the rules
# keep working on a list that is going stale. Two consecutive periods with an
# error ride out a single bad fetch at the default hourly schedule.
resource "aws_cloudwatch_metric_alarm" "tor_exit_errors" {
  count = local.tor_exit_enabled ? 1 : 0

  alarm_name          = "${var.name}-tor-exit-sync-errors"
  alarm_description   = "The ${var.name} Tor exit sync is failing; the Tor exit IP set is not being refreshed"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_sns_topic_arns
  ok_actions          = var.alarm_sns_topic_arns
  tags                = local.tags

  dimensions = {
    FunctionName = aws_lambda_function.tor_exit[0].function_name
  }
}
