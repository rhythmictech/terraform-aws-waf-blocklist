data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Fixed name so target accounts can trust the ARN before the role exists in
# their state (see modules/target).
resource "aws_iam_role" "reconciler" {
  name               = "${var.name}-reconciler"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "reconciler" {
  statement {
    effect    = "Allow"
    resources = ["${aws_cloudwatch_log_group.reconciler.arn}:*"]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }

  statement {
    effect    = "Allow"
    resources = [aws_dynamodb_table.this.arn]
    actions   = ["dynamodb:Scan"]
  }

  statement {
    effect    = "Allow"
    resources = [aws_dynamodb_table.this.stream_arn]

    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams"
    ]
  }

  dynamic "statement" {
    for_each = length(local.assume_role_arns) > 0 ? [1] : []

    content {
      effect    = "Allow"
      resources = local.assume_role_arns
      actions   = ["sts:AssumeRole"]
    }
  }

  dynamic "statement" {
    for_each = length(local.local_ip_set_arns) > 0 ? [1] : []

    content {
      effect    = "Allow"
      resources = local.local_ip_set_arns

      actions = [
        "wafv2:GetIPSet",
        "wafv2:UpdateIPSet"
      ]
    }
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

resource "aws_iam_role_policy" "reconciler" {
  name   = "reconcile"
  role   = aws_iam_role.reconciler.id
  policy = data.aws_iam_policy_document.reconciler.json
}

data "archive_file" "reconciler" {
  type        = "zip"
  source_file = "${path.module}/lambda/reconcile.py"
  output_path = "${path.module}/lambda/reconcile.zip"
}

resource "aws_cloudwatch_log_group" "reconciler" {
  name              = "/aws/lambda/${var.name}-reconciler"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

# X-Ray tracing adds nothing for a two-call batch job.
#trivy:ignore:AVD-AWS-0066
resource "aws_lambda_function" "reconciler" {
  function_name    = "${var.name}-reconciler"
  description      = "Reconciles the ${var.name} table into ${length(local.all_targets)} WAFv2 IP set(s)"
  handler          = "reconcile.lambda_handler"
  role             = aws_iam_role.reconciler.arn
  runtime          = var.lambda_runtime
  filename         = data.archive_file.reconciler.output_path
  source_code_hash = data.archive_file.reconciler.output_base64sha256
  timeout          = var.lambda_timeout
  memory_size      = 256
  tags             = local.tags

  # Runs are full reconciles, so overlapping invocations only race for the
  # same end state. Serializing them keeps the lock-token retries quiet.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      TABLE_NAME         = aws_dynamodb_table.this.name
      TARGETS            = jsonencode(local.all_targets)
      MAX_IP_SET_ENTRIES = var.max_ip_set_entries
    }
  }

  depends_on = [aws_iam_role_policy.reconciler]
}

# Fast path: any write to the table triggers a reconcile within seconds.
resource "aws_lambda_event_source_mapping" "stream" {
  event_source_arn                   = aws_dynamodb_table.this.stream_arn
  function_name                      = aws_lambda_function.reconciler.arn
  starting_position                  = "LATEST"
  batch_size                         = 100
  maximum_batching_window_in_seconds = 5
  maximum_retry_attempts             = var.stream_maximum_retry_attempts
}

# Slow path: retires expired entries and repairs any drift (console edits to
# an IP set, a target that was unreachable when its row changed).
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name}-reconcile"
  description         = "Scheduled expiry sweep for the ${var.name} WAF blocklist"
  schedule_expression = var.schedule_expression
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "reconciler"
  arn       = aws_lambda_function.reconciler.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reconciler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# The function raises when any target could not be updated, so a single error
# datapoint means some IP set is out of sync with the table.
resource "aws_cloudwatch_metric_alarm" "reconciler_errors" {
  alarm_name          = "${var.name}-reconciler-errors"
  alarm_description   = "The ${var.name} reconciler failed; at least one WAF IP set is out of sync with the blocklist table"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_sns_topic_arns
  ok_actions          = var.alarm_sns_topic_arns
  tags                = local.tags

  dimensions = {
    FunctionName = aws_lambda_function.reconciler.function_name
  }
}
