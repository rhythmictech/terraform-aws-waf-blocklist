output "reconciler_function_arn" {
  description = "ARN of the reconciler Lambda"
  value       = aws_lambda_function.reconciler.arn
}

output "reconciler_role_arn" {
  description = "ARN of the reconciler execution role. Pass this as hub_role_arn to modules/target in each account that owns an IP set"
  value       = aws_iam_role.reconciler.arn
}

output "table_arn" {
  description = "ARN of the blocklist DynamoDB table"
  value       = aws_dynamodb_table.this.arn
}

output "table_name" {
  description = "Name of the blocklist DynamoDB table (set BLOCKLIST_TABLE to this for bin/blocklist)"
  value       = aws_dynamodb_table.this.name
}
