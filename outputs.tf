output "ip_set_arns" {
  description = "Map of address version to the ARN of the IP set the hub created (rule group mode)"
  value       = { for v, s in aws_wafv2_ip_set.this : v => s.arn }
}

output "permission_policy_json" {
  description = "The sharing policy applied to the rule group, for reference"
  value       = local.share_rule_group ? data.aws_iam_policy_document.share[0].json : null
}

output "reconciler_function_arn" {
  description = "ARN of the reconciler Lambda"
  value       = aws_lambda_function.reconciler.arn
}

output "reconciler_role_arn" {
  description = "ARN of the reconciler execution role. Pass this as hub_role_arn to modules/target in each account that owns an IP set"
  value       = aws_iam_role.reconciler.arn
}

output "rule_group_arn" {
  description = "ARN of the shared rule group. Reference it from each web ACL with rule_group_reference_statement"
  value       = var.create_rule_group ? aws_wafv2_rule_group.this[0].arn : null
}

output "rule_group_rule_names" {
  description = "Names of the rules inside the rule group, for rule_action_override in consuming web ACLs"
  value       = [for r in local.rule_group_rules : r.name]
}

output "table_arn" {
  description = "ARN of the blocklist DynamoDB table"
  value       = aws_dynamodb_table.this.arn
}

output "table_name" {
  description = "Name of the blocklist DynamoDB table (set BLOCKLIST_TABLE to this for bin/blocklist)"
  value       = aws_dynamodb_table.this.name
}
