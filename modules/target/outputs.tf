output "ip_set_arns" {
  description = "ARNs of every IP set the role may update (created and pre-existing). Each goes into the root module's targets with role_arn set to role_arn"
  value       = local.ip_set_arns
}

output "created_ip_sets" {
  description = "Map of created IP set name to its ARN and id"
  value       = { for k, s in aws_wafv2_ip_set.this : k => { arn = s.arn, id = s.id } }
}

output "role_arn" {
  description = "ARN of the role the reconciler assumes for this account"
  value       = aws_iam_role.this.arn
}
