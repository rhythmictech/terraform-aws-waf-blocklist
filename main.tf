data "aws_partition" "current" {
}

module "tags" {
  source  = "rhythmictech/tags/terraform"
  version = "~> 1.1.1"

  names = [var.name]
  tags  = var.tags
}

locals {
  partition = data.aws_partition.current.partition
  tags      = module.tags.tags_no_name

  # Everything the reconciler writes: the hub's own IP sets plus any fan-out
  # targets. Targets without a role are written with the function's own
  # credentials, so the execution role needs direct access to those IP sets.
  all_targets = concat(
    [for s in aws_wafv2_ip_set.this : { ip_set_arn = s.arn, role_arn = null }],
    var.targets,
  )
  local_ip_set_arns = [for t in local.all_targets : t.ip_set_arn if t.role_arn == null]
  assume_role_arns  = distinct([for t in var.targets : t.role_arn if t.role_arn != null])
}
