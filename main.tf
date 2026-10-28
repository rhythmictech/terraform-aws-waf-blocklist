module "tags" {
  source  = "rhythmictech/tags/terraform"
  version = "~> 1.1.1"

  names = [var.name]
  tags  = var.tags
}

locals {
  tags = module.tags.tags_no_name

  # Targets without a role are reconciled with the function's own credentials,
  # so the execution role needs direct access to those IP sets.
  local_ip_set_arns = [for t in var.targets : t.ip_set_arn if t.role_arn == null]
  assume_role_arns  = distinct([for t in var.targets : t.role_arn if t.role_arn != null])
}
