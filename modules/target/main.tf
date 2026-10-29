module "tags" {
  source  = "rhythmictech/tags/terraform"
  version = "~> 1.1.1"

  names = [var.name]
  tags  = var.tags
}

locals {
  tags = module.tags.tags_no_name

  ip_set_arns = concat(var.ip_set_arns, [for s in aws_wafv2_ip_set.this : s.arn])
}

# IP sets created here are owned by Terraform but populated by the hub
# reconciler, so address changes are ignored after creation.
resource "aws_wafv2_ip_set" "this" {
  for_each = var.ip_sets

  name               = each.key
  description        = each.value.description
  scope              = each.value.scope
  ip_address_version = each.value.ip_address_version
  addresses          = []
  tags               = local.tags

  lifecycle {
    ignore_changes = [addresses]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "AWS"
      identifiers = [var.hub_role_arn]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.name
  description        = "Lets the WAF blocklist reconciler update this account's IP sets"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "this" {
  statement {
    effect    = "Allow"
    resources = local.ip_set_arns

    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
    ]
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "update-ip-sets"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.this.json
}
