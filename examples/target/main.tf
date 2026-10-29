# Fan-out mode, applied once in each account that owns an IP set the hub
# should write to directly (for accounts the hub cannot share a rule group
# with, or CLOUDFRONT-scope sets when the hub is REGIONAL). Creates the role
# the reconciler assumes. The IP set is managed here with its addresses
# ignored so Terraform never empties it.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "env" {
  default     = "dev"
  description = "Environment name"
  type        = string
}

resource "aws_wafv2_ip_set" "manual_block" {
  name               = "manual-block-${var.env}"
  description        = "Hand-curated block list, populated by the waf-blocklist reconciler"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  lifecycle {
    ignore_changes = [addresses]
  }
}

module "blocklist_target" {
  source = "../../modules/target"

  name         = "waf-blocklist-target"
  hub_role_arn = "arn:aws:iam::111111111111:role/waf-blocklist-reconciler"
  ip_set_arns  = [aws_wafv2_ip_set.manual_block.arn]
}

output "ip_set_arn" {
  description = "Add to the hub's targets with role_arn = role_arn"
  value       = aws_wafv2_ip_set.manual_block.arn
}

output "role_arn" {
  description = "Add to the hub's targets alongside ip_set_arn"
  value       = module.blocklist_target.role_arn
}
