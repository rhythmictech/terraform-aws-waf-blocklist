# Hub side, applied in the ops account. Modeled on the FEC layout: one ops
# account holds the table and reconciler; each environment's workload account
# owns a regional IP set that the docquery and external web ACLs reference.
#
# Apply this first. The targets' role ARNs are predictable from the name each
# modules/target deployment uses, so they can be listed before they exist.

terraform {
  required_version = ">= 1.5"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.5.0"
    }

    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

locals {
  # account id => manual-block IP set ARN, one per environment
  workload_ip_sets = {
    "473934273253" = "arn:aws:wafv2:us-east-1:473934273253:regional/ipset/manual-block-dev/00000000-0000-0000-0000-000000000000"
    "181308349486" = "arn:aws:wafv2:us-east-1:181308349486:regional/ipset/manual-block-stage/00000000-0000-0000-0000-000000000000"
    "944631384106" = "arn:aws:wafv2:us-east-1:944631384106:regional/ipset/manual-block-prod/00000000-0000-0000-0000-000000000000"
  }
}

module "blocklist" {
  source = "../.."

  name = "waf-blocklist"

  targets = [
    for account, arn in local.workload_ip_sets : {
      ip_set_arn = arn
      role_arn   = "arn:aws:iam::${account}:role/waf-blocklist-target"
    }
  ]

  alarm_sns_topic_arns = []
}

output "reconciler_role_arn" {
  description = "Pass as hub_role_arn to each modules/target deployment"
  value       = module.blocklist.reconciler_role_arn
}

output "table_name" {
  description = "export BLOCKLIST_TABLE to this before using bin/blocklist"
  value       = module.blocklist.table_name
}
