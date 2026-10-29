# Hub, applied in the ops account. Modeled on the FEC layout: one ops account
# owns the table, the IP set and a rule group shared with each environment's
# workload account. The docquery and external web ACLs in those accounts each
# add one rule referencing the shared rule group (see examples/consumer).
#
# Apply this first; the consumers need the rule_group_arn output.

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

module "blocklist" {
  source = "../.."

  name = "waf-blocklist"

  # dev, stage, prod workload accounts
  share_with_account_ids = ["473934273253", "181308349486", "944631384106"]

  # docquery sits behind CloudFront, which stamps the viewer IP into this
  # header; the external ALB sees clients directly and matches on source IP.
  forwarded_ip_headers = ["x-real-viewer-ip"]

  alarm_sns_topic_arns = []
}

output "rule_group_arn" {
  description = "Reference from each consuming web ACL"
  value       = module.blocklist.rule_group_arn
}

output "rule_group_rule_names" {
  description = "For rule_action_override in consuming web ACLs"
  value       = module.blocklist.rule_group_rule_names
}

output "table_name" {
  description = "export BLOCKLIST_TABLE to this before using bin/blocklist"
  value       = module.blocklist.table_name
}
