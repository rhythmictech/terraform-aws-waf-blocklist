# Hub, applied in a central (ops/security) account. It owns the table, the IP
# set and a rule group shared with each environment's workload account. The
# web ACLs in those accounts each add one rule referencing the shared rule
# group (see examples/consumer).
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
  share_with_account_ids = ["222222222222", "333333333333", "444444444444"]

  # For web ACLs behind CloudFront or a proxy that stamps the viewer IP into
  # a header. ACLs that see clients directly match on source IP instead.
  forwarded_ip_headers = ["x-client-ip"]

  # Optional second list: Tor exit nodes, synced hourly. The rules land in
  # the same rule group, so every consuming web ACL picks them up; count first.
  tor_exit_enabled = true
  tor_exit_action  = "count"

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

output "tor_exit_rule_names" {
  description = "For rule_action_override on the Tor exit rules in consuming web ACLs"
  value       = module.blocklist.tor_exit_rule_names
}

output "table_name" {
  description = "export BLOCKLIST_TABLE to this before using bin/blocklist"
  value       = module.blocklist.table_name
}
