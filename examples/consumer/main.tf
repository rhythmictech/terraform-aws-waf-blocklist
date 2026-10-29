# Consumer, in a workload account the hub shares with. Nothing is deployed
# for the blocklist here beyond one rule in the web ACL that references the
# shared rule group. The rule group does not appear in this account's WAF
# console listing, but the ARN resolves.
#
# FEC: this rule replaces the block-manual-list rule in the docquery and
# external web ACLs, and the SSM-published manual-block IP set goes away.

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

variable "blocklist_rule_group_arn" {
  default     = "arn:aws:wafv2:us-east-1:867342139022:regional/rulegroup/waf-blocklist/00000000-0000-0000-0000-000000000000"
  description = "rule_group_arn output of the hub"
  type        = string
}

variable "blocklist_enforce" {
  default     = true
  description = "Block (true) or only count (false) matches from the shared blocklist"
  type        = bool
}

resource "aws_wafv2_web_acl" "example" {
  name  = "example"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "shared-blocklist"
    priority = 0

    override_action {
      none {}
    }

    statement {
      rule_group_reference_statement {
        arn = var.blocklist_rule_group_arn

        # Rule names come from the hub's rule_group_rule_names output. Override
        # to count while validating, then drop the overrides to enforce.
        dynamic "rule_action_override" {
          for_each = var.blocklist_enforce ? [] : ["block-source-ipv4", "block-forwarded-ipv4-x-real-viewer-ip"]

          content {
            name = rule_action_override.value

            action_to_use {
              count {}
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "example-shared-blocklist"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "example"
    sampled_requests_enabled   = true
  }
}
