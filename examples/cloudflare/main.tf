# Cloudflare-only hub: the blocklist table and reconciler, feeding a Cloudflare
# custom IP list instead of AWS WAF IP sets.
#
# On the Cloudflare side (not managed here), create a custom list of kind "ip"
# and a custom rule in each zone, e.g. `ip.src in $waf_blocklist` -> Block.
# Leave the list's items out of Terraform; the reconciler owns them.
#
# After the first apply, store an API token with Account Filter Lists Edit:
#   aws secretsmanager put-secret-value --secret-id waf-blocklist-cloudflare \
#     --secret-string "$CLOUDFLARE_LISTS_TOKEN"
# The reconciler fails (and alarms) until the secret has a value.

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

variable "cloudflare_account_id" {
  description = "Cloudflare account that owns the list"
  type        = string
}

variable "cloudflare_list_id" {
  description = "ID of the custom IP list the reconciler replaces"
  type        = string
}

# Secrets Manager's default key is enough for a single-account hub.
#trivy:ignore:AVD-AWS-0098
resource "aws_secretsmanager_secret" "cloudflare_lists" {
  name        = "waf-blocklist-cloudflare"
  description = "Cloudflare API token (Account Filter Lists Edit) for the waf-blocklist reconciler"
}

module "blocklist" {
  source = "../.."

  name              = "waf-blocklist"
  create_rule_group = false

  cloudflare_targets = [
    {
      account_id           = var.cloudflare_account_id
      list_id              = var.cloudflare_list_id
      api_token_secret_arn = aws_secretsmanager_secret.cloudflare_lists.arn
    },
  ]

  alarm_sns_topic_arns = []
}

output "table_name" {
  description = "export BLOCKLIST_TABLE to this before using bin/blocklist"
  value       = module.blocklist.table_name
}
