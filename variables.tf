variable "alarm_sns_topic_arns" {
  default     = []
  description = "SNS topics to notify when a reconcile run fails (any target could not be updated)"
  type        = list(string)
}

variable "create_rule_group" {
  default     = true
  description = "Create IP sets and a rule group in this account that web ACLs reference directly (see share_with_account_ids). Set false to run in fan-out mode with targets only"
  type        = bool
}

variable "deletion_protection_enabled" {
  default     = true
  description = "Enable DynamoDB deletion protection on the blocklist table"
  type        = bool
}

variable "forwarded_ip_headers" {
  default     = []
  description = "Headers carrying the client IP when the web ACL sits behind CloudFront or a proxy, e.g. [\"x-real-viewer-ip\"]. Each adds a rule to the rule group that matches the header instead of the connection source"
  type        = list(string)
}

variable "forwarded_ip_position" {
  default     = "FIRST"
  description = "Which address in a forwarded-IP header to match: FIRST, LAST or ANY"
  type        = string

  validation {
    condition     = contains(["FIRST", "LAST", "ANY"], var.forwarded_ip_position)
    error_message = "forwarded_ip_position must be FIRST, LAST or ANY."
  }
}

variable "ip_address_versions" {
  default     = ["IPV4"]
  description = "Address versions to create IP sets for in rule group mode. Table rows are routed to the set of the matching version; rows with no matching set are ignored"
  type        = list(string)

  validation {
    condition     = alltrue([for v in var.ip_address_versions : contains(["IPV4", "IPV6"], v)])
    error_message = "ip_address_versions entries must be IPV4 or IPV6."
  }
}

variable "kms_key_arn" {
  default     = null
  description = "KMS key for the blocklist table and Lambda log group. Uses AWS-managed keys when unset"
  type        = string
}

variable "lambda_runtime" {
  default     = "python3.12"
  description = "Lambda runtime for the reconciler"
  type        = string
}

variable "lambda_timeout" {
  default     = 120
  description = "Reconciler timeout in seconds. Each target costs an assume-role plus two WAF calls"
  type        = number
}

variable "log_retention_days" {
  default     = 30
  description = "CloudWatch log retention for the reconciler"
  type        = number
}

variable "max_ip_set_entries" {
  default     = 10000
  description = "Refuse to write an IP set larger than this. Matches the default WAFv2 quota; raise only if the quota has been raised"
  type        = number
}

variable "name" {
  default     = "waf-blocklist"
  description = "Name for the table, reconciler function and IAM role"
  type        = string
}

variable "point_in_time_recovery_enabled" {
  default     = true
  description = "Enable point-in-time recovery on the blocklist table"
  type        = bool
}

variable "rule_group_capacity" {
  default     = 20
  description = "WCU capacity of the rule group. Each IP set rule costs about 1 WCU; changing this replaces the rule group"
  type        = number
}

variable "schedule_expression" {
  default     = "rate(1 day)"
  description = "EventBridge schedule for the expiry sweep. The stream trigger handles edits immediately; this only needs to run often enough to retire expired entries"
  type        = string
}

variable "scope" {
  default     = "REGIONAL"
  description = "Scope of the IP sets and rule group: REGIONAL for ALB/API Gateway web ACLs, CLOUDFRONT for distributions (must be applied in us-east-1)"
  type        = string

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.scope)
    error_message = "scope must be REGIONAL or CLOUDFRONT."
  }
}

variable "share_with_account_ids" {
  default     = []
  description = "Account IDs allowed to reference the rule group from their web ACLs. Ignored when share_with_organization_id is set"
  type        = list(string)

  validation {
    condition     = alltrue([for id in var.share_with_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "share_with_account_ids entries must be 12-digit account IDs."
  }
}

variable "share_with_organization_id" {
  default     = null
  description = "Share the rule group with every account in this organization (o-xxxxxxxxxx) instead of listing accounts"
  type        = string
}

variable "stream_maximum_retry_attempts" {
  default     = 3
  description = "Retries for a failed stream-triggered run before the batch is discarded. The scheduled run picks up anything dropped"
  type        = number
}

variable "tags" {
  default     = {}
  description = "User-defined tags"
  type        = map(string)
}

variable "targets" {
  default     = []
  description = "Fan-out mode: additional WAFv2 IP sets to keep in sync with the table, in this or other accounts. role_arn is the role to assume in the owning account (see modules/target); omit it for IP sets in this account"
  type = list(object({
    ip_set_arn = string
    role_arn   = optional(string)
  }))

  validation {
    condition = alltrue([
      for t in var.targets : can(regex("^arn:[^:]+:wafv2:[^:]+:[0-9]{12}:(regional|global)/ipset/[^/]+/[0-9a-f-]+$", t.ip_set_arn))
    ])
    error_message = "Every ip_set_arn must be a WAFv2 IP set ARN, e.g. arn:aws:wafv2:us-east-1:123456789012:regional/ipset/name/id."
  }

  validation {
    condition     = length(var.targets) == length(distinct([for t in var.targets : t.ip_set_arn]))
    error_message = "Each ip_set_arn may appear only once."
  }
}
