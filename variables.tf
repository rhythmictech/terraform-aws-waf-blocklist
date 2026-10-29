variable "alarm_sns_topic_arns" {
  default     = []
  description = "SNS topics to notify when a reconcile run fails (any target could not be updated)"
  type        = list(string)
}

variable "deletion_protection_enabled" {
  default     = true
  description = "Enable DynamoDB deletion protection on the blocklist table"
  type        = bool
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

variable "schedule_expression" {
  default     = "rate(1 day)"
  description = "EventBridge schedule for the expiry sweep. The stream trigger handles edits immediately; this only needs to run often enough to retire expired entries"
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
  description = "WAFv2 IP sets to keep in sync with the table. role_arn is the role to assume in the owning account (see modules/target); omit it for IP sets in this account"
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
