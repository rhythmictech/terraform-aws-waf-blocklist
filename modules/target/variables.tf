variable "hub_role_arn" {
  description = "ARN of the reconciler role in the hub account (the root module's reconciler_role_arn output). The role must exist before this module is applied"
  type        = string
}

variable "ip_set_arns" {
  default     = []
  description = "Existing WAFv2 IP sets in this account the reconciler may update. Set lifecycle ignore_changes on their addresses wherever they are managed"
  type        = list(string)
}

variable "ip_sets" {
  default     = {}
  description = "IP sets to create for the reconciler to manage, keyed by name. CLOUDFRONT scope must be applied in us-east-1"
  type = map(object({
    scope              = optional(string, "REGIONAL")
    ip_address_version = optional(string, "IPV4")
    description        = optional(string, "Managed by the WAF blocklist reconciler")
  }))

  validation {
    condition     = alltrue([for s in var.ip_sets : contains(["REGIONAL", "CLOUDFRONT"], s.scope) && contains(["IPV4", "IPV6"], s.ip_address_version)])
    error_message = "scope must be REGIONAL or CLOUDFRONT and ip_address_version must be IPV4 or IPV6."
  }
}

variable "name" {
  default     = "waf-blocklist-target"
  description = "Name of the IAM role the reconciler assumes"
  type        = string
}

variable "tags" {
  default     = {}
  description = "User-defined tags"
  type        = map(string)
}
