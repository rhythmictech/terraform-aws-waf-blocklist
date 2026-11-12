# terraform-aws-waf-blocklist
A WAF IP set blocklist with a reason and an expiry for every entry.

[![tflint](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/tflint.yaml/badge.svg)](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/tflint.yaml)
[![trivy](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/trivy.yaml/badge.svg)](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/trivy.yaml)
[![yamllint](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/yamllint.yaml/badge.svg)](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/yamllint.yaml)
[![misspell](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/misspell.yaml/badge.svg)](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/misspell.yaml)
[![pre-commit-check](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/rhythmictech/terraform-aws-waf-blocklist/actions/workflows/pre-commit.yaml)
<a href="https://twitter.com/intent/follow?screen_name=RhythmicTech"><img src="https://img.shields.io/twitter/follow/RhythmicTech?style=social&logo=twitter" alt="follow on Twitter"></a>

Hand-maintained WAF IP sets rot: addresses get added during an incident and
nobody remembers why they are still there a year later. This module makes a
DynamoDB table the source of truth, where every row carries the reason, the
ticket, who added it and when it expires, and keeps WAF in sync with the
active rows across any number of accounts.

## How it works

```
 hub account                                       consumer accounts
 ┌────────────────────────────────────────┐        ┌──────────────────────────┐
 │ DynamoDB table ──stream──┐             │        │ web ACL                  │
 │   cidr, reason, ticket,  ▼             │        │   rule_group_reference ──┼──┐
 │   added_by, expires_at  Lambda         │        └──────────────────────────┘  │
 │ EventBridge (daily) ─────┘  │          │        ┌──────────────────────────┐  │
 │                             ▼          │        │ web ACL                  │  │
 │ IP set ◀── rule group (shared) ◀───────┼────────┼── rule_group_reference   │  │
 │                                        │        └──────────────────────────┘◀─┘
 └────────────────────────────────────────┘
```

* **Table** (`cidr` is the key): `reason`, `added_by`, `added_at`, optional
  `ticket`, optional `expires_at`. No `expires_at` means permanent.
* **Reconciler**: reads the whole table, keeps rows whose `expires_at` is unset
  or in the future, and replaces each IP set's addresses when they differ.
  IPv4 and IPv6 rows are routed to sets of the matching version. It runs from
  the table's stream (seconds after any edit) and on a schedule (default daily)
  so expired entries are retired without anyone remembering. A failure errors
  the run, which trips the included CloudWatch alarm.
* **Rule group mode (default)**: the hub owns the IP sets and a rule group
  that blocks on them, shared with other accounts through a WAF permission
  policy. Each consuming web ACL adds one `rule_group_reference_statement`.
  One IP set write reaches every web ACL at once, there are no cross-account
  roles, and each ACL can override the rules to count. With
  `forwarded_ip_headers` the rule group also matches a viewer-IP header for
  ACLs behind CloudFront or a proxy; a missing header is simply no match.
* **Fan-out mode**: for IP sets the hub cannot reach through a shared rule
  group (another partition, a CLOUDFRONT-scope set when the hub is REGIONAL),
  `targets` lists IP set ARNs plus a role to assume, and `modules/target`
  creates that role in the owning account. Both modes can run together.
* **`bin/blocklist`** is the write path. It validates and canonicalizes CIDRs,
  defaults the expiry to 90 days, requires a reason, and records the caller.
  `remove` expires a row instead of deleting it so the history survives.

DynamoDB TTL is deliberately not used for expiry: it is best-effort with
multi-hour lag and would erase the audit trail.

There is no Terraform resource for the WAF rule group permission policy, so
the hub applies it with a one-shot Lambda invoked through
`aws_lambda_invocation`. That keeps the call on the provider's credentials
(usually an assumed role) rather than the operator's shell.

## Usage

Hub, in the account that should own the list:

```hcl
module "blocklist" {
  source  = "rhythmictech/waf-blocklist/aws"

  share_with_account_ids = ["222222222222", "333333333333"]
  # or: share_with_organization_id = "o-xxxxxxxxxx"

  # only if some web ACLs sit behind CloudFront or a proxy
  forwarded_ip_headers = ["x-client-ip"]

  alarm_sns_topic_arns = [aws_sns_topic.ops_alerts.arn]
}
```

Each consuming web ACL, in any shared-with account (same region and scope):

```hcl
rule {
  name     = "shared-blocklist"
  priority = 0

  override_action {
    none {}
  }

  statement {
    rule_group_reference_statement {
      arn = "arn:aws:wafv2:us-east-1:111111111111:regional/rulegroup/waf-blocklist/..."
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "shared-blocklist"
    sampled_requests_enabled   = true
  }
}
```

Shared rule groups do not appear in the consumer's WAF console listing, but
the ARN resolves. The hub's `rule_group_rule_names` output gives the names to
use in `rule_action_override` for a count-only rollout.

Fan-out mode, for IP sets outside the rule group's reach:

```hcl
module "blocklist" {
  source  = "rhythmictech/waf-blocklist/aws"

  create_rule_group = false   # or leave true and use both

  targets = [
    {
      ip_set_arn = "arn:aws:wafv2:us-east-1:222222222222:regional/ipset/manual-block/..."
      role_arn   = "arn:aws:iam::222222222222:role/waf-blocklist-target"
    },
  ]
}

# in account 222222222222, after the hub exists
module "blocklist_target" {
  source  = "rhythmictech/waf-blocklist/aws//modules/target"

  hub_role_arn = "arn:aws:iam::111111111111:role/waf-blocklist-reconciler"
  ip_set_arns  = [aws_wafv2_ip_set.manual_block.arn]
}
```

Any IP set the reconciler writes must ignore address changes wherever it is
defined, or the next apply there will empty it:

```hcl
resource "aws_wafv2_ip_set" "manual_block" {
  # ...
  addresses = []

  lifecycle {
    ignore_changes = [addresses]
  }
}
```

Then manage entries:

```
export BLOCKLIST_TABLE=waf-blocklist
bin/blocklist add 203.0.113.7 --reason "credential stuffing against /login" --ticket OPS-123
bin/blocklist add 198.51.100.0/24 --reason "scanner range" --expires 7d
bin/blocklist list
bin/blocklist remove 203.0.113.7 --reason "customer confirmed legitimate"
```

See `examples/hub` and `examples/consumer` for the multi-account layout this
was built for: one ops account, web ACLs in one account per environment.
`examples/target` shows fan-out mode.

## Migrating an existing list

1. Apply the hub, sharing with the accounts that own the web ACLs.
2. Add every current address with `bin/blocklist add`, with the best reason you
   have. The reconciler fills the hub IP set within seconds.
3. In each web ACL, add the `rule_group_reference_statement` rule. Use
   `rule_action_override` to count first if you want to compare against the
   old rule's metrics.
4. Remove the old IP set rule and the tfvars list it was fed from.

## About
Rhythmic is an AWS Managed Services Provider. We rely heavily on automation to deliver our services, ingesting configuration, event and state information from AWS via listeners (e.g., EventBridge and SNS), services (e.g., Anomaly Detection), and APIs via custom scripts (e.g., Trusted Advisor).

We open source the vast majority of the resources we use to deliver our managed services because transparency is one of our principles.

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.5.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.40 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | >= 2.5.0 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.40 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_tags"></a> [tags](#module\_tags) | rhythmictech/tags/terraform | ~> 1.1.1 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_metric_alarm.reconciler_errors](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_dynamodb_table.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |
| [aws_iam_role.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_event_source_mapping.stream](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_event_source_mapping) | resource |
| [aws_lambda_function.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_invocation.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_invocation) | resource |
| [aws_lambda_permission.schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_wafv2_ip_set.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_rule_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_rule_group) | resource |
| [archive_file.reconciler](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.share](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_iam_policy_document.lambda_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.share_lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_sns_topic_arns"></a> [alarm\_sns\_topic\_arns](#input\_alarm\_sns\_topic\_arns) | SNS topics to notify when a reconcile run fails (any target could not be updated) | `list(string)` | `[]` | no |
| <a name="input_create_rule_group"></a> [create\_rule\_group](#input\_create\_rule\_group) | Create IP sets and a rule group in this account that web ACLs reference directly (see share\_with\_account\_ids). Set false to run in fan-out mode with targets only | `bool` | `true` | no |
| <a name="input_deletion_protection_enabled"></a> [deletion\_protection\_enabled](#input\_deletion\_protection\_enabled) | Enable DynamoDB deletion protection on the blocklist table | `bool` | `true` | no |
| <a name="input_forwarded_ip_headers"></a> [forwarded\_ip\_headers](#input\_forwarded\_ip\_headers) | Headers carrying the client IP when the web ACL sits behind CloudFront or a proxy, e.g. ["x-client-ip"]. Each adds a rule to the rule group that matches the header instead of the connection source | `list(string)` | `[]` | no |
| <a name="input_forwarded_ip_position"></a> [forwarded\_ip\_position](#input\_forwarded\_ip\_position) | Which address in a forwarded-IP header to match: FIRST, LAST or ANY | `string` | `"FIRST"` | no |
| <a name="input_ip_address_versions"></a> [ip\_address\_versions](#input\_ip\_address\_versions) | Address versions to create IP sets for in rule group mode. Table rows are routed to the set of the matching version; rows with no matching set are ignored | `list(string)` | <pre>[<br/>  "IPV4"<br/>]</pre> | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | KMS key for the blocklist table and Lambda log group. Uses AWS-managed keys when unset | `string` | `null` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | Lambda runtime for the reconciler | `string` | `"python3.12"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | Reconciler timeout in seconds. Each target costs an assume-role plus two WAF calls | `number` | `120` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | CloudWatch log retention for the reconciler | `number` | `30` | no |
| <a name="input_max_ip_set_entries"></a> [max\_ip\_set\_entries](#input\_max\_ip\_set\_entries) | Refuse to write an IP set larger than this. Matches the default WAFv2 quota; raise only if the quota has been raised | `number` | `10000` | no |
| <a name="input_name"></a> [name](#input\_name) | Name for the table, reconciler function and IAM role | `string` | `"waf-blocklist"` | no |
| <a name="input_point_in_time_recovery_enabled"></a> [point\_in\_time\_recovery\_enabled](#input\_point\_in\_time\_recovery\_enabled) | Enable point-in-time recovery on the blocklist table | `bool` | `true` | no |
| <a name="input_rule_group_capacity"></a> [rule\_group\_capacity](#input\_rule\_group\_capacity) | WCU capacity of the rule group. Each IP set rule costs about 1 WCU; changing this replaces the rule group | `number` | `20` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | EventBridge schedule for the expiry sweep. The stream trigger handles edits immediately; this only needs to run often enough to retire expired entries | `string` | `"rate(1 day)"` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Scope of the IP sets and rule group: REGIONAL for ALB/API Gateway web ACLs, CLOUDFRONT for distributions (must be applied in us-east-1) | `string` | `"REGIONAL"` | no |
| <a name="input_share_with_account_ids"></a> [share\_with\_account\_ids](#input\_share\_with\_account\_ids) | Account IDs allowed to reference the rule group from their web ACLs. Ignored when share\_with\_organization\_id is set | `list(string)` | `[]` | no |
| <a name="input_share_with_organization_id"></a> [share\_with\_organization\_id](#input\_share\_with\_organization\_id) | Share the rule group with every account in this organization (o-xxxxxxxxxx) instead of listing accounts | `string` | `null` | no |
| <a name="input_stream_maximum_retry_attempts"></a> [stream\_maximum\_retry\_attempts](#input\_stream\_maximum\_retry\_attempts) | Retries for a failed stream-triggered run before the batch is discarded. The scheduled run picks up anything dropped | `number` | `3` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | User-defined tags | `map(string)` | `{}` | no |
| <a name="input_targets"></a> [targets](#input\_targets) | Fan-out mode: additional WAFv2 IP sets to keep in sync with the table, in this or other accounts. role\_arn is the role to assume in the owning account (see modules/target); omit it for IP sets in this account | <pre>list(object({<br/>    ip_set_arn = string<br/>    role_arn   = optional(string)<br/>  }))</pre> | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ip_set_arns"></a> [ip\_set\_arns](#output\_ip\_set\_arns) | Map of address version to the ARN of the IP set the hub created (rule group mode) |
| <a name="output_permission_policy_json"></a> [permission\_policy\_json](#output\_permission\_policy\_json) | The sharing policy applied to the rule group, for reference |
| <a name="output_reconciler_function_arn"></a> [reconciler\_function\_arn](#output\_reconciler\_function\_arn) | ARN of the reconciler Lambda |
| <a name="output_reconciler_role_arn"></a> [reconciler\_role\_arn](#output\_reconciler\_role\_arn) | ARN of the reconciler execution role. Pass this as hub\_role\_arn to modules/target in each account that owns an IP set |
| <a name="output_rule_group_arn"></a> [rule\_group\_arn](#output\_rule\_group\_arn) | ARN of the shared rule group. Reference it from each web ACL with rule\_group\_reference\_statement |
| <a name="output_rule_group_rule_names"></a> [rule\_group\_rule\_names](#output\_rule\_group\_rule\_names) | Names of the rules inside the rule group, for rule\_action\_override in consuming web ACLs |
| <a name="output_table_arn"></a> [table\_arn](#output\_table\_arn) | ARN of the blocklist DynamoDB table |
| <a name="output_table_name"></a> [table\_name](#output\_table\_name) | Name of the blocklist DynamoDB table (set BLOCKLIST\_TABLE to this for bin/blocklist) |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
