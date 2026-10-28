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
ticket, who added it and when it expires, and a Lambda keeps any number of
WAFv2 IP sets across any number of accounts equal to the active rows.

## How it works

```
 ops account                                  workload accounts
 ┌──────────────────────────────────┐         ┌────────────────────────┐
 │ DynamoDB table ──stream──┐       │  assume │ IAM role (modules/     │
 │   cidr, reason, ticket,  ▼       │  role   │   target)              │
 │   added_by, expires_at  Lambda ──┼────────▶│   └─ UpdateIPSet       │
 │ EventBridge (daily) ─────┘       │         │ WAFv2 IP set ◀─ web ACL│
 └──────────────────────────────────┘         └────────────────────────┘
```

* **Table** (`cidr` is the key): `reason`, `added_by`, `added_at`, optional
  `ticket`, optional `expires_at`. No `expires_at` means permanent.
* **Reconciler**: reads the whole table, keeps rows whose `expires_at` is unset
  or in the future, and replaces each target IP set's addresses when they
  differ. IPv4 and IPv6 rows are routed to sets of the matching version. It
  runs from the table's stream (seconds after any edit) and on a schedule
  (default daily) so expired entries are retired without anyone remembering.
  Targets are reconciled independently and a failure on any of them errors the
  run, which trips the included CloudWatch alarm.
* **Targets** are IP set ARNs plus an optional role to assume. Same-account IP
  sets need no role. `modules/target` creates the role (and optionally the IP
  sets) in each spoke account.
* **`bin/blocklist`** is the write path. It validates and canonicalizes CIDRs,
  defaults the expiry to 90 days, requires a reason, and records the caller.
  `remove` expires a row instead of deleting it so the history survives.

DynamoDB TTL is deliberately not used for expiry: it is best-effort with
multi-hour lag and would erase the audit trail.

## Usage

Hub, in the account that should own the list:

```hcl
module "blocklist" {
  source  = "rhythmictech/waf-blocklist/aws"

  targets = [
    {
      ip_set_arn = "arn:aws:wafv2:us-east-1:222222222222:regional/ipset/manual-block-prod/..."
      role_arn   = "arn:aws:iam::222222222222:role/waf-blocklist-target"
    },
    {
      # same account as the hub, no role needed
      ip_set_arn = aws_wafv2_ip_set.cloudfront_block.arn
    },
  ]

  alarm_sns_topic_arns = [aws_sns_topic.ops_alerts.arn]
}
```

Spoke, once per account that owns an IP set (apply after the hub so the
reconciler role exists):

```hcl
module "blocklist_target" {
  source  = "rhythmictech/waf-blocklist/aws//modules/target"

  hub_role_arn = "arn:aws:iam::111111111111:role/waf-blocklist-reconciler"
  ip_set_arns  = [aws_wafv2_ip_set.manual_block.arn]
}
```

Any IP set the reconciler manages must ignore address changes wherever it is
defined, or the next Terraform apply there will empty it:

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

See `examples/hub` and `examples/target` for the multi-account layout this was
built for: one ops account, one IP set per environment account.

## Migrating an existing list

1. Apply the hub with the existing IP sets as targets.
2. Apply `modules/target` in each owning account.
3. Add every current address with `bin/blocklist add`, with the best reason you
   have. The first reconcile replaces the set with exactly those rows, so do
   this before step 4 or the set will be emptied.
4. Switch the IP set's `addresses` to `[]` with `ignore_changes` and remove the
   old tfvars list.

## About
Rhythmic is an AWS Managed Services Provider. We rely heavily on automation to deliver our services, ingesting configuration, event and state information from AWS via listeners (e.g., EventBridge and SNS), services (e.g., Anomaly Detection), and APIs via custom scripts (e.g., Trusted Advisor).

We open source the vast majority of the resources we use to deliver our managed services because transparency is one of our principles.

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.5.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.40 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | 2.8.1 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.71.0 |

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
| [aws_cloudwatch_metric_alarm.reconciler_errors](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_dynamodb_table.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |
| [aws_iam_role.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_event_source_mapping.stream](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_event_source_mapping) | resource |
| [aws_lambda_function.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [archive_file.reconciler](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_iam_policy_document.lambda_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.reconciler](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_sns_topic_arns"></a> [alarm\_sns\_topic\_arns](#input\_alarm\_sns\_topic\_arns) | SNS topics to notify when a reconcile run fails (any target could not be updated) | `list(string)` | `[]` | no |
| <a name="input_deletion_protection_enabled"></a> [deletion\_protection\_enabled](#input\_deletion\_protection\_enabled) | Enable DynamoDB deletion protection on the blocklist table | `bool` | `true` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | KMS key for the blocklist table and Lambda log group. Uses AWS-managed keys when unset | `string` | `null` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | Lambda runtime for the reconciler | `string` | `"python3.12"` | no |
| <a name="input_lambda_timeout"></a> [lambda\_timeout](#input\_lambda\_timeout) | Reconciler timeout in seconds. Each target costs an assume-role plus two WAF calls | `number` | `120` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | CloudWatch log retention for the reconciler | `number` | `30` | no |
| <a name="input_max_ip_set_entries"></a> [max\_ip\_set\_entries](#input\_max\_ip\_set\_entries) | Refuse to write an IP set larger than this. Matches the default WAFv2 quota; raise only if the quota has been raised | `number` | `10000` | no |
| <a name="input_name"></a> [name](#input\_name) | Name for the table, reconciler function and IAM role | `string` | `"waf-blocklist"` | no |
| <a name="input_point_in_time_recovery_enabled"></a> [point\_in\_time\_recovery\_enabled](#input\_point\_in\_time\_recovery\_enabled) | Enable point-in-time recovery on the blocklist table | `bool` | `true` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | EventBridge schedule for the expiry sweep. The stream trigger handles edits immediately; this only needs to run often enough to retire expired entries | `string` | `"rate(1 day)"` | no |
| <a name="input_stream_maximum_retry_attempts"></a> [stream\_maximum\_retry\_attempts](#input\_stream\_maximum\_retry\_attempts) | Retries for a failed stream-triggered run before the batch is discarded. The scheduled run picks up anything dropped | `number` | `3` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | User-defined tags | `map(string)` | `{}` | no |
| <a name="input_targets"></a> [targets](#input\_targets) | WAFv2 IP sets to keep in sync with the table. role\_arn is the role to assume in the owning account (see modules/target); omit it for IP sets in this account | <pre>list(object({<br/>    ip_set_arn = string<br/>    role_arn   = optional(string)<br/>  }))</pre> | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_reconciler_function_arn"></a> [reconciler\_function\_arn](#output\_reconciler\_function\_arn) | ARN of the reconciler Lambda |
| <a name="output_reconciler_role_arn"></a> [reconciler\_role\_arn](#output\_reconciler\_role\_arn) | ARN of the reconciler execution role. Pass this as hub\_role\_arn to modules/target in each account that owns an IP set |
| <a name="output_table_arn"></a> [table\_arn](#output\_table\_arn) | ARN of the blocklist DynamoDB table |
| <a name="output_table_name"></a> [table\_name](#output\_table\_name) | Name of the blocklist DynamoDB table (set BLOCKLIST\_TABLE to this for bin/blocklist) |
<!-- END_TF_DOCS -->