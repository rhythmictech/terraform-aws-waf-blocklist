# target

Deploy once per account that owns WAF IP sets the blocklist should feed. Creates
the IAM role the hub reconciler assumes, scoped to `wafv2:GetIPSet` and
`wafv2:UpdateIPSet` on the listed IP sets, and optionally the IP sets themselves.

The hub role must already exist (apply the root module first) because IAM
validates role principals in trust policies.

```hcl
module "blocklist_target" {
  source = "rhythmictech/waf-blocklist/aws//modules/target"

  hub_role_arn = "arn:aws:iam::111111111111:role/waf-blocklist-reconciler"

  # existing set, managed elsewhere with lifecycle { ignore_changes = [addresses] }
  ip_set_arns = [aws_wafv2_ip_set.manual_block.arn]

  # or let the module create one
  ip_sets = {
    "manual-block-prod" = {}
  }
}
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.40 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.40 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_tags"></a> [tags](#module\_tags) | rhythmictech/tags/terraform | ~> 1.1.1 |

## Resources

| Name | Type |
|------|------|
| [aws_iam_role.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_wafv2_ip_set.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_iam_policy_document.assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_hub_role_arn"></a> [hub\_role\_arn](#input\_hub\_role\_arn) | ARN of the reconciler role in the hub account (the root module's reconciler\_role\_arn output). The role must exist before this module is applied | `string` | n/a | yes |
| <a name="input_ip_set_arns"></a> [ip\_set\_arns](#input\_ip\_set\_arns) | Existing WAFv2 IP sets in this account the reconciler may update. Set lifecycle ignore\_changes on their addresses wherever they are managed | `list(string)` | `[]` | no |
| <a name="input_ip_sets"></a> [ip\_sets](#input\_ip\_sets) | IP sets to create for the reconciler to manage, keyed by name. CLOUDFRONT scope must be applied in us-east-1 | <pre>map(object({<br/>    scope              = optional(string, "REGIONAL")<br/>    ip_address_version = optional(string, "IPV4")<br/>    description        = optional(string, "Managed by the WAF blocklist reconciler")<br/>  }))</pre> | `{}` | no |
| <a name="input_name"></a> [name](#input\_name) | Name of the IAM role the reconciler assumes | `string` | `"waf-blocklist-target"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | User-defined tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_created_ip_sets"></a> [created\_ip\_sets](#output\_created\_ip\_sets) | Map of created IP set name to its ARN and id |
| <a name="output_ip_set_arns"></a> [ip\_set\_arns](#output\_ip\_set\_arns) | ARNs of every IP set the role may update (created and pre-existing). Each goes into the root module's targets with role\_arn set to role\_arn |
| <a name="output_role_arn"></a> [role\_arn](#output\_role\_arn) | ARN of the role the reconciler assumes for this account |
<!-- END_TF_DOCS -->