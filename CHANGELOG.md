# Changelog

## 1.2.2

- Compare WAF IP set contents in canonical form. WAF returns IPv6 addresses fully expanded (`2001:0db8:0001:0000:…/48`) while the table holds the compressed form, so the reconciler rewrote every IPv6 IP set on every run, and the Tor exit sync rewrote its IPv6 set every hour, even when nothing had changed. IPv4 sets were not affected. No Terraform change.

## 1.2.1

- Keep the IP set description when the reconciler or the Tor exit sync updates addresses. `UpdateIPSet` replaces the whole IP set, so the calls that omitted `Description` cleared it, and every later `terraform plan` showed the description being added back. An IP set that already lost its description gets it back on the next apply and keeps it from then on.

## 1.2.0

- Optional Tor exit-node feed (`tor_exit_enabled`, off by default). Adds Tor exit IP sets and `tor-exit-*` rules to the shared rule group, kept current by a scheduled Lambda that unions the Tor Project's bulk exit list with Onionoo's running exits. `tor_exit_action` sets block or count, `tor_exit_min_count` stops a truncated download from shrinking the sets, and a CloudWatch alarm reports sustained sync failures to `alarm_sns_topic_arns`. New outputs `tor_exit_ip_set_arns` and `tor_exit_rule_names`.
- Enabling the feed adds rules to the existing rule group in place; it reaches every web ACL that references the rule group without a consumer change. Existing rule names and priorities are unchanged.
- Development and CI now run on the Terraform 1.6 line (`.terraform-version`). The module's own floor is unchanged at `>= 1.5`.
- `bin/blocklist` declares boto3 as PEP 723 inline script metadata and uses a `uv run --script` shebang, so it runs without a pre-installed boto3 wherever uv is present (`uv run bin/blocklist …` also works).


## 1.1.2

- Order the sharing invocation after the share role's policy and retry on AccessDenied, so replacing the rule group (e.g. a capacity change) re-shares it in one apply instead of failing on IAM propagation.

## 1.1.1

- Send the rule group permission policy to WAF as compact JSON. The pretty-printed document from `aws_iam_policy_document` failed WAF's validation pattern, so sharing never applied.

## 1.1.0 (unreleased)

- Rule group mode, now the default: the hub creates the IP sets and a rule group that blocks on them, shared with other accounts through a WAF permission policy (`share_with_account_ids` or `share_with_organization_id`). Consuming web ACLs reference the rule group instead of needing a per-account role and IP set.
- `forwarded_ip_headers` adds rules that match a viewer-IP header for web ACLs behind CloudFront or a proxy.
- `targets` is now optional; fan-out mode and `modules/target` remain for IP sets a shared rule group cannot reach.
- New `examples/consumer`.

## 1.0.0

- Initial release: DynamoDB-backed WAF IP set blocklist with cross-account reconciler, `modules/target` for spoke accounts, and the `bin/blocklist` CLI.
