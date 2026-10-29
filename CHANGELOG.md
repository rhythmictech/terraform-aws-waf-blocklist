# Changelog

## 1.1.0 (unreleased)

- Rule group mode, now the default: the hub creates the IP sets and a rule group that blocks on them, shared with other accounts through a WAF permission policy (`share_with_account_ids` or `share_with_organization_id`). Consuming web ACLs reference the rule group instead of needing a per-account role and IP set.
- `forwarded_ip_headers` adds rules that match a viewer-IP header for web ACLs behind CloudFront or a proxy.
- `targets` is now optional; fan-out mode and `modules/target` remain for IP sets a shared rule group cannot reach.
- New `examples/consumer`.

## 1.0.0

- Initial release: DynamoDB-backed WAF IP set blocklist with cross-account reconciler, `modules/target` for spoke accounts, and the `bin/blocklist` CLI.
