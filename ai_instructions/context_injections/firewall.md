# Firewall allowlist rules

Firewall files are network policy, not convenience hints. Broad or all-inclusive
DNS rules are disallowed by default.

Do not add wildcard or catch-all entries such as:

- `.*`
- `.*\.example\.com`
- `.*\.cloudfront\.net`
- broad CDN/provider domains that allow unrelated tenants

Prefer the narrowest exact hostname required by the setup. If a broad DNS rule
cannot be avoided, stop and ask the user for explicit confirmation before adding
or keeping it.
