# Contributing

Thanks for helping. netscope-mcp is a **read-only** MCP server for RouterOS; the security model matters more than features.

## Setup

```sh
node -v        # 22 or 24
npm ci
npx tsc --noEmit && npx eslint . && npx vitest run && npm run build
```

## Rules

- **Read-only is a hard requirement.** Changes that add write/config capability are rejected. Allowlist changes need tests for both allowed and denied forms.
- **No real data.** Fixtures and docs use only RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), private ASNs (64512–65534), MACs `02:00:00:…`, and names like `rtr-core-1`. CI runs gitleaks on the full history.
- Keep PRs small and focused; update `CHANGELOG.md` under `Unreleased`.
- Commit messages: imperative mood (`fix: reject fullwidth slash in menu path`). Sign off with `git commit -s` (DCO).
- Automated Codex review comments are advisory only; a human maintainer approves every PR.

## Security issues

Do not open a public issue. See `SECURITY.md` and use private vulnerability reporting.

## License

By contributing you agree your contribution is licensed under Apache-2.0.
