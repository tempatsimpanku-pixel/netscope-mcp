## Summary

<!-- What and why. Link issues: Fixes #123 -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Docs / CI / chore

## Checklist

- [ ] `npx tsc --noEmit`, `npx eslint .`, `npx vitest run` pass locally
- [ ] Tests added/updated (allowlist changes need both allow and deny cases)
- [ ] Does **not** add any write capability; read-only guarantee unchanged (or explained below)
- [ ] No secrets, real IPs, hostnames, customer data in code, fixtures, logs or screenshots (use RFC 5737 / 3849 ranges)
- [ ] `CHANGELOG.md` updated under `Unreleased` (user-visible changes)
- [ ] Docs updated if behavior or config changed

## Security impact

<!-- None / describe: new menus or commands exposed, new network access, config defaults. -->
