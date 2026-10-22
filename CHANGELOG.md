# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `server.json` violated the official MCP registry schema (`description` was 128 characters, the limit is 100). It is now shortened, and `npm run check:server-json` (vendored schema `scripts/server.schema.2025-12-11.json`, Ajv) validates it and checks name/version agree with `package.json`; it runs in CI and in the release workflow.
- `routers.example.yaml` and the README quickstart YAML now pass `netscope-mcp --check` exactly as written (only the documented environment variables are needed): options that point to files on disk (`tls_ca_file`, `ssh.key_file`, `credentials.file`) are shown as commented-out alternatives. A regression test (`test/unit/docs-config.test.ts`) keeps them runnable.
- `/snmp community print` returned empty rows: it now shows the access scope (`addresses`, `security`, `read-access`, `write-access`, `disabled`) and never the community or the passwords; a row with no visible fields says so.
- `mikrotik_batch` shows the device name (or the reference as given) for refused items instead of `?`.
- ARP summaries (recipe `neighbors-map`, snapshot) separate entries with `;` and quote interface names with spaces/dots, so `1. ether1` no longer reads like a list number.
- `monitor <name>` answering `no such item` now names the interface and says it is not a connection problem.

### Added
- Per-call circuit breaker: after a device fails to connect, the remaining items/sections for that device in the same batch or recipe fail immediately instead of waiting for the connect timeout again.
- `redact_ppp_names` setting (default `false`, requires `redact_pii`) to mask PPP login names; the default and its reason are documented in README and `docs/CONFIG.md`.
- "Tested on" compatibility matrix (README, README.id); RouterOS v6 `export` over SSH and 6.49.x are marked not yet tested.
- Regression fixtures for RouterOS v6 and v7 answer shapes, x86 without `/system routerboard`, and switches without PoE (`test/unit/compat.test.ts`).

### Changed
- The corpus-hygiene test no longer spells the forbidden internal names: it compares SHA-256 digests and can read extra words from `NETSCOPE_BANNED_FILE` (outside the repository); it also scans README, docs and the example config.
- `engines.node` lowered to `>=20` for the shipped package (runtime dependencies support it); development tooling (vitest 5) needs Node >= 22. `node:sqlite` is loaded lazily, so only `--snapshot` needs Node >= 22.5 (clear error otherwise). CI tests on Node 22 and 24 and smoke-runs the built package on Node 20.

### Added
- `repository`, `homepage`, `bugs`, `author`, `mcpName` in `package.json` (GitHub user `tempatsimpanku-pixel`) and `server.json` for the official MCP registry.
- Multi-stage, non-root `Dockerfile` (works with `--read-only --tmpfs /tmp`) and a CI job that builds it.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- SECURITY.md "Known limitations" section.

## [0.1.0] - 2026-10-22

### Added
- Initial read-only MCP server for MikroTik RouterOS (stdio transport).
- Command allowlist with RouterOS API sentence construction (`print`, `monitor`, `ping`, `traceroute`, `export hide-sensitive`).
- Secret and PII redaction of tool output.
- Security regression corpus (`test/security/`): 770 allowlist cases, 73 redaction cases, HTTP guard cases, property tests.
- Documentation: README (en/id), recipes, configuration, snapshot, FAQ, SECURITY.md, read-only RouterOS user guide.
- CI, security scanning (gitleaks, CodeQL, dependency review, npm audit, Scorecard) and release workflow with npm provenance and CycloneDX SBOM.

### Fixed
- SSH `export` no longer fails with `ControlPath too long` when `state_dir` is long: control sockets live in a short private directory (`$XDG_RUNTIME_DIR` or `/tmp`, `nsc-<uid>-<hash>`), with a clear error if none fits.
- Docs and refusal messages show `export` with its full menu path (`/ip service export hide-sensitive`); a bare `export` is refused with that hint.
- Locale `id` now also covers the `list_devices` fragments (`alat:`, `export lewat SSH: tidak tersedia`).
- `mikrotik_recipe health` no longer fails as a whole on routers whose interface names contain spaces or `+` (e.g. `sfp+ 1`): SFPs are monitored by their router id (`*N`) or a quoted name, `monitor "sfp+ 1" once` is accepted by the allowlist, and every recipe step reports its own error line instead of cancelling the recipe.
- Our own policy explanations ("refused (secrets, endless stream, …)", the list of allowed menus) are no longer run through the secret scrubber and stay readable; key=value pairs echoed from the caller and all router-originated text are still masked.
- The plain-API warning names the configured port; `list_devices` shows the SNMP port for SwOS/SNMP-only devices instead of an API port.

### Added
- `locale: 'en' | 'id'` (server setting `settings.locale`) and an injectable `messages` dictionary in `NetScopeOptions` for the headers, errors and footers; exported `Messages`, `MESSAGES`, `resolveMessages`.
- `export` over SSH with a password now uses `SSH_ASKPASS` (OpenSSH >= 8.4): no `sshpass` dependency, no password in argv, helper answers password prompts only. Friendlier errors for a missing client, a refused login and host-key problems.

### Security
- SNMP OIDs: every arc must be <= 4294967295 and no surrounding whitespace is accepted (`checkSnmpOid`).
- Redaction now covers snmp community rows without a header, script variable assignments (`:local pw "…"`), free text such as `pw is …`, credential-looking `name=` on header-less `add` rows and PEM private-key blocks.
- Error text masks the value following `password`/`key`/`token`/`secret`/`community`/`psk`.
- HTTP: a same-origin `Origin` header is accepted; any other origin still needs `--allowed-origin`.
- `print … detail` on secret menus is accepted because the safe column list is still forced.
