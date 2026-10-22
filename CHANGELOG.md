# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `engines.node` lowered to `>=20` for the shipped package (runtime dependencies support it); development tooling (vitest 5) needs Node >= 22. `node:sqlite` is loaded lazily, so only `--snapshot` needs Node >= 22.5 (clear error otherwise). CI tests on Node 22 and 24 and smoke-runs the built package on Node 20.

### Added
- `repository`, `homepage`, `bugs`, `author`, `mcpName` in `package.json` (placeholder `OWNER`) and `server.json` for the official MCP registry.
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
