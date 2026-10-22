# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- Initial read-only MCP server for MikroTik RouterOS (stdio transport).
- Command allowlist with RouterOS API sentence construction (`print`, `monitor`, `ping`, `traceroute`, `export hide-sensitive`).
- Secret and PII redaction of tool output.
- Security regression corpus (`test/security/`): 770 allowlist cases, 73 redaction cases, HTTP guard cases, property tests.
- Documentation: README (en/id), recipes, configuration, snapshot, FAQ, SECURITY.md, read-only RouterOS user guide.
- CI, security scanning (gitleaks, CodeQL, dependency review, npm audit, Scorecard) and release workflow with npm provenance and CycloneDX SBOM.

### Security
- SNMP OIDs: every arc must be <= 4294967295 and no surrounding whitespace is accepted (`checkSnmpOid`).
- Redaction now covers snmp community rows without a header, script variable assignments (`:local pw "…"`), free text such as `pw is …`, credential-looking `name=` on header-less `add` rows and PEM private-key blocks.
- Error text masks the value following `password`/`key`/`token`/`secret`/`community`/`psk`.
- HTTP: a same-origin `Origin` header is accepted; any other origin still needs `--allowed-origin`.
- `print … detail` on secret menus is accepted because the safe column list is still forced.
