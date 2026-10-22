# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- Initial read-only MCP server for MikroTik RouterOS (stdio transport).
- Command allowlist with RouterOS API sentence construction (`print`, `monitor`, `ping`, `traceroute`, `export hide-sensitive`).
- Secret and PII redaction of tool output.
- CI, security scanning (gitleaks, CodeQL, dependency review, npm audit, Scorecard) and release workflow with npm provenance and CycloneDX SBOM.
