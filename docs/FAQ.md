# FAQ

## Is it really read-only?

The server only sends commands that match a deny-by-default allowlist (`print`, `monitor … once`, `/<menu> export hide-sensitive`, `ping`, `traceroute`, on a positive list of menus). Write verbs, scripting, file operations, `/user`, certificates and the like are refused **before** credentials are even loaded or a device is contacted. That is one layer. **Also use a RouterOS account with a read-only policy** ([guide](ROUTEROS-READONLY-USER.md)), so a bug in any tool still cannot change a router. The regression corpus in `test/security/` (770 allowlist cases, 73 redaction cases, HTTP and property tests) runs in CI.

## Can the model see passwords?

Output is redacted by key name (`password`, `secret`, `psk`, `token`, `community`, `key`, …), by pattern (script variables, `pw is …`, PEM private keys, long base64 keys) and by the exact credential values the server holds. Script and `on-event` bodies are masked entirely. Redaction is best-effort on free-form text; the read-only router account is what limits the impact of anything missed. See [SECURITY.md](../SECURITY.md).

## Which RouterOS versions work?

RouterOS v6 and v7 over the binary API / API-SSL, plus SSH for `export`. A REST transport for v7 is planned for v0.2. Please report version-specific behavior as an issue.

## Why not just use plain API on port 8728?

No TLS, so credentials and data cross the network in clear text. It works only with `settings.allow_insecure: true`, and logs a warning. API-SSL on 8729 is the default.

## Does it support VyOS, GenieACS, or SNMPv3?

SNMP v2c and CRS/SwOS switch reads are in v0.1. VyOS read tools, GenieACS read-only tools and SNMPv3 are planned for v0.2.

## Will it lock my router account?

Sessions are reused, commands are queued per device, and a rejected login is never retried automatically (the snapshot worker also waits at least 30 minutes). Test with one router first.

## Can I run it for a team over HTTP?

Yes: `--http` with `NETSCOPE_MCP_TOKEN`. It binds to loopback by default; remote binding needs `--allow-remote` and a TLS reverse proxy. Per-token device ACLs are planned for v0.3, so every holder of the token sees every configured device.

## Where do credentials live?

In environment variables named in `routers.yaml`, or in a `0600` credentials file. Never in the YAML itself, never in the snapshot, never in logs.

## The snapshot says STALE. What now?

Data older than 30 minutes is flagged. Check that the router is reachable, then use a live tool or recipe. See [SNAPSHOT.md](SNAPSHOT.md).

## Why is `ping` refusing my target?

Targets must be literal IP addresses (no host names). Loopback, link-local, multicast, broadcast and unspecified addresses are refused in every textual form, including IPv4-mapped IPv6 (`::ffff:127.0.0.1`). `probe.deny_cidrs` / `probe.allow_cidrs` narrow it further.

## A command was denied. Can I allow it?

No, by design. If a legitimate read-only command is missing, open an issue with the command and RouterOS version.

## Is this affiliated with MikroTik?

No. MikroTik and RouterOS are trademarks of their respective owners.
