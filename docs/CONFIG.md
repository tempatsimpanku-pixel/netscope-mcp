# Configuration

## Command line

```text
netscope-mcp --config routers.yaml [options]

  --config <file>        routers file                                   [required]
  --http <host:port>     serve Streamable HTTP at /mcp instead of stdio (e.g. 127.0.0.1:8080)
  --allow-remote         allow binding a non-loopback address (put a TLS proxy in front)
  --allowed-host <h>     extra accepted Host header value (repeatable)
  --allowed-origin <o>   accepted Origin value (repeatable; browsers are refused by default)
  --snapshot <file>      enable periodic snapshots stored in this SQLite file (mode 0600)
  --audit-log <target>   stderr (default) | off | <file>
  --check                validate the configuration and exit
  -h, --help | -v, --version
```

Node.js 24 or newer is required. Run `--check` after every edit: errors name the offending key, never its value.

## `routers.yaml`

The file has three top-level keys: `settings`, `defaults`, `routers` (unknown keys are rejected).

```yaml
settings:
  redact_pii: true
  allow_insecure: false
  allow_local_probe: false
  max_inflight: 10
  probe: { deny_cidrs: [], allow_cidrs: [] }
  snapshot: { interval_min: 10, store_customer_data: false }
  audit_log: stderr
  locale: en                            # en | id
  # state_dir: /var/lib/netscope-mcp     # default: $XDG_STATE_HOME/netscope-mcp or ~/.local/state/netscope-mcp

defaults:
  transport: api-ssl
  verify_tls: true
  # timeout_ms: 8000                      # 1000-120000

routers:
  - id: rtr-core-1
    host: 192.0.2.10
    port: 8729
    family: routeros
    group: backbone
    labels: { role: core }
    tls_fingerprint256: "00:11:...:FF"
    credentials: { user_env: ROS_CORE1_USER, pass_env: ROS_CORE1_PASS }
    ssh: { port: 22, key_file: /etc/netscope-mcp/ssh/core-1.key, host_key_sha256: "SHA256:..." }
    snmp: { community_env: SNMP_CORE1_COMMUNITY }
    fallback: { host: 198.51.100.1, port: 28729, label: "management port-forward" }
```

### `settings`

| Key | Default | Description |
|---|---|---|
| `redact_pii` | `true` | Mask the device part of customer MAC addresses and free-text customer columns (`comment`, `host-name`, `username`…); `/log` is refused while on. |
| `allow_insecure` | `false` | Needed for plain API (8728) and for `verify_tls: false` without a pinned fingerprint. A warning is logged per such router. |
| `allow_local_probe` | `false` | Allow `ping`/`traceroute` with `from: "local"` (the MCP host itself). |
| `max_inflight` | `10` | Concurrent device commands (1-50). |
| `probe.deny_cidrs` / `probe.allow_cidrs` | `[]` | Probe targets inside a deny CIDR are refused; when `allow_cidrs` is non-empty, targets must fall inside it. |
| `snapshot.interval_min` | `10` | Minutes between snapshot cycles (2-1440). See [SNAPSHOT.md](SNAPSHOT.md). |
| `snapshot.store_customer_data` | `false` | Also store PPP names/addresses/caller-ids in the snapshot file. |
| `audit_log` | `stderr` | `stderr`, `off`, or a file path (created with mode 0600). `--audit-log` overrides it. |
| `locale` | `en` | Language of the sentences the server writes itself: headers, errors, footers (`refused`/`ditolak`, `failed`/`gagal`, `ERROR`/`GALAT`, `no rows`/`tidak ada baris`, `no snapshot yet`/`belum ada snapshot`…). Router output and the explanation of *why* a command was denied stay in English. |
| `state_dir` | see above | SSH control sockets, the askpass helper and pinned host keys (mode 0700). |

### `defaults` and per-router overrides

`defaults` accepts `transport`, `verify_tls`, `timeout_ms`; a router may override `transport` and `verify_tls`.

### `routers[]`

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique (case-insensitive); letters, digits, `. _ -`; used in every tool call. |
| `name` | no | Display name (defaults to `id`). |
| `host` | yes | IP address or host name. |
| `port` | no | `8729` for `api-ssl`, `8728` for `api`, `161`-style SNMP port via `snmp.port`. |
| `family` | no (`routeros`) | `routeros`, `switch` (CRS), `swos` (SNMP only), `snmp`. |
| `group`, `labels` | no | Filtering in `list_devices`; `labels.role: core` makes the snapshot worker poll it less often. |
| `transport` | no | `api-ssl` (default, TCP 8729) or `api` (TCP 8728, plain text, needs `allow_insecure`). |
| `verify_tls` | no | Default `true`. `false` needs `allow_insecure` unless a fingerprint is pinned. |
| `tls_ca_file` | no | PEM CA to verify the router certificate. |
| `tls_fingerprint256` | no | SHA-256 fingerprint (32 hex bytes, colons optional) to pin a self-signed certificate. |
| `credentials` | yes | Either `user_env` + `pass_env` (+ optional `community_env`) **or** `file` (mode 0600, lines `user=`, `password=`, `community=`). Never both. SNMP-only devices need `community_env`. |
| `ssh` | no | Only used for `/<menu> export hide-sensitive`: `port` (`null` = export unavailable), `key_file`, `host_key_sha256` (`SHA256:…`; without it the key is trust-on-first-use in `state_dir`). |
| `snmp` | no | `port`, `community_env`. |
| `fallback` | no | Alternate address tried **once, only when the direct address does not connect** (never after a rejected login). Shown in the output as its `label`. |

Relative file paths are resolved against the directory of the routers file. Environment variables must be set when the server starts. Credentials files must not be readable by group/others: the server refuses to start otherwise (`chmod 600`).

## Transports to the router

| Transport | Port | Notes |
|---|---|---|
| `api-ssl` (recommended) | 8729 | TLS with certificate verification; CA file or fingerprint pin. |
| `api` | 8728 | **No TLS.** Credentials travel in clear text. Only on an isolated management network, with `allow_insecure: true`. |
| SSH | `ssh.port` | Only for `/<menu> export hide-sensitive`; host key always checked (pinned, or trust-on-first-use). Any port works (`ssh.port` is never guessed). Prefer `key_file`. Without a key the router password is given to OpenSSH through `SSH_ASKPASS` (OpenSSH 8.4 or newer, no `sshpass` needed): see below. |

**SSH with a password.** The server writes a fixed helper (`askpass.sh`, mode 0700, no secret inside) to the SSH state directory and starts `ssh` with `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force`. The password is in the environment of that one child process only: not in the command line (`/proc/<pid>/cmdline`), not on disk, not in logs. The helper answers a *password* prompt and refuses every other prompt (host-key questions, passphrases), so the host-key check cannot be bypassed. If the OpenSSH client is older than 8.4 or missing, `export` returns a short explanation instead of a stack trace; use `key_file` there, or `print` per menu. The router user needs the `ssh` policy ([guide](ROUTEROS-READONLY-USER.md)).

To pin a self-signed certificate: `openssl s_client -connect 192.0.2.10:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`, and paste the value into `tls_fingerprint256`.

## Environment variables

| Variable | Purpose |
|---|---|
| names in `user_env` / `pass_env` / `community_env` | Router credentials. |
| `NETSCOPE_MCP_TOKEN` | Bearer token for HTTP mode (at least 32 characters). |
| `NETSCOPE_MCP_TOKEN_FILE` | Alternative: file holding the token (mode 0600). |

## HTTP transport

```bash
export NETSCOPE_MCP_TOKEN="$(openssl rand -hex 32)"
netscope-mcp --config ./routers.yaml --http 127.0.0.1:8080
```

- Refuses to start without a token of at least 32 characters.
- Binds to loopback by default; a non-loopback address needs `--allow-remote` (put a TLS-terminating reverse proxy in front and add its host name with `--allowed-host`).
- Only `POST /mcp` is served (other methods -> 405, other paths -> 404). Clients send `Authorization: Bearer <token>`; comparison is constant-time. Tokens in the URL are not accepted.
- `Host` must be loopback or listed (`--allowed-host`); an `Origin` header is accepted only if it is the server's own origin or listed with `--allowed-origin`. No CORS headers are ever sent.
- Request bodies are limited to 4 MiB; a rate limit of 60 requests per minute applies.

Generic client entry:

```json
{ "mcpServers": { "netscope": { "url": "http://127.0.0.1:8080/mcp", "headers": { "Authorization": "Bearer <token>" } } } }
```

## Audit log

Each call is one JSON line: tool, device, normalized command, duration, result status. Secret values are never logged.

## Embedding: `locale` and `messages`

`new NetScope({ ..., locale: 'id' })` selects the built-in Indonesian frame (default `'en'`; an unknown value throws at construction). To change single sentences, pass a partial dictionary on top of it: `messages: { error: 'GALAT', footer: (ms, route) => \`(${ms} ms${route})\` }`. The full set of keys is the `Messages` interface exported from `netscope-mcp/core` (`MESSAGES`, `resolveMessages`). Only the frame is translated: router output, command-policy explanations and the structured `data` payload are unchanged.
