# netscope-mcp

[![CI](https://github.com/OWNER/netscope-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/netscope-mcp/actions/workflows/ci.yml)
[![Security](https://github.com/OWNER/netscope-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/OWNER/netscope-mcp/actions/workflows/security.yml)
[![npm](https://img.shields.io/npm/v/netscope-mcp.svg)](https://www.npmjs.com/package/netscope-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OWNER/netscope-mcp/badge)](https://securityscorecards.dev/viewer/?uri=github.com/OWNER/netscope-mcp)

**Give your LLM eyes on your ISP network, without giving it hands.**

`netscope-mcp` is a strictly **read-only** [Model Context Protocol](https://modelcontextprotocol.io) server for ISP/WISP network operators. It lets an AI assistant (Claude, Codex, Cursor, any MCP client) inspect many MikroTik RouterOS (v6/v7) routers and switches at once, using one-call diagnosis recipes built for NOC work. VyOS and GenieACS (TR-069) support is planned for v0.2.

> **Status:** v0.1. npm publication is pending; until then install from a release tarball or from source (see Quickstart).
> Not affiliated with or endorsed by MikroTik. "MikroTik" and "RouterOS" are trademarks of their owners.

<!-- demo: replace with the recorded GIF/asciinema once published, see docs/DEMO.md -->

## The problem

A NOC engineer at a small ISP answers the same questions all day: *Is this router healthy? Why is this optical link weak? Which router is customer X on? What is plugged into this port?* Each answer means logging in to several routers and running a handful of commands.

An LLM can do that legwork, but handing a model a RouterOS login with write access is a bad idea: one hallucinated `/system reset-configuration` or `/ip firewall filter remove` can take down customers. Most MikroTik MCP servers expose the whole router and rely on you to be careful.

## Why read-only matters

`netscope-mcp` makes the safe thing the only thing:

- **Deny-by-default allowlist.** Only `print`, `monitor … once`, `/<menu> export hide-sensitive`, `ping` and `traceroute` on a positive list of menus are ever sent. Anything else is refused *before* credentials are loaded or a device is contacted.
- **Secrets never reach the model.** Output is redacted by key name, by pattern and by the exact credential values the server holds; script bodies are masked.
- **A read-only router account is the real boundary.** The guard is one layer, not a sandbox. [We show you how to create the RouterOS user](docs/ROUTEROS-READONLY-USER.md) so that even a bug in this project cannot change a router.
- **Auditable.** 1,270+ automated tests including a security corpus (770 allowlist cases, 73 redaction cases, HTTP and property tests) run in CI, plus gitleaks, CodeQL, dependency review and OpenSSF Scorecard.

## Why it is different

| | Typical MikroTik MCP | netscope-mcp |
|---|---|---|
| Goal | Manage a router through an LLM (often including writes) | Let an LLM **observe** a fleet safely |
| Write protection | Optional read-only switch, or none | Read-only is the only mode: **deny-by-default** allowlist of `print`, `monitor … once`, `/<menu> export hide-sensitive`, `ping`, `traceroute` |
| Secrets in output | Returned as the router sends them | Redacted by key name, by pattern and by the exact credential values the server knows; script bodies masked |
| Tool design | Roughly one tool per RouterOS menu | Nine tools plus **diagnosis recipes** (`health`, `neighbors-map`, `pppoe-lookup`) |
| Many routers | One device per call | **Batch** across routers in one call; one failing router does not fail the rest |
| "Which router has customer X?" | Query routers one by one | `pppoe-lookup` across all routers, or a periodic snapshot you can search in milliseconds |

## Features

- Deny-by-default command guard: no abbreviations, no write verbs, no scripts, `where` only on non-secret columns, safe columns forced on `/ppp secret`, `/user`, `/radius`, `/snmp`.
- Redaction on every response; exact scrubbing of known credentials in error messages.
- Recipes that replace 5–25 raw calls with one answer.
- Multi-router batch (up to 30 commands): parallel across routers, sequential per router over one reused session.
- Optional snapshot store with cross-router search and explicit data age.
- Account-lockout protection: per-device queue, session reuse, cooldown after a rejected login.
- Output clipping, concurrency limits, timeouts, JSONL audit log (no secret values).
- Transports: stdio (default) and Streamable HTTP with a mandatory bearer token.
- API-SSL (port 8729) with certificate verification by default, optional fingerprint pinning, SSH (with host-key pin) for `export`.

## 60-second overview

1. **Create a read-only RouterOS user** (a `read` policy group, API access only).
2. **Describe your routers** in `routers.yaml` (credentials come from environment variables or a `0600` file, never plain YAML).
3. **Add the server to your MCP client** and ask in plain language:

> "Which router has customer `alice@example.net` connected, and is its uplink optical level OK?"

A full worked example is in [docs/DEMO.md](docs/DEMO.md). The detailed steps follow.

## Quickstart

Requires Node.js 24 or newer.

### 1. Create a read-only RouterOS user

Do this first. The tool-level guard is one layer; a read-only router account is the real boundary.
See [docs/ROUTEROS-READONLY-USER.md](docs/ROUTEROS-READONLY-USER.md).

### 2. Install

From a release tarball (or build one yourself with `npm ci && npm run build && npm pack`):

```bash
npm install -g ./netscope-mcp-0.1.0.tgz
netscope-mcp --version
```

From source, without installing: `npm ci && npm run build`, then use `node dist/cli.js` wherever this guide says `netscope-mcp`.

### 3. Describe your routers

Create `routers.yaml` (a complete example with every field is in [routers.example.yaml](routers.example.yaml)):

```yaml
settings:
  audit_log: stderr

routers:
  - id: core-1
    host: 192.0.2.10        # documentation address (RFC 5737)
    port: 8729
    family: routeros
    group: backbone
    tls_ca_file: /etc/netscope-mcp/ca.pem   # or tls_fingerprint256 to pin a self-signed certificate
    credentials: { user_env: ROS_CORE1_USER, pass_env: ROS_CORE1_PASS }
```

Credentials are never accepted as plain values in YAML: only environment-variable names or a mode-`0600` file. Full schema: [docs/CONFIG.md](docs/CONFIG.md).

### 4. Check the configuration, then run

```bash
export ROS_CORE1_USER=netscope-ro
export ROS_CORE1_PASS='<long random password>'
netscope-mcp --config ./routers.yaml --check     # prints "configuration OK: 1 router(s)."
netscope-mcp --config ./routers.yaml             # stdio transport
```

### 5. Connect your client

**Claude Code:**

```bash
claude mcp add netscope \
  --env ROS_CORE1_USER=netscope-ro --env ROS_CORE1_PASS='<password>' \
  -- netscope-mcp --config /path/to/routers.yaml
```

**Claude Desktop / Cursor** (`claude_desktop_config.json`, `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "netscope": {
      "command": "netscope-mcp",
      "args": ["--config", "/path/to/routers.yaml"],
      "env": { "ROS_CORE1_USER": "netscope-ro", "ROS_CORE1_PASS": "<password>" }
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.netscope]
command = "netscope-mcp"
args = ["--config", "/path/to/routers.yaml"]

[mcp_servers.netscope.env]
ROS_CORE1_USER = "netscope-ro"
ROS_CORE1_PASS = "<password>"
```

Prefer no passwords in client configs? Use `credentials: { file: /etc/netscope-mcp/core-1.cred }` (mode 0600, lines `user=…`, `password=…`).

**Streamable HTTP** (several users, or a client that cannot spawn processes):

```bash
export NETSCOPE_MCP_TOKEN="$(openssl rand -hex 32)"
netscope-mcp --config ./routers.yaml --http 127.0.0.1:8080
# clients: POST http://127.0.0.1:8080/mcp with  Authorization: Bearer <token>
```

### 6. Try it

> "List my devices, then run the health recipe on core-1 and tell me if anything looks wrong."
>
> "Which router has customer `alice@example.net` connected?"

Sample output: [docs/RECIPES.md](docs/RECIPES.md).

## Tools

| Tool | Purpose |
|---|---|
| `list_devices` | List configured devices (`filter`, `group`); never credentials. |
| `mikrotik_read` | One read-only command: `print` (with `where`/`proplist`/`count-only`), `monitor … once`, `/<menu> export hide-sensitive` (SSH; full menu path only, e.g. `/ip service export hide-sensitive`). |
| `mikrotik_batch` | Up to 30 `{device, command}` items, fault-tolerant. |
| `mikrotik_recipe` | `health`, `neighbors-map`, `pppoe-lookup`. |
| `ping` / `traceroute` | From a router (or `local` when enabled) to a **literal** IP address. |
| `snmp_get` | SNMP v2c GET/walk on an allowlisted set of subtrees (max 500 rows). |
| `switch_read` | Ready-made reads for CRS switches; SwOS over SNMP. |
| `mikrotik_snapshot` | Periodic data and cross-router search, always with data age. Needs `--snapshot`. |

Each response is concise text plus `structuredContent`; failures are real errors (`isError: true`) with a cause: `policy`, `auth`, `timeout`, `connect`, `not-found`, `device`, `busy`, `config`.

## Security at a glance

- Read-only by construction: anything not on the allowlist is refused with a `policy` error before a device is contacted.
- Secrets are redacted before they reach the model.
- HTTP mode refuses to start without a token of at least 32 characters, binds to loopback by default, validates `Host` and `Origin`, accepts `POST /mcp` only and sends no CORS headers.
- Plain API (port 8728) and unverified TLS work only with `settings.allow_insecure: true`.
- **Limits, stated honestly:** the guard is a tool-level layer, not a sandbox. Always use a RouterOS account whose policy is read-only.

Details: [SECURITY.md](SECURITY.md) · [docs/ROUTEROS-READONLY-USER.md](docs/ROUTEROS-READONLY-USER.md)

## Documentation

[Demo](docs/DEMO.md) · [Recipes](docs/RECIPES.md) · [Configuration](docs/CONFIG.md) · [Snapshot](docs/SNAPSHOT.md) · [FAQ](docs/FAQ.md) · [Bahasa Indonesia](README.id.md)

## Library use

The core is importable without MCP: `import { NetScope, planRosCommand, redactText } from 'netscope-mcp/core'`; the MCP and HTTP front-ends are in `netscope-mcp/server`.

## Used in production

netscope-mcp was built by, and is used daily at, a small Indonesian ISP to give its NOC assistant read access to dozens of MikroTik routers (backbone, aggregation and edge). It is exercised against real fleets, not only simulators. Names and addresses are intentionally omitted here; if you run it, please open an issue or discussion and tell us your scale (anonymous is fine) so we can list adopters.

## Roadmap

- **v0.1** — RouterOS v6/v7 (API, API-SSL, SSH for export), recipes, batch, snapshot, SNMP v2c, CRS/SwOS switches, stdio + HTTP.
- **v0.2** — VyOS read tools, GenieACS read-only tools, SNMPv3, RouterOS v7 REST transport.
- **v0.3** — change detection between snapshots, per-token device ACLs, MCP prompts/resources.

## Contributing

Issues and pull requests are welcome, especially: RouterOS version quirks, new read-only recipes, translations of the docs, and security-test cases for the allowlist. Read [CONTRIBUTING.md](CONTRIBUTING.md) first (read-only is a hard requirement; fixtures use only documentation addresses). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
