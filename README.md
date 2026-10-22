# netscope-mcp

Read-only [MCP](https://modelcontextprotocol.io) server for ISP/NOC operators: give a model eyes on your network without giving it hands.
MikroTik RouterOS first.

> Work in progress (v0.1). Full documentation is coming; this is the minimum to run it.

## Quick start

```sh
npm ci && npm run build
cp routers.example.yaml routers.yaml        # edit: your devices; credentials only via env vars or 0600 files
export ROS_CORE1_USER=... ROS_CORE1_PASS=... # see the example file
node dist/cli.js --config routers.yaml       # stdio transport (Claude Desktop/Code, Codex, ...)
```

HTTP (Streamable HTTP at `/mcp`, bound to 127.0.0.1, bearer token required):

```sh
export NETSCOPE_MCP_TOKEN="$(openssl rand -hex 32)"
node dist/cli.js --config routers.yaml --http 127.0.0.1:8080
```

## Tools

`list_devices`, `mikrotik_read`, `mikrotik_batch`, `mikrotik_recipe` (`health`, `neighbors-map`, `pppoe-lookup`), `ping`, `traceroute`, `snmp_get`, `switch_read`, `mikrotik_snapshot`.

## Safety model (read this)

The tool-side guard is deny-by-default (only `print`, `monitor … once`, `export hide-sensitive`, `ping`, `traceroute` on a positive list of menus) and secrets are redacted in every output.
It is **not a sandbox**: the real protection is a RouterOS user whose group has no `write`, `policy`, `sensitive`, `reboot`, … rights. Always connect with such a user.
Output can contain customer data and is sent to your model provider; keep `redact_pii: true` unless you accept that.

`MikroTik` and `RouterOS` are trademarks of their owner; this project is not affiliated with MikroTik.

## License

Apache-2.0
