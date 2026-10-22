#!/usr/bin/env node
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ConfigError, checkPrivateFile, loadConfig } from './server/config.js';
import { MIN_TOKEN_LENGTH, startHttpServer } from './server/http.js';
import { createMcpServer } from './server/mcp.js';
import { buildServer } from './server/run.js';

const VERSION = '0.1.0';
const USAGE = `netscope-mcp ${VERSION} — read-only MCP server for ISP/NOC operators

Usage: netscope-mcp --config routers.yaml [options]

  --config <file>        routers file (see routers.example.yaml)          [required]
  --http <host:port>     serve Streamable HTTP at /mcp instead of stdio (e.g. 127.0.0.1:8080)
  --allow-remote         allow binding a non-loopback address (put a TLS proxy in front)
  --allowed-host <h>     extra accepted Host header value (repeatable)
  --allowed-origin <o>   accepted Origin value (repeatable; browsers are refused by default)
  --snapshot <file>      enable periodic snapshots stored in this SQLite file (mode 0600)
  --audit-log <target>   stderr (default) | off | <file>
  --check                validate the configuration and exit
  -h, --help | -v, --version

HTTP mode needs a bearer token of at least ${MIN_TOKEN_LENGTH} characters in NETSCOPE_MCP_TOKEN
or in the file named by NETSCOPE_MCP_TOKEN_FILE (mode 0600).
`;

const log = (line: string) => process.stderr.write(`${line}\n`);

function readToken(env: NodeJS.ProcessEnv): string {
  if (env.NETSCOPE_MCP_TOKEN) return env.NETSCOPE_MCP_TOKEN;
  if (env.NETSCOPE_MCP_TOKEN_FILE) { checkPrivateFile(env.NETSCOPE_MCP_TOKEN_FILE, 'NETSCOPE_MCP_TOKEN_FILE'); return fs.readFileSync(env.NETSCOPE_MCP_TOKEN_FILE, 'utf8').trim(); }
  throw new ConfigError('HTTP mode needs NETSCOPE_MCP_TOKEN or NETSCOPE_MCP_TOKEN_FILE.');
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      config: { type: 'string' }, http: { type: 'string' }, 'allow-remote': { type: 'boolean' }, 'allowed-host': { type: 'string', multiple: true }, 'allowed-origin': { type: 'string', multiple: true },
      snapshot: { type: 'string' }, 'audit-log': { type: 'string' }, check: { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
    },
    strict: true,
  });
  if (values.help) { process.stdout.write(USAGE); return; }
  if (values.version) { process.stdout.write(`${VERSION}\n`); return; }
  if (!values.config) { process.stderr.write(USAGE); process.exitCode = 2; return; }
  const config = loadConfig(values.config);
  for (const w of config.warnings) log(`[warn] ${w}`);
  if (values.check) { log(`configuration OK: ${config.routers.length} router(s).`); return; }

  const built = buildServer(config, {
    log, ...(values.snapshot ? { snapshotFile: values.snapshot } : {}), ...(values['audit-log'] ? { auditLog: values['audit-log'] } : {}),
  });
  const shutdown = () => { built.close(); process.exit(0); };
  process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);

  if (values.http) {
    const m = /^(.*):(\d{1,5})$/.exec(values.http);
    if (!m) throw new ConfigError('--http expects host:port, e.g. 127.0.0.1:8080.');
    const host = m[1]!.replace(/^\[|\]$/g, '') || '127.0.0.1';
    const running = await startHttpServer({
      createServer: () => createMcpServer(built.scope, VERSION), token: readToken(process.env), host, port: Number(m[2]),
      allowRemote: !!values['allow-remote'], allowedHosts: values['allowed-host'] ?? [], allowedOrigins: values['allowed-origin'] ?? [], log,
    });
    log(`[http] listening on http://${running.host}:${running.port}/mcp (bearer token required)`);
    if (values['allow-remote']) log('[warn] remote binding enabled: terminate TLS in front of this server.');
    return;
  }
  await createMcpServer(built.scope, VERSION).connect(new StdioServerTransport());
  log(`[netscope-mcp] ${VERSION} ready on stdio (${config.routers.length} device(s), redact_pii=${config.settings.redact_pii})`);
}

main().catch((e: unknown) => {
  if (e instanceof ConfigError) log(`configuration error: ${e.message}`);
  else log(`fatal: ${e instanceof Error ? e.message.split('\n')[0] : 'unknown error'}`);
  process.exit(1);
});
