import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fakeRos, type FakeRos } from '../helpers/fake-ros.js';

const root = path.resolve(import.meta.dirname, '..', '..');
const cli = path.join(root, 'dist', 'cli.js');
const TOKEN = 'x'.repeat(40);
const EXPECTED_TOOLS = ['list_devices', 'mikrotik_batch', 'mikrotik_read', 'mikrotik_recipe', 'mikrotik_snapshot', 'ping', 'snmp_get', 'switch_read', 'traceroute'];

let dir: string; let ros: FakeRos; let cfgFile: string; let env: Record<string, string>;
beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-int-'));
  ros = await fakeRos({ user: 'ro-user', password: 'LAB-PASSWORD-ONE', handlers: { '/ip/address/print': [{ address: '192.0.2.1/24', interface: 'ether1' }] } });
  cfgFile = path.join(dir, 'routers.yaml');
  fs.writeFileSync(cfgFile, `settings: { allow_insecure: true, audit_log: off, state_dir: ${dir}/state }
routers:
  - { id: rtr-core-1, host: 127.0.0.1, port: ${ros.port}, transport: api, group: backbone, credentials: { user_env: ROS_U, pass_env: ROS_P } }
`);
  env = { PATH: process.env.PATH ?? '', ROS_U: 'ro-user', ROS_P: 'LAB-PASSWORD-ONE', NETSCOPE_MCP_TOKEN: TOKEN };
});
afterAll(async () => { await ros.close(); fs.rmSync(dir, { recursive: true, force: true }); });

async function exercise(client: Client): Promise<void> {
  const tools = await client.listTools();
  expect(tools.tools.map((t) => t.name).sort()).toEqual(EXPECTED_TOOLS);
  for (const t of tools.tools) expect(t.annotations?.readOnlyHint).toBe(true);
  const list = await client.callTool({ name: 'list_devices', arguments: {} });
  expect(JSON.stringify(list)).toContain('rtr-core-1'); expect(JSON.stringify(list)).not.toContain('LAB-PASSWORD-ONE');
  const ok = await client.callTool({ name: 'mikrotik_read', arguments: { device: 'rtr-core-1', command: '/ip address print' } }) as { content: Array<{ text: string }>; structuredContent?: { ok: boolean }; isError?: boolean };
  expect(ok.isError).toBeUndefined(); expect(ok.content[0]!.text).toContain('192.0.2.1/24'); expect(ok.structuredContent?.ok).toBe(true);
  const bad = await client.callTool({ name: 'mikrotik_read', arguments: { device: 'rtr-core-1', command: '/system reboot' } }) as { isError?: boolean; content: Array<{ text: string }>; structuredContent?: { error: string } };
  expect(bad.isError).toBe(true); expect(bad.structuredContent?.error).toBe('policy'); expect(bad.content[0]!.text).toMatch(/refused/);
  const batch = await client.callTool({ name: 'mikrotik_batch', arguments: { items: [{ device: 'rtr-core-1', command: '/ip address print' }, { device: 'rtr-core-1', command: '/system script run x' }] } }) as { content: Array<{ text: string }> };
  expect(batch.content[0]!.text).toMatch(/1 ok, 1 error/);
  const snap = await client.callTool({ name: 'mikrotik_snapshot', arguments: {} }) as { isError?: boolean };
  expect(snap.isError).toBe(true);
  const invalid = await client.callTool({ name: 'mikrotik_read', arguments: { device: 'rtr-core-1' } }) as { isError?: boolean };
  expect(invalid.isError).toBe(true); // schema: command required
}

describe('MCP over stdio (spawned CLI)', () => {
  it('answers tools/list and tool calls; no write verb reaches the device', async () => {
    const before = ros.st.sentences.length;
    const client = new Client({ name: 'test', version: '1' });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [cli, '--config', cfgFile], env, stderr: 'ignore' }));
    try { await exercise(client); } finally { await client.close(); }
    const paths = ros.st.sentences.slice(before).map((w) => w[0]);
    expect(paths.length).toBeGreaterThan(0);
    for (const p of paths) expect(p).toBe('/ip/address/print');
  });
});

describe('MCP over Streamable HTTP (spawned CLI)', () => {
  let child: ReturnType<typeof spawn>; let port = 0;
  beforeAll(async () => {
    child = spawn(process.execPath, [cli, '--config', cfgFile, '--http', '127.0.0.1:0', '--snapshot', path.join(dir, 'snap.sqlite')], { env, stdio: ['ignore', 'ignore', 'pipe'] });
    port = await new Promise<number>((resolve, reject) => {
      let buf = ''; const t = setTimeout(() => reject(new Error('server did not start')), 10_000);
      child.stderr!.on('data', (d) => { buf += d; const m = /listening on http:\/\/127\.0\.0\.1:(\d+)\/mcp/.exec(buf); if (m) { clearTimeout(t); resolve(Number(m[1])); } });
      child.on('exit', () => reject(new Error(`exited early: ${buf}`)));
    });
  });
  afterAll(() => { child.kill('SIGTERM'); });

  it('works with the bearer token', async () => {
    const client = new Client({ name: 'test', version: '1' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
    try {
      const tools = await client.listTools(); expect(tools.tools).toHaveLength(EXPECTED_TOOLS.length);
      const snap = await client.callTool({ name: 'mikrotik_snapshot', arguments: {} }) as { content: Array<{ text: string }> };
      expect(snap.content[0]!.text).toMatch(/no snapshot yet|router\(s\)/);
    } finally { await client.close(); }
  });
  const post = (headers: Record<string, string>, method = 'POST', body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}') => new Promise<{ status: number; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/mcp', method, headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers } }, (res) => { res.resume(); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers })); });
    req.on('error', reject); req.end(method === 'POST' ? body : undefined);
  });
  it('rejects a missing or wrong token with 401', async () => {
    expect((await post({})).status).toBe(401);
    expect((await post({ authorization: 'Bearer wrong' })).status).toBe(401);
    expect((await post({ authorization: `Bearer ${TOKEN}x` })).status).toBe(401);
    expect((await post({ authorization: `Basic ${TOKEN}` })).status).toBe(401);
  });
  it('rejects foreign Host and Origin headers, non-POST, and sends no CORS headers', async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    expect((await post({ ...auth, host: 'evil.example' })).status).toBe(403);
    expect((await post({ ...auth, origin: 'https://evil.example' })).status).toBe(403);
    const get = await post(auth, 'GET'); expect(get.status).toBe(405);
    const ok = await post(auth); expect(ok.status).toBe(200);
    for (const r of [ok, get]) expect(Object.keys(r.headers).filter((h) => h.startsWith('access-control-'))).toEqual([]);
  });
});

describe('CLI start-up checks', () => {
  const run = (args: string[], e: Record<string, string> = env) => new Promise<{ code: number | null; stderr: string; stdout: string }>((resolve) => {
    const c = spawn(process.execPath, [cli, ...args], { env: e, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = ''; let stdout = ''; c.stderr.on('data', (d) => { stderr += d; }); c.stdout.on('data', (d) => { stdout += d; });
    c.on('close', (code) => resolve({ code, stderr, stdout }));
  });
  it('--check validates the config; --version prints the version', async () => {
    expect((await run(['--config', cfgFile, '--check'])).code).toBe(0);
    expect((await run(['--version'])).stdout.trim()).toBe('0.1.0');
  });
  it('a missing environment variable is reported by name without leaking values', async () => {
    const r = await run(['--config', cfgFile, '--check'], { PATH: env.PATH! });
    expect(r.code).toBe(1); expect(r.stderr).toMatch(/ROS_U/); expect(r.stderr).not.toContain('LAB-PASSWORD-ONE');
  });
  it('HTTP mode refuses to start without a token, with a short token, or on a non-loopback address', async () => {
    const noTok = { PATH: env.PATH!, ROS_U: 'u', ROS_P: 'p' };
    expect((await run(['--config', cfgFile, '--http', '127.0.0.1:0'], noTok)).stderr).toMatch(/NETSCOPE_MCP_TOKEN/);
    expect((await run(['--config', cfgFile, '--http', '127.0.0.1:0'], { ...noTok, NETSCOPE_MCP_TOKEN: 'short' })).stderr).toMatch(/at least 32/);
    expect((await run(['--config', cfgFile, '--http', '0.0.0.0:0'])).stderr).toMatch(/--allow-remote/);
  });
  it('a token file must be mode 0600', async () => {
    const f = path.join(dir, 'token'); fs.writeFileSync(f, TOKEN, { mode: 0o644 }); fs.chmodSync(f, 0o644);
    const r = await run(['--config', cfgFile, '--http', '127.0.0.1:0'], { PATH: env.PATH!, ROS_U: 'u', ROS_P: 'p', NETSCOPE_MCP_TOKEN_FILE: f });
    expect(r.stderr).toMatch(/chmod 600/);
  });
});
