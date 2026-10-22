import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ConfigError, EnvFileCredentials, YamlSource, loadConfig, parseConfig } from '../../src/server/config.js';

const dirs: string[] = [];
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-cfg-')); dirs.push(d); return d; };
afterEach(() => { dirs.splice(0).forEach((d) => fs.rmSync(d, { recursive: true, force: true })); });

const ENV = { ROS_A_USER: 'ro-user', ROS_A_PASS: 'LAB-PASSWORD-ONE', SNMP_A: 'LAB-COMMUNITY-ONE' };
const basic = (extra = '') => `
routers:
  - id: rtr-a
    host: 192.0.2.10
    ${extra}
    credentials: { user_env: ROS_A_USER, pass_env: ROS_A_PASS }
`;
const err = (text: string, env: NodeJS.ProcessEnv = ENV) => { try { parseConfig(text, { env }); } catch (e) { return (e as Error).message; } return ''; };

describe('routers.example.yaml stays valid', () => {
  it('parses once its placeholder paths and env vars exist', () => {
    const d = tmp();
    for (const f of ['ssh/core-1.key', 'ca.pem', 'edge-1.cred']) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), f === 'edge-1.cred' ? 'user=ro\npassword=pw-123\n' : 'x', { mode: 0o600 }); }
    const text = fs.readFileSync(path.resolve(import.meta.dirname, '../../routers.example.yaml'), 'utf8').replaceAll('/etc/netscope-mcp', d);
    const env = { ROS_CORE1_USER: 'u', ROS_CORE1_PASS: 'p', SNMP_CORE1_COMMUNITY: 'c', ROS_SW1_USER: 'u', ROS_SW1_PASS: 'p', SNMP_SW2_COMMUNITY: 'c' };
    const cfg = parseConfig(text, { env, baseDir: d });
    expect(cfg.routers.map((r) => r.device.id)).toEqual(['rtr-core-1', 'rtr-edge-1', 'sw-crs-1', 'sw-css-1']);
    expect(cfg.settings).toMatchObject({ redact_pii: true, allow_insecure: false, allow_local_probe: false });
    expect(cfg.warnings).toEqual([]);
    expect(cfg.routers[0]!.device).toMatchObject({ port: 8729, transport: 'api-ssl', tls: { verify: true, fingerprint256: expect.any(String) }, ssh: { port: 22 }, labels: { role: 'core' } });
    expect(cfg.routers[1]!.device.fallback).toMatchObject({ port: 28729 });
    expect(cfg.routers[3]!.device).toMatchObject({ family: 'swos' });
  });
  it('contains no real-looking addresses (documentation ranges only)', () => {
    const text = fs.readFileSync(path.resolve(import.meta.dirname, '../../routers.example.yaml'), 'utf8');
    for (const ip of text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) expect(ip, ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.|^0\.0\.0\.0$/);
  });
});

describe('parseConfig', () => {
  it('applies safe defaults', () => {
    const c = parseConfig(basic(), { env: ENV });
    expect(c.settings).toMatchObject({ redact_pii: true, allow_insecure: false, allow_local_probe: false, max_inflight: 10, audit_log: 'stderr', snapshot: { interval_min: 10, store_customer_data: false } });
    expect(c.routers[0]!.device).toMatchObject({ id: 'rtr-a', name: 'rtr-a', port: 8729, family: 'routeros', transport: 'api-ssl', tls: { verify: true } });
  });
  it('plain-text API needs settings.allow_insecure (and warns)', () => {
    expect(err(basic('transport: api'))).toMatch(/requires settings\.allow_insecure/);
    const c = parseConfig(`settings: { allow_insecure: true }\n${basic('transport: api')}`, { env: ENV });
    expect(c.routers[0]!.device).toMatchObject({ transport: 'api', port: 8728 }); expect(c.routers[0]!.device.tls).toBeUndefined(); expect(c.warnings[0]).toMatch(/plain-text API/);
    expect(parseConfig(`settings: { allow_insecure: true }\n${basic('transport: api\n    port: 18728')}`, { env: ENV }).routers[0]!.device.port).toBe(18728);
  });
  it('defaults.transport is honoured and still guarded', () => {
    expect(err(`defaults: { transport: api }\n${basic()}`)).toMatch(/allow_insecure/);
  });
  it('disabling certificate verification without a pin needs allow_insecure', () => {
    expect(err(basic('verify_tls: false'))).toMatch(/verification without a pinned fingerprint/);
    expect(() => parseConfig(basic(`verify_tls: false\n    tls_fingerprint256: "${'ab:'.repeat(31)}ab"`), { env: ENV })).not.toThrow();
  });
  it('rejects bad ids, duplicates, hosts, unknown keys and empty router lists — messages name the key, not the value', () => {
    expect(err(basic().replace('rtr-a', 'bad id!'))).toMatch(/routers\.0\.id/);
    expect(err(`routers:\n  - { id: A, host: 192.0.2.1, credentials: { user_env: ROS_A_USER, pass_env: ROS_A_PASS } }\n  - { id: a, host: 192.0.2.2, credentials: { user_env: ROS_A_USER, pass_env: ROS_A_PASS } }`)).toMatch(/duplicate id/);
    expect(err(basic().replace('192.0.2.10', 'bad host/x'))).toMatch(/routers\.0\.host/);
    const unknown = err(basic('passwd: SENSITIVE-VALUE-123'));
    expect(unknown).toMatch(/passwd/); expect(unknown).not.toContain('SENSITIVE-VALUE-123');
    const badEnv = err(basic().replace('ROS_A_USER', 'bad env name'));
    expect(badEnv).toMatch(/user_env/); expect(badEnv).not.toContain('bad env name');
    expect(err('routers: []')).toMatch(/routers/); expect(err('settings: {}')).toMatch(/routers/);
    expect(err('::: not yaml :::\n\t-')).toMatch(/not valid YAML|invalid configuration/);
  });
  it('credentials: *_env variables must be set; env and file are exclusive', () => {
    expect(err(basic(), {})).toMatch(/environment variable ROS_A_USER is not set/);
    expect(err(basic().replace('{ user_env', '{ file: x, user_env'))).toMatch(/either file or \*_env/);
    expect(err(`routers:\n  - { id: a, host: 192.0.2.1, credentials: {} }`)).toMatch(/user_env and pass_env/);
    expect(err(`routers:\n  - { id: a, host: 192.0.2.1, family: snmp, credentials: {} }`)).toMatch(/community_env/);
  });
  it('credential files must be 0600', () => {
    const d = tmp(); const f = path.join(d, 'a.cred'); fs.writeFileSync(f, 'user=u\npassword=p\n', { mode: 0o644 }); fs.chmodSync(f, 0o644);
    const text = `routers:\n  - { id: a, host: 192.0.2.1, credentials: { file: ${f} } }`;
    expect(err(text)).toMatch(/readable by group\/others.*chmod 600/);
    fs.chmodSync(f, 0o600); expect(() => parseConfig(text, { env: {} })).not.toThrow();
    expect(err(text.replace(f, path.join(d, 'missing')))).toMatch(/does not exist/);
  });
  it('relative paths resolve against the config directory; missing CA/key files are reported', () => {
    const d = tmp(); fs.writeFileSync(path.join(d, 'ca.pem'), 'PEMTEXT');
    const c = parseConfig(basic('tls_ca_file: ca.pem'), { env: ENV, baseDir: d });
    expect(c.routers[0]!.device.tls!.ca).toBe('PEMTEXT');
    expect(err(basic('tls_ca_file: nope.pem'))).toMatch(/tls_ca_file/);
    expect(err(basic('ssh: { port: 22, key_file: /nonexistent/key }'))).toMatch(/ssh\.key_file/);
  });
  it('probe CIDRs are validated', () => {
    expect(err(`settings: { probe: { deny_cidrs: [nope] } }\n${basic()}`)).toMatch(/CIDR/);
  });
  it('loadConfig reads a file and resolves relative paths from its directory', () => {
    const d = tmp(); fs.writeFileSync(path.join(d, 'ca.pem'), 'PEM'); fs.writeFileSync(path.join(d, 'routers.yaml'), basic('tls_ca_file: ca.pem'));
    expect(loadConfig(path.join(d, 'routers.yaml'), ENV).routers[0]!.device.tls!.ca).toBe('PEM');
    expect(() => loadConfig(path.join(d, 'nope.yaml'), ENV)).toThrow(ConfigError);
  });
});

describe('YamlSource / EnvFileCredentials', () => {
  it('lists devices; credentials come from env or a 0600 file, read on demand', async () => {
    const d = tmp(); const f = path.join(d, 'b.cred'); fs.writeFileSync(f, 'user=file-user\npassword=file-pass\ncommunity=file-comm\n', { mode: 0o600 });
    const cfg = parseConfig(`routers:\n  - { id: a, host: 192.0.2.1, snmp: { community_env: SNMP_A }, credentials: { user_env: ROS_A_USER, pass_env: ROS_A_PASS } }\n  - { id: b, host: 192.0.2.2, credentials: { file: ${f} } }`, { env: ENV });
    expect((await new YamlSource(cfg.routers).list()).map((x) => x.id)).toEqual(['a', 'b']);
    const creds = new EnvFileCredentials(cfg.routers, ENV);
    expect(await creds.credentials('a')).toEqual({ user: 'ro-user', secret: 'LAB-PASSWORD-ONE', community: 'LAB-COMMUNITY-ONE' });
    expect(await creds.credentials('b')).toEqual({ user: 'file-user', secret: 'file-pass', community: 'file-comm' });
    fs.writeFileSync(f, 'user=u2\npassword=p2\n'); fs.chmodSync(f, 0o600);
    expect((await creds.credentials('b')).secret).toBe('p2');
    fs.chmodSync(f, 0o644);
    await expect(creds.credentials('b')).rejects.toThrow(/chmod 600/);
    await expect(creds.credentials('zzz')).rejects.toThrow(/unknown device/);
  });
});
