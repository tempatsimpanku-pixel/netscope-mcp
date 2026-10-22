import net from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { NetScope, RosPool, type AuditEntry, type CredentialSource, type DeviceCredentials, type DeviceInfo, type NetScopeOptions, type RosTransport } from '../../src/core/index.js';
import { fakeRos, type FakeRos } from '../helpers/fake-ros.js';
import { CREDS, DEVICES, staticCreds, staticSource } from '../helpers/fixtures.js';

const scopes: NetScope[] = [];
const servers: FakeRos[] = [];
function mk(opts: Omit<Partial<NetScopeOptions>, 'devices'> & { devices?: DeviceInfo[] } = {}): NetScope {
  const { devices, ...rest } = opts;
  const s = new NetScope({ devices: staticSource(devices ?? DEVICES), credentials: staticCreds(), probe: { gapMs: 0 }, redactPii: false, ...rest });
  scopes.push(s);
  return s;
}
/** A stub transport: answers by API path. */
const stub = (answers: Record<string, Array<Record<string, string>> | Error> = {}, log: string[] = []): RosTransport => async (_t, plan) => {
  log.push(`${plan.apiPath} ${plan.words.join(' ')}`.trim());
  const a = answers[plan.apiPath];
  if (a instanceof Error) throw a;
  return { rows: a ?? [{ name: 'x', password: 'LAB-PASSWORD-ONE' }], truncated: false };
};
const live = async (o: Parameters<typeof fakeRos>[0] = {}) => { const s = await fakeRos({ password: CREDS.secret, user: CREDS.user, ...o }); servers.push(s); return s; };
const onPort = (port: number, id = 'rtr-core-1'): DeviceInfo => ({ ...DEVICES.find((d) => d.id === id)!, host: '127.0.0.1', port, transport: 'api' });
afterEach(async () => { scopes.splice(0).forEach((s) => s.close()); await Promise.all(servers.splice(0).map((s) => s.close())); });

describe('mikrotik_read', () => {
  it('refuses a forbidden command BEFORE credentials are loaded and before any device call', async () => {
    const log: string[] = []; const calls: string[] = [];
    const s = mk({ credentials: staticCreds(CREDS, log), transport: stub({}, calls) });
    const r = await s.read({ device: 'rtr-core-1', command: '/system reboot' });
    expect(r.isError).toBe(true); expect(r.errorKind).toBe('policy'); expect(r.text).toMatch(/refused/);
    expect(log).toEqual([]); expect(calls).toEqual([]);
  });
  it('returns masked output and structured data; never the credentials', async () => {
    const s = mk({ transport: stub({ '/system/resource/print': [{ uptime: '1d', 'cpu-load': '3', password: 'LAB-PASSWORD-ONE', comment: 'note LAB-PASSWORD-ONE' }] }) });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.isError).toBe(false); expect(r.text).toContain('cpu-load=3');
    expect(r.text).not.toMatch(/LAB-PASSWORD-ONE|LAB-COMMUNITY-ONE/);
    expect(JSON.stringify(r.data)).not.toContain('LAB-PASSWORD-ONE');
    expect(r.data).toMatchObject({ device: 'rtr-core-1', rows: [{ 'cpu-load': '3' }] });
  });
  it('error messages never carry credentials', async () => {
    const s = mk({ transport: async () => { throw new Error('boom password=LAB-PASSWORD-ONE and user ro-user LAB-PASSWORD-ONE'); } });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.isError).toBe(true); expect(r.text).not.toContain('LAB-PASSWORD-ONE');
  });
  it('unknown / ambiguous / out-of-family devices are not-found errors', async () => {
    const s = mk({ transport: stub() });
    expect((await s.read({ device: '203.0.113.9', command: '/system resource print' })).errorKind).toBe('not-found');
    expect((await s.read({ device: 'sw-css-1', command: '/system resource print' })).errorKind).toBe('not-found');
    const dup = mk({ devices: [{ ...DEVICES[0]!, id: 'rtr-a1', name: 'edge' }, { ...DEVICES[0]!, id: 'rtr-a2', name: 'edge' }], transport: stub() });
    const r = await dup.read({ device: 'edge', command: '/system resource print' });
    expect(r.text).toMatch(/ambiguous.*rtr-a1.*rtr-a2/);
  });
  it('resolves by id, by name (case-insensitive) and by host, never a free host', async () => {
    const s = mk({ transport: stub() });
    for (const ref of ['rtr-core-1', 'RTR-CORE-1', '192.0.2.10', 'id:rtr-core-1']) expect((await s.read({ device: ref, command: '/system resource print' })).isError, ref).toBe(false);
    expect((await s.read({ device: '203.0.113.9', command: '/system resource print' })).isError).toBe(true);
    expect((await s.read({ device: undefined, command: '/system resource print' })).isError).toBe(true);
  });
  it('talks to a real (fake) RouterOS over the pool; write verbs never reach the wire', async () => {
    const srv = await live({ handlers: { '/ip/address/print': [{ address: '192.0.2.1/24', interface: 'ether1', disabled: 'false' }, { address: '192.0.2.9/24', interface: 'ether2', disabled: 'false' }] } });
    const s = mk({ devices: [onPort(srv.port)], allowInsecure: true });
    const ok = await s.read({ device: 'rtr-core-1', command: '/ip address print where interface=ether2' });
    expect(ok.text).toContain('192.0.2.9/24'); expect(ok.text).not.toContain('192.0.2.1/24');
    for (const bad of ['/ip address add address=192.0.2.5/24', '/system reboot', '/ip address remove 0', '/system script run x', '/tool fetch url=http://x']) await s.read({ device: 'rtr-core-1', command: bad });
    expect(srv.paths()).toEqual(['/ip/address/print']);
  });
  it('plain-text API is refused unless allow_insecure', async () => {
    const srv = await live();
    const s = mk({ devices: [onPort(srv.port)] });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.isError).toBe(true); expect(r.text).toMatch(/plain-text API/); expect(srv.st.logins).toBe(0);
  });
  it('denied login drops the cached credentials so the next call re-reads the source', async () => {
    const srv = await live({ password: 'rotated-password' });
    let reads = 0; let dropped = 0;
    const credentials: CredentialSource = { credentials: async () => { reads++; return { ...CREDS }; }, drop: () => { dropped++; } };
    const s = mk({ devices: [onPort(srv.port)], allowInsecure: true, credentials });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.errorKind).toBe('auth'); expect(dropped).toBe(1);
    await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(reads).toBe(2);
  });
  it('falls back ONCE to the alternate address when the direct one does not connect, and says so', async () => {
    const srv = await live();
    const dead = await new Promise<number>((res) => { const t = net.createServer().listen(0, '127.0.0.1', () => { const p = (t.address() as net.AddressInfo).port; t.close(() => res(p)); }); });
    const dev: DeviceInfo = { ...onPort(dead), fallback: { host: '127.0.0.1', port: srv.port, label: 'alternate path' } };
    const s = mk({ devices: [dev], allowInsecure: true });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.isError).toBe(false); expect(r.text).toMatch(/via alternate path/); expect(srv.st.logins).toBe(1);
  });
  it('a denied login is never retried on the fallback path', async () => {
    const srv = await live({ password: 'other' }); const alt = await live();
    const s = mk({ devices: [{ ...onPort(srv.port), fallback: { host: '127.0.0.1', port: alt.port, label: 'alt' } }], allowInsecure: true });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.errorKind).toBe('auth'); expect(alt.st.logins).toBe(0);
  });
  it('hints that a missing menu is not a connection problem', async () => {
    const s = mk({ transport: stub({ '/interface/ethernet/poe/print': new Error('device refused: no such command prefix') }) });
    const r = await s.read({ device: 'rtr-core-1', command: '/interface ethernet poe print' });
    expect(r.text).toMatch(/not a connection problem/);
  });
  it('notes truncation and the newest-entries tail', async () => {
    const s = mk({ transport: async () => ({ rows: [{ message: 'newest' }], truncated: true, scanned: 5000 }) });
    const r = await s.read({ device: 'rtr-core-1', command: '/log print tail=1' });
    expect(r.text).toMatch(/showing the 1 NEWEST of 5000/);
  });
  it('export goes over SSH with the configured port; secrets never reach the output', async () => {
    const calls: Array<{ port: number; remote: string; hasPw: boolean; user: string }> = [];
    const s = mk({ ssh: async (t, remote) => { calls.push({ port: t.port, remote, hasPw: !!t.password, user: t.user }); return { code: 0, stdout: '/ip address\nadd address=192.0.2.1/24 comment="x password=LAB-PASSWORD-ONE"\nadd name=u secret=LAB-PASSWORD-ONE', stderr: '' }; } });
    const r = await s.read({ device: 'rtr-core-1', command: '/ip address export hide-sensitive' });
    expect(r.isError).toBe(false); expect(calls).toEqual([{ port: 22, remote: '/ip address export hide-sensitive', hasPw: true, user: 'ro-user' }]);
    expect(r.text).not.toContain('LAB-PASSWORD-ONE'); expect(r.text).toContain('192.0.2.1/24');
  });
  it('export: closed or unconfigured SSH explains instead of guessing port 22', async () => {
    const s = mk({ ssh: async () => { throw new Error('should not be called'); } });
    const closed = await s.read({ device: 'rtr-edge-1', command: '/ip address export hide-sensitive' });
    expect(closed.text).toMatch(/SSH of rtr-edge-1 is closed/);
    const unset = await s.read({ device: 'rtr-edge-2', command: '/ip address export hide-sensitive' });
    expect(unset.text).toMatch(/not configured/); expect(unset.errorKind).toBe('config');
  });
  it('export: a failing SSH reports a scrubbed error', async () => {
    const s = mk({ ssh: async () => ({ code: 255, stdout: '', stderr: 'Permission denied LAB-PASSWORD-ONE' }) });
    const r = await s.read({ device: 'rtr-core-1', command: '/ip address export hide-sensitive' });
    expect(r.isError).toBe(true); expect(r.text).not.toContain('LAB-PASSWORD-ONE');
  });
  it('key-file SSH devices send no password', async () => {
    let seen: { password?: string; keyFile?: string } = {};
    const dev: DeviceInfo = { ...DEVICES[0]!, ssh: { port: 22, keyFile: '/etc/example/key', hostKeySha256: 'SHA256:abc' } };
    const s = mk({ devices: [dev], ssh: async (t) => { seen = t; return { code: 0, stdout: '/ip address', stderr: '' }; } });
    await s.read({ device: 'rtr-core-1', command: '/ip address export hide-sensitive' });
    expect(seen.password).toBeUndefined(); expect(seen.keyFile).toBe('/etc/example/key');
  });
});

describe('privacy (redact_pii)', () => {
  it('is on by default: /log is refused, customer MACs are masked', async () => {
    const s = new NetScope({ devices: staticSource(), credentials: staticCreds(), transport: stub({ '/ppp/active/print': [{ name: 'cust-a', 'caller-id': 'AA:BB:CC:11:22:33', address: '10.0.0.5' }] }) });
    scopes.push(s);
    expect(s.redactPii).toBe(true);
    const log = await s.read({ device: 'rtr-core-1', command: '/log print' });
    expect(log.errorKind).toBe('policy'); expect(log.text).toMatch(/redact_pii/);
    const r = await s.read({ device: 'rtr-core-1', command: '/ppp active print' });
    expect(r.text).toContain('AA:BB:CC:xx:xx:xx'); expect(r.text).not.toContain('11:22:33'); expect(r.text).toContain('cust-a');
  });
  it('can be switched off', async () => {
    const s = mk({ redactPii: false, transport: stub({ '/ppp/active/print': [{ name: 'cust-a', 'caller-id': 'AA:BB:CC:11:22:33' }], '/log/print': [{ message: 'hello' }] }) });
    expect((await s.read({ device: 'rtr-core-1', command: '/ppp active print' })).text).toContain('AA:BB:CC:11:22:33');
    expect((await s.read({ device: 'rtr-core-1', command: '/log print' })).isError).toBe(false);
  });
});

describe('audit log', () => {
  it('records tool, device, normalised command, outcome and duration — no values, no secrets', async () => {
    const entries: AuditEntry[] = [];
    const s = mk({ audit: (e) => entries.push(e), transport: stub() });
    await s.read({ device: 'rtr-core-1', command: '/ppp active print where name=customer-name-x' });
    await s.read({ device: 'rtr-core-1', command: '/system reboot' });
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ tool: 'mikrotik_read', device: 'rtr-core-1', command: '/ppp active print where name', ok: true });
    expect(entries[1]).toMatchObject({ tool: 'mikrotik_read', ok: false, errorKind: 'policy' });
    expect(JSON.stringify(entries)).not.toMatch(/customer-name-x|LAB-PASSWORD-ONE/);
    expect(typeof entries[0]!.durationMs).toBe('number'); expect(() => new Date(entries[0]!.ts).toISOString()).not.toThrow();
  });
});

describe('credentials cache', () => {
  const counting = (fail = false) => { let calls = 0; const src: CredentialSource = { credentials: async (): Promise<DeviceCredentials> => { calls++; await new Promise((r) => setTimeout(r, 5)); if (fail) throw new Error('unavailable'); return { ...CREDS }; } }; return { src, calls: () => calls }; };
  it('concurrent loads share one lookup; cached for the TTL; reloaded after; copies are independent', async () => {
    let t = 1_000_000; const c = counting();
    const s = mk({ credentials: c.src, now: () => t });
    const [a, b] = await Promise.all([s.credentialsOf('rtr-core-1'), s.credentialsOf('rtr-core-1')]);
    expect(c.calls()).toBe(1); a.secret = 'mutated'; expect(b.secret).toBe(CREDS.secret);
    t += 299_999; expect((await s.credentialsOf('rtr-core-1')).secret).toBe(CREDS.secret); expect(c.calls()).toBe(1);
    await s.credentialsOf('rtr-edge-1'); expect(c.calls()).toBe(2);
    t += 2; await s.credentialsOf('rtr-core-1'); expect(c.calls()).toBe(3);
  });
  it('failures are not cached; dropCredentials forces a re-read', async () => {
    const c = counting(true); const s = mk({ credentials: c.src });
    await Promise.allSettled([s.credentialsOf('x'), s.credentialsOf('x')]); expect(c.calls()).toBe(1);
    await expect(s.credentialsOf('x')).rejects.toThrow('unavailable'); expect(c.calls()).toBe(2);
    const ok = counting(); const s2 = mk({ credentials: ok.src });
    await s2.credentialsOf('a'); s2.dropCredentials('a'); await s2.credentialsOf('a'); expect(ok.calls()).toBe(2);
  });
});

describe('list_devices', () => {
  it('lists devices without any credential, filtered by text or group', async () => {
    const s = mk();
    const all = await s.listDevices();
    expect(all.text).toMatch(/6 device\(s\)/); expect(all.text).not.toMatch(/LAB-|ro-user/);
    expect((await s.listDevices({ filter: 'crs' })).text).toMatch(/1 device\(s\).*sw-crs-1/s);
    expect((await s.listDevices({ group: 'edge' })).text).toMatch(/2 device\(s\)/);
    expect(all.data).toHaveLength(6);
  });
});

describe('mikrotik_batch', () => {
  it('denied login: the remaining items on that router do not try again', async () => {
    let calls = 0;
    const s = mk({ transport: async () => { calls++; const { LoginDeniedError } = await import('../../src/core/index.js'); throw new LoginDeniedError(); } });
    const out = await s.batch({ items: ['/ip address print', '/ip arp print', '/ip neighbor print'].map((command) => ({ device: 'rtr-edge-1', command })) });
    expect(calls).toBe(1); expect(out.text).toMatch(/0 ok, 3 error/); expect(out.isError).toBe(true);
  });
  it('refuses per item without failing the others, and masks secrets', async () => {
    const calls: string[] = [];
    const s = mk({ transport: stub({}, calls) });
    const out = await s.batch({ items: [
      { device: 'rtr-edge-1', command: '/system resource print' }, { device: 'rtr-edge-1', command: '/system reboot' },
      { device: 'nope', command: '/ip address print' }, { device: 'rtr-edge-2', command: '/ip neighbor print' },
    ] });
    expect(out.isError).toBe(false); expect(out.text).toMatch(/2 ok, 2 error\(s\) of 4/); expect(out.text).toMatch(/ERROR refused/);
    expect(out.text).not.toContain('LAB-PASSWORD-ONE'); expect(calls).toHaveLength(2);
  });
  it('sequential on one router, parallel across routers', async () => {
    const order: string[] = [];
    const s = mk({ transport: async (t, plan) => { order.push(`s:${t.host}${plan.apiPath}`); await new Promise((r) => setTimeout(r, 30)); order.push(`e:${t.host}${plan.apiPath}`); return { rows: [{ a: '1' }], truncated: false }; } });
    await s.batch({ items: [{ device: 'rtr-edge-1', command: '/ip address print' }, { device: 'rtr-edge-1', command: '/ip arp print' }, { device: 'rtr-core-1', command: '/ip route print count-only' }] });
    expect(order.indexOf('e:192.0.2.11/ip/address/print')).toBeLessThan(order.indexOf('s:192.0.2.11/ip/arp/print'));
    expect(order.indexOf('s:192.0.2.10/ip/route/print')).toBeLessThan(order.indexOf('e:192.0.2.11/ip/address/print'));
  });
  it('limits: empty list and more than 30 items', async () => {
    const s = mk({ transport: stub() });
    expect((await s.batch({ items: [] })).isError).toBe(true);
    expect((await s.batch({ items: Array.from({ length: 31 }, () => ({ device: 'rtr-edge-1', command: '/system resource print' })) })).text).toMatch(/at most 30/);
    expect((await s.batch({})).isError).toBe(true);
  });
  it('switches are accepted for RouterOS commands; SwOS/SNMP-only devices are refused per item', async () => {
    const s = mk({ transport: stub() });
    const out = await s.batch({ items: [{ device: 'sw-crs-1', command: '/interface print' }, { device: 'sw-css-1', command: '/interface print' }] });
    expect(out.text).toMatch(/1 ok, 1 error/);
  });
  it('benchmark: 8 routers × 3 commands finish in well under twice one router\'s sequential chain', async () => {
    const latency = 60;
    const fakes = await Promise.all(Array.from({ length: 8 }, () => live({ latencyMs: latency })));
    const devices = fakes.map((f, i) => ({ ...onPort(f.port), id: `rtr-bench-${i}`, name: `rtr-bench-${i}` }));
    const s = mk({ devices, allowInsecure: true });
    const items = devices.flatMap((d) => ['/system resource print', '/ip address print', '/interface print'].map((command) => ({ device: d.id, command })));
    const t0 = Date.now();
    const out = await s.batch({ items });
    const took = Date.now() - t0;
    expect(out.text).toMatch(/\d+ ok, \d+ error/);
    const chain = 3 * latency;
    expect(took).toBeLessThan(2 * chain);
    expect(fakes.every((f) => f.st.maxOpen === 1 && f.st.logins === 1)).toBe(true);
  });
});

describe('mikrotik_recipe', () => {
  it('refuses unknown recipes', async () => { expect((await mk({ transport: stub() }).recipe({ recipe: 'reboot' })).isError).toBe(true); });
  it('neighbors-map: edges, matching against the inventory, ARP counts, down interfaces', async () => {
    const s = mk({ transport: stub({
      '/ip/neighbor/print': [{ interface: 'sfp1', address: '192.0.2.10', identity: 'rtr-core-1', 'mac-address': '02:00:00:00:00:01', platform: 'MikroTik' }, { interface: 'ether2', identity: 'ap-x', 'mac-address': '02:00:00:00:00:02' }],
      '/ip/arp/print': [{ interface: 'bridge', address: '10.0.0.1' }, { interface: 'bridge', address: '10.0.0.2' }],
      '/interface/print': [{ name: 'ether5', type: 'ether', running: 'false' }],
    }) });
    const out = await s.recipe({ recipe: 'neighbors-map', device: 'rtr-edge-1' });
    expect(out.isError).toBe(false);
    expect(out.text).toMatch(/rtr-edge-1\[sfp1\] -> rtr-core-1 .*known rtr-core-1/); expect(out.text).toMatch(/ap-x.*not in inventory/);
    expect(out.text).toMatch(/arp: 2 entries; bridge=2/); expect(out.text).toMatch(/down: ether5/); expect(out.text).not.toContain('LAB-PASSWORD-ONE');
  });
  it('health: resource + only the running SFPs are monitored', async () => {
    const log: string[] = [];
    const s = mk({ transport: stub({
      '/system/resource/print': [{ 'board-name': 'CCR-LAB', version: '7.15', uptime: '1d', 'cpu-load': '5' }],
      '/interface/ethernet/print': [{ name: 'sfp1', running: 'true' }, { name: 'sfp2', running: 'false' }, { name: 'ether1', running: 'true' }],
      '/interface/ethernet/monitor': [{ status: 'link-ok', 'sfp-rx-power': '-3.1' }],
    }, log) });
    const out = await s.recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.text).toMatch(/cpu-load=5/); expect(out.text).toMatch(/sfp sfp1: .*sfp-rx-power=-3.1/); expect(out.text).toMatch(/1 down \(sfp2\)/);
    expect(log.filter((l) => l.startsWith('/interface/ethernet/monitor'))).toHaveLength(1);
  });
  it('health: interface names with spaces/"+" are selected by id or quoted, and a bad name never cancels the other sections', async () => {
    const log: string[] = [];
    const s = mk({ transport: stub({
      '/system/resource/print': [{ 'board-name': 'CCR-LAB', version: '7.21', uptime: '1d', 'cpu-load': '5' }],
      '/interface/ethernet/print': [
        { '.id': '*1', name: 'sfp+ 1', running: 'true' }, { name: 'sfp+ 2', running: 'true' }, { name: 'sfp(3)', running: 'true' }, { name: 'ether1', running: 'true' },
      ],
      '/interface/ethernet/monitor': [{ status: 'link-ok', 'sfp-rx-power': '-2.0' }],
    }, log) });
    const out = await s.recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.isError).toBe(false);
    expect(log).toContain('/interface/ethernet/monitor =numbers=*1 =once=');
    expect(log).toContain('/interface/ethernet/monitor =numbers=sfp+ 2 =once=');
    expect(out.text).toMatch(/sfp sfp\+ 1: .*sfp-rx-power=-2.0/); expect(out.text).toMatch(/sfp sfp\+ 2: .*link-ok/);
    expect(out.text).toMatch(/sfp sfp\(3\): ERROR .*not allowed/); expect(out.text).toMatch(/resource: board-name=CCR-LAB/); expect(out.text).toMatch(/interface: 4 ethernet/);
  });
  it('health against the wire: a spaced SFP name arrives as ONE `=numbers=` word', async () => {
    const seen: string[][] = [];
    const srv = await live({ handlers: {
      '/system/resource/print': [{ 'board-name': 'CCR-LAB', 'cpu-load': '1' }],
      '/interface/ethernet/print': [{ name: 'sfp+ 1', running: 'true' }],
      '/interface/ethernet/monitor': (words) => { seen.push(words); return [{ status: 'link-ok' }]; },
    } });
    const s = mk({ devices: [onPort(srv.port)], allowInsecure: true });
    const out = await s.recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.text).toMatch(/sfp sfp\+ 1: status=link-ok/);
    expect(seen[0]).toEqual(['/interface/ethernet/monitor', '=numbers=sfp+ 1', '=once=']);
  });
  it('a monitor command with an unquoted spaced name is still refused, with a hint to quote', async () => {
    const s = mk({ transport: stub() });
    const r = await s.read({ device: 'rtr-core-1', command: '/interface ethernet monitor sfp+ 1 once' });
    expect(r.isError).toBe(true); expect(r.text).toMatch(/single name/);
    const ok = await s.read({ device: 'rtr-core-1', command: '/interface ethernet monitor "sfp+ 1" once' });
    expect(ok.isError).toBe(false);
  });
  it('pppoe-lookup: strict name validation, safe secret columns only', async () => {
    const log: string[] = [];
    const s = mk({ transport: stub({
      '/ppp/active/print': [{ name: 'budi', address: '10.1.1.2', uptime: '1h', 'caller-id': '02:00:00:00:00:09' }],
      '/ppp/secret/print': [{ name: 'budi', password: 'LAB-PASSWORD-ONE', profile: 'p10' }],
    }, log) });
    for (const bad of ['a b;reboot', '', '../x', 'x'.repeat(65), 'a"b']) expect((await s.recipe({ recipe: 'pppoe-lookup', name: bad, device: 'rtr-edge-1' })).isError, bad).toBe(true);
    const out = await s.recipe({ recipe: 'pppoe-lookup', name: 'budi', device: 'rtr-edge-1' });
    expect(out.text).toMatch(/active: name=budi .*address=10\.1\.1\.2/); expect(out.text).toMatch(/profile=p10/); expect(out.text).not.toContain('LAB-PASSWORD-ONE');
    expect(log.some((l) => l.includes('=.proplist=') && !/password/.test(l))).toBe(true);
    expect(log.some((l) => l.startsWith('/interface/print') && l.includes('?name=<pppoe-budi>'))).toBe(true);
  });
  it('pppoe-lookup without a device searches every RouterOS router (not switches)', async () => {
    const seen = new Set<string>();
    const s = mk({ transport: async (t, plan) => { seen.add(t.host); return { rows: plan.apiPath === '/ppp/active/print' && t.host === '192.0.2.12' ? [{ name: 'budi' }] : [], truncated: false }; } });
    const out = await s.recipe({ recipe: 'pppoe-lookup', name: 'budi' });
    expect([...seen].sort()).toEqual(['192.0.2.10', '192.0.2.11', '192.0.2.12']);
    expect(out.text).toMatch(/## rtr-edge-2/); expect(out.text).toMatch(/checked without a hit: .*rtr-core-1.*rtr-edge-1/);
  });
  it('one failing section never fails the whole recipe', async () => {
    const s = mk({ transport: stub({ '/ip/arp/print': new Error('connection failed: ECONNRESET'), '/ip/neighbor/print': [], '/interface/print': [] }) });
    const out = await s.recipe({ recipe: 'neighbors-map', device: 'rtr-edge-1' });
    expect(out.isError).toBe(false); expect(out.text).toMatch(/arp: ERROR/);
  });
  it('limits: at most 8 devices; device required for health', async () => {
    const s = mk({ transport: stub() });
    expect((await s.recipe({ recipe: 'health', device: Array.from({ length: 9 }, () => 'rtr-edge-1') })).text).toMatch(/at most 8/);
    expect((await s.recipe({ recipe: 'health' })).text).toMatch(/required/);
  });
  it('truncated tables are reported as a lower bound', async () => {
    const s = mk({ transport: async (_t, plan) => ({ rows: plan.apiPath === '/ip/arp/print' ? Array.from({ length: 300 }, () => ({ interface: 'bridge' })) : [], truncated: plan.apiPath === '/ip/arp/print' }) });
    const out = await s.recipe({ recipe: 'neighbors-map', device: 'rtr-edge-1' });
    expect(out.text).toMatch(/arp: ≥300 \(truncated\)/);
  });
});

describe('ping / traceroute', () => {
  it('from a router: only /ping reaches the device; hostnames and loopback never do', async () => {
    const calls: string[] = [];
    const s = mk({ transport: stub({ '/ping': [{ host: '192.0.2.8', sent: '3', received: '3' }] }, calls) });
    expect((await s.ping({ from: 'rtr-core-1', target: '192.0.2.8', count: 3 })).isError).toBe(false);
    for (const target of ['localhost', '127.0.0.1', 'example.com', '-f', '::1']) expect((await s.ping({ from: 'rtr-core-1', target })).isError, target).toBe(true);
    expect(calls).toEqual(['/ping =address=192.0.2.8 =count=3']);
  });
  it('traceroute from a router builds the hops of the last broadcast', async () => {
    const s = mk({ transport: stub({ '/tool/traceroute': [{ '.section': '0', address: '192.0.2.1' }, { '.section': '1', address: '192.0.2.1' }, { '.section': '1', address: '198.51.100.9' }] }) });
    const r = await s.traceroute({ from: 'rtr-core-1', target: '198.51.100.9', max_hops: 5 });
    expect(r.text).toMatch(/1 192\.0\.2\.1 .*\n2 198\.51\.100\.9 /);
  });
  it('local probing is disabled by default and needs allow_local_probe', async () => {
    const calls: string[][] = [];
    const local = async (_f: string, a: string[]) => { calls.push(a); return { code: 0, stdout: 'ok', stderr: '' }; };
    const off = mk({ local });
    const r = await off.ping({ from: 'local', target: '192.0.2.8' });
    expect(r.errorKind).toBe('policy'); expect(calls).toHaveLength(0);
    const on = mk({ local, allowLocalProbe: true });
    expect((await on.ping({ from: 'local', target: '192.0.2.8', count: 10, size: 1400 })).isError).toBe(false);
    expect(calls[0]).toEqual(['-n', '-c', '10', '-W', '2', '-s', '1372', '192.0.2.8']);
  });
  it('the last argv element is always a clean address; bad numbers never reach the runner', async () => {
    const calls: string[][] = [];
    const s = mk({ allowLocalProbe: true, local: async (_f, a) => { calls.push(a); return { code: 0, stdout: 'ok', stderr: '' }; } });
    for (const t of ['-f', '-i0.001', '--help', '203.0.113.1 -f', '203.0.113.1\n-f', '$(id)', '`id`', '203.0.113.1|id', '203.0.113.1/8']) { await s.ping({ from: 'local', target: t }); await s.traceroute({ from: 'local', target: t }); }
    for (const c of calls) expect(c[c.length - 1]).toMatch(/^[A-Za-z0-9][A-Za-z0-9.:-]*$/);
    calls.length = 0;
    for (const n of [0, 11, -1, 1.5, '1e1', '0x5', Infinity, {}]) await s.ping({ from: 'local', target: '192.0.2.8', count: n });
    for (const n of [0, 27, 1401, 65000, '1e3']) await s.ping({ from: 'local', target: '192.0.2.8', size: n });
    for (const n of [0, 21, 1e9]) await s.traceroute({ from: 'local', target: '192.0.2.8', max_hops: n });
    expect(calls).toHaveLength(0);
  });
  it('the same probe twice in a row is held back; other targets are not', async () => {
    const s = mk({ allowLocalProbe: true, probe: { gapMs: 1000 }, local: async () => ({ code: 0, stdout: 'ok', stderr: '' }) });
    const a = await s.ping({ from: 'local', target: '192.0.2.8' }); const b = await s.ping({ from: 'local', target: '192.0.2.8' }); const c = await s.ping({ from: 'local', target: '192.0.2.9' });
    expect(a.isError).toBe(false); expect(b.isError).toBe(true); expect(b.text).toMatch(/just ran/); expect(c.isError).toBe(false);
  });
  it('parallel local probes are capped (no local flood)', async () => {
    let live = 0; let peak = 0;
    const s = mk({ allowLocalProbe: true, local: async () => { live++; peak = Math.max(peak, live); await new Promise((r) => setTimeout(r, 30)); live--; return { code: 0, stdout: 'ok', stderr: '' }; } });
    await Promise.all(Array.from({ length: 40 }, (_v, i) => s.ping({ from: 'local', target: `192.0.2.${i + 1}`, count: 10 })));
    expect(peak).toBeLessThanOrEqual(4);
  });
  it('probe.deny_cidrs / allow_cidrs restrict targets', async () => {
    const calls: string[] = [];
    const s = mk({ transport: stub({}, calls), probe: { gapMs: 0, denyCidrs: ['192.0.2.0/25', '2001:db8:dead::/48'], allowCidrs: ['192.0.2.0/24', '198.51.100.0/24', '2001:db8::/32'] } });
    expect((await s.ping({ from: 'rtr-core-1', target: '192.0.2.8' })).text).toMatch(/denied network/);
    expect((await s.ping({ from: 'rtr-core-1', target: '2001:db8:dead::1' })).text).toMatch(/denied network/);
    expect((await s.ping({ from: 'rtr-core-1', target: '203.0.113.9' })).text).toMatch(/outside the allowed/);
    expect((await s.ping({ from: 'rtr-core-1', target: '192.0.2.200' })).isError).toBe(false);
    expect((await s.ping({ from: 'rtr-core-1', target: '198.51.100.7' })).isError).toBe(false);
    expect(calls).toHaveLength(2);
  });
  it('invalid CIDR configuration is rejected at construction', () => {
    expect(() => mk({ probe: { denyCidrs: ['not-a-cidr'] } })).toThrow(/invalid CIDR/);
    expect(() => mk({ probe: { denyCidrs: ['192.0.2.0/33'] } })).toThrow(/invalid CIDR/);
  });
  it('`from` is required', async () => { expect((await mk().ping({ target: '192.0.2.8' })).isError).toBe(true); });
});

describe('snmp_get', () => {
  const calls: Array<{ op: string; oids: string[]; rows: number; community: string; port: number }> = [];
  const snmp = async (t: { community: string; port: number }, op: string, oids: string[], rows: number) => { calls.push({ op, oids, rows, community: t.community, port: t.port }); return [{ oid: oids[0]!, value: 'ok' }]; };
  const mkSnmp = () => { calls.length = 0; return mk({ snmp: snmp as never }); };
  it('exactly one of name/oid; bounds; non-numeric or over-long oids are refused', async () => {
    const s = mkSnmp();
    for (const a of [{}, { name: 'sysName', oid: '1.3.6.1.2.1.1.5.0' }, { oid: '1.3' }, { oid: `1.3.6.1.2.1.1.5.0${'.9'.repeat(40)}` }, { oid: '1.3.6.1.2.1.1.5.0;' }, { oid: '1.3.6.1.2.1.1.5.0', limit: 501 }, { oid: '1.3.6.1.2.1.1.5.0', limit: -1 }, { oid: '1.3.6.1.2.1.1.5.0', limit: '1e2' }])
      expect((await s.snmpGet({ device: 'rtr-core-1', ...a })).isError, JSON.stringify(a)).toBe(true);
    expect(calls).toHaveLength(0);
  });
  it('prototype-ish names are refused cleanly', async () => {
    const s = mkSnmp();
    for (const n of ['constructor', 'toString', 'valueOf', '__proto__', 'hasOwnProperty']) expect((await s.snmpGet({ device: 'rtr-core-1', name: n })).text, n).toMatch(/unknown SNMP name/);
  });
  it('dangerous subtrees are refused, readable ones pass', async () => {
    const s = mkSnmp();
    for (const oid of ['1.3.6.1.2.1.25.4.2.1.5', '1.3.6.1.2.1.25.4', '1.3.6.1.4.1.8072.1.3.2', '1.3.6.1.4.1.2021.8', '1.3.6.1.6.3.18', '1.3.6.1.6.3.16', '1.3.6.1.6.3.15', '1.3.6.1', '1.3.6.1.2.1', '1.3.6.1.4.1', '1.3.6.1.4.1.2021.50.1.2'])
      expect((await s.snmpGet({ device: 'rtr-core-1', oid, walk: true })).isError, oid).toBe(true);
    for (const oid of ['1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.2.2.1.8', '1.3.6.1.2.1.31.1.1.1.1', '1.3.6.1.2.1.25.3.3.1.2', '1.3.6.1.4.1.14988.1.1.3', '1.3.6.1.2.1.4.22'])
      expect((await s.snmpGet({ device: 'rtr-core-1', oid, walk: true })).isError, oid).toBe(false);
  });
  it('uses the community of the device, the SNMP port, and never prints the community', async () => {
    const s = mk({ snmp: async () => [{ oid: '1.3.6.1.2.1.1.1.0', value: 'descr LAB-COMMUNITY-ONE x' }] });
    const r = await s.snmpGet({ device: 'ap-snmp-1', name: 'sysDescr' });
    expect(r.text).not.toContain('LAB-COMMUNITY-ONE');
    const boom = mk({ snmp: async () => { throw new Error('failed LAB-COMMUNITY-ONE'); } });
    expect((await boom.snmpGet({ device: 'ap-snmp-1', name: 'sysDescr' })).text).not.toContain('LAB-COMMUNITY-ONE');
    const s2 = mkSnmp(); await s2.snmpGet({ device: 'ap-snmp-1', name: 'sysDescr' });
    expect(calls[0]).toMatchObject({ community: 'LAB-COMMUNITY-ONE', port: 161, op: 'get' });
  });
  it('a missing community is a config error; an unknown device is not-found', async () => {
    const s = mk({ credentials: staticCreds({ user: 'u', secret: 's' }), snmp: snmp as never });
    expect((await s.snmpGet({ device: 'ap-snmp-1', name: 'sysName' })).errorKind).toBe('config');
    expect((await mkSnmp().snmpGet({ device: 'nope', name: 'sysName' })).errorKind).toBe('not-found');
  });
  it('parallel calls are limited to 10 at once; the rest wait', async () => {
    let live = 0; let peak = 0;
    const s = mk({ snmp: async () => { live++; peak = Math.max(peak, live); await new Promise((r) => setTimeout(r, 20)); live--; return [{ oid: '1.3.6.1.2.1.1.3.0', value: '1' }]; } });
    const out = await Promise.all(Array.from({ length: 20 }, () => s.snmpGet({ device: 'rtr-core-1', name: 'sysUpTime' })));
    expect(peak).toBe(10); expect(out.every((r) => !r.isError)).toBe(true);
  });
  it('the source tree has no SNMP SET PDU', async () => {
    const fs = await import('node:fs'); const src = fs.readFileSync(new URL('../../src/core/snmp.ts', import.meta.url), 'utf8');
    expect(/0xa3|setRequest|0xa4\b/i.test(src)).toBe(false);
  });
});

describe('switch_read', () => {
  const run = (a: Record<string, unknown>, calls: string[] = []) => mk({ transport: stub({}, calls) }).switchRead({ device: 'sw-crs-1', ...a });
  it('maps ready-made commands to allowlisted print commands', async () => {
    const calls: string[] = [];
    await run({ command: 'bridge-host', filter: 'on-interface=sfp-sfpplus1' }, calls);
    expect(calls).toEqual(['/interface/bridge/host/print ?on-interface=sfp-sfpplus1']);
    const c2: string[] = []; await run({ command: 'mac-table-count' }, c2); expect(c2[0]).toMatch(/^\/interface\/bridge\/host\/print =count-only=/);
  });
  it('hostile filters never produce an unsafe command', async () => {
    for (const f of ['x=y" or ""="', 'on-interface=a"; /system reboot; "', 'a=b\nc=d', 'a=b$(x)', 'a=[x]', 'a=b\\', 'on-interface=a b" "', 'password=x', 'secret=x']) {
      const calls: string[] = []; const r = await run({ command: 'bridge-host', filter: f }, calls);
      expect(r.isError, f).toBe(true); expect(calls, f).toEqual([]);
    }
  });
  it('rejects prototype keys and unknown commands; non-switches are not found', async () => {
    for (const v of ['constructor', '__proto__', 'toString', 'reboot', '']) expect((await run({ command: v })).isError, v).toBe(true);
    expect((await mk({ transport: stub() }).switchRead({ device: 'rtr-core-1', command: 'resource' })).errorKind).toBe('not-found');
  });
  it('PoE on a model without PoE gets a clear message', async () => {
    const s = mk({ transport: stub({ '/interface/ethernet/poe/print': new Error('device refused: no such command prefix') }) });
    const r = await s.switchRead({ device: 'sw-crs-1', command: 'poe' });
    expect(r.text).toMatch(/has no PoE/); expect(r.text).not.toMatch(/no such command/);
  });
  it('SwOS switches are read over SNMP: sysinfo and interfaces', async () => {
    const s = mk({ snmp: async (_t, op, oids) => {
      if (op === 'get') return [{ oid: '1.3.6.1.2.1.1.5.0', value: 'sw-css-1' }];
      if (oids[0] === '1.3.6.1.2.1.2.2.1.2') return [{ oid: '1.3.6.1.2.1.2.2.1.2.1', value: 'port1' }];
      if (oids[0] === '1.3.6.1.2.1.2.2.1.8') return [{ oid: '1.3.6.1.2.1.2.2.1.8.1', value: '1' }];
      return [{ oid: '1.3.6.1.2.1.31.1.1.1.15.1', value: '1000' }];
    } });
    expect((await s.switchRead({ device: 'sw-css-1', command: 'sysinfo' })).text).toContain('sysName = sw-css-1');
    expect((await s.switchRead({ device: 'sw-css-1', command: 'interfaces' })).text).toContain('1 port1 status=up speed=1000Mbps');
    expect((await s.switchRead({ device: 'sw-css-1', command: 'resource' })).isError).toBe(true);
  });
});

describe('snapshot tool wiring', () => {
  it('is a clear config error when not enabled', async () => { const r = await mk().snapshot({}); expect(r.errorKind).toBe('config'); });
});

describe('a real pool behind the facade', () => {
  it('uses its own RosPool (one login for many calls)', async () => {
    const srv = await live();
    const pool = new RosPool();
    const s = mk({ devices: [onPort(srv.port)], allowInsecure: true, pool });
    for (let i = 0; i < 3; i++) await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(pool.stats.logins).toBe(1); expect(srv.st.logins).toBe(1);
  });
});

describe('policy text is not redacted; locale', () => {
  it('our own refusal explanation stays readable (no [redacted] inside the policy sentence)', async () => {
    const s = mk({ transport: stub() });
    const r = await s.read({ device: 'rtr-core-1', command: '/system scheduler print' });
    expect(r.isError).toBe(true); expect(r.text).toContain('(secrets, endless stream, or file writes)'); expect(r.text).not.toMatch(/\[redacted\]/);
    const list = await s.read({ device: 'rtr-core-1', command: '/ppp aaa-x print' });
    expect(list.text).toContain('/ppp secret'); expect(list.text).not.toMatch(/\[redacted\]/);
  });
  it('key=value pairs echoed by the caller are still masked in the refusal', async () => {
    const s = mk({ transport: stub() });
    const r = await s.read({ device: 'rtr-core-1', command: '/ip address print password=Zq63Syn6vTok' });
    expect(r.isError).toBe(true); expect(r.text).not.toContain('Zq63Syn6vTok');
  });
  it('router-originated error text is still scrubbed', async () => {
    const s = mk({ transport: stub({ '/system/resource/print': new Error('boom password=LAB-PASSWORD-ONE secret LAB-COMMUNITY-ONE') }) });
    const r = await s.read({ device: 'rtr-core-1', command: '/system resource print' });
    expect(r.isError).toBe(true); expect(r.text).not.toMatch(/LAB-PASSWORD-ONE|LAB-COMMUNITY-ONE/);
  });
  it('locale en is the default and byte-identical in the frame', async () => {
    const s = mk({ transport: stub() });
    expect((await s.read({ device: 'rtr-core-1', command: '/system reboot' })).text).toMatch(/^mikrotik_read refused: /);
    expect((await s.read({ device: 'rtr-core-1', command: '/system resource print' })).text).toMatch(/\(\d+ ms, read-only\)$/);
    expect((await s.batch({ items: [] })).text).toMatch(/^mikrotik_batch refused: /);
  });
  it('locale id translates the frame (refused/failed/ERROR/footer/no rows/batch/recipe) and leaves router output alone', async () => {
    const s = mk({ locale: 'id', transport: stub({ '/ip/address/print': [], '/system/resource/print': [{ 'cpu-load': '3' }], '/ppp/active/print': new Error('boom') }) });
    expect((await s.read({ device: 'rtr-core-1', command: '/system reboot' })).text).toMatch(/^mikrotik_read ditolak: /);
    expect((await s.read({ device: 'rtr-core-1', command: '/ip address print' })).text).toMatch(/\(tidak ada baris\)\n\(\d+ ms, hanya baca\)$/);
    const failed = await s.read({ device: 'rtr-core-1', command: '/ppp active print' });
    expect(failed.text).toMatch(/^mikrotik_read gagal \[rtr-core-1\]: boom/);
    const batch = await s.batch({ items: [{ device: 'rtr-core-1', command: '/system resource print' }, { device: 'rtr-core-1', command: '/system reboot' }] });
    expect(batch.text).toMatch(/1 ok, 1 galat dari 2 item/); expect(batch.text).toMatch(/GALAT ditolak: /); expect(batch.text).toContain('cpu-load=3');
    expect((await s.batch({ items: [] })).text).toMatch(/^mikrotik_batch ditolak: /);
    const rec = await s.recipe({ recipe: 'pppoe-lookup', name: 'nobody', device: 'rtr-core-1' });
    expect(rec.text).toMatch(/GALAT boom|diperiksa tanpa hasil/);
    expect((await s.listDevices({})).text).toMatch(/^6 perangkat:/);
    expect((await s.snapshot({})).text).toMatch(/tidak aktif/);
  });
  it('an injected dictionary overrides single sentences on top of the locale', async () => {
    const s = mk({ locale: 'id', messages: { error: 'KO', footer: (ms) => `<${ms}>` }, transport: stub() });
    expect((await s.read({ device: 'rtr-core-1', command: '/system resource print' })).text).toMatch(/<\d+>$/);
    expect((await s.batch({ items: [{ device: 'rtr-core-1', command: '/system reboot' }] })).text).toContain('KO ditolak');
  });
  it('an unknown locale is rejected at construction', () => {
    expect(() => mk({ locale: 'xx' as 'en' })).toThrow(/unknown locale/);
  });
  it('list_devices: SNMP-only/SwOS devices show the SNMP port, API devices the API port', async () => {
    const t = (await mk().listDevices({})).text;
    expect(t).toMatch(/rtr-core-1 \| 192\.0\.2\.10:8729 \|/); expect(t).toMatch(/sw-css-1 \| 198\.51\.100\.22 \(snmp:161\) \|/); expect(t).toMatch(/ap-snmp-1 \| 198\.51\.100\.23 \(snmp:161\) \|/);
    expect(t).not.toMatch(/sw-css-1 \| 198\.51\.100\.22:8729/);
  });
  it('export over SSH: friendly errors for a missing client and a refused password', async () => {
    const missing = mk({ ssh: async () => ({ code: 255, stdout: '', stderr: 'ENOENT: ssh not found' }) });
    expect((await missing.read({ device: 'rtr-core-1', command: '/ip address export hide-sensitive' })).text).toMatch(/OpenSSH client \(ssh\) is not installed/);
    const denied = mk({ ssh: async () => ({ code: 255, stdout: '', stderr: 'Permission denied, please try again.' }) });
    expect((await denied.read({ device: 'rtr-core-1', command: '/ip address export hide-sensitive' })).text).toMatch(/SSH login was refused.*key file/);
  });
});
