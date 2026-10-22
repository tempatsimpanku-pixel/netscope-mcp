import { afterEach, describe, expect, it } from 'vitest';
import { ConnectError, NetScope, type DeviceInfo, type NetScopeOptions, type RosTransport } from '../../src/core/index.js';
import { quoteName } from '../../src/core/format.js';
import { fakeRos, type FakeRos } from '../helpers/fake-ros.js';
import { DEVICES, staticCreds, staticSource, CREDS } from '../helpers/fixtures.js';
import { V6, V7 } from '../helpers/ros-versions.js';

const scopes: NetScope[] = [];
const servers: FakeRos[] = [];
const mk = (opts: Partial<NetScopeOptions> = {}): NetScope => {
  const s = new NetScope({ devices: staticSource(DEVICES), credentials: staticCreds(), probe: { gapMs: 0 }, redactPii: false, ...opts });
  scopes.push(s);
  return s;
};
const answering = (table: Record<string, Array<Record<string, string>> | Error>, log: string[] = []): RosTransport => async (_t, plan) => {
  log.push(plan.apiPath);
  const a = table[plan.apiPath];
  if (a instanceof Error) throw a;
  if (!a) throw new Error('no such command prefix');
  return { rows: a, truncated: false };
};
afterEach(async () => { scopes.splice(0).forEach((s) => s.close()); await Promise.all(servers.splice(0).map((s) => s.close())); });

describe.each([['v6', V6], ['v7', V7]] as const)('RouterOS %s answers', (_name, table) => {
  it('resource, clock and neighbors are returned as the router wrote them', async () => {
    const s = mk({ transport: answering(table) });
    const clock = await s.read({ device: 'rtr-core-1', command: '/system clock print' });
    expect(clock.isError).toBe(false);
    expect(clock.text).toContain(`date=${table['/system/clock/print']![0]!.date}`);
    const nb = await s.read({ device: 'rtr-core-1', command: '/ip neighbor print' });
    expect(nb.text).toContain('identity=sw-crs-1');
  });
  it('neighbors-map matches the neighbor with the inventory in both shapes', async () => {
    const out = await mk({ transport: answering(table) }).recipe({ recipe: 'neighbors-map', device: 'rtr-core-1' });
    expect(out.text).toMatch(/= known sw-crs-1/); expect(out.text).toMatch(/\(total 1 edges\)/);
  });
});

describe('/system health shapes', () => {
  it('v6 flat row is shown as key=value pairs', async () => {
    const out = await mk({ transport: answering(V6) }).recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.text).toMatch(/health: voltage=24\.2 temperature=38/); expect(out.text).toMatch(/board-name=RB-LAB-V6/);
  });
  it('v7 name/value/type rows are shown as name=value+unit', async () => {
    const out = await mk({ transport: answering(V7) }).recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.text).toMatch(/health: voltage=24\.2V temperature=32C/); expect(out.text).toMatch(/sfp sfp-sfpplus1: status=link-ok/);
  });
});

describe('models without a feature', () => {
  it('x86 has no /system routerboard: the hint says it is not a connection problem', async () => {
    const srv = await fakeRos({ password: CREDS.secret, user: CREDS.user }); servers.push(srv);
    const dev: DeviceInfo = { ...DEVICES[0]!, host: '127.0.0.1', port: srv.port, transport: 'api' };
    const out = await mk({ devices: staticSource([dev]), allowInsecure: true }).read({ device: dev.id, command: '/system routerboard print' });
    expect(out.isError).toBe(true); expect(out.text).toMatch(/does not exist on this device model/);
  });
  it('x86 health with only `state=disabled` is printed as is', async () => {
    const out = await mk({ transport: answering({ ...V7, '/system/health/print': [{ state: 'disabled' }] }) }).recipe({ recipe: 'health', device: 'rtr-core-1' });
    expect(out.text).toMatch(/health: state=disabled/);
  });
  it('a switch without PoE says so', async () => {
    const out = await mk({ transport: answering({}) }).switchRead({ device: 'sw-crs-1', command: 'poe' });
    expect(out.isError).toBe(true); expect(out.text).toMatch(/has no PoE/);
  });
});

describe('field reports', () => {
  it('/snmp community print shows the access scope (never the community or the passwords)', async () => {
    const seen: string[][] = [];
    const srv = await fakeRos({ password: CREDS.secret, user: CREDS.user, handlers: { '/snmp/community/print': (w) => { seen.push(w); return [{ name: 'LAB-COMMUNITY-ONE', addresses: '192.0.2.0/24', security: 'none', 'read-access': 'true', 'write-access': 'false', 'authentication-password': 'x' }]; } } }); servers.push(srv);
    const dev: DeviceInfo = { ...DEVICES[0]!, host: '127.0.0.1', port: srv.port, transport: 'api' };
    const out = await mk({ devices: staticSource([dev]), allowInsecure: true }).read({ device: dev.id, command: '/snmp community print' });
    expect(seen[0]).toContain('=.proplist=addresses,security,read-access,write-access,disabled');
    expect(out.text).toMatch(/addresses=192\.0\.2\.0\/24/); expect(out.text).not.toContain('LAB-COMMUNITY-ONE');
  });
  it('a row with nothing to show says why instead of printing a bare index', async () => {
    const out = await mk({ transport: answering({ '/snmp/community/print': [{}] }) }).read({ device: 'rtr-core-1', command: '/snmp community print' });
    expect(out.text).toMatch(/0 \(no fields returned/);
  });
  it('batch names the device of a refused item (and shows an unknown reference as given)', async () => {
    const out = await mk({ transport: answering(V7) }).batch({ items: [{ device: 'rtr-core-1', command: '/system reboot' }, { device: 'nope-1', command: '/ip arp print' }] });
    expect(out.text).toMatch(/1\. ERROR — rtr-core-1: \/system reboot/); expect(out.text).toMatch(/2\. ERROR — nope-1: /);
  });
  it('redact_ppp_names is off by default and masks PPP login names when on', async () => {
    const t = answering({ '/ppp/active/print': [{ name: 'pelanggan-01', service: 'pppoe', address: '192.0.2.77', 'caller-id': '02:00:5E:00:53:99' }] });
    const off = await mk({ transport: t, redactPii: true }).read({ device: 'rtr-core-1', command: '/ppp active print' });
    expect(off.text).toContain('name=pelanggan-01'); expect(off.text).toContain('02:00:5E:xx:xx:xx');
    const on = await mk({ transport: t, redactPii: true, redactPppNames: true }).read({ device: 'rtr-core-1', command: '/ppp active print' });
    expect(on.text).toContain('name=[redacted]'); expect(on.text).not.toContain('pelanggan-01');
  });
  it('ARP summary quotes interface names that would read like a list number', async () => {
    expect(quoteName('ether5')).toBe('ether5'); expect(quoteName('1. ether1')).toBe('"1. ether1"'); expect(quoteName('sfp+ 1')).toBe('"sfp+ 1"');
    const out = await mk({ transport: answering(V7) }).recipe({ recipe: 'neighbors-map', device: 'rtr-core-1' });
    expect(out.text).toMatch(/arp: 2 entries; ether1=1; "1\. ether1"=1/);
  });
  it('monitor of an unknown interface names the interface', async () => {
    const out = await mk({ transport: answering({ '/interface/ethernet/monitor': new Error('device refused: no such item') }) }).read({ device: 'rtr-core-1', command: '/interface ethernet monitor ether1 once' });
    expect(out.isError).toBe(true); expect(out.text).toMatch(/no item named "ether1"/);
  });
});

describe('circuit breaker per device', () => {
  it('batch: after one failed connect the other items of that device fail at once; other devices are unaffected', async () => {
    let calls = 0; const hosts: string[] = [];
    const s = mk({ transport: async (t) => { calls++; hosts.push(t.host); if (t.host === '192.0.2.11') throw new ConnectError('could not connect within 6 s.'); return { rows: [{ a: '1' }], truncated: false }; } });
    const t0 = Date.now();
    const out = await s.batch({ items: [
      { device: 'rtr-edge-1', command: '/ip address print' }, { device: 'rtr-edge-1', command: '/ip arp print' }, { device: 'rtr-edge-1', command: '/ip neighbor print' },
      { device: 'rtr-core-1', command: '/ip address print' },
    ] });
    expect(hosts.filter((h) => h === '192.0.2.11')).toHaveLength(1); expect(calls).toBe(2);
    expect(out.text).toMatch(/1 ok, 3 error/); expect((out.text.match(/did not connect earlier in this call/g) ?? [])).toHaveLength(2);
    expect(Date.now() - t0).toBeLessThan(2_000);
  });
  it('recipe: the sections of an unreachable device make one attempt, and the next call tries again', async () => {
    let calls = 0;
    const s = mk({ transport: async () => { calls++; throw new ConnectError('could not connect within 6 s.'); } });
    const out = await s.recipe({ recipe: 'health', device: 'rtr-edge-1' });
    expect(calls).toBe(1); expect(out.text).toMatch(/resource: ERROR/);
    await s.recipe({ recipe: 'health', device: 'rtr-edge-1' });
    expect(calls).toBe(2);
  });
  it('a non-connection failure (device error) does not open the breaker', async () => {
    let calls = 0;
    const s = mk({ transport: async () => { calls++; throw new Error('device refused: no such item'); } });
    await s.batch({ items: [{ device: 'rtr-edge-1', command: '/ip address print' }, { device: 'rtr-edge-1', command: '/ip arp print' }] });
    expect(calls).toBe(2);
  });
});
