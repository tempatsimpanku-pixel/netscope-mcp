import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  LoginDeniedError, NetScope, SNAPSHOT_FAIL_MULT_MAX, SNAPSHOT_LOGIN_DENIED_MS, SnapshotStore, SnapshotWorker, collectRouter, monitorPlan, searchSnapshots, snapshotTool,
  type DeviceInfo, type NetScopeOptions, type RosTransport, type SnapData,
} from '../../src/core/index.js';
import { DEVICES, staticCreds, staticSource } from '../helpers/fixtures.js';

const tmp: string[] = [];
const tmpdir = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'netscope-snap-')); tmp.push(d); return d; };
const stores: SnapshotStore[] = [];
const store = (file = ':memory:') => { const s = new SnapshotStore(file); stores.push(s); return s; };
afterEach(() => { stores.splice(0).forEach((s) => s.close()); tmp.splice(0).forEach((d) => fs.rmSync(d, { recursive: true, force: true })); });

const ROUTES: Record<string, Array<Record<string, string>>> = {
  '/system/resource/print': [{ 'board-name': 'CCR-LAB', version: '7.15.2 (stable)', uptime: '3d', 'cpu-load': '7', 'free-memory': '250', 'total-memory': '1000' }],
  '/interface/print': [{ name: 'ether1', type: 'ether', running: 'true', disabled: 'false', comment: 'uplink to ix' }, { name: 'ether2', type: 'ether', running: 'false', disabled: 'false' }, { name: 'sfp1', type: 'ether', running: 'true', disabled: 'false' }, { name: 'bridge1', type: 'bridge', running: 'true', disabled: 'false' }],
  '/interface/ethernet/monitor': [{ name: 'ether1', rate: '1Gbps' }, { name: 'sfp1', rate: '10Gbps' }],
  '/ip/neighbor/print': [{ interface: 'sfp1', address: '192.0.2.10', 'mac-address': '02:00:00:00:00:01', identity: 'rtr-core-1', platform: 'MikroTik', board: 'CCR', version: '7.15 (stable)' }],
  '/ip/route/print': [{ gateway: '192.0.2.1', disabled: 'false', active: 'true' }],
  '/ip/arp/print': [{ interface: 'bridge1', address: '192.0.2.1', 'mac-address': '02:00:00:00:00:aa', complete: 'true', disabled: 'false' }, { interface: 'bridge1', address: '10.0.0.7', complete: 'false', disabled: 'false' }, { interface: 'bridge1', address: '10.0.0.8', 'mac-address': '02:00:00:00:00:bb', complete: 'true', disabled: 'false' }],
  '/ppp/active/print': [{ name: 'cust-alpha', address: '10.1.0.5', 'caller-id': '02:00:00:00:00:cc', uptime: '1h' }, { name: 'cust-beta', address: '10.1.0.6', 'caller-id': '02:00:00:00:00:dd', uptime: '2h' }],
};
const routerTransport = (routes = ROUTES, log: string[] = []): RosTransport => async (_t, plan) => {
  log.push(plan.apiPath);
  const r = routes[plan.apiPath];
  if (!r) throw new Error('device refused: no such command prefix');
  return { rows: r, truncated: false };
};
const scope = (transport: RosTransport, extra: Partial<NetScopeOptions> = {}) => new NetScope({ devices: staticSource(), credentials: staticCreds(), transport, redactPii: false, ...extra });
const core = DEVICES.find((d) => d.id === 'rtr-edge-1')!;

describe('SnapshotStore', () => {
  it('creates the database file privately (0600), the new directory 0700, and keeps WAL files private', () => {
    const dir = path.join(tmpdir(), 'state', 'snap'); const file = path.join(dir, 'snap.sqlite');
    const s = store(file);
    s.saveOk({ id: 'a', alias: 'a', family: 'routeros' }, { resource: { cpu: 1, uptime: '', version: '', board: '', freeMem: null, totalMem: null } }, 1000, 2000, 5);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    for (const side of [`${file}-wal`, `${file}-shm`]) if (fs.existsSync(side)) expect(fs.statSync(side).mode & 0o777).toBe(0o600);
  });
  it('tightens an existing, looser file', () => {
    const file = path.join(tmpdir(), 'loose.sqlite'); fs.writeFileSync(file, '', { mode: 0o644 });
    store(file);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });
  it('failure keeps old data and its age; success resets the failure count; prune drops removed routers', () => {
    const s = store(); const meta = { id: 'a', alias: 'a', family: 'routeros' };
    s.saveOk(meta, { skipped: ['x'] }, 1000, 5000, 3);
    s.saveFail(meta, 'timeout', 2000, 9000); s.saveFail(meta, 'timeout', 3000, 9000);
    expect(s.get('a')).toMatchObject({ takenAt: 1000, fails: 2, error: 'timeout', nextDue: 9000, data: { skipped: ['x'] } });
    s.saveOk(meta, {}, 4000, 8000, 1); expect(s.get('a')).toMatchObject({ fails: 0, error: '' });
    s.saveOk({ id: 'b', alias: 'b', family: 'routeros' }, {}, 1, 2, 1);
    expect(s.prune(['a'])).toBe(1); expect(s.all().map((r) => r.routerId)).toEqual(['a']); expect(s.prune([])).toBe(0);
  });
  it('survives a restart (data on disk)', () => {
    const file = path.join(tmpdir(), 'r.sqlite');
    const a = new SnapshotStore(file); a.saveOk({ id: 'a', alias: 'a', family: 'routeros' }, { skipped: ['arp'] }, 10, 99, 1); a.close();
    const b = store(file);
    expect(b.get('a')).toMatchObject({ takenAt: 10, nextDue: 99, data: { skipped: ['arp'] } });
  });
});

describe('collectRouter', () => {
  it('collects resource, interfaces (+speeds), neighbors, ARP (+gateway), PPP — only via allowlisted print commands', async () => {
    const log: string[] = []; const s = scope(routerTransport(ROUTES, log));
    const d = await collectRouter(s, core, { storeCustomerData: true });
    expect(d.resource).toMatchObject({ cpu: 7, version: '7.15.2', board: 'CCR-LAB', freeMem: 250 });
    expect(d.interfaces!.find((i) => i.n === 'ether1')).toMatchObject({ r: 1, d: 0, s: '1Gbps', c: 'uplink to ix' });
    expect(d.interfaces!.find((i) => i.n === 'sfp1')!.s).toBe('10Gbps');
    expect(d.neighbors).toEqual([{ i: 'sfp1', a: '192.0.2.10', m: '02:00:00:00:00:01', id: 'rtr-core-1', p: 'MikroTik', b: 'CCR', v: '7.15' }]);
    expect(d.arp).toMatchObject({ total: 3, failed: 1, perIf: { bridge1: { t: 3, f: 1 } }, failedList: [{ i: 'bridge1', a: '10.0.0.7' }], gateway: [{ a: '192.0.2.1', m: '02:00:00:00:00:AA', ok: true }] });
    expect(d.ppp).toMatchObject({ count: 2, entries: [{ n: 'cust-alpha', a: '10.1.0.5', c: '02:00:00:00:00:CC', u: '1h' }, { n: 'cust-beta' }] });
    expect(log).toEqual(['/system/resource/print', '/interface/print', '/interface/ethernet/monitor', '/ip/neighbor/print', '/ip/route/print', '/ip/arp/print', '/ppp/active/print']);
  });
  it('keeps only counts for customer data unless asked (default)', async () => {
    const d = await collectRouter(scope(routerTransport()), core);
    expect(d.ppp).toMatchObject({ count: 2, entries: [] }); expect(d.arp).toMatchObject({ failed: 1, failedList: [] });
    expect(JSON.stringify(d)).not.toMatch(/cust-alpha|10\.1\.0\.5|02:00:00:00:00:cc/i);
  });
  it('skips ARP and PPP when the router CPU is high', async () => {
    const routes = { ...ROUTES, '/system/resource/print': [{ 'cpu-load': '95', version: '7.15' }] }; const log: string[] = [];
    const d = await collectRouter(scope(routerTransport(routes, log)), core);
    expect(d.skipped).toEqual(['arp', 'ppp']); expect(log).not.toContain('/ip/arp/print'); expect(log).not.toContain('/ppp/active/print');
  });
  it('core routers skip the default-route lookup (big tables)', async () => {
    const log: string[] = [];
    await collectRouter(scope(routerTransport(ROUTES, log)), { ...core, labels: { role: 'core' } });
    expect(log).not.toContain('/ip/route/print');
  });
  it('a failing section is recorded, the rest still collected; a failing resource fails the router', async () => {
    const routes = { ...ROUTES }; delete (routes as Record<string, unknown>)['/ip/neighbor/print'];
    const d = await collectRouter(scope(routerTransport(routes)), core);
    expect(d.errors!.neighbor).toMatch(/no such command/); expect(d.arp).toBeDefined();
    await expect(collectRouter(scope(async () => { throw new Error('connection failed: ECONNREFUSED'); }), core)).rejects.toThrow(/ECONNREFUSED/);
  });
  it('monitorPlan only accepts clean port names (max 40)', () => {
    expect(monitorPlan(['ether1', 'bad name;', 'sfp-sfpplus1']).words).toEqual(['=numbers=ether1,sfp-sfpplus1', '=once=']);
    expect(() => monitorPlan(['bad name;'])).toThrow();
    expect(monitorPlan(Array.from({ length: 60 }, (_v, i) => `p${i}`)).words[0]!.split(',').length).toBe(40);
  });
});

describe('SnapshotWorker', () => {
  const data: SnapData = { resource: { cpu: 5, uptime: '1d', version: '7.15', board: 'CCR', freeMem: 1, totalMem: 2 } };
  const mkWorker = (st: SnapshotStore, o: { now: () => number; collect?: (d: DeviceInfo) => Promise<SnapData>; sc?: NetScope }) => {
    const sc = o.sc ?? scope(routerTransport());
    return new SnapshotWorker({ scope: sc, store: st, intervalMs: 600_000, gapMs: 0, now: o.now, sleep: async () => undefined, collect: o.collect ?? (async () => data) });
  };
  const ROS_COUNT = DEVICES.filter((d) => d.family === 'routeros' || d.family === 'switch').length;

  it('collects every RouterOS device once; a second cycle before the interval does nothing (idempotent)', async () => {
    let t = 1_000_000; const st = store(); const calls: string[] = [];
    const w = mkWorker(st, { now: () => t, collect: async (d) => { calls.push(d.id); return data; } });
    const a = await w.runCycle(); expect(a).toMatchObject({ ok: ROS_COUNT, failed: 0 });
    t += 60_000; const b = await w.runCycle(); expect(b).toMatchObject({ ok: 0, skipped: ROS_COUNT });
    expect(calls).toHaveLength(ROS_COUNT); expect(calls).not.toContain('sw-css-1'); expect(calls).not.toContain('ap-snmp-1');
    t += 600_001; expect((await w.runCycle()).ok).toBe(ROS_COUNT - 1); // the core router (×3 interval) is not due yet
  });
  it('core routers are polled less often (×3)', async () => {
    const t = 1_000_000; const st = store();
    const w = mkWorker(st, { now: () => t });
    await w.runCycle();
    expect(st.get('rtr-core-1')!.nextDue - t).toBe(600_000 * 3); expect(st.get('rtr-edge-1')!.nextDue - t).toBe(600_000);
  });
  it('a restart (new worker, same file) does not re-collect what is not due', async () => {
    const file = path.join(tmpdir(), 'w.sqlite'); const t = 5_000_000;
    const s1 = new SnapshotStore(file); await mkWorker(s1, { now: () => t }).runCycle(); s1.close();
    const s2 = store(file); const calls: string[] = [];
    const r = await mkWorker(s2, { now: () => t + 1000, collect: async (d) => { calls.push(d.id); return data; } }).runCycle();
    expect(r.ok).toBe(0); expect(calls).toHaveLength(0);
  });
  it('failures back off (1+fails × interval, capped), keep old data, and report', async () => {
    let t = 1_000_000; const st = store(); let fail = false;
    const w = mkWorker(st, { now: () => t, collect: async () => { if (fail) throw new Error('timed out (15 s).'); return data; } });
    await w.runCycle(); fail = true;
    for (let i = 0; i < 9; i++) { t += 10_000_000; await w.runCycle(); }
    const row = st.get('rtr-edge-1')!;
    expect(row.fails).toBe(9); expect(row.data).not.toBeNull(); expect(row.takenAt).not.toBeNull(); expect(row.error).toMatch(/timed out/);
    expect(row.nextDue - row.attemptAt).toBe(600_000 * SNAPSHOT_FAIL_MULT_MAX);
  });
  it('a denied login waits at least 30 minutes and drops the cached credentials', async () => {
    const t = 1_000_000; const st = store(); let dropped = 0;
    const sc = scope(routerTransport(), { credentials: { credentials: async () => ({ user: 'u', secret: 'secret-x' }), drop: () => { dropped++; } } });
    const w = mkWorker(st, { now: () => t, sc, collect: async () => { throw new LoginDeniedError(); } });
    await w.runCycle();
    const row = st.get('rtr-edge-1')!;
    expect(dropped).toBeGreaterThan(0); expect(row.nextDue - t).toBeGreaterThanOrEqual(SNAPSHOT_LOGIN_DENIED_MS); expect(row.error).toMatch(/login denied/);
  });
  it('never runs two cycles at once; start/stop are safe', async () => {
    let t = 1; const st = store(); let release!: () => void; let started = 0;
    const gate = new Promise<void>((r) => { release = r; });
    const w = mkWorker(st, { now: () => t, collect: async () => { started++; await gate; return data; } });
    const first = w.runCycle(); await new Promise((r) => setTimeout(r, 10));
    expect(w.busy).toBe(true); expect(await w.runCycle()).toMatchObject({ ok: 0, failed: 0 });
    release(); await first; expect(started).toBe(ROS_COUNT); t += 1;
    w.start(10_000_000, 10_000_000); w.stop(); w.stop();
  });
  it('prunes routers that left the inventory', async () => {
    const t = 1; const st = store(); st.saveOk({ id: 'gone', alias: 'gone', family: 'routeros' }, data, 1, 2, 1);
    await mkWorker(st, { now: () => t }).runCycle();
    expect(st.get('gone')).toBeNull();
  });
});

describe('mikrotik_snapshot tool', () => {
  const NOW = 10_000_000;
  const seed = () => {
    const st = store(); const meta = (id: string) => ({ id, alias: id, family: 'routeros' });
    const d: SnapData = {
      resource: { cpu: 9, uptime: '4d', version: '7.15', board: 'CCR', freeMem: 500, totalMem: 1000 },
      interfaces: [{ n: 'ether1', t: 'ether', r: 1, d: 0, s: '1Gbps', c: 'uplink to ix' }, { n: 'ether2', t: 'ether', r: 0, d: 0 }],
      neighbors: [{ i: 'sfp1', a: '192.0.2.10', m: '02:00:00:00:00:01', id: 'rtr-core-1', v: '7.15' }],
      arp: { total: 3, failed: 1, perIf: { bridge1: { t: 3, f: 1 } }, failedList: [{ i: 'bridge1', a: '10.0.0.7' }], gateway: [{ a: '192.0.2.1', m: '02:00:00:00:00:AA', i: 'bridge1', ok: true }] },
      ppp: { count: 2, entries: [{ n: 'cust-alpha', a: '10.1.0.5', c: '02:00:00:00:00:CC', u: '1h' }] },
    };
    st.saveOk(meta('rtr-edge-1'), d, NOW - 5 * 60_000, NOW + 1, 12);
    st.saveOk(meta('rtr-edge-2'), { ...d, ppp: { count: 0, entries: [] } }, NOW - 3 * 3600_000, NOW + 1, 12);
    st.saveFail(meta('rtr-core-1'), 'login denied by device', NOW - 60_000, NOW + 1);
    return st;
  };
  const sc = () => scope(routerTransport());
  const run = (st: SnapshotStore, args: Record<string, unknown>) => snapshotTool(sc(), st, args, { now: () => NOW });

  it('summary of all routers always reports data age, marks STALE and failed attempts, and says it is not live', async () => {
    const r = await run(seed(), {});
    expect(r.isError).toBe(false);
    expect(r.text).toMatch(/rtr-edge-1: age 5 min/); expect(r.text).toMatch(/rtr-edge-2: age 3 h 0 min STALE/); expect(r.text).toMatch(/rtr-core-1: NO DATA · last attempt FAILED 1×/);
    expect(r.text).toMatch(/WARNING: some data is older than 30 minutes/); expect(r.text).toMatch(/did not touch any router/);
  });
  it('one device: sections', async () => {
    const st = seed();
    const sum = await run(st, { device: 'rtr-edge-1' });
    expect(sum.text).toMatch(/taken 5 min ago/); expect(sum.text).toMatch(/interface: 2 total, 1 physical down \(ether2\)/); expect(sum.text).toMatch(/gateway: 192\.0\.2\.1 02:00:00:00:00:AA ok/); expect(sum.text).toMatch(/ppp active: 2/);
    expect((await run(st, { device: 'rtr-edge-1', section: 'ppp' })).text).toContain('cust-alpha(10.1.0.5)');
    expect((await run(st, { device: 'rtr-edge-1', section: 'interface' })).text).toMatch(/ether1 type=ether running=yes rate=1Gbps comment="uplink to ix"/);
    expect((await run(st, { device: 'rtr-edge-1', section: 'arp' })).text).toMatch(/failed: 10\.0\.0\.7@bridge1/);
    expect((await run(st, { device: 'rtr-edge-1', section: 'neighbor' })).text).toMatch(/sfp1 -> rtr-core-1 192\.0\.2\.10/);
    expect((await run(st, { device: 'rtr-edge-1', section: 'resource' })).text).toMatch(/cpu=9% .* free-memory=50%/);
    expect((await run(st, { device: 'rtr-edge-1', section: 'bogus' })).isError).toBe(true);
    expect((await run(st, { device: 'rtr-core-1' })).text).toMatch(/NEVER succeeded/);
    expect((await run(st, { device: 'nope' })).errorKind).toBe('policy');
  });
  it('search across routers: PPP name, IP, MAC (any separator), neighbor identity, interface text', async () => {
    const st = seed();
    for (const q of ['cust-alpha', '10.1.0.5', '02:00:00:00:00:cc', '0200.0000.00cc', 'rtr-core-1', 'uplink']) {
      const r = await run(st, { search: q });
      expect(r.text, q).toMatch(/[1-9]\d* match/);
    }
    expect((await run(st, { search: 'nothing-here' })).text).toMatch(/0 match/);
    expect((await run(st, { search: 'x' })).isError).toBe(true);
    expect((await run(st, { search: 'bad;value' })).isError).toBe(true);
  });
  it('empty store gives a clear message', async () => { expect((await run(store(), {})).text).toMatch(/no snapshot yet/); });
  it('searchSnapshots respects the limit and counts the rest', () => {
    const rows = seed().all(); const r = searchSnapshots(rows, 'ether', 1);
    expect(r.hits).toHaveLength(1); expect(r.more).toBeGreaterThan(0);
  });
});
