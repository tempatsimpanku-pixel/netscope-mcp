import net from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { ConnectError, ConnectionLostError, LoginDeniedError, RosPool, fingerprintMatches, planRosCommand, type RosApiPlan, type RosTarget } from '../../src/core/index.js';
import { fakeRos, type FakeRos } from '../helpers/fake-ros.js';
import { makeCert } from '../helpers/tls-cert.js';

const target = (port: number, extra: Partial<RosTarget> = {}): RosTarget => ({ host: '127.0.0.1', port, user: 'ro-user', password: 'lab-password-1', ...extra });
const plan = planRosCommand('/system resource print') as RosApiPlan;
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

let pool = new RosPool();
const servers: FakeRos[] = [];
const start = async (o: Parameters<typeof fakeRos>[0] = {}) => { const s = await fakeRos(o); servers.push(s); return s; };
afterEach(async () => { pool.close(); pool = new RosPool(); await Promise.all(servers.splice(0).map((s) => s.close())); });

describe('RouterOS API session pool', () => {
  it('reuses one logged-in socket for many commands', async () => {
    const srv = await start();
    for (let i = 0; i < 5; i++) expect((await pool.transport(target(srv.port), plan, 5000)).rows[0]).toMatchObject({ 'board-name': 'RB-LAB' });
    expect(srv.st.logins).toBe(1); expect(srv.st.cmds).toBe(5); expect(pool.stats.logins).toBe(1); expect(pool.stats.reuses).toBe(4);
  });
  it('queues concurrent commands to one router: never more than one connection', async () => {
    const srv = await start();
    await Promise.all(Array.from({ length: 8 }, () => pool.transport(target(srv.port), plan, 5000)));
    expect(srv.st.maxOpen).toBe(1); expect(srv.st.logins).toBe(1); expect(srv.st.cmds).toBe(8);
  });
  it('closing the pool (what the idle timer does) closes sockets; the next call logs in cleanly', async () => {
    const srv = await start();
    await pool.transport(target(srv.port), plan, 5000);
    expect(pool.size).toBe(1);
    pool.close(); await wait(50);
    expect(pool.size).toBe(0); expect(srv.st.open).toBe(0);
    await pool.transport(target(srv.port), plan, 5000);
    expect(srv.st.logins).toBe(2);
  });
  it('closes idle sessions by itself after idleMs', async () => {
    const srv = await start();
    pool = new RosPool({ idleMs: 60 });
    await pool.transport(target(srv.port), plan, 5000);
    await wait(200);
    expect(pool.size).toBe(0); expect(srv.st.open).toBe(0);
  });
  it('replaces a socket cut by the device once, and still succeeds', async () => {
    const srv = await start();
    await pool.transport(target(srv.port), plan, 5000);
    srv.dropSockets(); await wait(30);
    expect((await pool.transport(target(srv.port), plan, 5000)).rows).toHaveLength(1);
    expect(srv.st.logins).toBe(2); expect(pool.stats.reconnects).toBeLessThanOrEqual(1);
  });
  it('denied login: clear error, NOT retried, no session left over', async () => {
    const srv = await start({ reject: true });
    await expect(pool.transport(target(srv.port), plan, 5000)).rejects.toBeInstanceOf(LoginDeniedError);
    expect(srv.st.logins).toBe(1); expect(pool.size).toBe(0);
  });
  it('denied login: the same password is postponed (router not hammered); a new password may try', async () => {
    const srv = await start({ reject: true });
    await expect(pool.transport(target(srv.port), plan, 5000)).rejects.toThrow(/login denied/);
    await expect(pool.transport(target(srv.port), plan, 5000)).rejects.toThrow(/postponed/);
    expect(srv.st.logins).toBe(1);
    await expect(pool.transport(target(srv.port, { password: 'another-password' }), plan, 5000)).rejects.toBeInstanceOf(LoginDeniedError);
    expect(srv.st.logins).toBe(2);
  });
  it('wrong user is a denied login too (and the password is never in the error)', async () => {
    const srv = await start();
    const err = await pool.transport(target(srv.port, { user: 'someone', password: 'WRONG-PW-123' }), plan, 5000).catch((e: Error) => e);
    expect(err).toBeInstanceOf(LoginDeniedError); expect((err as Error).message).not.toContain('WRONG-PW-123');
  });
  it('connection failure is a ConnectError (the fallback path may be tried)', async () => {
    await expect(pool.transport(target(1), plan, 2000, 1500)).rejects.toBeInstanceOf(ConnectError);
    expect(pool.size).toBe(0);
  });
  it('a result cut by the row limit drops the session; the next command is clean', async () => {
    const srv = await start({ rowsPerPrint: 400 });
    const out = await pool.transport(target(srv.port), plan, 5000);
    expect(out.truncated).toBe(true); expect(out.rows).toHaveLength(300);
    await wait(30); expect(pool.size).toBe(0);
    expect((await pool.transport(target(srv.port), plan, 5000)).rows.length).toBeGreaterThan(0);
  });
  it('different routers use different sessions, one each', async () => {
    const a = await start(); const b = await start();
    await Promise.all([a, b, a, b].map((s) => pool.transport(target(s.port), plan, 5000)));
    expect(a.st.maxOpen).toBe(1); expect(b.st.maxOpen).toBe(1); expect(pool.size).toBe(2);
  });
  it('a session destroyed mid-command finishes the promise (no hang) and the queue stays alive', async () => {
    const srv = await start({ hang: true });
    const p = pool.transport(target(srv.port), plan, 3000);
    await wait(60); pool.close();
    await expect(Promise.race([p.then(() => 'ok', (e: Error) => e), wait(1500).then(() => 'HANG')])).resolves.toBeInstanceOf(ConnectionLostError);
  });
  it('a command that never answers times out', async () => {
    const srv = await start({ hang: true });
    await expect(pool.transport(target(srv.port), plan, 150)).rejects.toThrow(/timed out/);
  });
  it('a device that refuses a command (trap) leaves the session usable', async () => {
    const srv = await start();
    const bad = planRosCommand('/ip neighbor print') as RosApiPlan;
    await expect(pool.transport(target(srv.port), bad, 3000)).rejects.toThrow(/device refused: no such command/);
    expect((await pool.transport(target(srv.port), plan, 3000)).rows).toHaveLength(1);
    expect(srv.st.logins).toBe(1);
  });
  it('count-only answers as a single count row', async () => {
    const srv = await start({ handlers: { '/ip/arp/print': [{ a: '1' }, { a: '2' }, { a: '3' }] } });
    const out = await pool.transport(target(srv.port), planRosCommand('/ip arp print count-only') as RosApiPlan, 3000);
    expect(out.rows).toEqual([{ count: '3' }]);
  });
  it('log: keeps only the newest rows (tail)', async () => {
    const rows = Array.from({ length: 1000 }, (_v, i) => ({ message: `entry ${i}` }));
    const srv = await start({ handlers: { '/log/print': rows } });
    const out = await pool.transport(target(srv.port), planRosCommand('/log print tail=5') as RosApiPlan, 5000);
    expect(out.rows.map((r) => r.message)).toEqual(['entry 995', 'entry 996', 'entry 997', 'entry 998', 'entry 999']); expect(out.scanned).toBe(1000);
  });
  it('limits total sessions by dropping idle ones', async () => {
    pool = new RosPool({ maxSessions: 2 });
    const [a, b, c] = [await start(), await start(), await start()];
    for (const s of [a, b, c]) await pool.transport(target(s.port), plan, 3000);
    expect(pool.size).toBeLessThanOrEqual(2);
  });
  it('a reply flood beyond maxBufferBytes kills the session', async () => {
    const srv = await start({ handlers: { '/system/resource/print': [{ big: 'x'.repeat(5000) }] } });
    pool = new RosPool({ maxBufferBytes: 1000 });
    await expect(pool.transport(target(srv.port), plan, 3000)).rejects.toThrow(/too large/);
  });
  it('uses a custom dialer when given (tunnel / jump host)', async () => {
    const srv = await start(); let dialed = 0;
    const out = await pool.transport(target(1, { dialer: async () => { dialed++; return net.connect({ host: '127.0.0.1', port: srv.port }); } }), plan, 3000);
    expect(out.rows).toHaveLength(1); expect(dialed).toBe(1);
  });
});

describe('API-SSL (TLS)', () => {
  const cert = makeCert();
  it('verifies the chain against a given CA and talks over TLS', async () => {
    const srv = await start({ tls: cert });
    const out = await pool.transport(target(srv.port, { tls: { verify: true, ca: cert.cert } }), plan, 5000);
    expect(out.rows[0]).toMatchObject({ 'board-name': 'RB-LAB' }); expect(srv.st.logins).toBe(1);
  });
  it('refuses an untrusted (self-signed, no CA) certificate BEFORE sending any credentials', async () => {
    const srv = await start({ tls: cert });
    await expect(pool.transport(target(srv.port, { tls: { verify: true } }), plan, 5000)).rejects.toBeInstanceOf(ConnectError);
    expect(srv.st.logins).toBe(0);
  });
  it('accepts a self-signed certificate pinned by SHA-256 fingerprint', async () => {
    const srv = await start({ tls: cert });
    const out = await pool.transport(target(srv.port, { tls: { verify: true, fingerprint256: cert.fingerprint256 } }), plan, 5000);
    expect(out.rows).toHaveLength(1);
  });
  it('rejects a wrong pin, before any login', async () => {
    const srv = await start({ tls: cert });
    const wrong = cert.fingerprint256.replace(/[0-9A-F]{2}$/, (h) => (h === '00' ? '01' : '00'));
    await expect(pool.transport(target(srv.port, { tls: { verify: false, fingerprint256: wrong } }), plan, 5000)).rejects.toThrow(/fingerprint does not match/);
    expect(srv.st.logins).toBe(0);
  });
  it('a plain-text client against a TLS port fails as a connect error, not a hang', async () => {
    const srv = await start({ tls: cert });
    await expect(pool.transport(target(srv.port), plan, 1500, 1500)).rejects.toThrow();
    expect(srv.st.logins).toBe(0);
  });
  it('fingerprintMatches ignores colons/case and compares whole values', () => {
    expect(fingerprintMatches('AA:BB:CC', 'aabbcc')).toBe(true);
    expect(fingerprintMatches('AA:BB:CC', 'aabbcd')).toBe(false);
    expect(fingerprintMatches('AA:BB:CC', 'aabb')).toBe(false);
    expect(fingerprintMatches('', '')).toBe(false);
  });
});
