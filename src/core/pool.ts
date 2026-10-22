import { createHash, timingSafeEqual } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { ConnectError, ConnectionLostError, DeviceTimeout, LoginDeniedError } from './errors.js';
import { MAX_ROWS } from './format.js';
import type { RosApiPlan, RosResult, RosRow, RosTarget, RosTransport, TlsSpec } from './types.js';
import { decodeSentence, encodeSentence, sentenceAttrs } from './wire.js';

/** Persistent session pool for the RouterOS API (plain :8728 and TLS :8729).
 *
 * One logged-in socket per (host, port, user) = ONE session per router (hard limit: weak switches and busy cores reject
 * "too many concurrent logins"). Commands on the same session run one after another (queue per key). Idle sessions close after
 * `idleMs`. A socket that died silently (cut by the device/NAT) is detected on use and replaced ONCE, never when the login is denied.
 * A command cut mid-stream (row/time limit) drops its session, so no leftover reply can be mixed into the next command. */

export interface PoolOptions {
  idleMs?: number;
  loginMs?: number;
  maxSessions?: number;
  /** After a denied login, the same password is not tried again for this long. */
  denyCooldownMs?: number;
  /** A reply larger than this (bytes, unparsed) kills the session. */
  maxBufferBytes?: number;
}

const LOG_SCAN_ROWS = 30_000;
const DEFAULTS = { idleMs: 45_000, loginMs: 10_000, maxSessions: 24, denyCooldownMs: 30_000, maxBufferBytes: 8 * 1024 * 1024 };

const normFp = (s: string) => s.replace(/[^0-9a-f]/gi, '').toLowerCase();
const pwTag = (pw: string) => createHash('sha256').update(pw).digest('hex');

/** Constant-time comparison of two fingerprints (hex, colons optional). */
export function fingerprintMatches(actual: string, expected: string): boolean {
  const a = Buffer.from(normFp(actual)); const b = Buffer.from(normFp(expected));
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

/** Open a connected (and, for TLS, verified) socket. Rejects with ConnectError; never writes anything. */
export function openSocket(target: RosTarget, connectMs: number): Promise<Duplex> {
  return new Promise<Duplex>((resolve, reject) => {
    let done = false;
    let sock: Duplex | undefined;
    const finish = (err: Error | null, s?: Duplex) => {
      if (done) { if (s && err) s.destroy(); return; }
      done = true; clearTimeout(timer);
      if (err) { (sock ?? s)?.destroy(); reject(err); } else resolve(s!);
    };
    const timer = setTimeout(() => finish(new ConnectError(`could not connect within ${connectMs / 1000} s.`)), connectMs);
    const lost = (e: Error) => finish(new ConnectError(`connection failed: ${(e as NodeJS.ErrnoException).code || 'error'}`));
    const tlsOptions = (spec: TlsSpec): tls.ConnectionOptions => {
      const pinned = !!spec.fingerprint256;
      const opts: tls.ConnectionOptions = { minVersion: 'TLSv1.2', rejectUnauthorized: spec.verify && !pinned };
      if (spec.ca) opts.ca = spec.ca;
      const name = spec.servername ?? (net.isIP(target.host) ? undefined : target.host);
      if (name) opts.servername = name;
      if (pinned) opts.checkServerIdentity = () => undefined;
      return opts;
    };
    const verifyPin = (s: tls.TLSSocket, spec: TlsSpec) => {
      if (!spec.fingerprint256) return true;
      const peer = s.getPeerCertificate();
      return !!peer && !!peer.fingerprint256 && fingerprintMatches(peer.fingerprint256, spec.fingerprint256);
    };
    const wrapTls = (spec: TlsSpec, base?: Duplex) => {
      const s = base
        ? tls.connect({ ...tlsOptions(spec), socket: base })
        : tls.connect({ ...tlsOptions(spec), host: target.host, port: target.port });
      sock = s;
      s.once('secureConnect', () => {
        if (!s.authorized && spec.verify && !spec.fingerprint256) return finish(new ConnectError(`certificate verification failed: ${String(s.authorizationError)}`));
        if (!verifyPin(s, spec)) return finish(new ConnectError('certificate fingerprint does not match the pinned value.'));
        finish(null, s);
      });
      s.on('error', (e) => lost(e));
    };
    const start = async () => {
      try {
        if (target.dialer) {
          const base = await target.dialer();
          sock = base;
          base.on('error', lost);
          if (target.tls) { wrapTls(target.tls, base); return; }
          finish(null, base);
          return;
        }
        if (target.tls) { wrapTls(target.tls); return; }
        const s = net.createConnection({ host: target.host, port: target.port });
        sock = s;
        s.once('connect', () => finish(null, s));
        s.on('error', lost);
      } catch (e) { lost(e as Error); }
    };
    void start();
  });
}

interface Cmd {
  plan: { apiPath: string; words: string[]; tail?: number; maxRows?: number };
  rows: RosRow[]; scanned: number; truncated: boolean; trap?: string;
  done: (err: Error | null, truncated?: boolean) => void;
}

class RosSession {
  private buf: Buffer = Buffer.alloc(0);
  private stage: 'login' | 'ready' | 'dead' = 'login';
  private cmd: Cmd | null = null;
  private idle?: NodeJS.Timeout;
  private onLogin?: { ok: () => void; bad: (e: Error) => void };
  private closed = false;

  constructor(readonly sock: Duplex, private readonly opts: Required<PoolOptions>, readonly onClose: (s: RosSession) => void) {
    (sock as net.Socket).setKeepAlive?.(true, 15_000);
    (sock as net.Socket).setNoDelay?.(true);
    sock.on('data', (chunk: Buffer) => this.onData(chunk));
    sock.on('error', (e) => this.fail(new ConnectionLostError(`connection failed: ${(e as NodeJS.ErrnoException).code || 'error'}`)));
    sock.on('close', () => this.fail(new ConnectionLostError('connection closed by the device.')));
  }

  get alive(): boolean { return this.stage === 'ready'; }
  get busy(): boolean { return this.cmd !== null || this.stage !== 'ready'; }

  login(target: RosTarget): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new DeviceTimeout('timed out waiting for the API login.')), this.opts.loginMs);
      this.onLogin = { ok: () => { clearTimeout(timer); resolve(); }, bad: (e) => { clearTimeout(timer); reject(e); } };
      this.sock.write(encodeSentence(['/login', `=name=${target.user}`, `=password=${target.password}`]));
    });
  }

  private onData(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk]);
    if (this.buf.length > this.opts.maxBufferBytes) return this.fail(new Error('device reply too large.'));
    for (;;) {
      const s = decodeSentence(this.buf);
      if (!s) return;
      this.buf = this.buf.subarray(s.used);
      const kind = s.words[0];
      const attrs = sentenceAttrs(s.words);
      if (this.stage === 'login') {
        if (kind === '!done') {
          if (attrs.ret) return this.fail(new Error('RouterOS older than 6.43 is not supported.'));
          this.stage = 'ready'; const cb = this.onLogin; this.onLogin = undefined; cb?.ok(); continue;
        }
        if (kind === '!trap' || kind === '!fatal') return this.fail(new LoginDeniedError());
        continue;
      }
      const cmd = this.cmd;
      if (!cmd) continue; // leftover reply without an owner: ignore
      if (kind === '!fatal') return this.fail(new Error(`device refused: ${attrs.message || kind}`));
      if (kind === '!trap') { cmd.trap = attrs.message || kind; continue; } // session stays valid; wait for !done
      if (kind === '!re') {
        cmd.scanned++; cmd.rows.push(attrs);
        if (cmd.plan.tail) { if (cmd.rows.length > cmd.plan.tail) cmd.rows.shift(); if (cmd.scanned >= LOG_SCAN_ROWS) return this.endCmd(null, true, true); }
        else if (cmd.rows.length >= (cmd.plan.maxRows ?? MAX_ROWS)) return this.endCmd(null, true, true);
      } else if (kind === '!done') {
        if (cmd.trap) return this.endCmd(new Error(`device refused: ${cmd.trap}`), false, false);
        if (attrs.ret !== undefined && !cmd.rows.length) cmd.rows.push({ count: attrs.ret });
        return this.endCmd(null, false, false);
      }
    }
  }

  /** Finish the running command. `drop`: the stream is not exhausted, so the session must go. */
  private endCmd(err: Error | null, truncated: boolean, drop: boolean): void {
    const cmd = this.cmd; this.cmd = null;
    if (drop) this.destroy(); else this.armIdle();
    cmd?.done(err, truncated);
  }

  run(plan: Cmd['plan'], timeoutMs: number): Promise<RosResult & { scanned: number }> {
    return new Promise((resolve, reject) => {
      if (this.idle) clearTimeout(this.idle);
      const timer = setTimeout(() => {
        const c = this.cmd;
        if (c && c.rows.length) this.endCmd(null, true, true); // partial results beat an error
        else this.fail(new DeviceTimeout(`timed out (${timeoutMs / 1000} s).`));
      }, timeoutMs);
      const cmd: Cmd = {
        plan, rows: [], scanned: 0, truncated: false,
        done: (err, truncated) => { clearTimeout(timer); if (err) reject(err); else resolve({ rows: cmd.rows, truncated: !!truncated, scanned: cmd.scanned }); },
      };
      this.cmd = cmd;
      this.sock.write(encodeSentence([plan.apiPath, ...plan.words]), (e) => { if (e) this.fail(new ConnectionLostError('connection failed: write.')); });
    });
  }

  private armIdle(): void {
    if (this.idle) clearTimeout(this.idle);
    this.idle = setTimeout(() => this.destroy(), this.opts.idleMs);
    this.idle.unref?.();
  }

  private fail(err: Error): void {
    const wasDead = this.stage === 'dead';
    this.stage = 'dead';
    const login = this.onLogin; this.onLogin = undefined;
    const cmd = this.cmd; this.cmd = null;
    this.destroy();
    if (wasDead) return;
    login?.bad(err);
    cmd?.done(err);
  }

  /** A command/login still hanging is finished with an error too: otherwise the router's queue would stall forever. */
  destroy(): void {
    if (this.idle) clearTimeout(this.idle);
    this.stage = 'dead';
    const login = this.onLogin; this.onLogin = undefined;
    const cmd = this.cmd; this.cmd = null;
    this.sock.destroy();
    if (!this.closed) { this.closed = true; this.onClose(this); }
    if (login) login.bad(new ConnectionLostError('connection closed by the device.'));
    if (cmd) cmd.done(new ConnectionLostError('connection closed by the device.'));
  }
}

export class RosPool {
  readonly stats = { logins: 0, reuses: 0, reconnects: 0 };
  private readonly opts: Required<PoolOptions>;
  private readonly sessions = new Map<string, RosSession>();
  private readonly queues = new Map<string, Promise<unknown>>();
  private readonly denied = new Map<string, { until: number; pw: string }>();

  constructor(opts: PoolOptions = {}) { this.opts = { ...DEFAULTS, ...opts }; }

  get size(): number { return this.sessions.size; }

  close(): void { for (const s of [...this.sessions.values()]) s.destroy(); this.sessions.clear(); this.denied.clear(); }
  clearDenied(): void { this.denied.clear(); }

  private keyOf(t: RosTarget): string { return `${t.host}:${t.port}|${t.user}${t.tls ? '|tls' : ''}`; }

  private async getSession(t: RosTarget, connectMs: number): Promise<{ s: RosSession; fresh: boolean }> {
    const key = this.keyOf(t);
    const cur = this.sessions.get(key);
    if (cur && cur.alive) return { s: cur, fresh: false };
    if (cur) this.sessions.delete(key);
    if (this.sessions.size >= this.opts.maxSessions) { // total limit: drop the oldest IDLE session; never a busy one
      for (const x of this.sessions.values()) if (!x.busy) { x.destroy(); break; }
    }
    const sock = await openSocket(t, connectMs);
    const s = new RosSession(sock, this.opts, (x) => { if (this.sessions.get(key) === x) this.sessions.delete(key); });
    this.sessions.set(key, s);
    this.stats.logins++;
    try { await s.login(t); } catch (e) { s.destroy(); throw e; }
    return { s, fresh: true };
  }

  /** Pooled transport: sockets are reused. A denied login or failed connection is never retried; a stale socket is replaced once. */
  readonly transport: RosTransport = (target, plan, timeoutMs, connectMs = 6_000) => {
    const key = this.keyOf(target);
    const exec = async (): Promise<RosResult> => {
      const d = this.denied.get(key);
      if (d && d.until > Date.now() && d.pw === pwTag(target.password)) throw new LoginDeniedError(`login denied by device (retry postponed ${Math.round(this.opts.denyCooldownMs / 1000)} s; the stored password may have changed).`);
      const first = await this.getSession(target, connectMs).catch((e) => {
        if (e instanceof LoginDeniedError) this.denied.set(key, { until: Date.now() + this.opts.denyCooldownMs, pw: pwTag(target.password) });
        throw e;
      });
      const { fresh } = first;
      if (!fresh) this.stats.reuses++;
      try {
        return await first.s.run(plan, timeoutMs);
      } catch (e) {
        // An old session died before answering (not a device error / timeout): replace it once with a new session.
        const stale = !fresh && e instanceof ConnectionLostError;
        if (!stale) throw e;
        this.stats.reconnects++;
        const again = await this.getSession(target, connectMs);
        return await again.s.run(plan, timeoutMs);
      }
    };
    const prev = this.queues.get(key) || Promise.resolve();
    const run = prev.then(exec, exec);
    const tail = run.catch(() => undefined);
    this.queues.set(key, tail);
    void tail.then(() => { if (this.queues.get(key) === tail) this.queues.delete(key); });
    return run;
  };
}

export type { RosApiPlan };
