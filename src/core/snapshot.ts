import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { planRosCommand } from './allow.js';
import { resolveDevice } from './devices.js';
import { PolicyDenied, DeviceNotFound, LoginDeniedError } from './errors.js';
import type { NetScope } from './engine.js';
import { clip, maskInlineSecrets, scrubExact, scrubMessage } from './redact.js';
import type { DeviceCredentials, DeviceInfo, NetResult, RosApiPlan, RosRow } from './types.js';

/** Periodic read-only snapshots: one row per router (last successful data + status of the last attempt) in a private SQLite file.
 *
 * Why in-process: the session pool (one session per router) and the login-denied cooldown live in the process that owns the
 * `NetScope`; a second process would open a SECOND session per router. The snapshot never writes to a router.
 *
 * Privacy: by default only counts are kept for customer data (PPP names/addresses/caller-ids, failed-ARP addresses). Set
 * `storeCustomerData` to keep them (needed for searching PPP by name/IP/MAC across routers from the snapshot). The file is mode 0600
 * (its directory 0700), WAL/SHM files included. */

export const SNAPSHOT_INTERVAL_MIN = 10;
export const SNAPSHOT_MIN_INTERVAL_MIN = 2;
export const SNAPSHOT_GAP_MS = 1_500;
export const SNAPSHOT_CORE_MULT = 3;
/** After a failure the next try is (1 + consecutive failures, capped at this) × interval; a denied login waits at least LOGIN_DENIED_MS. */
export const SNAPSHOT_FAIL_MULT_MAX = 6;
export const SNAPSHOT_LOGIN_DENIED_MS = 30 * 60_000;
/** A router whose CPU is this high is not asked for big tables (ARP/PPP) in that cycle. */
export const SNAPSHOT_CPU_SKIP = 80;
/** Data older than this (minutes) is flagged STALE: use a live tool. */
export const SNAPSHOT_STALE_MIN = 30;
const BIG_ROWS = 20_000;
const SECTION_TIMEOUT_MS = 20_000;

export interface SnapResource { cpu: number | null; uptime: string; version: string; board: string; freeMem: number | null; totalMem: number | null }
export interface SnapIface { n: string; t: string; r: 0 | 1; d: 0 | 1; s?: string; c?: string }
export interface SnapNeighbor { i: string; a?: string; m?: string; id?: string; p?: string; b?: string; v?: string }
export interface SnapArp { total: number; failed: number; truncated?: boolean; perIf: Record<string, { t: number; f: number }>; failedList: Array<{ i: string; a: string }>; gateway: Array<{ a: string; m?: string; i?: string; ok: boolean }> }
export interface SnapPpp { count: number; truncated?: boolean; entries: Array<{ n: string; a?: string; c?: string; u?: string }> }
export interface SnapData {
  resource?: SnapResource; interfaces?: SnapIface[]; neighbors?: SnapNeighbor[]; arp?: SnapArp; ppp?: SnapPpp;
  errors?: Record<string, string>; skipped?: string[];
}
export interface SnapRow {
  routerId: string; alias: string; family: string; takenAt: number | null; attemptAt: number; fails: number; error: string; nextDue: number; data: SnapData | null; ms: number;
}

// ───────────────────────────── store ─────────────────────────────

export class SnapshotStore {
  readonly db: DatabaseSync;
  private readonly file: string;
  constructor(file: string) {
    this.file = file;
    if (file !== ':memory:') {
      const dir = path.dirname(file);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      // Create the file privately BEFORE sqlite does, so it never exists with looser bits.
      if (!fs.existsSync(file)) fs.closeSync(fs.openSync(file, 'wx', 0o600));
    }
    this.db = new DatabaseSync(file);
    if (file !== ':memory:') { this.db.exec('PRAGMA journal_mode=WAL'); this.db.exec('PRAGMA synchronous=NORMAL'); }
    this.db.exec(`CREATE TABLE IF NOT EXISTS snapshot (
      router_id TEXT PRIMARY KEY, alias TEXT NOT NULL, family TEXT NOT NULL DEFAULT '',
      taken_at INTEGER, attempt_at INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
      next_due INTEGER NOT NULL DEFAULT 0, ms INTEGER NOT NULL DEFAULT 0, data TEXT)`);
    this.lockdown();
  }
  /** Files created by sqlite (-wal, -shm) follow the umask: tighten them every time we may have created them. */
  private lockdown(): void {
    if (this.file === ':memory:') return;
    for (const f of [this.file, `${this.file}-wal`, `${this.file}-shm`]) { try { fs.chmodSync(f, 0o600); } catch { /* not created yet */ } }
  }
  close(): void { try { this.db.close(); } catch { /* already closed */ } }

  private row(r: Record<string, unknown>): SnapRow {
    let data: SnapData | null = null;
    if (typeof r.data === 'string') { try { data = JSON.parse(r.data) as SnapData; } catch { data = null; } }
    return {
      routerId: String(r.router_id), alias: String(r.alias), family: String(r.family), takenAt: r.taken_at === null ? null : Number(r.taken_at),
      attemptAt: Number(r.attempt_at), fails: Number(r.fails), error: String(r.error || ''), nextDue: Number(r.next_due), data, ms: Number(r.ms || 0),
    };
  }
  get(id: string): SnapRow | null { const r = this.db.prepare('SELECT * FROM snapshot WHERE router_id=?').get(id); return r ? this.row(r) : null; }
  all(): SnapRow[] { return this.db.prepare('SELECT * FROM snapshot ORDER BY router_id').all().map((r) => this.row(r)); }
  state(id: string): { nextDue: number; fails: number } | null {
    const r = this.db.prepare('SELECT next_due, fails FROM snapshot WHERE router_id=?').get(id) as { next_due: number; fails: number } | undefined;
    return r ? { nextDue: r.next_due, fails: r.fails } : null;
  }
  saveOk(d: { id: string; alias: string; family: string }, data: SnapData, now: number, nextDue: number, ms: number): void {
    this.db.prepare(`INSERT INTO snapshot(router_id,alias,family,taken_at,attempt_at,fails,error,next_due,ms,data) VALUES(?,?,?,?,?,0,'',?,?,?)
      ON CONFLICT(router_id) DO UPDATE SET alias=excluded.alias,family=excluded.family,taken_at=excluded.taken_at,attempt_at=excluded.attempt_at,fails=0,error='',next_due=excluded.next_due,ms=excluded.ms,data=excluded.data`)
      .run(d.id, d.alias, d.family, now, now, nextDue, ms, JSON.stringify(data));
    this.lockdown();
  }
  /** Failure: old data (and its age) stays; only the attempt status changes. */
  saveFail(d: { id: string; alias: string; family: string }, error: string, now: number, nextDue: number): void {
    this.db.prepare(`INSERT INTO snapshot(router_id,alias,family,taken_at,attempt_at,fails,error,next_due,ms,data) VALUES(?,?,?,NULL,?,1,?,?,0,NULL)
      ON CONFLICT(router_id) DO UPDATE SET alias=excluded.alias,family=excluded.family,attempt_at=excluded.attempt_at,fails=fails+1,error=excluded.error,next_due=excluded.next_due`)
      .run(d.id, d.alias, d.family, now, error.slice(0, 300), nextDue);
    this.lockdown();
  }
  /** Rows of routers that are no longer in the inventory are dropped. */
  prune(keepIds: string[]): number {
    if (!keepIds.length) return 0;
    const r = this.db.prepare(`DELETE FROM snapshot WHERE router_id NOT IN (${keepIds.map(() => '?').join(',')})`).run(...keepIds);
    this.lockdown();
    return Number(r.changes);
  }
}

// ───────────────────────────── collector (one router) ─────────────────────────────

const num = (v: string | undefined): number | null => { const n = Number(v); return v !== undefined && v !== '' && Number.isFinite(n) ? n : null; };
const isPhys = (i: { n: string; t: string }): boolean => i.t === 'ether' || /^(ether|sfp|qsfp)/.test(i.n);
const flag = (v: string | undefined): 0 | 1 => (v === 'true' ? 1 : 0);
const mask = (v: string | undefined, max = 80): string | undefined => (v ? maskInlineSecrets(v).slice(0, max) : undefined);

/** Only fixed print commands pass planRosCommand (same allowlist as mikrotik_read); the big row limit belongs to this code only. */
function fixed(command: string, maxRows?: number): RosApiPlan {
  const plan = planRosCommand(command);
  if (plan.kind !== 'api') throw new PolicyDenied('snapshot only uses API commands.');
  return maxRows ? { ...plan, maxRows } : plan;
}

/** Monitor several ports at once (`numbers=a,b,c once`): one round trip. Names come from the router's own table and are validated. */
const PORT_NAME = /^[A-Za-z0-9_.:-]{1,40}$/;
export function monitorPlan(names: string[]): RosApiPlan {
  const ok = names.filter((n) => PORT_NAME.test(n)).slice(0, 40);
  if (!ok.length) throw new PolicyDenied('no valid port names.');
  return { kind: 'api', verb: 'monitor', path: ['interface', 'ethernet'], apiPath: '/interface/ethernet/monitor', words: [`=numbers=${ok.join(',')}`, '=once='], display: `/interface ethernet monitor ${ok.length} ports once` };
}

export interface CollectOptions { storeCustomerData?: boolean }

export async function collectRouter(scope: NetScope, device: DeviceInfo, opts: CollectOptions = {}): Promise<SnapData> {
  const cred: DeviceCredentials = await scope.credentialsOf(device.id);
  if (!cred.user || !cred.secret) throw new Error('device credentials are empty.');
  const secrets = [cred.secret, cred.community, cred.user].filter((v): v is string => !!v);
  const errors: Record<string, string> = {};
  const skipped: string[] = [];
  const get = async (key: string, plan: RosApiPlan): Promise<RosRow[] | null> => {
    try { return (await scope.runPlan(device, cred, plan, SECTION_TIMEOUT_MS)).rows; }
    catch (e) { errors[key] = scrubExact(scrubMessage(e instanceof Error ? e.message : String(e)), secrets).slice(0, 160); return null; }
  };

  // resource first: failure = unreachable / login denied → the whole router fails, no other section is tried.
  const res = (await scope.runPlan(device, cred, fixed('/system resource print'), SECTION_TIMEOUT_MS).catch((e) => { if (e instanceof LoginDeniedError) throw e; throw new Error(scrubExact(scrubMessage(e instanceof Error ? e.message : String(e)), secrets)); })).rows[0];
  if (!res) throw new Error('empty resource reply.');
  const data: SnapData = {
    resource: { cpu: num(res['cpu-load']), uptime: res.uptime || '', version: (res.version || '').split(' ')[0] || '', board: res['board-name'] || '', freeMem: num(res['free-memory']), totalMem: num(res['total-memory']) },
  };

  const ifs = await get('interface', fixed('/interface print proplist=name,type,running,disabled,comment', 1_000));
  if (ifs) {
    data.interfaces = ifs.filter((i) => i.name).map((i) => ({ n: i.name!, t: i.type || '', r: flag(i.running), d: flag(i.disabled), ...(i.comment ? { c: mask(i.comment, 60) } : {}) }));
    const live = data.interfaces.filter((i) => i.r === 1 && i.d === 0 && isPhys(i)).map((i) => i.n);
    if (live.length) {
      const mon = await get('monitor', monitorPlan(live));
      if (mon) {
        const speed = new Map<string, string>();
        // The multi-port monitor reply carries `name` per row; with a single port, use the order.
        mon.forEach((m, idx) => { const nm = m.name || (mon.length === live.length ? live[idx] : undefined); const rate = m.rate || m.speed; if (nm && rate) speed.set(nm, rate); });
        for (const i of data.interfaces) { const s = speed.get(i.n); if (s) i.s = s; }
      }
    }
  }

  const nb = await get('neighbor', fixed('/ip neighbor print proplist=interface,address,mac-address,identity,platform,board,version', 1_000));
  if (nb) {
    const seen = new Set<string>();
    data.neighbors = [];
    for (const n of nb) {
      const k = `${n.interface}|${n['mac-address'] || n.identity}`;
      if (seen.has(k)) continue; seen.add(k);
      data.neighbors.push({ i: n.interface || '', ...(n.address ? { a: n.address.split(',')[0] } : {}), ...(n['mac-address'] ? { m: n['mac-address'].toUpperCase() } : {}), ...(n.identity ? { id: mask(n.identity) } : {}), ...(n.platform ? { p: n.platform } : {}), ...(n.board ? { b: n.board } : {}), ...(n.version ? { v: n.version.split(' ')[0] } : {}) });
    }
  }

  const cpu = data.resource!.cpu;
  if (cpu !== null && cpu >= SNAPSHOT_CPU_SKIP) {
    skipped.push('arp', 'ppp');
  } else {
    // Gateway: next hop of the default route. Core routers are skipped (big route tables; keep their CPU quiet).
    let gws = new Set<string>();
    if (device.labels?.role !== 'core') {
      const routes = await get('route', fixed('/ip route print where dst-address=0.0.0.0/0 proplist=gateway,disabled,active', 20));
      if (routes) gws = new Set(routes.filter((r) => r.disabled !== 'true').map((r) => (r.gateway || '').split('%')[0]!).filter((g) => /^\d{1,3}(\.\d{1,3}){3}$/.test(g)));
    }
    const arp = await get('arp', fixed('/ip arp print proplist=interface,address,mac-address,complete,disabled', BIG_ROWS));
    if (arp) {
      const a: SnapArp = { total: arp.length, failed: 0, perIf: {}, failedList: [], gateway: [] };
      if (arp.length >= BIG_ROWS) a.truncated = true;
      for (const r of arp) {
        const ifn = r.interface || '?';
        const slot = (a.perIf[ifn] ||= { t: 0, f: 0 });
        slot.t++;
        const failed = r.complete === 'false' && r.disabled !== 'true';
        if (failed) { slot.f++; a.failed++; if (opts.storeCustomerData && a.failedList.length < 40) a.failedList.push({ i: ifn, a: r.address || '' }); }
        if (r.address && gws.has(r.address)) a.gateway.push({ a: r.address, ...(r['mac-address'] ? { m: r['mac-address'].toUpperCase() } : {}), i: ifn, ok: !failed });
      }
      data.arp = a;
    }
    const ppp = await get('ppp', fixed('/ppp active print proplist=name,address,caller-id,uptime', BIG_ROWS));
    if (ppp) data.ppp = { count: ppp.length, ...(ppp.length >= BIG_ROWS ? { truncated: true } : {}), entries: opts.storeCustomerData ? ppp.filter((p) => p.name).map((p) => ({ n: p.name!.slice(0, 64), ...(p.address ? { a: p.address } : {}), ...(p['caller-id'] ? { c: p['caller-id'].toUpperCase() } : {}), ...(p.uptime ? { u: p.uptime } : {}) })) : [] };
  }
  if (Object.keys(errors).length) data.errors = errors;
  if (skipped.length) data.skipped = skipped;
  return data;
}

// ───────────────────────────── worker ─────────────────────────────

export interface CycleReport { ok: number; failed: number; skipped: number; ms: number; failures: Array<{ alias: string; error: string }> }
export interface WorkerOptions {
  scope: NetScope;
  store: SnapshotStore;
  intervalMs?: number;
  gapMs?: number;
  coreMult?: number;
  storeCustomerData?: boolean;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  log?: (line: string) => void;
  /** Test hook: replacement collector. */
  collect?: (device: DeviceInfo) => Promise<SnapData>;
  devices?: () => Promise<DeviceInfo[]>;
}

export const isSnapshotTarget = (d: DeviceInfo): boolean => d.family === 'routeros' || d.family === 'switch';

export function intervalFromMinutes(minutes: number | undefined): number {
  const min = Number.isFinite(minutes) && (minutes as number) > 0 ? (minutes as number) : SNAPSHOT_INTERVAL_MIN;
  return Math.max(SNAPSHOT_MIN_INTERVAL_MIN, min) * 60_000;
}

export class SnapshotWorker {
  private readonly intervalMs: number;
  private readonly gapMs: number;
  private readonly coreMult: number;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private stopped = false;
  last: CycleReport | null = null;

  constructor(private readonly opts: WorkerOptions) {
    this.intervalMs = opts.intervalMs ?? intervalFromMinutes(undefined);
    this.gapMs = opts.gapMs ?? SNAPSHOT_GAP_MS;
    this.coreMult = opts.coreMult ?? SNAPSHOT_CORE_MULT;
  }
  private now(): number { return (this.opts.now ?? Date.now)(); }
  private sleep(ms: number): Promise<void> { return (this.opts.sleep ?? ((n) => new Promise((r) => { const t = setTimeout(r, n); t.unref?.(); })))(ms); }
  private log(line: string): void { this.opts.log?.(line); }
  get busy(): boolean { return this.running; }

  /** Tick every minute: only due routers are fetched, so the real frequency is intervalMs (core slower, failures slower still). */
  start(firstDelayMs = 20_000, tickMs = 60_000): void {
    if (this.timer || this.stopped) return;
    const loop = () => {
      if (this.stopped) return;
      void this.runCycle().catch((e) => this.log(`[snapshot] cycle error: ${scrubMessage(e instanceof Error ? e.message : String(e))}`)).finally(() => {
        if (this.stopped) return;
        this.timer = setTimeout(loop, tickMs); this.timer.unref?.();
      });
    };
    this.timer = setTimeout(loop, firstDelayMs); this.timer.unref?.();
  }
  stop(): void { this.stopped = true; if (this.timer) clearTimeout(this.timer); this.timer = null; }

  async runCycle(): Promise<CycleReport> {
    const report: CycleReport = { ok: 0, failed: 0, skipped: 0, ms: 0, failures: [] };
    if (this.running) return report; // never two overlapping cycles (one session per router)
    this.running = true;
    const t0 = this.now();
    try {
      const devices = (await (this.opts.devices ? this.opts.devices() : this.opts.scope.devices())).filter(isSnapshotTarget);
      this.opts.store.prune(devices.map((d) => d.id));
      let first = true;
      for (const device of devices) {
        if (this.stopped) break;
        const st = this.opts.store.state(device.id);
        if (st && st.nextDue > this.now()) { report.skipped++; continue; }
        if (!first) await this.sleep(this.gapMs); // pause between routers
        first = false;
        if (this.stopped) break;
        const started = this.now();
        const meta = { id: device.id, alias: device.name, family: device.family };
        try {
          const data = await (this.opts.collect ? this.opts.collect(device) : collectRouter(this.opts.scope, device, { storeCustomerData: this.opts.storeCustomerData }));
          const done = this.now();
          const mult = device.labels?.role === 'core' ? this.coreMult : 1;
          this.opts.store.saveOk(meta, data, done, done + this.intervalMs * mult, done - started);
          report.ok++;
        } catch (e) {
          const message = scrubMessage(e instanceof Error ? e.message : String(e)).slice(0, 200);
          const denied = e instanceof LoginDeniedError;
          if (denied) this.opts.scope.dropCredentials(device.id); // the stored password may have changed: re-read next time
          const fails = (st?.fails ?? 0) + 1;
          const base = this.intervalMs * Math.min(1 + fails, SNAPSHOT_FAIL_MULT_MAX);
          this.opts.store.saveFail(meta, message, this.now(), this.now() + (denied ? Math.max(base, SNAPSHOT_LOGIN_DENIED_MS) : base));
          report.failed++; report.failures.push({ alias: device.name, error: message });
        }
      }
    } finally {
      this.running = false;
      report.ms = this.now() - t0;
      this.last = report;
    }
    if (report.ok + report.failed > 0) this.log(`[snapshot] cycle: ${report.ok} ok, ${report.failed} failed, ${report.skipped} not due, ${report.ms} ms${report.failures.length ? ` · failed: ${report.failures.map((f) => `${f.alias} (${f.error.slice(0, 60)})`).join('; ')}` : ''}`);
    return report;
  }
}

// ───────────────────────────── tool: mikrotik_snapshot ─────────────────────────────

export interface SnapshotToolOptions { staleMin?: number; now?: () => number }

const fmtAge = (ms: number): string => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 120) return `${m} min`;
  const h = Math.floor(m / 60);
  return `${h} h ${m % 60} min`;
};
const macKey = (v: string) => v.toLowerCase().replace(/[^0-9a-f]/g, '');
const SEARCH = /^[A-Za-z0-9_.:@ -]{2,64}$/;
export const SNAPSHOT_SECTIONS = ['summary', 'resource', 'interface', 'neighbor', 'arp', 'ppp'] as const;

interface Hit { row: SnapRow; part: string; line: string }

export function searchSnapshots(rows: SnapRow[], query: string, limit: number): { hits: Hit[]; more: number } {
  const q = query.trim().toLowerCase();
  const hexQ = macKey(q);
  const macLike = /^[0-9a-f:.-]+$/i.test(q) && hexQ.length >= 4;
  const fullIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(q);
  const test = (value: string | undefined, kind: 'text' | 'mac' | 'ip'): boolean => {
    if (!value) return false;
    const v = value.toLowerCase();
    if (kind === 'mac') return macLike && macKey(v).includes(hexQ);
    if (kind === 'ip') return fullIp ? v === q : v.includes(q);
    return v.includes(q);
  };
  const hits: Hit[] = [];
  for (const row of rows) {
    const d = row.data; if (!d) continue;
    for (const p of d.ppp?.entries || []) if (test(p.n, 'text') || test(p.a, 'ip') || test(p.c, 'mac')) hits.push({ row, part: 'ppp', line: `name=${p.n}${p.a ? ` address=${p.a}` : ''}${p.c ? ` caller-id=${p.c}` : ''}${p.u ? ` uptime=${p.u}` : ''}` });
    for (const n of d.neighbors || []) if (test(n.id, 'text') || test(n.a, 'ip') || test(n.m, 'mac')) hits.push({ row, part: 'neighbor', line: `interface=${n.i}${n.id ? ` identity=${JSON.stringify(n.id)}` : ''}${n.a ? ` address=${n.a}` : ''}${n.m ? ` mac=${n.m}` : ''}${n.b ? ` board=${n.b}` : ''}${n.v ? ` ver=${n.v}` : ''}` });
    for (const g of d.arp?.gateway || []) if (test(g.a, 'ip') || test(g.m, 'mac')) hits.push({ row, part: 'arp-gateway', line: `address=${g.a}${g.m ? ` mac=${g.m}` : ''} interface=${g.i}${g.ok ? '' : ' FAILED'}` });
    for (const f of d.arp?.failedList || []) if (test(f.a, 'ip')) hits.push({ row, part: 'arp-failed', line: `address=${f.a} interface=${f.i} (ARP failed)` });
    for (const i of d.interfaces || []) if (test(i.n, 'text') || test(i.c, 'text')) hits.push({ row, part: 'interface', line: `name=${i.n} type=${i.t} running=${i.r ? 'yes' : 'no'}${i.d ? ' disabled' : ''}${i.s ? ` rate=${i.s}` : ''}${i.c ? ` comment=${JSON.stringify(i.c)}` : ''}` });
  }
  return { hits: hits.slice(0, limit), more: Math.max(0, hits.length - limit) };
}

export async function snapshotTool(scope: NetScope, store: SnapshotStore, args: Record<string, unknown>, opts: SnapshotToolOptions = {}): Promise<NetResult> {
  const t0 = Date.now();
  const now = (opts.now ?? Date.now)();
  const staleMs = (opts.staleMin ?? SNAPSHOT_STALE_MIN) * 60_000;
  const fail = (text: string, errorKind: 'policy' | 'internal' = 'internal'): NetResult => ({ text, isError: true, errorKind });
  try {
    const rows = store.all();
    if (!rows.length) return { text: '[mikrotik_snapshot] no snapshot yet (the worker just started, or every router failed). Use mikrotik_read / mikrotik_recipe (live).', isError: false, action: 'mikrotik_snapshot empty' };
    const limitRaw = Number(args.limit);
    const limit = Math.min(200, Math.max(1, Math.floor(Number.isFinite(limitRaw) && limitRaw > 0 ? limitRaw : 30)));
    const search = typeof args.search === 'string' ? args.search.trim() : '';
    const ref = args.device !== undefined && args.device !== '' ? args.device : undefined;
    const section = typeof args.section === 'string' && args.section.trim() ? args.section.trim().toLowerCase() : 'summary';
    if (!(SNAPSHOT_SECTIONS as readonly string[]).includes(section)) throw new PolicyDenied(`section must be one of ${SNAPSHOT_SECTIONS.join(', ')}.`);
    const ageOf = (r: SnapRow) => (r.takenAt === null ? Infinity : now - r.takenAt);
    const stale = (r: SnapRow) => ageOf(r) > staleMs;
    const failNote = (r: SnapRow) => (r.fails > 0 ? ` · last attempt FAILED ${r.fails}× (${fmtAge(now - r.attemptAt)} ago: ${r.error.slice(0, 100)})` : '');
    const oldest = rows.reduce((m, r) => Math.max(m, r.takenAt === null ? 0 : ageOf(r)), 0);
    const newest = rows.reduce((m, r) => Math.min(m, r.takenAt === null ? Infinity : ageOf(r)), Infinity);
    const advice = (anyStale: boolean) => (anyStale ? `\nWARNING: some data is older than ${Math.round(staleMs / 60_000)} minutes — for decisions/changes use a LIVE tool (mikrotik_read / mikrotik_recipe / mikrotik_batch).` : '\nSnapshot data (not live): to confirm the current state use mikrotik_read / mikrotik_recipe.');
    const foot = () => `\n(${Date.now() - t0} ms, from the snapshot — did not touch any router)`;

    if (search) {
      if (!SEARCH.test(search)) throw new PolicyDenied('search is not valid (2–64 characters: letters/digits/._:@- and space).');
      const { hits, more } = searchSnapshots(rows, search, limit);
      const header = `[mikrotik_snapshot] search "${search}" in ${rows.filter((r) => r.data).length} router(s) — ${hits.length}${more ? `+${more}` : ''} match(es); newest data ${Number.isFinite(newest) ? fmtAge(newest) : '-'}, oldest ${fmtAge(oldest)}`;
      const body = hits.map((h) => `${h.row.alias} [${h.part}] ${h.line} · age ${h.row.takenAt === null ? '?' : fmtAge(ageOf(h.row))}${stale(h.row) ? ' STALE' : ''}`).join('\n') || '(nothing matches in the snapshot; routers that failed or were not fetched yet are not covered — customer data (PPP) is only searchable when snapshot.store_customer_data is on; use mikrotik_recipe pppoe-lookup for a live search)';
      const missing = rows.filter((r) => !r.data).map((r) => r.alias);
      return { text: `${header}\n${clip(body, 12_000)}${more ? `\n… ${more} more match(es) (raise limit or narrow the search)` : ''}${missing.length ? `\nNo snapshot: ${missing.join(', ')}` : ''}${advice(rows.some(stale))}${foot()}`, isError: false, action: `mikrotik_snapshot search ${search.slice(0, 40)}`, data: { matches: hits.length + more } };
    }

    if (ref !== undefined) {
      const device = resolveDevice(await scope.devices(), ref, 'ros');
      const row = rows.find((r) => r.routerId === device.id);
      if (!row) return { text: `[mikrotik_snapshot] ${device.name}: no snapshot yet (the worker has not fetched it, or the device family is not covered). Use mikrotik_read (live).${foot()}`, isError: false, action: `mikrotik_snapshot ${device.name}` };
      const d = row.data;
      const head = `[mikrotik_snapshot] ${row.alias} — ${row.takenAt === null ? 'NEVER succeeded' : `taken ${fmtAge(ageOf(row))} ago${stale(row) ? ' (STALE)' : ''}`}${failNote(row)}`;
      if (!d) return { text: `${head}${advice(true)}${foot()}`, isError: false, action: `mikrotik_snapshot ${row.alias}` };
      const lines: string[] = [];
      const r = d.resource;
      if (section === 'summary' || section === 'resource') lines.push(r ? `resource: cpu=${r.cpu ?? '?'}% uptime=${r.uptime} version=${r.version} board=${r.board} free-memory=${r.freeMem !== null && r.totalMem ? `${Math.round((r.freeMem / r.totalMem) * 100)}%` : '?'}` : 'resource: -');
      if (section === 'summary' || section === 'interface') {
        const ifs = d.interfaces || [];
        const down = ifs.filter((i) => !i.r && !i.d && isPhys(i));
        lines.push(`interface: ${ifs.length} total, ${down.length} physical down${down.length ? ` (${down.slice(0, 12).map((i) => i.n).join(', ')})` : ''}, ${ifs.filter((i) => i.d).length} disabled`);
        if (section === 'interface') for (const i of ifs.slice(0, limit)) lines.push(`  ${i.n} type=${i.t} running=${i.r ? 'yes' : 'no'}${i.d ? ' disabled' : ''}${i.s ? ` rate=${i.s}` : ''}${i.c ? ` comment=${JSON.stringify(i.c)}` : ''}`);
        else { const fast = ifs.filter((i) => i.r && i.s).slice(0, 10); if (fast.length) lines.push(`  link: ${fast.map((i) => `${i.n}=${i.s}`).join(' ')}`); }
      }
      if (section === 'summary' || section === 'neighbor') {
        const ns = d.neighbors || [];
        lines.push(`neighbor: ${ns.length}`);
        if (section === 'neighbor') for (const n of ns.slice(0, limit)) lines.push(`  ${n.i} -> ${n.id || '?'}${n.a ? ` ${n.a}` : ''}${n.m ? ` ${n.m}` : ''}${n.b ? ` ${n.b}` : ''}${n.v ? ` ${n.v}` : ''}`);
      }
      if (section === 'summary' || section === 'arp') {
        const a = d.arp;
        if (a) {
          lines.push(`arp: ${a.total}${a.truncated ? '+' : ''} entries, ${a.failed} failed; per interface: ${Object.entries(a.perIf).sort((x, y) => y[1].t - x[1].t).slice(0, section === 'arp' ? 40 : 8).map(([i, v]) => `${i}=${v.t}${v.f ? `(${v.f} failed)` : ''}`).join(' ') || '-'}`);
          lines.push(`  gateway: ${a.gateway.length ? a.gateway.map((g) => `${g.a}${g.m ? ` ${g.m}` : ''} ${g.ok ? 'ok' : 'FAILED'}`).join('; ') : '(none / not covered)'}`);
          if (section === 'arp' && a.failedList.length) lines.push(`  failed: ${a.failedList.map((f) => `${f.a}@${f.i}`).join(' ')}`);
        } else lines.push(`arp: - ${d.skipped?.includes('arp') ? '(skipped: high CPU during that cycle)' : d.errors?.arp ? `(ERROR ${d.errors.arp})` : ''}`);
      }
      if (section === 'summary' || section === 'ppp') {
        const p = d.ppp;
        if (p) {
          lines.push(`ppp active: ${p.count}${p.truncated ? '+' : ''}`);
          if (section === 'ppp') lines.push(p.entries.length ? `  ${p.entries.slice(0, limit).map((e) => `${e.n}${e.a ? `(${e.a})` : ''}`).join(' ')}${p.entries.length > limit ? ` … +${p.entries.length - limit} (raise limit or use search)` : ''}` : '  (names are not stored: snapshot.store_customer_data is off)');
        } else lines.push(`ppp active: - ${d.skipped?.includes('ppp') ? '(skipped: high CPU)' : d.errors?.ppp ? `(ERROR ${d.errors.ppp})` : ''}`);
      }
      if (d.errors && section === 'summary') lines.push(`failed sections: ${Object.entries(d.errors).map(([k, v]) => `${k}: ${v}`).join('; ')}`);
      return { text: `${head}\n${clip(scrubMessage(lines.join('\n')), 12_000)}${advice(stale(row))}${foot()}`, isError: false, action: `mikrotik_snapshot ${row.alias} ${section}`, data: { device: row.routerId, takenAt: row.takenAt, stale: stale(row) } };
    }

    // No device and no search: summary of every router.
    const lines = rows.map((r) => {
      const d = r.data;
      const age = r.takenAt === null ? 'never' : `${fmtAge(ageOf(r))}${stale(r) ? ' STALE' : ''}`;
      if (!d) return `${r.alias}: NO DATA${failNote(r)}`;
      const res = d.resource;
      const down = (d.interfaces || []).filter((i) => !i.r && !i.d && isPhys(i)).length;
      return `${r.alias}: age ${age} · cpu ${res?.cpu ?? '?'}% · up ${res?.uptime || '?'} · v${res?.version || '?'} · if down ${down} · neighbors ${(d.neighbors || []).length} · arp ${d.arp ? `${d.arp.total}/${d.arp.failed} failed` : '-'} · ppp ${d.ppp ? d.ppp.count : '-'}${failNote(r)}`;
    });
    return { text: `[mikrotik_snapshot] ${rows.length} router(s); newest data ${Number.isFinite(newest) ? fmtAge(newest) : '-'}, oldest ${fmtAge(oldest)}\n${clip(lines.join('\n'), 14_000)}${advice(rows.some(stale))}${foot()}`, isError: false, action: 'mikrotik_snapshot summary', data: { routers: rows.length } };
  } catch (e) {
    return e instanceof PolicyDenied || e instanceof DeviceNotFound ? fail(`mikrotik_snapshot refused: ${e.message}`, 'policy') : fail(`mikrotik_snapshot failed: ${scrubMessage(e instanceof Error ? e.message : String(e))}`);
  }
}
