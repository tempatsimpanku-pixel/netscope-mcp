import net from 'node:net';
import { auditCommand, checkProbeTarget, planRosCommand } from './allow.js';
import { resolveDevice, familyTools } from './devices.js';
import { BusyError, ConnectError, DeviceNotFound, LoginDeniedError, PolicyDenied, errorKindOf, type ErrorKind } from './errors.js';
import { formatRosRows, formatTraceroute, maskRows, quoteName } from './format.js';
import { Gate, KeyedQueue } from './limits.js';
import { RosPool } from './pool.js';
import { MASK, clip, maskInlineSecrets, maskMac, redactText, scrubExact, scrubMessage, SECRET_KEY } from './redact.js';
import { defaultSnmp, formatSnmp, nameFor, planSnmp, SNMP_NAMES } from './snmp.js';
import { resolveMessages, type Locale, type Messages } from './messages.js';
import { createSshRunner } from './ssh.js';
import type {
  AuditEntry, CredentialSource, DeviceCredentials, DeviceInfo, DeviceSource, Dialer, LocalRunner, NetResult, RosApiPlan, RosPlan, RosResult, RosRow, RosTarget, RosTransport,
  SnmpTransport, SshRunner, TlsSpec,
} from './types.js';
import { execFile } from 'node:child_process';

export interface ProbePolicy {
  /** When non-empty, probe targets must fall inside one of these CIDRs. */
  allowCidrs?: string[];
  /** Probe targets inside these CIDRs are refused (e.g. your management network). */
  denyCidrs?: string[];
  /** Minimum gap between identical probes (kind, origin, target). Default 1000 ms. */
  gapMs?: number;
}

export interface NetScopeOptions {
  devices: DeviceSource;
  credentials: CredentialSource;
  /** Optional custom connector (tunnel/jump host). */
  dialer?: Dialer;
  pool?: RosPool;
  transport?: RosTransport;
  ssh?: SshRunner;
  snmp?: SnmpTransport;
  local?: LocalRunner;
  /** Mask customer-identifying data (MAC tails, host names, comments on customer menus) and disable /log. Default true. */
  redactPii?: boolean;
  /** With `redactPii`: also mask the `name` column (customer login) of /ppp active, /ppp secret and PPPoE servers. Default false: the name is what `pppoe-lookup` searches for. */
  redactPppNames?: boolean;
  /** Allow `ping`/`traceroute` from the MCP host itself (`from: "local"`). Default false. */
  allowLocalProbe?: boolean;
  /** Allow devices configured with the plain-text API. Default false. */
  allowInsecure?: boolean;
  probe?: ProbePolicy;
  /** Max concurrent device commands (default 10). */
  maxInflight?: number;
  slotWaitMs?: number;
  credentialCacheMs?: number;
  inventoryTtlMs?: number;
  audit?: (entry: AuditEntry) => void;
  now?: () => number;
  /** Language of the frame sentences the server builds itself (headers, errors, footers). Default `en`. */
  locale?: Locale;
  /** Replace individual sentences (see `Messages`); applied on top of `locale`. */
  messages?: Partial<Messages>;
}

const ROS_TIMEOUT = { ping: 25_000, traceroute: 45_000, other: 15_000 };
const BATCH_MAX = 30;
const ITEM_LIMIT = 3_500;
const TOTAL_LIMIT = 40_000;
const MAX_RECIPE_DEVICES = 8;
const PPPOE_NAME = /^[A-Za-z0-9_.@-]{1,64}$/;

export const RECIPES = ['health', 'neighbors-map', 'pppoe-lookup'] as const;
export type Recipe = typeof RECIPES[number];

const SWITCH_COMMANDS: Record<string, string> = {
  resource: '/system resource print', health: '/system health print', 'ethernet-all': '/interface ethernet print', ethernet: '/interface ethernet print stats',
  'bridge-port': '/interface bridge port print', 'bridge-vlan': '/interface bridge vlan print', 'bridge-host': '/interface bridge host print',
  'mac-table-count': '/interface bridge host print count-only', poe: '/interface ethernet poe print', neighbor: '/ip neighbor print',
};
const FILTER_RE = /^[a-z0-9.-]{1,40}=[A-Za-z0-9_.:/@ -]{1,80}$/;

const fail = (text: string, errorKind: ErrorKind = 'device'): NetResult => ({ text, isError: true, errorKind });
/** Policy texts are written by this library (no router data in them): only key=value pairs echoed from the caller are masked,
 * so explanations such as "refused (secrets, endless stream, …)" stay readable. Everything else goes through the full scrub. */
const errText = (e: unknown) => (e instanceof PolicyDenied || e instanceof DeviceNotFound ? maskInlineSecrets(e.message).slice(0, 2_000) : scrubMessage(e instanceof Error ? e.message : String(e)));

function intArg(v: unknown, lo: number, hi: number, dflt: number, name: string): number {
  if (v === undefined || v === null || v === '') return dflt;
  const n = typeof v === 'number' ? v : /^\d{1,6}$/.test(String(v)) ? Number(v) : NaN;
  if (!Number.isInteger(n) || n < lo || n > hi) throw new PolicyDenied(`${name} must be an integer between ${lo} and ${hi}.`);
  return n;
}

const execLocal: LocalRunner = (file, args, timeoutMs) => new Promise((resolve) => {
  execFile(file, args, { timeout: timeoutMs, maxBuffer: 1_000_000, env: { PATH: '/usr/sbin:/usr/bin:/bin', LANG: 'C' }, windowsHide: true }, (error, stdout, stderr) => {
    const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 2) : 0;
    resolve({ code, stdout: String(stdout || ''), stderr: String(stderr || '').slice(0, 300) });
  });
});

const secretsOf = (c: DeviceCredentials | undefined): string[] => (c ? [c.secret, c.community, c.user, ...Object.values(c.extras ?? {})].filter((v): v is string => !!v) : []);

interface CredEntry { at?: number; promise: Promise<DeviceCredentials> }

/** The facade: every read-only operation, with allowlist, redaction, limits and audit in one place. */
export class NetScope {
  readonly pool: RosPool;
  readonly gate: Gate;
  private readonly localGate = new Gate(4, 30_000);
  private readonly perDevice = new KeyedQueue();
  private readonly o: NetScopeOptions;
  /** Frame sentences in the configured language. */
  readonly m: Messages;
  private readonly now: () => number;
  private readonly creds = new Map<string, CredEntry>();
  private inventory: { at: number; devices: DeviceInfo[] } | null = null;
  private readonly probeSeen = new Map<string, number>();
  private readonly allow?: net.BlockList;
  private readonly denyList?: net.BlockList;
  private snapshotHandler?: (args: Record<string, unknown>) => Promise<NetResult>;

  constructor(opts: NetScopeOptions) {
    this.o = opts;
    this.m = resolveMessages(opts.locale, opts.messages);
    this.now = opts.now ?? Date.now;
    this.pool = opts.pool ?? new RosPool();
    this.gate = new Gate(opts.maxInflight ?? 10, opts.slotWaitMs ?? 30_000);
    this.allow = buildBlockList(opts.probe?.allowCidrs);
    this.denyList = buildBlockList(opts.probe?.denyCidrs);
  }

  get redactPii(): boolean { return this.o.redactPii ?? true; }
  private get transport(): RosTransport { return this.o.transport ?? this.pool.transport; }
  private get ssh(): SshRunner { return (this.o.ssh ??= createSshRunner()); }

  close(): void { this.pool.close(); this.creds.clear(); }

  // ───────────── inventory & credentials ─────────────

  async devices(): Promise<DeviceInfo[]> {
    const ttl = this.o.inventoryTtlMs ?? 60_000;
    if (this.inventory && this.now() - this.inventory.at < ttl) return this.inventory.devices;
    const devices = await this.o.devices.list();
    this.inventory = { at: this.now(), devices };
    return devices;
  }
  resetInventory(): void { this.inventory = null; }

  /** In-memory cache (never disk/log): one lookup per device per 5 minutes, concurrent loads share one promise, failures are not kept. */
  async credentialsOf(id: string): Promise<DeviceCredentials> {
    const ttl = this.o.credentialCacheMs ?? 300_000;
    const hit = this.creds.get(id);
    if (hit && (hit.at === undefined || this.now() - hit.at < ttl)) return { ...(await hit.promise) };
    const entry: CredEntry = { promise: this.o.credentials.credentials(id) };
    this.creds.set(id, entry);
    entry.promise.then(() => { entry.at = this.now(); }, () => { if (this.creds.get(id) === entry) this.creds.delete(id); });
    return { ...(await entry.promise) };
  }
  dropCredentials(id: string): void { this.creds.delete(id); this.o.credentials.drop?.(id); }

  // ───────────── core execution ─────────────

  private target(device: DeviceInfo, cred: DeviceCredentials, host = device.host, port = device.port): RosTarget {
    const plain = device.transport === 'api';
    if (plain && !this.o.allowInsecure) throw new PolicyDenied(`device "${device.id}" uses the plain-text API; enable allow_insecure explicitly or switch it to api-ssl.`);
    const tls: TlsSpec | undefined = plain ? undefined : (device.tls ?? { verify: true });
    const dialer = this.o.dialer ? () => this.o.dialer!({ host, port, device }) : undefined;
    return { host, port, user: cred.user, password: cred.secret, ...(tls ? { tls } : {}), ...(dialer ? { dialer } : {}) };
  }

  /** Run one API sentence: queued per device, limited globally. Falls back once to `device.fallback` when the direct address does not connect. */
  async runPlan(device: DeviceInfo, cred: DeviceCredentials, plan: RosApiPlan, timeoutMs: number, breaker?: Breaker): Promise<RosResult & { route: string }> {
    const via = device.fallback;
    const connectMs = via ? 3_000 : 6_000;
    // Circuit breaker (per batch/recipe call): once a device failed to connect, the rest of that call does not wait for it again.
    const trip = (e: unknown): void => { if (e instanceof ConnectError && !(e instanceof SkippedError)) breaker?.add(device.id); };
    try {
      const out = await this.perDevice.run(device.id, () => this.gate.run(() => {
        if (breaker?.has(device.id)) throw new SkippedError(this.m.unreachableSkipped(device.name));
        return this.transport(this.target(device, cred), plan, timeoutMs, connectMs);
      }));
      return { ...out, route: '' };
    } catch (e) {
      if (!via || !(e instanceof ConnectError) || e instanceof SkippedError) { trip(e); throw e; }
      try {
        const out = await this.perDevice.run(device.id, () => this.gate.run(() => this.transport(this.target(device, cred, via.host, via.port), plan, timeoutMs, 3_000)));
        return { ...out, route: `via ${via.label}` };
      } catch (e2) { trip(e2); throw e2; }
    }
  }

  private pii(): { redactPii: boolean; redactPppNames: boolean } { return { redactPii: this.redactPii, redactPppNames: this.o.redactPppNames ?? false }; }

  private async audited(tool: string, device: string | undefined, command: string | undefined, fn: () => Promise<NetResult>): Promise<NetResult> {
    const t0 = this.now();
    let r: NetResult;
    try { r = await fn(); } catch (e) { r = fail(this.m.failed(tool, errText(e)), errorKindOf(e)); }
    this.o.audit?.({ ts: new Date(t0).toISOString(), tool, ...(device ? { device } : {}), ...(command ? { command } : {}), ok: !r.isError, ...(r.isError && r.errorKind ? { errorKind: r.errorKind } : {}), durationMs: this.now() - t0 });
    return r;
  }

  private guardPlan(plan: RosPlan): void {
    if (this.redactPii && plan.kind === 'api' && plan.path.join(' ') === 'log') throw new PolicyDenied('/log is disabled while redact_pii is on (log text is free-form and often contains customer data).');
  }

  /** Execute a planned command on a device and format the (redacted) result. */
  async exec(device: DeviceInfo, plan: RosPlan, tool: string, breaker?: Breaker): Promise<NetResult> {
    const started = this.now();
    const head = `[${device.name}] ${plan.display}`;
    let cred: DeviceCredentials | undefined;
    try {
      cred = await this.credentialsOf(device.id);
      if (!cred.user || !cred.secret) return fail(this.m.credentialsEmpty(tool), 'config');
      let body: string; let route = ''; let data: unknown;
      if (plan.kind === 'api') {
        const timeout = plan.verb === 'ping' ? ROS_TIMEOUT.ping : plan.verb === 'traceroute' ? ROS_TIMEOUT.traceroute : ROS_TIMEOUT.other;
        const out = await this.runPlan(device, cred, plan, timeout, breaker);
        body = plan.verb === 'traceroute' ? formatTraceroute(out.rows, this.m) : formatRosRows(out.rows, plan.apiPath, out.truncated, out.scanned, plan.tail, { ...this.pii(), messages: this.m });
        route = out.route ? `, ${out.route}` : '';
        data = { device: device.id, command: plan.display, truncated: out.truncated, rows: scrubRows(maskRows(out.rows, plan.apiPath, this.pii()), cred) };
      } else {
        const sshPort = device.ssh?.port;
        if (sshPort === undefined) return fail(this.m.sshNotConfigured(tool, device.name), 'config');
        if (sshPort === null) return fail(this.m.sshClosed(tool, device.name), 'config');
        const out = await this.perDevice.run(device.id, () => this.gate.run(() => this.ssh({
          host: device.host, port: sshPort, user: cred!.user, deviceId: device.id,
          ...(device.ssh?.keyFile ? { keyFile: device.ssh.keyFile } : { password: cred!.secret }),
          ...(device.ssh?.hostKeySha256 ? { hostKeySha256: device.ssh.hostKeySha256 } : {}),
        }, plan.sshCommand, 40_000)));
        if (out.code !== 0) return fail(this.m.sshFailed(tool, device.name, sshFailureDetail(out, secretsOf(cred))));
        body = clipExport(out.stdout);
        data = { device: device.id, command: plan.display };
      }
      const text = clip(this.finish(scrubExact(redactText(body), secretsOf(cred))));
      return { text: `${head}\n${text}\n${this.m.footer(this.now() - started, route)}`, isError: false, action: head, data };
    } catch (e) {
      const message = scrubExact(errText(e), secretsOf(cred));
      if (e instanceof LoginDeniedError) this.dropCredentials(device.id);
      let hint = /no such command|bad command name|unknown command/i.test(message) ? this.m.missingCommandHint : '';
      const missing = plan.kind === 'api' && plan.verb === 'monitor' ? plan.words.find((w) => w.startsWith('=numbers='))?.slice(9) : undefined;
      if (missing && /no such item/i.test(message)) hint = ` (${this.m.noSuchItem(missing.slice(0, 60))})`;
      return fail(this.m.failedOn(tool, device.name, `${message}${hint}`), errorKindOf(e));
    }
  }

  private finish(text: string): string { return this.redactPii ? maskMac(text) : text; }

  // ───────────── tools ─────────────

  async listDevices(args: { filter?: unknown; group?: unknown } = {}): Promise<NetResult> {
    return this.audited('list_devices', undefined, undefined, async () => {
      const all = await this.devices();
      const q = typeof args.filter === 'string' ? args.filter.trim().toLowerCase().slice(0, 60) : '';
      const group = typeof args.group === 'string' ? args.group.trim().toLowerCase() : '';
      const rows = all.filter((d) => (!q || `${d.id} ${d.name} ${d.host} ${d.family} ${d.group ?? ''}`.toLowerCase().includes(q)) && (!group || (d.group ?? '').toLowerCase() === group));
      const lines = rows.slice(0, 120).map((d) => `id=${d.id} | ${d.name} | ${d.host}${portOf(d)} | ${d.family}${d.group ? ` | group ${d.group}` : ''} | ${this.m.toolsLabel}: ${familyTools(d.family)}${d.family === 'routeros' || d.family === 'switch' ? ` | ${this.m.exportOverSsh}: ${d.ssh?.port ? this.m.exportPort(d.ssh.port) : this.m.exportUnavailable}` : ''}`);
      return {
        text: `${this.m.deviceCount(rows.length, q)}\n${lines.join('\n')}${rows.length > 120 ? `\n${this.m.narrowFilter}` : ''}`, isError: false,
        data: rows.map((d) => ({ id: d.id, name: d.name, host: d.host, port: apiPortOf(d) ?? d.snmpPort ?? 161, family: d.family, group: d.group ?? null })),
      };
    });
  }

  async read(args: { device?: unknown; command?: unknown }): Promise<NetResult> {
    let plan: RosPlan; let device: DeviceInfo;
    try {
      plan = planRosCommand(args.command);
      this.guardPlan(plan);
      device = resolveDevice(await this.devices(), args.device, 'ros');
    } catch (e) { return this.refused('mikrotik_read', e, args.device); }
    return this.audited('mikrotik_read', device.id, auditCommand(plan), () => this.exec(device, plan, 'mikrotik_read'));
  }

  private refused(tool: string, e: unknown, device?: unknown): NetResult {
    const r = fail(this.m.refused(tool, errText(e)), errorKindOf(e));
    this.o.audit?.({ ts: new Date(this.now()).toISOString(), tool, ...(typeof device === 'string' ? { device: device.slice(0, 64) } : {}), ok: false, errorKind: r.errorKind!, durationMs: 0 });
    return r;
  }

  async batch(args: { items?: unknown }): Promise<NetResult> {
    const items = args.items;
    if (!Array.isArray(items) || !items.length) return fail(this.m.refused('mikrotik_batch', this.m.batchNeedsItems), 'policy');
    if (items.length > BATCH_MAX) return fail(this.m.refused('mikrotik_batch', this.m.batchTooMany(BATCH_MAX, items.length)), 'policy');
    const t0 = this.now();
    let devices: DeviceInfo[];
    try { devices = await this.devices(); } catch (e) { return fail(this.m.failed('mikrotik_batch', errText(e)), errorKindOf(e)); }
    interface Prepared { index: number; device?: DeviceInfo; plan?: RosPlan; command: string; label: string; error?: string }
    const prepared: Prepared[] = (items as Array<{ device?: unknown; command?: unknown }>).map((raw, index) => {
      const command = typeof raw?.command === 'string' ? raw.command : '';
      // Name the device even when the item is refused (an unknown reference is shown as given).
      let known: DeviceInfo | undefined;
      try { known = resolveDevice(devices, raw?.device, 'ros'); } catch { /* reported below */ }
      const label = known?.name ?? (typeof raw?.device === 'string' && raw.device.trim() ? maskInlineSecrets(raw.device.trim().slice(0, 60)) : '?');
      try {
        const plan = planRosCommand(raw?.command);
        this.guardPlan(plan);
        return { index, device: resolveDevice(devices, raw?.device, 'ros'), plan, command, label };
      } catch (e) { return { index, command, label, error: e instanceof PolicyDenied || e instanceof DeviceNotFound ? this.m.refusedItem(errText(e)) : errText(e) }; }
    });
    const breaker: Breaker = new Set();
    // Parallel across routers; sequential on one router (one session per router; the per-device queue still applies underneath).
    const groups = new Map<string, Prepared[]>();
    for (const p of prepared) if (p.device) (groups.get(p.device.id) || groups.set(p.device.id, []).get(p.device.id)!).push(p);
    const outcome = new Map<number, NetResult>();
    await Promise.all([...groups.values()].map(async (list) => {
      let denied: NetResult | undefined; // login denied: remaining items on this router do not try to log in again
      for (const p of list) {
        if (denied) { outcome.set(p.index, denied); continue; }
        const r = await this.audited('mikrotik_batch', p.device!.id, auditCommand(p.plan!), () => this.exec(p.device!, p.plan!, 'mikrotik_batch', breaker));
        if (r.isError && r.errorKind === 'auth') denied = r;
        outcome.set(p.index, r);
      }
    }));
    let ok = 0; let bad = 0;
    const blocks = prepared.map((p) => {
      const r = outcome.get(p.index);
      const failed = p.error !== undefined || r?.isError;
      if (failed) bad++; else ok++;
      const body = p.error !== undefined ? `${this.m.error} ${p.error}` : r!.isError ? `${this.m.error} ${r!.text}` : r!.text;
      return `### ${p.index + 1}. ${failed ? this.m.error : this.m.ok} — ${p.label}: ${p.command.slice(0, 120)}\n${clip(body, ITEM_LIMIT)}`;
    });
    const text = `${this.m.batchSummary(ok, bad, prepared.length, this.now() - t0)}\n${clip(blocks.join('\n\n'), TOTAL_LIMIT)}`;
    return { text, isError: ok === 0, ...(ok === 0 ? { errorKind: 'device' as ErrorKind } : {}), action: `mikrotik_batch: ${prepared.length} items, ${groups.size} routers`, data: { ok, errors: bad, total: prepared.length } };
  }

  // ───────────── recipes ─────────────

  async recipe(args: { recipe?: unknown; device?: unknown; name?: unknown }): Promise<NetResult> {
    const t0 = this.now();
    const recipe = typeof args.recipe === 'string' ? args.recipe.trim().toLowerCase() as Recipe : '' as Recipe;
    if (!RECIPES.includes(recipe)) return fail(this.m.refused('mikrotik_recipe', this.m.recipeUnknown(RECIPES.join(', '))), 'policy');
    return this.audited('mikrotik_recipe', typeof args.device === 'string' ? args.device : undefined, recipe, async () => {
      try {
        const all = await this.devices();
        const refs = Array.isArray(args.device) ? args.device : args.device !== undefined && args.device !== '' ? [args.device] : [];
        if (refs.length > MAX_RECIPE_DEVICES) throw new PolicyDenied(`at most ${MAX_RECIPE_DEVICES} devices per recipe.`);
        const picked = () => refs.map((r) => resolveDevice(all, r, 'ros'));
        const finish = (body: string, action: string, data?: unknown): NetResult => ({ text: `[mikrotik_recipe] ${recipe}\n${clip(body, 30_000)}\n${this.m.footer(this.now() - t0, '')}`, isError: false, action, ...(data !== undefined ? { data } : {}) });
        const ctx: RecipeCtx = { creds: new Map(), breaker: new Set() };
        if (recipe === 'pppoe-lookup') {
          const name = typeof args.name === 'string' ? args.name.trim() : '';
          if (!PPPOE_NAME.test(name)) throw new PolicyDenied('customer name is required (letters/digits/._@-, max 64) in `name`.');
          // No device given: search every router (not switches) in the inventory; the session pool keeps this cheap.
          const targets = refs.length ? picked() : all.filter((d) => d.family === 'routeros').slice(0, 40);
          const found: string[] = []; const miss: string[] = [];
          await Promise.all(targets.map(async (d) => {
            try { const r = await this.pppoeLookup(ctx, d, name); if (r) found.push(`## ${d.name}\n${r}`); else miss.push(d.name); } catch (e) { miss.push(`${d.name} (${this.m.error} ${errText(e)})`); }
          }));
          return finish(`${found.join('\n') || this.m.recipeNotFound(name, targets.length)}\n${this.m.recipeChecked(miss.length ? miss.join(', ') : '-')}`, `mikrotik_recipe pppoe-lookup`, { found: found.length, checked: targets.length });
        }
        const targets = picked();
        if (!targets.length) throw new PolicyDenied('`device` is required for this recipe.');
        const blocks: string[] = []; let edges = 0;
        await Promise.all(targets.map(async (d, i) => {
          let body: string;
          try {
            if (recipe === 'health') body = await this.health(ctx, d);
            else { const r = await this.neighborsMap(ctx, d, all); edges += r.edges; body = r.text; }
          } catch (e) { body = `${this.m.error} ${errText(e)}`; }
          blocks[i] = `## ${d.name}\n${body}`;
        }));
        return finish(`${blocks.join('\n')}${recipe === 'neighbors-map' ? `\n${this.m.recipeEdges(edges)}` : ''}`, `mikrotik_recipe ${recipe}: ${targets.map((d) => d.name).join(', ').slice(0, 80)}`);
      } catch (e) { return e instanceof PolicyDenied || e instanceof DeviceNotFound ? fail(this.m.refused('mikrotik_recipe', errText(e)), errorKindOf(e)) : fail(this.m.failed('mikrotik_recipe', errText(e)), errorKindOf(e)); }
    });
  }

  /** One planned API command → masked rows; errors become text so one failing section never kills the recipe. */
  private async section(ctx: RecipeCtx, device: DeviceInfo, plan: RosApiPlan): Promise<{ rows: RosRow[]; error?: string; truncated?: boolean }> {
    let cred = ctx.creds.get(device.id);
    try {
      if (!cred) { cred = await this.credentialsOf(device.id); ctx.creds.set(device.id, cred); }
      if (!cred.user || !cred.secret) throw new Error('device credentials are empty.');
      try {
        const out = await this.runPlan(device, cred, plan, ROS_TIMEOUT.other, ctx.breaker);
        return { rows: maskRows(out.rows, plan.apiPath, this.pii()), truncated: out.truncated };
      } catch (e) {
        const message = scrubExact(errText(e), secretsOf(cred));
        if (e instanceof LoginDeniedError) { this.dropCredentials(device.id); ctx.creds.delete(device.id); }
        throw new Error(message, { cause: e });
      }
    } catch (e) { return { rows: [], error: errText(e) }; }
  }

  /** One recipe step. A refused or failing step becomes an error line, so one bad name never cancels the other sections. */
  private async rows(ctx: RecipeCtx, device: DeviceInfo, command: string): Promise<{ rows: RosRow[]; error?: string; truncated?: boolean }> {
    try {
      const plan = planRosCommand(command);
      if (plan.kind !== 'api') throw new PolicyDenied('recipes only use API commands.');
      return await this.section(ctx, device, plan);
    } catch (e) { return { rows: [], error: errText(e) }; }
  }

  private async health(ctx: RecipeCtx, d: DeviceInfo): Promise<string> {
    const [res, hl, eth] = await Promise.all([this.rows(ctx, d, '/system resource print'), this.rows(ctx, d, '/system health print'), this.rows(ctx, d, '/interface ethernet print')]);
    const out: string[] = [];
    const r = res.rows[0];
    out.push(r ? `resource: ${pick(r, ['board-name', 'version', 'uptime', 'cpu-load', 'cpu-count', 'free-memory', 'total-memory', 'free-hdd-space'])}` : `resource: ${this.m.error} ${res.error}`);
    if (hl.rows.length) out.push(`health: ${hl.rows.map((h) => (h.name !== undefined ? `${h.name}=${h.value}${h.type ? h.type : ''}` : pick(h, Object.keys(h)))).join(' ')}`);
    else if (hl.error && !/no such command|not found|unknown/i.test(hl.error)) out.push(`health: ${this.m.error} ${hl.error}`);
    const sfp = eth.rows.filter((e) => /^sfp/i.test(e.name || '') && e.running === 'true').slice(0, 6);
    const down = eth.rows.filter((e) => e.running === 'false' && e.disabled !== 'true').map((e) => e.name);
    if (eth.error) out.push(`interface: ${this.m.error} ${eth.error}`);
    else out.push(`interface: ${atLeast(eth.rows.length, eth.truncated)} ethernet, ${down.length} down${down.length ? ` (${down.slice(0, 12).join(', ')})` : ''}`);
    // One monitor per SFP, each isolated. The router's own id (`*N`) is the most robust selector; otherwise the name is
    // quoted, because names such as "sfp+ 1" contain a space.
    const monitored = await Promise.all(sfp.map((e) => this.rows(ctx, d, `/interface ethernet monitor ${monitorRef(e)} once`)));
    sfp.forEach((e, i) => {
      const m = monitored[i]!;
      out.push(`sfp ${e.name}: ${m.rows[0] ? pick(m.rows[0], ['status', 'rate', 'sfp-module-present', 'sfp-rx-power', 'sfp-tx-power', 'sfp-temperature', 'sfp-supply-voltage']) : `${this.m.error} ${m.error ?? '-'}`}`);
    });
    return out.join('\n');
  }

  private async neighborsMap(ctx: RecipeCtx, d: DeviceInfo, all: DeviceInfo[]): Promise<{ text: string; edges: number }> {
    const [nb, arp, ifs] = await Promise.all([this.rows(ctx, d, '/ip neighbor print'), this.rows(ctx, d, '/ip arp print'), this.rows(ctx, d, '/interface print')]);
    const out: string[] = [];
    const seen = new Set<string>();
    let edges = 0;
    for (const n of nb.rows) {
      const id = n.identity || n['mac-address'] || '?';
      const key = `${n.interface}|${n['mac-address'] || id}`;
      if (seen.has(key)) continue; seen.add(key);
      const ip = (n.address || n.address4 || '').split(',')[0];
      const match = all.find((x) => x.id !== d.id && ((ip && x.host === ip) || (n.identity && norm(x.name) === norm(n.identity))));
      edges++;
      out.push(`edge ${d.name}[${n.interface || '?'}] -> ${id}${ip ? ` ${ip}` : ''}${n.platform ? ` ${n.platform}` : ''}${n.board ? `/${n.board}` : ''}${n.version ? ` ${n.version}` : ''}${match ? ` = known ${match.name}` : ' (not in inventory)'}`);
    }
    if (nb.error) out.push(`neighbor: ${this.m.error} ${nb.error}`);
    const perIf = new Map<string, number>();
    for (const a of arp.rows) if (a.interface) perIf.set(a.interface, (perIf.get(a.interface) || 0) + 1);
    if (arp.error) out.push(`arp: ${this.m.error} ${arp.error}`);
    else out.push(`arp: ${atLeast(arp.rows.length, arp.truncated)} entries; ${[...perIf].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([i, c]) => `${quoteName(i)}=${c}`).join('; ') || '-'}`);
    const downs = ifs.rows.filter((i) => i.running === 'false' && i.disabled !== 'true' && /ether|sfp|bond|vlan/.test(i.type || '')).map((i) => i.name);
    if (ifs.error) out.push(`interface: ${this.m.error} ${ifs.error}`);
    else out.push(`interface: ${atLeast(ifs.rows.length, ifs.truncated)} total${ifs.truncated ? ' (down list may be incomplete)' : ''}, down: ${downs.length ? downs.slice(0, 15).join(', ') : '-'}`);
    return { text: out.join('\n'), edges };
  }

  private async pppoeLookup(ctx: RecipeCtx, d: DeviceInfo, name: string): Promise<string | null> {
    const [act, sec, ifc] = await Promise.all([
      this.rows(ctx, d, `/ppp active print where name=${name}`), this.rows(ctx, d, `/ppp secret print where name=${name}`),
      this.section(ctx, d, pppoeInterfacePlan(name)),
    ]);
    if (act.error && sec.error) throw new Error(act.error);
    if (!act.rows.length && !sec.rows.length && !act.error && !sec.error) return null;
    const out: string[] = [];
    for (const a of act.rows) out.push(`active: ${pick(a, ['name', 'service', 'caller-id', 'address', 'uptime', 'encoding', 'session-id'])}`);
    if (!act.rows.length) out.push(act.error ? `active: ${this.m.error} ${act.error}` : 'active: no session (offline)');
    for (const s of sec.rows) out.push(`secret: ${pick(s, ['name', 'service', 'profile', 'remote-address', 'local-address', 'disabled', 'last-logged-out', 'last-caller-id', 'comment'])}`);
    if (!sec.rows.length) out.push(sec.error ? `secret: ${this.m.error} ${sec.error}` : 'secret: none');
    for (const i of ifc.rows) out.push(`interface: ${pick(i, ['name', 'type', 'running', 'disabled', 'last-link-up-time', 'rx-byte', 'tx-byte', 'rx-error', 'tx-error', 'rx-drop', 'tx-drop'])}`);
    if (!ifc.rows.length) out.push(ifc.error ? `interface: ${this.m.error} ${ifc.error}` : 'interface: no dynamic <pppoe-…> interface (session offline)');
    return out.join('\n');
  }

  // ───────────── ping / traceroute ─────────────

  private probePolicy(target: string): void {
    const fam = net.isIPv6(target) ? 'ipv6' : 'ipv4';
    if (this.denyList?.check(target, fam)) throw new PolicyDenied('probe target is inside a denied network (probe.deny_cidrs).');
    if (this.allow && !this.allow.check(target, fam)) throw new PolicyDenied('probe target is outside the allowed networks (probe.allow_cidrs).');
  }

  private throttle(key: string): string {
    const gap = this.o.probe?.gapMs ?? 1_000;
    const now = Date.now();
    for (const [k, at] of this.probeSeen) if (now - at > 60_000) this.probeSeen.delete(k);
    const prev = this.probeSeen.get(key);
    if (gap > 0 && prev !== undefined && now - prev < gap) return 'the same probe just ran; wait a moment.';
    this.probeSeen.set(key, now);
    return '';
  }

  private async probe(kind: 'ping' | 'traceroute', args: { from?: unknown; target?: unknown; count?: unknown; size?: unknown; max_hops?: unknown }): Promise<NetResult> {
    const tool = kind;
    let target: string; let from: string; let count = 0; let size: number | undefined; let hops = 0;
    try {
      target = checkProbeTarget(String(args.target ?? '').trim());
      this.probePolicy(target);
      from = String(args.from ?? '').trim();
      if (!from) throw new PolicyDenied('`from` is required: a device id/name, or "local" (the MCP host, if enabled).');
      if (kind === 'ping') { count = intArg(args.count, 1, 10, 4, 'count'); size = args.size === undefined ? undefined : intArg(args.size, 28, 1400, 56, 'size'); } else hops = intArg(args.max_hops, 1, 20, 15, 'max_hops');
    } catch (e) { return this.refused(tool, e, args.from); }
    const gate = this.throttle(`${kind}|${from.toLowerCase()}|${target}`);
    if (gate) return fail(this.m.refused(tool, gate), 'busy');
    return this.audited(tool, from, `${kind} from ${from}`, async () => {
      const t0 = this.now();
      try {
        if (from.toLowerCase() === 'local') {
          if (!this.o.allowLocalProbe) throw new PolicyDenied('probing from the MCP host is disabled (allow_local_probe).');
          const argv = kind === 'ping'
            ? ['-n', '-c', String(count), '-W', '2', ...(size ? ['-s', String(Math.max(0, size - 28))] : []), target]
            : ['-n', '-m', String(hops), target];
          const run = this.o.local ?? execLocal;
          const out = await this.gate.run(() => this.localGate.run(() => run(kind === 'ping' ? 'ping' : 'tracepath', argv, kind === 'ping' ? count * 3_000 + 5_000 : 45_000)));
          if (out.code > 1 && !out.stdout.trim()) return fail(this.m.failed(`${tool} (local host)`, out.stderr.trim() || `exit code ${out.code}`));
          return { text: `[local] ${kind} ${target}\n${clip(out.stdout)}\n${this.m.footer(this.now() - t0, '')}`, isError: false, action: `${kind} local → ${target}` };
        }
        const device = resolveDevice(await this.devices(), from, 'ros');
        const plan = planRosCommand(kind === 'ping' ? `ping ${target} count=${count}${size ? ` size=${size}` : ''}` : `/tool traceroute ${target} count=1 max-hops=${hops}`);
        return await this.exec(device, plan, tool);
      } catch (e) { return e instanceof PolicyDenied || e instanceof DeviceNotFound ? fail(this.m.refused(tool, errText(e)), errorKindOf(e)) : fail(this.m.failed(tool, errText(e).slice(0, 300)), errorKindOf(e)); }
    });
  }
  ping(args: { from?: unknown; target?: unknown; count?: unknown; size?: unknown }): Promise<NetResult> { return this.probe('ping', args); }
  traceroute(args: { from?: unknown; target?: unknown; max_hops?: unknown }): Promise<NetResult> { return this.probe('traceroute', args); }

  // ───────────── SNMP ─────────────

  async snmpGet(args: { device?: unknown; name?: unknown; oid?: unknown; walk?: unknown; limit?: unknown }): Promise<NetResult> {
    let device: DeviceInfo; let plan: ReturnType<typeof planSnmp>;
    try { plan = planSnmp(args); device = resolveDevice(await this.devices(), args.device, 'snmp'); } catch (e) { return this.refused('snmp_get', e, args.device); }
    return this.audited('snmp_get', device.id, `snmp ${plan.walk ? 'walk' : 'get'} ${nameFor(plan.oid)}`, async () => {
      const t0 = this.now();
      let cred: DeviceCredentials | undefined;
      try {
        cred = await this.credentialsOf(device.id);
        if (!cred.community) return fail('snmp_get: the device has no SNMP community configured.', 'config');
        const run = this.o.snmp ?? defaultSnmp;
        const rows = await this.gate.run(() => run({ host: device.host, port: device.snmpPort ?? 161, community: cred!.community! }, plan.walk ? 'walk' : 'get', [plan.oid], plan.limit));
        const text = clip(this.finish(scrubExact(redactText(formatSnmp(rows)), secretsOf(cred))));
        return { text: `[${device.name}] snmp ${plan.walk ? 'walk' : 'get'} ${nameFor(plan.oid)}\n${text || '(empty)'}\n${this.m.footer(this.now() - t0, ', SNMP v2c')}`, isError: false, action: `snmp ${device.name} ${nameFor(plan.oid)}`, data: { device: device.id, oid: plan.oid, count: rows.length } };
      } catch (e) { return fail(this.m.failedOn('snmp_get', device.name, scrubExact(errText(e), secretsOf(cred)).slice(0, 300)), errorKindOf(e)); }
    });
  }

  // ───────────── switch ─────────────

  async switchRead(args: { device?: unknown; command?: unknown; filter?: unknown }): Promise<NetResult> {
    let device: DeviceInfo; let command: string; let plan: RosPlan | undefined;
    try {
      device = resolveDevice(await this.devices(), args.device, 'switch');
      const verb = String(args.command ?? '').trim().toLowerCase();
      if (device.family === 'swos') {
        if (!['sysinfo', 'interfaces'].includes(verb)) throw new PolicyDenied('SwOS switches are read over SNMP only: command "sysinfo" or "interfaces".');
        command = verb;
      } else {
        command = Object.hasOwn(SWITCH_COMMANDS, verb) ? SWITCH_COMMANDS[verb]! : '';
        if (!command) throw new PolicyDenied(`unknown switch command. Allowed: ${Object.keys(SWITCH_COMMANDS).join(', ')}.`);
        const filter = typeof args.filter === 'string' ? args.filter.trim() : '';
        if (filter) {
          if (!FILTER_RE.test(filter)) throw new PolicyDenied('filter must look like field=value (e.g. on-interface=sfp-sfpplus1).');
          const at = filter.indexOf('=');
          command += ` where ${filter.slice(0, at)}="${filter.slice(at + 1)}"`;
        }
        plan = planRosCommand(command);
        this.guardPlan(plan);
      }
    } catch (e) { return this.refused('switch_read', e, args.device); }
    if (plan) {
      const p = plan; const dev = device;
      const result = await this.audited('switch_read', dev.id, auditCommand(p), () => this.exec(dev, p, 'switch_read'));
      if (result.isError && /no such command|bad command name|unknown command/i.test(result.text) && String(args.command).trim().toLowerCase() === 'poe') return fail(`switch_read: ${dev.name} has no PoE (this model/version does not know /interface ethernet poe). Not a connection problem.`);
      return result;
    }
    // SwOS: SNMP only.
    const dev = device;
    return this.audited('switch_read', dev.id, `swos ${command}`, async () => {
      const t0 = this.now();
      let cred: DeviceCredentials | undefined;
      try {
        cred = await this.credentialsOf(dev.id);
        if (!cred.community) return fail('switch_read: the device has no SNMP community configured.', 'config');
        const target = { host: dev.host, port: dev.snmpPort ?? 161, community: cred.community };
        const snmp = this.o.snmp ?? defaultSnmp;
        let text: string;
        if (command === 'sysinfo') text = formatSnmp(await this.gate.run(() => snmp(target, 'get', [SNMP_NAMES.sysName!, SNMP_NAMES.sysUpTime!, SNMP_NAMES.sysDescr!], 3)));
        else {
          const [names = [], oper = [], speed = []] = await Promise.all([SNMP_NAMES.ifDescr!, SNMP_NAMES.ifOperStatus!, SNMP_NAMES.ifHighSpeed!].map((o) => this.gate.run(() => snmp(target, 'walk', [o], 100))));
          const byIdx = (rows: Array<{ oid: string; value: string }>) => new Map(rows.map((r) => [r.oid.split('.').pop()!, r.value]));
          const o = byIdx(oper); const s = byIdx(speed);
          text = names.map((r) => { const i = r.oid.split('.').pop()!; return `${i} ${r.value} status=${({ 1: 'up', 2: 'down' } as Record<string, string>)[o.get(i) || ''] || o.get(i) || '?'} speed=${s.get(i) || '?'}Mbps`; }).join('\n');
        }
        return { text: `[${dev.name}] switch ${command} (SNMP)\n${clip(this.finish(scrubExact(redactText(text), secretsOf(cred))))}\n${this.m.footer(this.now() - t0, '')}`, isError: false, action: `switch ${dev.name} ${command}` };
      } catch (e) { return fail(this.m.failedOn('switch_read', dev.name, scrubExact(errText(e), secretsOf(cred)).slice(0, 300)), errorKindOf(e)); }
    });
  }

  // ───────────── snapshot hook ─────────────

  attachSnapshot(handler: (args: Record<string, unknown>) => Promise<NetResult>): void { this.snapshotHandler = handler; }
  async snapshot(args: Record<string, unknown>): Promise<NetResult> {
    if (!this.snapshotHandler) return fail(this.m.snapshotDisabled, 'config');
    return this.audited('mikrotik_snapshot', typeof args.device === 'string' ? args.device : undefined, undefined, () => this.snapshotHandler!(args));
  }
}

// ───────────── helpers ─────────────

interface RecipeCtx { creds: Map<string, DeviceCredentials>; breaker: Breaker }
/** Ids of devices that failed to connect during one batch/recipe call. */
type Breaker = Set<string>;
/** Thrown instead of a connection attempt when the breaker is open; never a fresh network failure. */
class SkippedError extends ConnectError {}

/** Selector for `monitor`: the router's `.id` when it looks like one, else the quoted name (double quotes are not valid inside names we accept). */
const monitorRef = (row: RosRow): string => (/^\*[0-9A-Fa-f]{1,8}$/.test(row['.id'] ?? '') ? row['.id']! : `"${(row.name ?? '').replace(/"/g, '')}"`);
/** API port shown to the operator; SNMP-only and SwOS devices have no RouterOS API. */
const apiPortOf = (d: DeviceInfo): number | undefined => (d.family === 'routeros' || d.family === 'switch' ? d.port : undefined);
const portOf = (d: DeviceInfo): string => {
  const api = apiPortOf(d);
  if (api) return `:${api}`;
  return d.family === 'swos' || d.family === 'snmp' ? ` (snmp:${d.snmpPort ?? 161})` : '';
};

/** Friendly reason for a failed export: a missing client, a refused password, a changed host key… */
function sshFailureDetail(out: { code: number; stderr: string }, secrets: string[]): string {
  const raw = scrubExact(out.stderr.trim(), secrets);
  if (/ENOENT|not found/i.test(raw)) return 'the OpenSSH client (ssh) is not installed on the MCP host';
  if (/permission denied/i.test(raw)) return 'SSH login was refused: wrong user/password, or the router user has no ssh policy; a key file (ssh.key_file) is preferred';
  if (/host key|REMOTE HOST IDENTIFICATION|pinned/i.test(raw)) return raw || 'SSH host key check failed';
  if (/timed? ?out|connection (refused|reset|closed)|no route/i.test(raw)) return `${raw}; check ssh.port and that the router allows SSH from this host`;
  return raw || `exit code ${out.code}`;
}

const norm = (s: string | undefined) => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
/** The table is cut at 300 rows: a count reported by a recipe is only a lower bound, so say so. */
const atLeast = (n: number, truncated?: boolean) => (truncated ? `≥${n} (truncated)` : String(n));
/** Pick safe columns only; free-text values are masked of secret pairs. */
function pick(row: RosRow, cols: string[]): string {
  return cols.filter((c) => row[c] !== undefined && row[c] !== '' && !SECRET_KEY.test(c)).map((c) => `${c}=${maskInlineSecrets(row[c]!).slice(0, 80)}`).join(' ');
}

/** Customer name for the dynamic PPPoE interface `<pppoe-NAME>`: built here from a name that already passed a strict pattern,
 * and sent as one API word (no script parsing), so the general allowlist is not loosened for `<` `>`. */
export function pppoeInterfacePlan(name: string): RosApiPlan {
  if (!PPPOE_NAME.test(name)) throw new PolicyDenied('invalid PPPoE name (letters/digits/._@-, max 64).');
  return {
    kind: 'api', verb: 'print', path: ['interface'], apiPath: '/interface/print',
    words: [`?name=<pppoe-${name}>`, '=.proplist=name,type,running,disabled,last-link-up-time,rx-byte,tx-byte,rx-error,tx-error,rx-drop,tx-drop'],
    display: `/interface print where name="<pppoe-${name}>"`,
  };
}

function scrubRows(rows: RosRow[], cred: DeviceCredentials): RosRow[] {
  const secrets = secretsOf(cred);
  return rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v === MASK ? v : scrubExact(v, secrets)])));
}

/** Export of a core can be 100+ KB: return the line count and the head, not everything. */
function clipExport(text: string): string {
  if (text.length <= 12_000) return text;
  return `(export of ${text.split('\n').length} lines, ${text.length} characters; showing the head — narrow with a menu, e.g. "/ip firewall nat export hide-sensitive terse")\n${text}`;
}

function buildBlockList(cidrs: string[] | undefined): net.BlockList | undefined {
  if (!cidrs?.length) return undefined;
  const list = new net.BlockList();
  for (const c of cidrs) {
    const m = /^([0-9a-fA-F:.]+)\/(\d{1,3})$/.exec(c.trim());
    const fam = m ? net.isIP(m[1]!) : 0;
    if (!m || !fam || Number(m[2]) > (fam === 4 ? 32 : 128)) throw new PolicyDenied(`invalid CIDR "${c.slice(0, 50)}".`);
    list.addSubnet(m[1]!, Number(m[2]), fam === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}

export { BusyError };
