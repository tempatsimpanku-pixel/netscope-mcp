import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { CredentialSource, DeviceCredentials, DeviceInfo, DeviceSource, SshSpec, TlsSpec } from '../core/types.js';

/** Raised for any configuration problem. Messages name the offending KEY, never its value. */
export class ConfigError extends Error {
  constructor(message: string) { super(message); this.name = 'ConfigError'; }
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,251}$/;
const FP = /^(?:[0-9a-fA-F]{2}:?){32}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

const credentialsSchema = z.object({
  user_env: z.string().regex(ENV_NAME).optional(),
  pass_env: z.string().regex(ENV_NAME).optional(),
  community_env: z.string().regex(ENV_NAME).optional(),
  /** Credentials file: lines `user=`, `password=`, `community=`. Must be mode 0600. */
  file: z.string().min(1).optional(),
}).strict();

const routerSchema = z.object({
  id: z.string().regex(ID),
  name: z.string().min(1).max(80).optional(),
  host: z.string().regex(HOST),
  port: z.number().int().min(1).max(65535).optional(),
  family: z.enum(['routeros', 'switch', 'swos', 'snmp']).default('routeros'),
  group: z.string().min(1).max(64).optional(),
  labels: z.record(z.string(), z.string()).optional(),
  transport: z.enum(['api-ssl', 'api']).optional(),
  verify_tls: z.boolean().optional(),
  tls_ca_file: z.string().optional(),
  tls_fingerprint256: z.string().regex(FP).optional(),
  credentials: credentialsSchema,
  snmp: z.object({ port: z.number().int().min(1).max(65535).optional(), community_env: z.string().regex(ENV_NAME).optional() }).strict().optional(),
  ssh: z.object({ port: z.number().int().min(1).max(65535).nullable(), key_file: z.string().optional(), host_key_sha256: z.string().min(20).max(80).optional() }).strict().optional(),
  fallback: z.object({ host: z.string().regex(HOST), port: z.number().int().min(1).max(65535), label: z.string().min(1).max(80) }).strict().optional(),
}).strict();

const settingsSchema = z.object({
  redact_pii: z.boolean().default(true),
  allow_insecure: z.boolean().default(false),
  allow_local_probe: z.boolean().default(false),
  max_inflight: z.number().int().min(1).max(50).default(10),
  probe: z.object({ allow_cidrs: z.array(z.string()).default([]), deny_cidrs: z.array(z.string()).default([]) }).strict().default({ allow_cidrs: [], deny_cidrs: [] }),
  snapshot: z.object({ interval_min: z.number().min(2).max(1440).default(10), store_customer_data: z.boolean().default(false) }).strict().default({ interval_min: 10, store_customer_data: false }),
  audit_log: z.string().default('stderr'),
  /** Language of the frame sentences (headers, errors, footers). */
  locale: z.enum(['en', 'id']).default('en'),
  state_dir: z.string().optional(),
}).strict();

const defaultsSchema = z.object({
  transport: z.enum(['api-ssl', 'api']).optional(),
  verify_tls: z.boolean().optional(),
  timeout_ms: z.number().int().min(1000).max(120_000).optional(),
}).strict();

const configSchema = z.object({
  settings: settingsSchema.default(settingsSchema.parse({})),
  defaults: defaultsSchema.default({}),
  routers: z.array(routerSchema).min(1),
}).strict();

export type ServerSettings = z.infer<typeof settingsSchema>;
type RouterConfig = z.infer<typeof routerSchema>;

export interface ResolvedRouter {
  device: DeviceInfo;
  credentials: RouterConfig['credentials'];
  snmpCommunityEnv?: string;
}
export interface ServerConfig {
  settings: ServerSettings;
  routers: ResolvedRouter[];
  stateDir: string;
  /** Non-fatal observations (plain-text API in use, …). */
  warnings: string[];
}

export interface ParseOptions {
  /** Directory against which relative file paths are resolved. */
  baseDir?: string;
  env?: NodeJS.ProcessEnv;
}

const issuePath = (p: PropertyKey[]) => p.map(String).join('.') || '(root)';

export function checkPrivateFile(file: string, what: string): void {
  let st: fs.Stats;
  try { st = fs.statSync(file); } catch { throw new ConfigError(`${what}: file does not exist or is not readable.`); }
  if (!st.isFile()) throw new ConfigError(`${what}: not a regular file.`);
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) throw new ConfigError(`${what}: file is readable by group/others (mode ${(st.mode & 0o777).toString(8)}); run chmod 600.`);
}

export function parseConfig(text: string, opts: ParseOptions = {}): ServerConfig {
  const env = opts.env ?? process.env;
  const baseDir = opts.baseDir ?? process.cwd();
  const abs = (p: string) => (path.isAbsolute(p) ? p : path.resolve(baseDir, p));
  let raw: unknown;
  try { raw = parseYaml(text); } catch (e) { throw new ConfigError(`routers file is not valid YAML: ${(e as Error).message.split('\n')[0]!.slice(0, 160)}`); }
  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) throw new ConfigError(`invalid configuration: ${parsed.error.issues.slice(0, 8).map((i) => `${issuePath(i.path)}: ${i.message}`).join('; ')}`);
  const cfg = parsed.data;
  const warnings: string[] = [];
  const seen = new Set<string>();
  const routers: ResolvedRouter[] = cfg.routers.map((r, idx) => {
    const where = `routers[${idx}]`;
    if (seen.has(r.id.toLowerCase())) throw new ConfigError(`${where}.id: duplicate id.`);
    seen.add(r.id.toLowerCase());
    const transport = r.transport ?? cfg.defaults.transport ?? 'api-ssl';
    const verify = r.verify_tls ?? cfg.defaults.verify_tls ?? true;
    const usesApi = r.family === 'routeros' || r.family === 'switch';
    if (usesApi && transport === 'api') {
      if (!cfg.settings.allow_insecure) throw new ConfigError(`${where}.transport: plain-text API requires settings.allow_insecure: true.`);
      warnings.push(`${r.id}: plain-text API (port ${r.port ?? 8728}): credentials cross the network unencrypted. Use api-ssl or a dedicated management network.`);
    }
    if (usesApi && transport === 'api-ssl' && !verify && !r.tls_fingerprint256) {
      if (!cfg.settings.allow_insecure) throw new ConfigError(`${where}.verify_tls: disabling certificate verification without a pinned fingerprint requires settings.allow_insecure: true.`);
      warnings.push(`${r.id}: TLS certificate is not verified (no CA, no pin).`);
    }
    let tls: TlsSpec | undefined;
    if (usesApi && transport === 'api-ssl') {
      tls = { verify };
      if (r.tls_ca_file) { try { tls.ca = fs.readFileSync(abs(r.tls_ca_file), 'utf8'); } catch { throw new ConfigError(`${where}.tls_ca_file: cannot read the file.`); } }
      if (r.tls_fingerprint256) tls.fingerprint256 = r.tls_fingerprint256;
    }
    let ssh: SshSpec | undefined;
    if (r.ssh) {
      ssh = { port: r.ssh.port };
      if (r.ssh.key_file) { const f = abs(r.ssh.key_file); if (!fs.existsSync(f)) throw new ConfigError(`${where}.ssh.key_file: file does not exist.`); ssh.keyFile = f; }
      if (r.ssh.host_key_sha256) ssh.hostKeySha256 = r.ssh.host_key_sha256;
    }
    const cr = r.credentials;
    if (cr.file) {
      if (cr.user_env || cr.pass_env || cr.community_env) throw new ConfigError(`${where}.credentials: use either file or *_env keys, not both.`);
      checkPrivateFile(abs(cr.file), `${where}.credentials.file`);
    } else if (usesApi) {
      if (!cr.user_env || !cr.pass_env) throw new ConfigError(`${where}.credentials: user_env and pass_env (or file) are required for RouterOS devices.`);
      for (const k of ['user_env', 'pass_env'] as const) if (env[cr[k]!] === undefined) throw new ConfigError(`${where}.credentials.${k}: environment variable ${cr[k]} is not set.`);
    } else if (!cr.community_env && !r.snmp?.community_env) throw new ConfigError(`${where}.credentials: community_env (or file) is required for SNMP devices.`);
    const commEnv = r.snmp?.community_env ?? cr.community_env;
    if (commEnv && !cr.file && env[commEnv] === undefined) throw new ConfigError(`${where}: environment variable ${commEnv} (SNMP community) is not set.`);
    const device: DeviceInfo = {
      id: r.id, name: r.name ?? r.id, host: r.host, port: r.port ?? (transport === 'api' ? 8728 : 8729), family: r.family,
      ...(r.group ? { group: r.group } : {}), ...(r.labels ? { labels: r.labels } : {}),
      ...(usesApi ? { transport } : {}), ...(tls ? { tls } : {}), ...(ssh ? { ssh } : {}),
      ...(r.snmp?.port ? { snmpPort: r.snmp.port } : {}), ...(r.fallback ? { fallback: r.fallback } : {}),
    };
    return { device, credentials: { ...cr, ...(cr.file ? { file: abs(cr.file) } : {}) }, ...(commEnv ? { snmpCommunityEnv: commEnv } : {}) };
  });
  for (const c of [...cfg.settings.probe.allow_cidrs, ...cfg.settings.probe.deny_cidrs]) if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(c)) throw new ConfigError('settings.probe: CIDR entries must look like 192.0.2.0/24.');
  const stateDir = abs(cfg.settings.state_dir ?? path.join(env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'netscope-mcp'));
  return { settings: cfg.settings, routers, stateDir, warnings };
}

export function loadConfig(file: string, env: NodeJS.ProcessEnv = process.env): ServerConfig {
  let text: string;
  try { text = fs.readFileSync(file, 'utf8'); } catch { throw new ConfigError(`cannot read the routers file.`); }
  return parseConfig(text, { baseDir: path.dirname(path.resolve(file)), env });
}

/** `routers.yaml` → inventory. */
export class YamlSource implements DeviceSource {
  constructor(private readonly routers: ResolvedRouter[]) {}
  async list(): Promise<DeviceInfo[]> { return this.routers.map((r) => r.device); }
}

function readCredentialFile(file: string): Record<string, string> {
  checkPrivateFile(file, 'credentials file');
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^\s*(user|password|community)\s*=\s*(.*?)\s*$/.exec(line);
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

/** Credentials from environment variables or a 0600 file; read on demand so a rotated secret is picked up after the cache expires. */
export class EnvFileCredentials implements CredentialSource {
  private readonly byId = new Map<string, ResolvedRouter>();
  constructor(routers: ResolvedRouter[], private readonly env: NodeJS.ProcessEnv = process.env) { for (const r of routers) this.byId.set(r.device.id, r); }
  async credentials(deviceId: string): Promise<DeviceCredentials> {
    const r = this.byId.get(deviceId);
    if (!r) throw new Error('unknown device.');
    const c = r.credentials;
    if (c.file) {
      const f = readCredentialFile(c.file);
      return { user: f.user ?? '', secret: f.password ?? '', ...(f.community ? { community: f.community } : {}) };
    }
    const community = r.snmpCommunityEnv ? this.env[r.snmpCommunityEnv] : undefined;
    return { user: c.user_env ? this.env[c.user_env] ?? '' : '', secret: c.pass_env ? this.env[c.pass_env] ?? '' : '', ...(community ? { community } : {}) };
  }
}
