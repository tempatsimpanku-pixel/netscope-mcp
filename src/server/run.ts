import fs from 'node:fs';
import path from 'node:path';
import { NetScope } from '../core/engine.js';
import { RosPool } from '../core/pool.js';
import { SnapshotStore, SnapshotWorker, intervalFromMinutes, snapshotTool } from '../core/snapshot.js';
import { createSshRunner } from '../core/ssh.js';
import type { AuditEntry } from '../core/types.js';
import { EnvFileCredentials, YamlSource, type ServerConfig } from './config.js';

export interface BuiltServer {
  scope: NetScope;
  close: () => void;
}

export interface BuildOptions {
  snapshotFile?: string;
  /** Overrides settings.audit_log. */
  auditLog?: string;
  log: (line: string) => void;
  env?: NodeJS.ProcessEnv;
  /** Test hook: custom scope pieces. */
  scopeOverrides?: Partial<ConstructorParameters<typeof NetScope>[0]>;
  /** Start the snapshot worker timers (default true when snapshotFile is set). */
  startWorker?: boolean;
}

function auditSink(target: string, log: (line: string) => void): ((e: AuditEntry) => void) | undefined {
  if (target === 'off') return undefined;
  if (target === 'stderr') return (e) => log(`[audit] ${JSON.stringify(e)}`);
  fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true, mode: 0o700 });
  if (!fs.existsSync(target)) fs.closeSync(fs.openSync(target, 'a', 0o600));
  fs.chmodSync(target, 0o600);
  return (e) => { try { fs.appendFileSync(target, `${JSON.stringify(e)}\n`, { mode: 0o600 }); } catch { /* audit must never break a call */ } };
}

/** Wire a validated configuration into a ready NetScope (+ optional snapshot worker). */
export function buildServer(config: ServerConfig, opts: BuildOptions): BuiltServer {
  const s = config.settings;
  const audit = auditSink(opts.auditLog ?? s.audit_log, opts.log);
  const pool = new RosPool();
  const scope = new NetScope({
    devices: new YamlSource(config.routers), credentials: new EnvFileCredentials(config.routers, opts.env),
    pool, ssh: createSshRunner({ stateDir: path.join(config.stateDir, 'ssh') }),
    locale: s.locale, redactPii: s.redact_pii, redactPppNames: s.redact_ppp_names, allowInsecure: s.allow_insecure, allowLocalProbe: s.allow_local_probe, maxInflight: s.max_inflight,
    probe: { allowCidrs: s.probe.allow_cidrs, denyCidrs: s.probe.deny_cidrs },
    ...(audit ? { audit } : {}), ...opts.scopeOverrides,
  });
  let worker: SnapshotWorker | undefined;
  let store: SnapshotStore | undefined;
  if (opts.snapshotFile) {
    store = new SnapshotStore(opts.snapshotFile);
    const st = store;
    scope.attachSnapshot((args) => snapshotTool(scope, st, args));
    worker = new SnapshotWorker({ scope, store: st, intervalMs: intervalFromMinutes(s.snapshot.interval_min), storeCustomerData: s.snapshot.store_customer_data, log: opts.log });
    if (opts.startWorker !== false) worker.start();
    opts.log(`[snapshot] enabled: every ${s.snapshot.interval_min} min into ${opts.snapshotFile} (customer data ${s.snapshot.store_customer_data ? 'STORED' : 'not stored'})`);
  }
  return { scope, close: () => { worker?.stop(); store?.close(); scope.close(); } };
}
