import type { Duplex } from 'node:stream';
import type { ErrorKind } from './errors.js';

/** Device family. `switch` = CRS-style RouterOS switch, `swos` = SwOS switch (SNMP only), `snmp` = SNMP-only device. */
export type DeviceFamily = 'routeros' | 'switch' | 'swos' | 'snmp';

export interface TlsSpec {
  /** Verify the certificate chain against `ca` (or the system store). Ignored when `fingerprint256` is set. */
  verify: boolean;
  /** PEM text of the CA / self-signed certificate to trust. */
  ca?: string;
  /** Pin the server certificate by SHA-256 fingerprint (hex, colons optional). */
  fingerprint256?: string;
  servername?: string;
}

export interface SshSpec {
  /** TCP port for SSH; `null` = SSH is closed, `export` is unavailable. */
  port: number | null;
  /** Private key file (preferred over password authentication). */
  keyFile?: string;
  /** Pin the SSH host key by SHA-256 fingerprint (`SHA256:...` or bare base64). Otherwise trust-on-first-use in the state directory. */
  hostKeySha256?: string;
}

export interface FallbackSpec { host: string; port: number; label: string }

export interface DeviceInfo {
  /** Stable identifier used in every tool call. */
  id: string;
  /** Display name (defaults to id). */
  name: string;
  host: string;
  /** API port (8729 for api-ssl, 8728 for plain API). */
  port: number;
  family: DeviceFamily;
  group?: string;
  labels?: Record<string, string>;
  /** `api-ssl` (default) or `api` (plain text, requires an explicit opt-in). */
  transport?: 'api-ssl' | 'api';
  tls?: TlsSpec;
  ssh?: SshSpec;
  snmpPort?: number;
  /** Alternate address tried once when the direct address does not connect. */
  fallback?: FallbackSpec;
}

export interface DeviceCredentials {
  user: string;
  secret: string;
  /** SNMP v2c community, when SNMP is used. */
  community?: string;
  /** Free-form extra secrets that must never appear in output (they are scrubbed like the rest). */
  extras?: Record<string, string>;
}

/** Where the inventory comes from. YAML for the public server; a database adapter for private embedders. */
export interface DeviceSource {
  list(): Promise<DeviceInfo[]>;
}

/** Where credentials come from. Called lazily; results are cached in memory (never on disk or in logs). */
export interface CredentialSource {
  credentials(deviceId: string): Promise<DeviceCredentials>;
  /** Called when a login was denied so the next attempt re-reads the source. */
  drop?(deviceId: string): void;
}

/** Optional custom connector (tunnel, jump host, port-forward). Must return an already connected duplex stream. */
export type Dialer = (target: { host: string; port: number; device: DeviceInfo }) => Promise<Duplex>;

export interface NetResult {
  text: string;
  isError: boolean;
  /** Short description of what was done, for audit/UI. */
  action?: string;
  errorKind?: ErrorKind;
  /** Machine-readable payload (already redacted). */
  data?: unknown;
}

export interface RosRow { [key: string]: string }

export interface RosApiPlan {
  kind: 'api';
  verb: 'print' | 'monitor' | 'ping' | 'traceroute';
  path: string[];
  apiPath: string;
  words: string[];
  display: string;
  tail?: number;
  maxRows?: number;
}
export interface RosExportPlan { kind: 'export'; path: string[]; display: string; sshCommand: string }
export type RosPlan = RosApiPlan | RosExportPlan;

export interface RosTarget {
  host: string;
  port: number;
  user: string;
  password: string;
  tls?: TlsSpec;
  dialer?: () => Promise<Duplex>;
}
export interface RosResult { rows: RosRow[]; truncated: boolean; scanned?: number }
/** Executes one API sentence against a device. The default implementation is the pooled client. */
export type RosTransport = (target: RosTarget, plan: RosApiPlan, timeoutMs: number, connectMs?: number) => Promise<RosResult>;

export interface SshTarget { host: string; port: number; user: string; password?: string; keyFile?: string; hostKeySha256?: string; deviceId: string }
export interface SshOutcome { code: number; stdout: string; stderr: string }
export type SshRunner = (target: SshTarget, remote: string, timeoutMs: number) => Promise<SshOutcome>;

export interface SnmpVarbind { oid: string; value: string }
export type SnmpTransport = (target: { host: string; port: number; community: string }, op: 'get' | 'walk', oids: string[], maxRows: number) => Promise<SnmpVarbind[]>;

export type LocalRunner = (file: string, args: string[], timeoutMs: number) => Promise<SshOutcome>;

export interface AuditEntry {
  ts: string;
  tool: string;
  device?: string;
  /** Normalised command without values (path, verb, where-keys only). */
  command?: string;
  ok: boolean;
  errorKind?: ErrorKind;
  durationMs: number;
}
