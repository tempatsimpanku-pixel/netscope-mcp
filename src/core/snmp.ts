import dgram from 'node:dgram';
import { PolicyDenied } from './errors.js';
import type { SnmpTransport, SnmpVarbind } from './types.js';

/** SNMP v2c, GET / GETNEXT / GETBULK only (there is no SET PDU in this code base). */

export const SNMP_NAMES: Record<string, string> = {
  sysDescr: '1.3.6.1.2.1.1.1.0', sysObjectID: '1.3.6.1.2.1.1.2.0', sysUpTime: '1.3.6.1.2.1.1.3.0', sysContact: '1.3.6.1.2.1.1.4.0', sysName: '1.3.6.1.2.1.1.5.0', sysLocation: '1.3.6.1.2.1.1.6.0',
  ifNumber: '1.3.6.1.2.1.2.1.0', ifDescr: '1.3.6.1.2.1.2.2.1.2', ifType: '1.3.6.1.2.1.2.2.1.3', ifMtu: '1.3.6.1.2.1.2.2.1.4', ifSpeed: '1.3.6.1.2.1.2.2.1.5', ifAdminStatus: '1.3.6.1.2.1.2.2.1.7', ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
  ifInErrors: '1.3.6.1.2.1.2.2.1.14', ifOutErrors: '1.3.6.1.2.1.2.2.1.20', ifName: '1.3.6.1.2.1.31.1.1.1.1', ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6', ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15', ifAlias: '1.3.6.1.2.1.31.1.1.1.18', hrProcessorLoad: '1.3.6.1.2.1.25.3.3.1.2',
};
const OID_RE = /^\.?[0-9]+(\.[0-9]+){2,30}$/;
/** Readable subtrees (walk and get). Anything else (hrSWRun parameters, nsExtend, UCD exec, snmpCommunity, VACM, MIB roots) is refused. */
export const SNMP_ALLOWED_PREFIXES: readonly string[] = [
  '1.3.6.1.2.1.1', '1.3.6.1.2.1.2', '1.3.6.1.2.1.31.1.1', '1.3.6.1.2.1.25.3.3', '1.3.6.1.2.1.25.2', '1.3.6.1.2.1.25.1.1',
  '1.3.6.1.2.1.4.20', '1.3.6.1.2.1.4.22', '1.3.6.1.2.1.17', '1.3.6.1.2.1.99', '1.3.6.1.4.1.2021.10', '1.3.6.1.4.1.2021.4', '1.3.6.1.4.1.2021.11',
  '1.3.6.1.4.1.14988.1.1',
];
export const snmpAllowed = (oid: string): boolean => SNMP_ALLOWED_PREFIXES.some((p) => oid === p || oid.startsWith(`${p}.`));
const OUTSIDE = 'OID is outside the readable subtrees (system, interfaces, hrProcessorLoad/hrStorage, IP/ARP, bridge MIB, sensors, UCD load/mem/cpu, vendor 14988.1.1).';
const MAX_ARC = 4_294_967_295;

/** Strict numeric-OID check (no surrounding whitespace, every arc <= 2^32-1, inside the readable subtrees). Returns the OID without a leading dot. */
export function checkSnmpOid(oid: string): string {
  if (!OID_RE.test(oid)) throw new PolicyDenied('oid must be numeric, e.g. 1.3.6.1.2.1.1.3.0.');
  const clean = oid.replace(/^\./, '');
  if (clean.split('.').some((a) => a.length > 10 || Number(a) > MAX_ARC)) throw new PolicyDenied('OID arc is out of range (max 4294967295).');
  if (!snmpAllowed(clean)) throw new PolicyDenied(OUTSIDE);
  return clean;
}
export const SNMP_MAX_ROWS = 500;
const SNMP_WALK_MS = 10_000;

export interface SnmpPlan { oid: string; walk: boolean; limit: number }

function int(v: unknown, lo: number, hi: number, dflt: number, name: string): number {
  if (v === undefined || v === null || v === '') return dflt;
  const n = typeof v === 'number' ? v : /^\d{1,6}$/.test(String(v)) ? Number(v) : NaN;
  if (!Number.isInteger(n) || n < lo || n > hi) throw new PolicyDenied(`${name} must be an integer between ${lo} and ${hi}.`);
  return n;
}

/** Validate tool arguments: exactly one of `name` / `oid`, subtree allowlist, bounded rows. Throws PolicyDenied. */
export function planSnmp(args: { name?: unknown; oid?: unknown; walk?: unknown; limit?: unknown }): SnmpPlan {
  const name = typeof args.name === 'string' ? args.name.trim() : '';
  const raw = typeof args.oid === 'string' ? args.oid.trim() : '';
  if (!name === !raw) throw new PolicyDenied('give exactly one of "name" (e.g. sysUpTime, ifOperStatus) or a numeric "oid".');
  let oid: string;
  if (name) {
    const m = /^([A-Za-z]+)(?:\.(\d{1,5}))?$/.exec(name);
    const base = m && Object.hasOwn(SNMP_NAMES, m[1]!) ? SNMP_NAMES[m[1]!] : undefined;
    if (!base) throw new PolicyDenied(`unknown SNMP name. Allowed: ${Object.keys(SNMP_NAMES).join(', ')} (or a numeric oid).`);
    oid = m![2] && !base.endsWith('.0') ? `${base}.${m![2]}` : base;
  } else {
    oid = checkSnmpOid(raw);
  }
  if (!snmpAllowed(oid)) throw new PolicyDenied(OUTSIDE);
  const limit = int(args.limit, 1, SNMP_MAX_ROWS, 100, 'limit');
  const walk = args.walk === true || args.walk === 'true' || (!!name && !name.includes('.') && !oid.endsWith('.0'));
  return { oid, walk, limit };
}

export const nameFor = (oid: string): string => {
  const entry = Object.entries(SNMP_NAMES).find(([, base]) => oid === base || oid.startsWith(`${base}.`));
  return entry ? `${entry[0]}${oid.slice(entry[1].length)}` : oid;
};
export const formatSnmp = (rows: SnmpVarbind[]): string => rows.map((r) => `${nameFor(r.oid)} = ${r.value}`).join('\n');

// ───────────────────────────── BER ─────────────────────────────

const berLen = (n: number): Buffer => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
export const tlv = (tag: number, body: Buffer): Buffer => Buffer.concat([Buffer.from([tag]), berLen(body.length), body]);
export const berInt = (n: number): Buffer => {
  const bytes: number[] = [];
  let v = n;
  do { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0 || (bytes[0]! & 0x80));
  return tlv(0x02, Buffer.from(bytes));
};
export function berOid(oid: string): Buffer {
  const parts = oid.replace(/^\./, '').split('.').map(Number);
  const out: number[] = [parts[0]! * 40 + parts[1]!];
  for (const p of parts.slice(2)) {
    const chunk = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) { chunk.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}
type Pdu = 0xa0 | 0xa1 | 0xa5; // GetRequest | GetNextRequest | GetBulkRequest
export function snmpPacket(community: string, pdu: Pdu, reqId: number, oids: string[], bulk = 0): Buffer {
  const binds = tlv(0x30, Buffer.concat(oids.map((o) => tlv(0x30, Buffer.concat([berOid(o), Buffer.from([0x05, 0x00])])))));
  const head = pdu === 0xa5 ? [berInt(reqId), berInt(0), berInt(bulk)] : [berInt(reqId), berInt(0), berInt(0)];
  return tlv(0x30, Buffer.concat([berInt(1), tlv(0x04, Buffer.from(community)), tlv(pdu, Buffer.concat([...head, binds]))]));
}
function readTlv(buf: Buffer, pos: number): { tag: number; start: number; end: number } {
  const tag = buf[pos]!;
  let len = buf[pos + 1]!; let start = pos + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i]!; start = pos + 2 + n; }
  if (start + len > buf.length) throw new Error('SNMP packet truncated');
  return { tag, start, end: start + len };
}
function decodeOid(b: Buffer): string {
  const out = [Math.floor(b[0]! / 40), b[0]! % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i]! & 0x7f); if (!(b[i]! & 0x80)) { out.push(v); v = 0; } }
  return out.join('.');
}
function decodeValue(tag: number, b: Buffer): string {
  switch (tag) {
    case 0x02: { let n = b.length && (b[0]! & 0x80) ? -1 : 0; for (const x of b) n = n * 256 + x; return String(n); }
    case 0x41: case 0x42: case 0x46: { let n = 0n; for (const x of b) n = n * 256n + BigInt(x); return String(n); }
    case 0x43: { let n = 0; for (const x of b) n = n * 256 + x; const s = Math.floor(n / 100); return `${Math.floor(s / 86400)}d ${String(Math.floor(s / 3600) % 24).padStart(2, '0')}:${String(Math.floor(s / 60) % 60).padStart(2, '0')}:${String(s % 60).padStart(2, '0')} (${n} ticks)`; }
    case 0x04: case 0x44: return /^[\x20-\x7e\r\n\t]*$/.test(b.toString('latin1')) ? b.toString('latin1') : `0x${b.toString('hex')}`;
    case 0x06: return decodeOid(b);
    case 0x40: return [...b].join('.');
    case 0x05: return '(null)';
    case 0x80: return '(noSuchObject)';
    case 0x81: return '(noSuchInstance)';
    case 0x82: return '(endOfMibView)';
    default: return `0x${b.toString('hex')}`;
  }
}
export function parseSnmpResponse(buf: Buffer, reqId: number): SnmpVarbind[] {
  const msg = readTlv(buf, 0);
  let p = msg.start;
  p = readTlv(buf, p).end; // version
  p = readTlv(buf, p).end; // community
  const pdu = readTlv(buf, p);
  if (pdu.tag !== 0xa2) throw new Error('SNMP reply is not a response');
  let q = pdu.start;
  const id = readTlv(buf, q); let rid = 0; for (let i = id.start; i < id.end; i++) rid = rid * 256 + buf[i]!;
  if (rid !== reqId) throw new Error('SNMP reply id does not match');
  q = id.end;
  const status = readTlv(buf, q); const st = status.end > status.start ? buf[status.start]! : 0; q = status.end;
  q = readTlv(buf, q).end;
  if (st !== 0) throw new Error(`SNMP error-status ${st}`);
  const binds = readTlv(buf, q);
  const out: SnmpVarbind[] = [];
  for (let r = binds.start; r < binds.end;) {
    const bind = readTlv(buf, r);
    const oid = readTlv(buf, bind.start);
    const val = readTlv(buf, oid.end);
    out.push({ oid: decodeOid(buf.subarray(oid.start, oid.end)), value: decodeValue(val.tag, buf.subarray(val.start, val.end)) });
    r = bind.end;
  }
  return out;
}

let reqCounter = Math.floor(Math.random() * 1_000_000) + 1;
function exchange(t: { host: string; port: number; community: string }, pdu: Pdu, oids: string[], bulk: number, timeoutMs: number): Promise<SnmpVarbind[]> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(t.host.includes(':') ? 'udp6' : 'udp4');
    const reqId = (reqCounter = (reqCounter % 2_000_000_000) + 1);
    const timer = setTimeout(() => { sock.close(); reject(new Error('SNMP did not answer (timed out).')); }, timeoutMs);
    sock.on('message', (msg) => {
      try { const out = parseSnmpResponse(msg, reqId); clearTimeout(timer); sock.close(); resolve(out); } catch (e) { clearTimeout(timer); sock.close(); reject(e); }
    });
    sock.on('error', (e) => { clearTimeout(timer); sock.close(); reject(new Error(`SNMP failed: ${(e as NodeJS.ErrnoException).code || 'error'}`)); });
    sock.send(snmpPacket(t.community, pdu, reqId, oids, bulk), t.port, t.host, (err) => { if (err) { clearTimeout(timer); sock.close(); reject(new Error('SNMP send failed.')); } });
  });
}

export const defaultSnmp: SnmpTransport = async (t, op, oids, maxRows) => {
  if (op === 'get') return exchange(t, 0xa0, oids, 0, 4_000);
  const root = oids[0]!.replace(/^\./, '');
  const out: SnmpVarbind[] = [];
  let cursor = root;
  const deadline = Date.now() + SNMP_WALK_MS;
  while (out.length < maxRows && Date.now() < deadline) {
    const batch = await exchange(t, 0xa5, [cursor], Math.min(20, maxRows - out.length), Math.max(1_000, deadline - Date.now()));
    let ended = false;
    for (const vb of batch) {
      if (!vb.oid.startsWith(`${root}.`) || vb.value === '(endOfMibView)') { ended = true; break; }
      out.push(vb); cursor = vb.oid;
    }
    if (ended || !batch.length) break;
  }
  return out;
};
