import dgram from 'node:dgram';
import { berInt, berOid, tlv } from '../../src/core/snmp.js';

export type SnmpValue = { kind: 'str'; v: string } | { kind: 'int'; v: number } | { kind: 'ticks'; v: number };
const cmp = (a: string, b: string): number => {
  const x = a.split('.').map(Number); const y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] ?? -1) - (y[i] ?? -1); if (d) return d; }
  return 0;
};
function readTlv(buf: Buffer, pos: number) {
  const tag = buf[pos]!; let len = buf[pos + 1]!; let start = pos + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i]!; start = pos + 2 + n; }
  return { tag, start, end: start + len };
}
const oidOf = (b: Buffer): string => { const out = [Math.floor(b[0]! / 40), b[0]! % 40]; let v = 0; for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i]! & 0x7f); if (!(b[i]! & 0x80)) { out.push(v); v = 0; } } return out.join('.'); };
const encode = (val: SnmpValue): Buffer => (val.kind === 'str' ? tlv(0x04, Buffer.from(val.v)) : val.kind === 'int' ? berInt(val.v) : tlv(0x43, Buffer.from([(val.v >> 24) & 0xff, (val.v >> 16) & 0xff, (val.v >> 8) & 0xff, val.v & 0xff])));

/** A tiny SNMP v2c agent (GET / GETNEXT / GETBULK over a sorted OID table) that only answers the right community. */
export async function fakeSnmp(table: Record<string, SnmpValue>, community = 'LAB-COMMUNITY-ONE') {
  const oids = Object.keys(table).sort(cmp);
  const requests: Array<{ pdu: number; oids: string[] }> = [];
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    const outer = readTlv(msg, 0);
    const ver = readTlv(msg, outer.start); const com = readTlv(msg, ver.end);
    if (msg.subarray(com.start, com.end).toString() !== community) return;
    const pdu = readTlv(msg, com.end);
    const id = readTlv(msg, pdu.start); const e1 = readTlv(msg, id.end); const e2 = readTlv(msg, e1.end);
    const maxRep = e2.end > e2.start ? msg[e2.start]! : 1;
    const binds = readTlv(msg, e2.end);
    const asked: string[] = [];
    for (let p = binds.start; p < binds.end;) { const b = readTlv(msg, p); const o = readTlv(msg, b.start); asked.push(oidOf(msg.subarray(o.start, o.end))); p = b.end; }
    requests.push({ pdu: pdu.tag, oids: asked });
    const answers: Array<[string, Buffer]> = [];
    const next = (from: string): [string, Buffer] => { const n = oids.find((o) => cmp(o, from) > 0); return n ? [n, encode(table[n]!)] : [from, Buffer.from([0x82, 0x00])]; };
    if (pdu.tag === 0xa0) for (const o of asked) answers.push(table[o] ? [o, encode(table[o]!)] : [o, Buffer.from([0x80, 0x00])]);
    else if (pdu.tag === 0xa1) for (const o of asked) answers.push(next(o));
    else { let cur = asked[0]!; for (let i = 0; i < maxRep; i++) { const a = next(cur); answers.push(a); if (a[1][0] === 0x82) break; cur = a[0]; } }
    const body = tlv(0x30, Buffer.concat(answers.map(([o, v]) => tlv(0x30, Buffer.concat([berOid(o), v])))));
    const reply = tlv(0x30, Buffer.concat([berInt(1), tlv(0x04, Buffer.from(community)), tlv(0xa2, Buffer.concat([msg.subarray(id.start - 2, id.end), berInt(0), berInt(0), body]))]));
    sock.send(reply, rinfo.port, rinfo.address);
  });
  await new Promise<void>((r) => sock.bind(0, '127.0.0.1', r));
  return { port: sock.address().port, requests, close: () => new Promise<void>((r) => sock.close(() => r())) };
}
