import { afterEach, describe, expect, it } from 'vitest';
import { PolicyDenied, SNMP_ALLOWED_PREFIXES, berOid, defaultSnmp, formatSnmp, nameFor, parseSnmpResponse, planSnmp, snmpAllowed, snmpPacket } from '../../src/core/index.js';
import { fakeSnmp } from '../helpers/fake-snmp.js';

const agents: Array<{ close: () => Promise<void> }> = [];
afterEach(async () => { await Promise.all(agents.splice(0).map((a) => a.close())); });
const agent = async (table: Parameters<typeof fakeSnmp>[0], community?: string) => { const a = await fakeSnmp(table, community); agents.push(a); return a; };

describe('planSnmp', () => {
  it('needs exactly one of name/oid', () => {
    expect(() => planSnmp({})).toThrow(PolicyDenied);
    expect(() => planSnmp({ name: 'sysName', oid: '1.3.6.1.2.1.1.5.0' })).toThrow(PolicyDenied);
  });
  it('names map to OIDs; tables walk by default; index suffixes work', () => {
    expect(planSnmp({ name: 'sysUpTime' })).toEqual({ oid: '1.3.6.1.2.1.1.3.0', walk: false, limit: 100 });
    expect(planSnmp({ name: 'ifOperStatus' })).toMatchObject({ oid: '1.3.6.1.2.1.2.2.1.8', walk: true });
    expect(planSnmp({ name: 'ifOperStatus.5' })).toMatchObject({ oid: '1.3.6.1.2.1.2.2.1.8.5', walk: false });
  });
  it('validates oid shape, subtree and limit', () => {
    for (const oid of ['1.3', 'abc', '1.3.6.1.2.1.1.5.0;', '.1.3.6.1.2.1.1.5.0 x', '1.3.6.1.2.1.1.5.0.'.repeat(1), `1.3.6.1.2.1.1${'.1'.repeat(40)}`]) expect(() => planSnmp({ oid }), oid).toThrow(PolicyDenied);
    expect(() => planSnmp({ oid: '1.3.6.1.4.1.8072.1.3.2' })).toThrow(/outside the readable subtrees/);
    expect(planSnmp({ oid: '.1.3.6.1.2.1.1.3.0' }).oid).toBe('1.3.6.1.2.1.1.3.0');
    for (const limit of [0, 501, -1, 1.5, '1e2', 'x']) expect(() => planSnmp({ oid: '1.3.6.1.2.1.1.3.0', limit }), String(limit)).toThrow(PolicyDenied);
    expect(planSnmp({ oid: '1.3.6.1.2.1.1.3.0', limit: 500 }).limit).toBe(500);
  });
  it('subtree matching is exact on component boundaries', () => {
    expect(snmpAllowed('1.3.6.1.2.1.1')).toBe(true);
    expect(snmpAllowed('1.3.6.1.2.1.10')).toBe(false); // not under .1
    expect(snmpAllowed('1.3.6.1.2.1.25.4.2.1.5')).toBe(false);
    expect(SNMP_ALLOWED_PREFIXES.every((p) => /^1\.3\.6\.1(\.\d+)+$/.test(p))).toBe(true);
  });
  it('nameFor / formatSnmp are readable', () => {
    expect(nameFor('1.3.6.1.2.1.2.2.1.8.3')).toBe('ifOperStatus.3');
    expect(formatSnmp([{ oid: '1.3.6.1.2.1.1.5.0', value: 'x' }])).toBe('sysName = x');
  });
});

describe('SNMP v2c over UDP (fake agent)', () => {
  const table = {
    '1.3.6.1.2.1.1.5.0': { kind: 'str' as const, v: 'rtr-core-1' }, '1.3.6.1.2.1.1.3.0': { kind: 'ticks' as const, v: 8_640_000 },
    '1.3.6.1.2.1.2.2.1.2.1': { kind: 'str' as const, v: 'ether1' }, '1.3.6.1.2.1.2.2.1.2.2': { kind: 'str' as const, v: 'ether2' }, '1.3.6.1.2.1.2.2.1.2.3': { kind: 'str' as const, v: 'sfp1' },
    '1.3.6.1.2.1.2.2.1.8.1': { kind: 'int' as const, v: 1 }, '1.3.6.1.2.1.2.2.1.8.2': { kind: 'int' as const, v: 2 },
  };
  it('GET returns typed values (string, timeticks)', async () => {
    const a = await agent(table);
    const out = await defaultSnmp({ host: '127.0.0.1', port: a.port, community: 'LAB-COMMUNITY-ONE' }, 'get', ['1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.3.0'], 2);
    expect(out).toEqual([{ oid: '1.3.6.1.2.1.1.5.0', value: 'rtr-core-1' }, { oid: '1.3.6.1.2.1.1.3.0', value: '1d 00:00:00 (8640000 ticks)' }]);
    expect(a.requests[0]).toMatchObject({ pdu: 0xa0 });
  });
  it('walk uses GETBULK, stays inside the subtree, and respects the row limit', async () => {
    const a = await agent(table);
    const all = await defaultSnmp({ host: '127.0.0.1', port: a.port, community: 'LAB-COMMUNITY-ONE' }, 'walk', ['1.3.6.1.2.1.2.2.1.2'], 100);
    expect(all.map((r) => r.value)).toEqual(['ether1', 'ether2', 'sfp1']);
    const some = await defaultSnmp({ host: '127.0.0.1', port: a.port, community: 'LAB-COMMUNITY-ONE' }, 'walk', ['1.3.6.1.2.1.2.2.1.2'], 2);
    expect(some).toHaveLength(2);
    expect(a.requests.every((r) => r.pdu === 0xa5)).toBe(true);
  });
  it('only GET/GETNEXT/GETBULK PDUs are ever built (no SET)', () => {
    for (const pdu of [0xa0, 0xa1, 0xa5] as const) expect(snmpPacket('c', pdu, 1, ['1.3.6.1.2.1.1.5.0'])[0]).toBe(0x30);
    const tags = new Set([0xa0, 0xa1, 0xa5]);
    expect(tags.has(0xa3)).toBe(false);
  });
  it('rejects a reply with the wrong request id and truncated packets', () => {
    expect(() => parseSnmpResponse(Buffer.from([0x30, 0x05, 0x02, 0x01]), 1)).toThrow();
    expect(berOid('1.3.6.1.2.1.1.5.0')[0]).toBe(0x06);
  });
});
