import { describe, expect, it } from 'vitest';
import { type RosRow, MASK, clip, formatRosRows, formatTraceroute, maskMac, maskRows, redactText, scrubExact, scrubMessage } from '../../src/core/index.js';

const SECRET = 'SECRET123';
const LEAK_CASES: Array<[string, string]> = [
  ['kv password', 'name=a password=SECRET123'], ['quoted password', 'name=a password="SECRET123 x"'], ['wpa psk', 'wpa2-pre-shared-key=SECRET123'],
  ['export script source', 'add name=s source=":local pw \\"SECRET123\\"; /tool fetch url=http://x password=hunter2"'],
  ['source escaped', 'add name=s source="/tool fetch password=\\"SECRET123\\" user=x"'], ['pass: form', 'comment="wifi pass: SECRET123"'],
  ['multi-line quoted', 'add name=s source="\\\n    :local x \\"y\\"\\r\\\n    password=SECRET123"'],
  ['export ppp secret', '/ppp secret\nadd name=u password=SECRET123 service=pppoe'], ['ipsec', 'add secret=SECRET123 peer=x'], ['ovpn cert pass', 'certificate-passphrase=SECRET123'],
  ['config password', "password 'SECRET123'"], ['plaintext-password', 'plaintext-password "SECRET123"'], ['set private-key', "set interfaces wireguard wg0 private-key 'SECRET123'"],
  ['md5-key', 'md5-key SECRET123'], ['authentication-key', 'authentication-key SECRET123'], ['community', 'community SECRET123 {'], ['psk tab', "ipsec secret: PSK\t'SECRET123'"],
  ['ipsec.secrets', ': PSK "SECRET123"'], ['shared-secret-key', 'shared-secret-key SECRET123'], ['key', 'key SECRET123'], ['inline braces', 'authentication { password SECRET123 }'],
  ['pppoe', 'username bob password SECRET123'], ['passphrase', 'passphrase SECRET123'], ['CRLF', "password 'SECRET123'\r"], ['password colon', 'password: SECRET123'],
  ['json', '"password": "SECRET123"'], ['json compact', '{"user":"a","password":"SECRET123"}'], ['json key', '{"api-key": "SECRET123"}'], ['token', 'token SECRET123'], ['psk', 'psk SECRET123'],
  ['pwd=', 'pwd=SECRET123'], ['pin=', 'pin=SECRET123'], ['wifi-pw:', 'wifi-pw: SECRET123'], ['upper', 'PASSWORD=SECRET123'], ['spaced', 'Password : SECRET123'],
  ['encrypted', 'encrypted-password $6$salt$SECRET123'], ['nested json', '{"a":{"password":"SECRET123"}}'], ['api token', 'x-api-token=SECRET123'], ['tcp-md5-key', 'tcp-md5-key=SECRET123'],
  ['pre-shared-key', 'pre-shared-key=SECRET123'], ['ipsec-secret', 'ipsec-secret="SECRET123"'], ['description', 'description=wifi password is SECRET123'],
];

describe('redactText', () => {
  for (const [name, text] of LEAK_CASES) it(`masks: ${name}`, () => { expect(redactText(text)).not.toMatch(/SECRET123|hunter2/); });
  it('masks WireGuard-style private keys (base64, 44 chars)', () => {
    expect(redactText('AbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf12=')).not.toContain('AbCdEfAbCdEf');
    expect(redactText('wg0 key: AbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf12=')).not.toContain('AbCdEfAbCdEf');
    expect(redactText("private-key 'AbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf12='")).not.toContain('AbCdEfAbCdEf');
  });
  it('masks RouterOS exports and keeps harmless context', () => {
    const out = redactText(['/ppp secret', 'add name=u1 password=hunter2 service=pppoe', 'add name=u2 password="a b c" profile=x', '/snmp community', 'add addresses=0.0.0.0/0 name=community-name-x',
      '/interface wireguard', 'set wg1 private-key="AAAA" public-key=PUB', '    key-id 5'].join('\n'));
    expect(out).not.toMatch(/hunter2|a b c|community-name-x|AAAA/);
    expect(out).toContain('public-key=PUB'); expect(out).toContain('service=pppoe'); expect(out).toContain('key-id 5');
  });
  it('does not over-mask ordinary values', () => {
    expect(redactText('Version: RouterOS 7.15\nUptime: 3d')).toContain('RouterOS 7.15');
    expect(formatRosRows([{ name: 'ether1', 'keepalive-timeout': '10s', address: '10.0.0.1/24' }], '/ip/address/print', false)).toContain('10.0.0.1/24');
    expect(formatRosRows([{ 'on-interface': 'ether1', ping: 'yes', mapping: 'x' }], '/x/print', false)).toBe('0 on-interface=ether1 ping=yes mapping=x');
  });
});

describe('formatRosRows / maskRows', () => {
  it('masks secret columns and SNMP community names', () => {
    expect(formatRosRows([{ name: 'u', password: 'p4ss' }], '/ppp/secret/print', false)).not.toContain('p4ss');
    expect(formatRosRows([{ name: 'community-name-x', addresses: '0.0.0.0/0' }], '/snmp/community/print', false)).not.toContain('community-name-x');
  });
  it('masks script bodies and secret pairs inside free text, for every script-like key', () => {
    for (const k of ['on-up', 'on-down', 'on-login', 'on-logout', 'lease-script', 'script', 'test-script', 'run-after', 'up-script', 'on-event', 'source']) {
      expect(formatRosRows([{ name: 'p', [k]: `:local pw "S3CRETX"` }], '/ppp/profile/print', false)).not.toContain('S3CRETX');
      expect(redactText(`add name=p ${k}=":local pw \\"S3CRETX\\""`)).not.toContain('S3CRETX');
    }
    for (const v of ['/tool fetch url=http://x user=a password=SECRET123', '/tool fetch password="SECRET123"', ':local pw "x"; /x pass=SECRET123', '/x secret=\\"SECRET123\\"', 'token: SECRET123', 'key=SECRET123;']) // gitleaks:allow (synthetic)
      for (const [k, path] of [['on-event', '/system/scheduler/print'], ['source', '/system/script/print'], ['comment', '/ip/address/print']] as const) expect(formatRosRows([{ name: 'j', [k]: v }], path, false)).not.toContain(SECRET);
  });
  it('masks pin/pwd/auth-like columns but not ping/mapping/on-interface', () => {
    for (const k of ['pin', 'pwd', 'auth', 'sim-pin', 'user-pwd', 'wifi-pw']) expect(formatRosRows([{ [k]: 'S3CRETX' }], '/x/print', false), k).not.toContain('S3CRETX');
  });
  it('drops SFP EEPROM dumps and truncates very long values', () => {
    const out = formatRosRows([{ name: 'sfp1', eeprom: 'ab'.repeat(256), 'sfp-rx-power': '-3.2dBm', note: 'y'.repeat(900) }], '/interface/ethernet/monitor', false);
    expect(out).not.toContain('abab'); expect(out).toContain('eeprom="(256 bytes dropped)"'); expect(out).toContain('sfp-rx-power=-3.2dBm'); expect(out).toMatch(/600 characters truncated/);
  });
  it('tail note and truncation note', () => {
    expect(formatRosRows([{ a: '1' }], '/log/print', true, 1000, 1)).toMatch(/showing the 1 NEWEST of 1000/);
    expect(formatRosRows([{ a: '1' }], '/ip/arp/print', true)).toMatch(/limited to 300 rows/);
    expect(formatRosRows([], '/ip/arp/print', false)).toBe('(no rows)');
  });
  it('redactPii masks MAC tails everywhere and free text only on customer menus', () => {
    const rows = [{ name: 'cust-a', 'caller-id': 'AA:BB:CC:11:22:33', comment: 'Alice Example', address: '10.0.0.5' }];
    const out = maskRows(rows, '/ppp/active/print', { redactPii: true })[0]!;
    expect(out['caller-id']).toBe('AA:BB:CC:xx:xx:xx'); expect(out.comment).toBe(MASK); expect(out.name).toBe('cust-a'); expect(out.address).toBe('10.0.0.5');
    const infra = maskRows([{ name: 'ether1', comment: 'uplink to ix', 'mac-address': 'AA:BB:CC:11:22:33' }], '/interface/print', { redactPii: true })[0]!;
    expect(infra.comment).toBe('uplink to ix'); expect(infra['mac-address']).toBe('AA:BB:CC:xx:xx:xx');
    expect(maskRows(rows, '/ppp/active/print')[0]!['caller-id']).toBe('AA:BB:CC:11:22:33');
    expect(maskMac('x aa-bb-cc-dd-ee-ff y')).toBe('x aa-bb-cc-xx-xx-xx y');
  });
});

describe('formatTraceroute', () => {
  it('uses the hops of the LAST broadcast, in order', () => {
    const rows: RosRow[] = [
      { '.section': '0', address: '10.0.0.1', loss: '0', sent: '1', last: '1ms', avg: '1ms' },
      { '.section': '1', address: '10.0.0.1', loss: '0', sent: '1', last: '1ms', avg: '1ms' }, { '.section': '1', address: '', loss: '100', sent: '1' },
      { '.section': '2', address: '10.0.0.1', loss: '0', sent: '1' }, { '.section': '2', address: '192.0.2.1', loss: '0', sent: '1' }, { '.section': '2', address: '198.51.100.8', loss: '0', sent: '1' },
    ];
    const out = formatTraceroute(rows).split('\n');
    expect(out).toHaveLength(3);
    expect(out[0]).toMatch(/^1 10\.0\.0\.1 /); expect(out[1]).toMatch(/^2 192\.0\.2\.1 /); expect(out[2]).toMatch(/^3 198\.51\.100\.8 /);
  });
  it('sections ≥ 10 sort numerically; no sections = one broadcast', () => {
    expect(formatTraceroute([{ '.section': '9', address: 'A' }, { '.section': '10', address: 'B' }, { '.section': '10', address: 'C' }])).toMatch(/^1 B .*\n2 C /);
    expect(formatTraceroute([{ address: '192.0.2.1' }, { address: '192.0.2.2' }]).split('\n')).toHaveLength(2);
  });
});

describe('scrub helpers', () => {
  it('scrubExact removes exact credential values (and ignores very short ones)', () => {
    expect(scrubExact('login as admin with PW-1234 ok', ['PW-1234', 'ab', undefined])).toBe(`login as admin with ${MASK} ok`);
  });
  it('scrubMessage masks secret-looking words and caps the length', () => {
    expect(scrubMessage('failed password=abc and token=xyz')).not.toMatch(/abc|xyz/);
    expect(scrubMessage('x'.repeat(1000)).length).toBe(300);
  });
  it('clip cuts on a line boundary and reports the line counts', () => {
    const text = Array.from({ length: 100 }, (_v, i) => `line-${i}-${'x'.repeat(30)}`).join('\n');
    const out = clip(text, 500);
    expect(out.split('\n… (')[0]!.split('\n').every((l) => /^line-\d+-x{30}$/.test(l))).toBe(true);
    expect(out).toMatch(/truncated: \d+ of 100 lines/);
    expect(clip('short', 500)).toBe('short');
  });
});
