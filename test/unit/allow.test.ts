import { describe, expect, it } from 'vitest';
import { PolicyDenied, auditCommand, checkProbeTarget, planRosCommand, tokenize } from '../../src/core/index.js';

const ROS_DENIED = [
  '/ip address add address=192.0.2.1/32 interface=ether1', '/system reboot', '/system shutdown', '/system reset-configuration', '/interface set ether1 disabled=yes',
  '/interface enable ether1', '/interface disable ether1', '/ip firewall filter remove 0', '/ip address print; /system reboot', '/ip address print | :put', ':put "x"', ':execute {/system reboot}',
  '/system script run x', '/system script print', '/import file-name=x.rsc', '/tool fetch url=http://x/y', '/ip address print file=out', '/tool sniffer start', '/tool torch ether1',
  '/log print follow', '/log print follow-only', '/interface monitor-traffic ether1', '/interface ethernet monitor ether1', '/user add name=x password=y', '/export file=a',
  '/export', '/ip address export', '/ip address print where name~"x"', '/ip address print where a=1 or b=2', '/ip address print $x', '/ip address print [find]', '/ip address print\n/system reboot',
  'ping 192.0.2.8 count=500', 'ping 192.0.2.8 interval=0', 'ping 192.0.2.8; set', '/tool traceroute 192.0.2.8 count=99', '/tool bandwidth-test 192.0.2.1', '/system backup save name=x', '/file print file=x',
  '/ip address print count-only; set', '', '   ', 'print', '/interface wireless scan wlan1', '/system ssh 192.0.2.3', '/tool mac-telnet aa:bb', '/ip address print `x`', '/ip address print `reboot`',
  '/system/reboot', '/ip/address/add', '/ip address print proplist=a;b', '/ping 192.0.2.8 count=3 address=192.0.2.9', '/ip service print && /system reboot', '/system resource print > x',
  ['verb hidden by ;', '/ip address print; /system reboot'],
];
const REJECT: Array<[string, string]> = [
  ['pipe', '/ip address print | /system reboot'], ['CR', '/ip address print\r/system reboot'], ['NUL', '/ip address print\0 x'], ['tab', '/ip address print\twhere x=y'], ['homoglyph', '/ip addrеss print'],
  ['fullwidth slash', '／ip address print'], ['upper SET', '/ip address SET numbers=0'], ['set', '/ip address set 0 address=192.0.2.1/24'],
  ['print file= quoted', '/ip address print "file=x"'], ['where file', '/ip address print where file=x'], ['as-value :', '/ip address print as-value :put'],
  ['script via slash', '/system/script/print'], ['tool/fetch print', '/tool/fetch/print'], ['export show-sensitive', '/export show-sensitive'], ['export hide + file', '/export hide-sensitive file=a'],
  ['cert export-cert', '/certificate export-certificate 0 export-passphrase=abc'], ['quote unbalanced', '/ip address print "'], ['dollar', '/ip address print where comment=$x'],
  ['bracket', '/ip address print where comment=[/system reboot]'], ['colon scripting', ':put hi'], ['flood-ping', '/tool flood-ping 192.0.2.1'], ['ping count 1e6', '/ping 192.0.2.1 count=1000000'],
  ['ping size huge', '/ping 192.0.2.1 size=65535'], ['ping interval', '/ping 192.0.2.1 interval=0.001'], ['ping host inj', '/ping 192.0.2.1;reboot'], ['trace 2 addrs', '/tool traceroute 192.0.2.1 198.51.100.2'],
  ['print two verbs', '/ip address export print'], ['upgrade', '/system routerboard upgrade'], ['log follow', '/log print follow'],
  ['export root hide', '/export hide-sensitive'], ['export abbrev scr', '/system scr export hide-sensitive'], ['export reset-configuration', '/system reset-configuration export hide-sensitive'],
  ['export package uninstall', '/system package uninstall export hide-sensitive'], ['export dns flush', '/ip dns cache flush export hide-sensitive'], ['export e-mail send', '/tool e-mail send export hide-sensitive'],
  ['export certificate', '/certificate export hide-sensitive'], ['export scheduler', '/system scheduler export hide-sensitive'], ['export netwatch', '/tool netwatch export hide-sensitive'],
  ['export system script', '/system script export hide-sensitive'], ['export dhcp lease', '/ip dhcp-server lease export hide-sensitive'], ['export dhcp-server', '/ip dhcp-server export hide-sensitive'],
  ['export abbrev ip addr', '/ip addr export hide-sensitive'], ['export abbrev fire', '/ip firewall fil export hide-sensitive'], ['export user', '/user export hide-sensitive'],
  ['export ppp secret', '/ppp secret export hide-sensitive'], ['export system', '/system export hide-sensitive'], ['export slash abbrev', '/ip/firewall/fil/export hide-sensitive'], ['export upper', '/IP address export hide-sensitive'],
  ['export w/ file=', '/ip address export hide-sensitive file=a'], ['export hide + compact + file', '/ip address export hide-sensitive compact file=a'], ['export + show-sensitive', '/ip address export hide-sensitive show-sensitive'],
  ['export wireguard', '/interface wireguard export hide-sensitive'], ['export ovpn-client', '/interface ovpn-client export hide-sensitive'], ['export ipsec identity', '/ip ipsec identity export hide-sensitive'],
  ['export hotspot user', '/ip hotspot user export hide-sensitive'], ['export snmp', '/snmp export hide-sensitive'], ['export radius', '/radius export hide-sensitive'], ['export file menu', '/file export hide-sensitive'],
  ['export without hide', '/ip firewall filter export terse'], ['export no hide', '/ip firewall filter export'], ['export where', '/ip firewall filter export hide-sensitive where x=y'], ['export =file=', '/ip firewall filter export hide-sensitive =file=x'],
  ['export slash all', '/ip/firewall/filter/export/hide-sensitive'], ['export as-value', '/ip firewall filter export hide-sensitive as-value'],
];
const ACCEPT: Array<[string, string]> = [
  ['print', '/ip address print'], ['resource', '/system resource print'], ['ping', '/ping 192.0.2.1 count=3'],
  ['export interface', '/interface export hide-sensitive'], ['export ip address', '/ip address export hide-sensitive'], ['export route', '/ip route export hide-sensitive terse'],
  ['export fw filter', '/ip firewall filter export hide-sensitive'], ['export fw nat', '/ip firewall nat export hide-sensitive'], ['export fw mangle', '/ip firewall mangle export hide-sensitive'],
  ['export fw raw', '/ip firewall raw export hide-sensitive'], ['export bridge', '/interface bridge export hide-sensitive'], ['export vlan', '/interface vlan export hide-sensitive'],
  ['export bgp', '/routing bgp export hide-sensitive'], ['export ppp profile', '/ppp profile export hide-sensitive'], ['export slash form', '/ip/firewall/filter/export hide-sensitive'],
  ['where with set-like value', '/ppp active print where name=set1'], ['log tail', '/log print tail=20'],
];

describe('RouterOS allowlist: deny by default', () => {
  for (const c of ROS_DENIED.filter((x): x is string => typeof x === 'string')) it(`refuses ${JSON.stringify(c)}`, () => { expect(() => planRosCommand(c)).toThrow(PolicyDenied); });
  for (const [name, cmd] of REJECT) it(`refuses: ${name}`, () => { expect(() => planRosCommand(cmd)).toThrow(PolicyDenied); });
  for (const [name, cmd] of ACCEPT) it(`accepts: ${name}`, () => { expect(() => planRosCommand(cmd)).not.toThrow(); });

  it('maps valid commands to API sentences', () => {
    expect(planRosCommand('/system resource print')).toMatchObject({ kind: 'api', apiPath: '/system/resource/print', words: [] });
    expect(planRosCommand('/ip/address/print')).toMatchObject({ apiPath: '/ip/address/print' });
    expect(planRosCommand('/ip address print where interface=ether1 and !disabled')).toMatchObject({ apiPath: '/ip/address/print', words: ['?interface=ether1', '?-disabled'] });
    expect(planRosCommand('/interface print terse without-paging proplist=name,running')).toMatchObject({ words: ['=.proplist=name,running'] });
    expect(planRosCommand('/interface ethernet monitor sfp-sfpplus1 once')).toMatchObject({ verb: 'monitor', apiPath: '/interface/ethernet/monitor', words: ['=numbers=sfp-sfpplus1', '=once='] });
    expect(planRosCommand('/ip firewall address-list print where comment="a b"')).toMatchObject({ words: ['?comment=a b'] });
    expect(planRosCommand('ping 192.0.2.8 count=3')).toMatchObject({ apiPath: '/ping', words: ['=address=192.0.2.8', '=count=3'] });
    expect(planRosCommand('/tool traceroute 192.0.2.8')).toMatchObject({ apiPath: '/tool/traceroute', words: ['=address=192.0.2.8', '=count=1', '=max-hops=15'] });
    expect(planRosCommand('/interface export hide-sensitive')).toMatchObject({ kind: 'export', sshCommand: '/interface export hide-sensitive' });
    expect(planRosCommand('/ip firewall filter export hide-sensitive terse')).toMatchObject({ kind: 'export', sshCommand: '/ip firewall filter export hide-sensitive terse' });
  });

  it('every API word of a plan starts with a known prefix', () => {
    for (const cmd of ['/ip address print where interface=ether1', '/ppp active print count-only', '/interface ethernet monitor ether1 once', 'ping 192.0.2.8 size=100', '/log print tail=5']) {
      const p = planRosCommand(cmd);
      if (p.kind === 'api') for (const w of p.words) expect(w).toMatch(/^[?=]/);
    }
  });

  it('where on secret columns is refused for every form, including pin/pwd/auth', () => {
    for (const c of ['/ppp secret print where password=guess', '/radius print where secret=guess', '/snmp community print where name=public', '/interface l2tp-server server print where ipsec-secret=guess',
      '/ppp secret print count-only where password=guess', '/ppp secret print where !password', '/ppp secret print where pwd=x', '/ppp active print where auth=x', '/ppp secret print where sim-pin=1']) expect(() => planRosCommand(c), c).toThrow(PolicyDenied);
    expect(() => planRosCommand('/interface bridge host print where on-interface=ether1')).not.toThrow();
    expect(() => planRosCommand('/ppp active print where name=abc')).not.toThrow();
  });

  it('proplist cannot ask for secret columns; secret menus get forced safe columns', () => {
    expect(() => planRosCommand('/ppp secret print proplist=name,password')).toThrow(PolicyDenied);
    const p = planRosCommand('/ppp secret print');
    expect(p.kind === 'api' && p.words.some((w) => w.startsWith('=.proplist=') && !/password/.test(w))).toBe(true);
    for (const c of ['/ppp secret print detail', '/user print detail']) { const d = planRosCommand(c); expect(d.kind === 'api' && d.words.some((w) => w.startsWith('=.proplist='))).toBe(true); } // detail stays harmless: the safe columns are still forced
  });

  it('abbreviated menus are refused (only whole words on the positive list)', () => {
    for (const c of ['/ppp sec print', '/system sch print', '/fil print', '/cert print', '/ip ipsec ident print', '/ip hot user print', '/system scr print', '/tool e-m print', '/tool fet print']) expect(() => planRosCommand(c), c).toThrow(PolicyDenied);
  });

  it('menus outside the positive list are refused', () => {
    for (const c of ['/tool netwatch print', '/system scheduler print', '/ip dns cache print', '/interface wireguard print', '/certificate print', '/file print', '/tool e-mail print', '/ppp print', '/ip ipsec identity print', '/interface lte print', '/system package print', '/log print tail=0', '/log print tail=201', '/ip address print tail=5']) expect(() => planRosCommand(c), c).toThrow(PolicyDenied);
  });

  it('heavy menus need count-only or where', () => {
    for (const c of ['/ip firewall connection print', '/routing route print', '/ip route print', '/ip dns cache print']) expect(() => planRosCommand(c), c).toThrow(PolicyDenied);
    for (const c of ['/ip firewall connection print count-only', '/ip route print count-only', '/ip route print where dst-address=0.0.0.0/0', '/routing route print where bgp']) expect(() => planRosCommand(c), c).not.toThrow();
  });

  it('monitor needs `once` and a listed menu; log defaults to the 60 newest', () => {
    expect(() => planRosCommand('/system resource monitor once')).toThrow(PolicyDenied);
    expect(() => planRosCommand('/interface ethernet monitor ether1')).toThrow(PolicyDenied);
    expect(() => planRosCommand('/interface ethernet monitor ether1 once')).not.toThrow();
    const p = planRosCommand('/log print'); expect(p.kind === 'api' && p.tail).toBe(60);
    const q = planRosCommand('/log print tail=5'); expect(q.kind === 'api' && q.tail).toBe(5);
  });

  it('non-string / empty / oversize input is refused', () => {
    for (const v of [undefined, null, 5, {}, [], '', '  ', 'x'.repeat(301)]) expect(() => planRosCommand(v)).toThrow(PolicyDenied);
  });
});

describe('probe targets: canonical literal IPs only', () => {
  for (const ok of ['192.0.2.8', '203.0.113.5', '2001:db8::1', '2001:db8:1:2::8']) it(`accepts ${ok}`, () => expect(checkProbeTarget(ok)).toBe(ok));
  for (const bad of ['127.0.0.1', '127.1', '127.0.1', '2130706433', '0x7f000001', '0177.0.0.1', '010.0.0.1', '203.0.113.01', '0.0.0.0', '224.0.0.1', '239.1', '255.255.255.255', '192.0.2.255', '169.254.169.254', '::', '::1', '0:0:0:0:0:0:0:1', '0::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::127.0.0.1', 'ff02::1', 'fe80::1', 'localhost', 'LOCALHOST', 'example.com', 'a.b', '-f', '203.0.113.1 -f', '203.0.113.1;id', '$(id)', '', '4294967295', '0'])
    it(`refuses ${JSON.stringify(bad)}`, () => expect(() => checkProbeTarget(bad), bad).toThrow(PolicyDenied));
});

describe('helpers', () => {
  it('tokenize keeps quoted values together and rejects unbalanced quotes', () => {
    expect(tokenize('a "b c" d')).toEqual(['a', 'b c', 'd']);
    expect(() => tokenize('a "b')).toThrow(PolicyDenied);
  });
  it('auditCommand never contains values', () => {
    const p = planRosCommand('/ppp active print where name=customer-secret-name and service=pppoe');
    const a = auditCommand(p);
    expect(a).toBe('/ppp active print where name,service');
    expect(a).not.toContain('customer');
  });
});
