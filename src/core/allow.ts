import net from 'node:net';
import { PolicyDenied } from './errors.js';
import type { RosPlan } from './types.js';

/** Allowlist engine for the read-only tools. DENY BY DEFAULT: a command passes only if every token matches the narrow
 * grammar below. There is no "blacklist then allow the rest" path; the forbidden-word list is only a second belt.
 *
 * This is a tool-side guard, not a sandbox. The real defence is a RouterOS user whose group has no write/policy/sensitive
 * rights (see docs/ROUTEROS-READONLY-USER.md). */

const deny = (why: string): never => { throw new PolicyDenied(why); };

/** Words that may never appear as a menu segment or flag in any command (second belt). */
export const FORBIDDEN_WORDS = new Set([
  'set', 'add', 'remove', 'enable', 'disable', 'reset', 'reboot', 'shutdown', 'poweroff', 'script', 'import', 'fetch', 'file', 'sniffer', 'torch', 'follow', 'follow-only',
  'edit', 'move', 'unset', 'export-file', 'upgrade', 'install', 'configure', 'commit', 'save', 'delete', 'clear', 'restart', 'rollback', 'load', 'merge', 'copy', 'rename',
  'comment', 'run', 'execute', 'eval', 'do', 'foreach', 'while', 'if', 'generate', 'format', 'erase', 'flash', 'tech-support', 'bandwidth-test', 'traffic-generator',
  'reset-counters', 'reset-counters-all', 'listen', 'refresh', 'release', 'renew', 'flush', 'sync', 'download', 'kill', 'check-installation', 'ssh', 'telnet', 'scan', 'sms', 'email', 'wake-on-lan', 'mac-telnet', 'mac-server', 'user-manager', 'certificate-import', 'backup', 'restore', 'cancel', 'quit', 'exit',
]);

const SAFE_VALUE = /^[A-Za-z0-9_.:/,@+*#% -]*$/;
const WORD = /^[a-z][a-z0-9-]*$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/;

/** Split a command into tokens; double quotes only wrap a value (no nesting, no escapes). */
export function tokenize(text: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quoted = false;
  let started = false;
  for (const ch of text) {
    if (ch === '"') { quoted = !quoted; started = true; continue; }
    if (ch === ' ' && !quoted) { if (started) tokens.push(current); current = ''; started = false; continue; }
    current += ch; started = true;
  }
  if (quoted) deny('unbalanced double quote.');
  if (started) tokens.push(current);
  return tokens;
}

function precheck(text: unknown, charset: RegExp): string {
  if (typeof text !== 'string' || !text.trim()) return deny('command must be a non-empty string.');
  const t = text.trim();
  if (t.length > 300) deny('command too long (max 300 characters).');
  if (!charset.test(t)) deny('command contains characters that are not allowed (e.g. ; | & $ [ ] { } ( ) \\ < > ~ \' ` or a newline).');
  if (t.includes('..')) deny('".." is not allowed.');
  return t;
}

function intIn(v: string, lo: number, hi: number, name: string): number {
  if (!/^\d{1,5}$/.test(v)) return deny(`${name} must be an integer.`);
  const n = Number(v);
  if (n < lo || n > hi) deny(`${name} must be between ${lo} and ${hi}.`);
  return n;
}

// ───────────────────────────── probe targets ─────────────────────────────

/** Ping/traceroute: literal IPs only (a host name is a DNS side channel), never broadcast/multicast/loopback/link-local/unspecified,
 * judged on the canonical form (127.1, 2130706433, 0x7f000001, ::ffff:127.0.0.1, 0:0:0:0:0:0:0:1 never pass as literals or are unwrapped to v4). */
function badV4(o: number[]): boolean {
  const [a, b, , d] = o as [number, number, number, number];
  return a === 0 || a === 127 || a >= 224 || d === 255 || (a === 169 && b === 254);
}
function expandV6(address: string): number[] | null {
  let text = address.toLowerCase();
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return null;
    text = `${text.slice(0, v4.index)}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string) => (part ? part.split(':') : []);
  const head = parse(halves[0]!); const tail = halves.length === 2 ? parse(halves[1]!) : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}
export function checkProbeTarget(address: string): string {
  if (!HOST.test(address)) deny('invalid target address.');
  const kind = net.isIP(address);
  if (!kind) deny('target must be a literal IP address (dotted IPv4 or IPv6); host names are refused.');
  if (kind === 4) {
    const o = address.split('.').map(Number);
    if (o.some((n, i) => n > 255 || String(n) !== address.split('.')[i])) deny('IPv4 target must be canonical a.b.c.d without leading zeros.');
    if (badV4(o)) deny('broadcast/multicast/loopback/link-local targets are refused.');
    return address;
  }
  const g = expandV6(address);
  if (!g) deny('invalid IPv6 target.');
  const six = g!;
  if (six.every((x) => x === 0) || (six.slice(0, 7).every((x) => x === 0) && six[7] === 1)) deny('unspecified/loopback targets are refused.');
  if ((six[0]! & 0xff00) === 0xff00) deny('multicast targets are refused.');
  if ((six[0]! & 0xffc0) === 0xfe80) deny('link-local targets are refused.');
  const mapped = six.slice(0, 5).every((x) => x === 0) && six[5] === 0xffff;
  const compat = six.slice(0, 6).every((x) => x === 0);
  if (mapped || compat) { if (badV4([six[6]! >> 8, six[6]! & 255, six[7]! >> 8, six[7]! & 255])) deny('IPv4-in-IPv6 targets to loopback/multicast are refused.'); }
  return address;
}

// ───────────────────────────── RouterOS ─────────────────────────────

/** Menus that may never be touched (secrets, endless streams, load, file writes). A belt on top of the positive lists. */
const DENY_PATH_PREFIXES: string[][] = [
  ['system', 'scheduler'], ['system', 'backup'], ['system', 'package'], ['system', 'upgrade'], ['system', 'routerboard', 'upgrade'], ['system', 'license'], ['system', 'logging'],
  ['system', 'special-login'], ['system', 'console'], ['system', 'telnet'], ['system', 'ntp', 'client', 'set'], ['user', 'group'], ['certificate'], ['file'],
  ['tool', 'fetch'], ['tool', 'bandwidth-test'], ['tool', 'speed-test'], ['tool', 'flood-ping'], ['tool', 'sniffer'], ['tool', 'torch'], ['tool', 'e-mail'], ['tool', 'sms'],
  ['tool', 'wol'], ['tool', 'ip-scan'], ['tool', 'mac-server'], ['tool', 'romon'], ['tool', 'mac-ping'],
  ['interface', 'wireguard'], ['interface', 'ovpn-client'], ['interface', 'l2tp-client'], ['interface', 'pptp-client'], ['interface', 'sstp-client'],
  ['interface', 'wireless', 'security-profiles'], ['interface', 'wifi', 'security'], ['interface', 'wifi', 'configuration'], ['interface', 'wifi', 'provisioning'],
  ['ip', 'ipsec', 'identity'], ['ip', 'ipsec', 'policy'], ['ip', 'ipsec', 'peer'], ['ip', 'hotspot', 'user'], ['ip', 'smb', 'users'], ['ip', 'cloud'],
  ['lcd'], ['console'], ['caps-man'], ['partitions'], ['disk'], ['container'], ['app'],
];
/** Menus that may only be read through safe columns (forced when the caller gives none). */
const SAFE_PROPLIST: Array<{ path: string[]; columns: string; forced: boolean }> = [
  { path: ['ppp', 'secret'], columns: 'name,service,profile,remote-address,disabled,comment,last-logged-out', forced: true },
  { path: ['user'], columns: 'name,group,last-logged-in,disabled', forced: true },
  { path: ['radius'], columns: 'address,service,disabled,comment', forced: true },
  { path: ['snmp'], columns: 'enabled,contact,location,trap-version', forced: true },
];
export const SECRET_COLUMN = /password|passwd|secret|psk|private|community|key|token|passphrase|credential|(^|[-_.])(pin|pwd|pw|pass|auth)($|[-_.])/i;

/** POSITIVE list of `print` menus (full paths, no abbreviations: the API accepts unique prefixes, so only whole words pass).
 * A menu outside the list is refused, so new menus/versions never open silently. Secrets are still masked per column (second layer). */
export const ROS_PRINT_PATHS = new Set([
  'system resource', 'system resource cpu', 'system health', 'system identity', 'system clock', 'system routerboard', 'system ntp client',
  'interface', 'interface ethernet', 'interface ethernet poe', 'interface ethernet switch', 'interface ethernet switch port', 'interface bridge', 'interface bridge port', 'interface bridge vlan', 'interface bridge host', 'interface bridge settings',
  'interface vlan', 'interface bonding', 'interface vrrp', 'interface list', 'interface list member', 'interface eoip', 'interface gre', 'interface vxlan', 'interface wireless registration-table', 'interface wifi registration-table',
  'interface pppoe-server', 'interface l2tp-server', 'interface l2tp-server server', 'interface ovpn-server', 'interface sstp-server', 'interface pptp-server',
  'ip address', 'ip route', 'ip route rule', 'ip pool', 'ip pool used', 'ip dns', 'ip dns static', 'ip service', 'ip arp', 'ip neighbor', 'ip vrf', 'ip settings', 'ip neighbor discovery-settings',
  'ip dhcp-server', 'ip dhcp-server lease', 'ip dhcp-server network', 'ip dhcp-client', 'ip dhcp-relay', 'ip hotspot', 'ip hotspot active', 'ip ipsec active-peers',
  'ip firewall filter', 'ip firewall nat', 'ip firewall mangle', 'ip firewall raw', 'ip firewall address-list', 'ip firewall connection',
  'ipv6 address', 'ipv6 neighbor', 'ipv6 route', 'ipv6 firewall filter', 'ipv6 firewall address-list',
  'routing bgp session', 'routing bgp connection', 'routing bgp template', 'routing bgp peer', 'routing bgp instance', 'routing bgp advertisements', 'routing ospf instance', 'routing ospf area', 'routing ospf interface-template', 'routing ospf neighbor', 'routing ospf lsa',
  'routing filter', 'routing filter rule', 'routing table', 'routing rule', 'routing route', 'routing stats',
  'ppp active', 'ppp profile', 'ppp secret', 'ppp aaa', 'queue simple', 'queue tree', 'queue type', 'queue interface',
  'user', 'user active', 'radius', 'snmp', 'snmp community', 'log',
]);
/** Menus that may be `monitor ... once`. */
export const ROS_MONITOR_PATHS = new Set(['interface ethernet', 'interface bonding', 'interface vrrp', 'interface wireless', 'interface wifi', 'system resource cpu', 'system health']);
/** Large tables (full BGP table, conntrack, DNS cache): a bare `print` is refused, `count-only` or `where` is required. */
export const ROS_HEAVY_PATHS = new Set(['ip route', 'ipv6 route', 'routing route', 'ip firewall connection', 'ip dns cache', 'ip firewall address-list']);
const startsWith = (path: string[], prefix: string[]) => prefix.every((w, i) => path[i] === w);

/** Full menu paths that may be `export`ed over SSH (deny-by-default; root, scheduler/script/netwatch/lease/user/secret are absent). */
export const ROS_EXPORT_PATHS = new Set([
  'interface', 'interface bridge', 'interface bridge port', 'interface bridge vlan', 'interface vlan', 'interface ethernet', 'interface bonding', 'interface vrrp', 'interface list', 'interface list member',
  'interface eoip', 'interface gre', 'interface vxlan',
  'ip address', 'ip route', 'ip route rule', 'ip pool', 'ip dns', 'ip service', 'ip arp', 'ip vrf', 'ip settings', 'ip neighbor discovery-settings',
  'ip firewall filter', 'ip firewall nat', 'ip firewall mangle', 'ip firewall raw', 'ip firewall address-list',
  'routing bgp', 'routing ospf', 'routing filter', 'routing table', 'routing rule', 'ppp profile',
  'queue simple', 'queue tree', 'queue type', 'system identity', 'system clock', 'system ntp client',
]);
const PRINT_FLAGS = new Set(['detail', 'brief', 'terse', 'without-paging', 'as-value', 'stats', 'count-only']);
const ROS_CHARSET = /^[A-Za-z0-9 _.,:/=@+*#%!"-]+$/;

export function planRosCommand(text: unknown): RosPlan {
  const raw = precheck(text, ROS_CHARSET);
  const tokens = tokenize(raw);
  if (!tokens.length) deny('empty command.');
  if (tokens[0]!.startsWith(':')) deny('":" (scripting) commands are refused.');
  // "/ip/address/print" and "/ip address print" are both accepted: split the first token on "/".
  const VERBS = new Set(['print', 'monitor', 'ping', 'traceroute', 'export']);
  const path: string[] = [];
  let i = 0;
  let verb = '';
  for (; i < tokens.length; i++) {
    const parts = tokens[i]!.replace(/^\//, '').split('/');
    let hit = -1;
    for (let p = 0; p < parts.length; p++) {
      const w = parts[p]!;
      if (!WORD.test(w)) { if (hit >= 0 || tokens[i]!.includes('=')) break; return deny(`menu segment "${w}" is not valid.`); }
      if (FORBIDDEN_WORDS.has(w)) deny(`word "${w}" is refused (read-only: only print / monitor once / <menu> export hide-sensitive (full path, e.g. /ip service export hide-sensitive) / ping / traceroute).`);
      if (VERBS.has(w)) { verb = w; hit = p; break; }
      path.push(w);
    }
    if (verb) {
      if (hit < parts.length - 1) deny('nothing may follow the verb inside the same token.');
      i++;
      break;
    }
    if (tokens[i]!.includes('=')) deny('the verb (print/monitor/ping/traceroute/export) must come before arguments.');
  }
  if (!verb) return deny('unknown verb. Allowed: print, monitor ... once, <menu> export hide-sensitive (e.g. /ip service export hide-sensitive), ping, traceroute.');
  const rest = tokens.slice(i);
  for (const t of rest) {
    const key = t.split('=')[0]!;
    if (FORBIDDEN_WORDS.has(key.toLowerCase()) && !t.includes('=')) deny(`argument "${t}" is refused.`);
    if (/^(file|script)$/i.test(key) && t.includes('=')) deny(`argument "${key}=" is refused.`);
    const value = t.includes('=') ? t.slice(t.indexOf('=') + 1) : '';
    if (!SAFE_VALUE.test(value)) deny('argument value contains characters that are not allowed.');
  }
  for (const prefix of DENY_PATH_PREFIXES) if (startsWith(path, prefix)) deny(`menu /${path.join(' ')} is refused (secrets, endless stream, or file writes).`);
  const safe = SAFE_PROPLIST.find((entry) => startsWith(path, entry.path) && !(path[0] === 'user' && path[1] === 'active'));
  const apiPath = `/${path.join('/')}${path.length ? '/' : ''}${verb}`;
  const display = `${path.length ? `/${path.join(' ')} ` : ''}${verb}${rest.length ? ` ${rest.join(' ')}` : ''}`;
  const kv = (t: string): [string, string] | null => { const at = t.indexOf('='); return at > 0 ? [t.slice(0, at), t.slice(at + 1)] : null; };

  if (verb === 'print') {
    if (!path.length) deny('print needs a menu (e.g. /system resource print).');
    const joined = path.join(' ');
    if (!ROS_PRINT_PATHS.has(joined)) deny(`print /${joined} is refused: only full menus on the positive list (no abbreviations): ${[...ROS_PRINT_PATHS].map((m) => `/${m}`).join(', ')}.`);
    const words: string[] = [];
    let inWhere = false; let sawWhere = false; let countOnly = false;
    let tail: number | undefined;
    for (const t of rest) {
      if (!inWhere) {
        if (t === 'where') { inWhere = true; sawWhere = true; continue; }
        if (PRINT_FLAGS.has(t)) { if (t === 'count-only') countOnly = true; if (t === 'count-only' || t === 'stats') words.push(`=${t}=`); continue; }
        const pair = kv(t);
        if (pair && pair[0] === 'tail') {
          if (joined !== 'log') deny('tail= is only for /log print.');
          tail = intIn(pair[1], 1, 200, 'tail'); continue;
        }
        if (pair && pair[0] === 'proplist') {
          if (pair[1].split(',').some((c) => SECRET_COLUMN.test(c))) deny(`secret columns cannot be requested on /${joined}.`);
          if (!/^[a-z0-9.,-]+$/i.test(pair[1])) deny('invalid proplist.');
          words.push(`=.proplist=${pair[1]}`); continue;
        }
        deny(`print argument "${t}" is not allowed (allowed: detail, brief, terse, without-paging, as-value, stats, count-only, proplist=, where key=value).`);
      }
      if (t === 'and') continue;
      if (t === 'or' || t === 'not') deny('where only supports equality (key=value) joined with "and"; other operators are refused.');
      const whereKey = (k: string): string => {
        if (!/^[a-z.][a-z0-9.-]*$/i.test(k)) deny('invalid where key.');
        if (SECRET_COLUMN.test(k)) deny(`where on secret column "${k.slice(0, 30)}" is refused (it could be used to guess the value).`);
        if (joined === 'snmp community' && k.toLowerCase() === 'name') deny('where on the community name is refused.');
        return k;
      };
      if (t.startsWith('!')) { words.push(`?-${whereKey(t.slice(1))}`); continue; }
      const pair = kv(t);
      if (pair) { words.push(`?${whereKey(pair[0])}=${pair[1]}`); continue; }
      words.push(`?${whereKey(t)}`);
    }
    if (ROS_HEAVY_PATHS.has(joined) && !countOnly && !sawWhere) deny(`a bare /${joined} print is too heavy for the router (large table): use count-only or where key=value.`);
    if (joined === 'log' && tail === undefined) tail = 60;
    if (safe) {
      if (!words.some((w) => w.startsWith('=.proplist='))) words.push(`=.proplist=${safe.columns}`);
      // `detail` is harmless here: the forced =.proplist= still limits the columns the router returns.
    }
    return { kind: 'api', verb: 'print', path, apiPath, words, display: tail !== undefined && joined === 'log' && !rest.some((t) => t.startsWith('tail=')) ? `${display} tail=${tail}` : display, ...(tail !== undefined ? { tail } : {}) };
  }

  if (verb === 'monitor') {
    if (!path.length) deny('monitor needs a menu (e.g. /interface ethernet monitor ether1 once).');
    if (!ROS_MONITOR_PATHS.has(path.join(' '))) deny(`monitor /${path.join(' ')} is refused: only ${[...ROS_MONITOR_PATHS].map((m) => `/${m}`).join(', ')}.`);
    if (!rest.includes('once')) deny('monitor must use "once" (without it the stream never ends).');
    const words: string[] = ['=once='];
    const positional = rest.filter((t) => t !== 'once');
    if (positional.length > 1) deny('monitor takes a single name/number.');
    if (positional[0]) {
      // Interface names may contain "+" and spaces ("sfp+ 1"): such a name must be double-quoted so it stays one token.
      if (positional[0].includes('=') || !/^[A-Za-z0-9_.:*+-](?:[A-Za-z0-9_.:*+ -]*[A-Za-z0-9_.:*+-])?$/.test(positional[0])) deny('invalid monitor name/number (quote names that contain spaces, e.g. "sfp+ 1").');
      words.unshift(`=numbers=${positional[0]}`);
    }
    return { kind: 'api', verb: 'monitor', path, apiPath, words, display };
  }

  if (verb === 'ping' || verb === 'traceroute') {
    if (verb === 'ping' && path.length) deny('ping is only allowed at the top level (/ping).');
    if (verb === 'traceroute' && !(path.length === 0 || (path.length === 1 && path[0] === 'tool'))) deny('traceroute is only /tool traceroute.');
    const apiP = verb === 'ping' ? '/ping' : '/tool/traceroute';
    let address = '';
    const opts = new Map<string, string>();
    const ok = verb === 'ping' ? new Set(['count', 'size']) : new Set(['count', 'max-hops']);
    for (const t of rest) {
      const pair = kv(t);
      if (!pair) { if (address) deny('only one target address is allowed.'); address = t; continue; }
      if (pair[0] === 'address') { if (address) deny('only one target address is allowed.'); address = pair[1]; continue; }
      if (!ok.has(pair[0])) deny(`option "${pair[0]}" is not allowed for ${verb}.`);
      opts.set(pair[0], pair[1]);
    }
    checkProbeTarget(address);
    const count = opts.has('count') ? intIn(opts.get('count')!, 1, verb === 'ping' ? 10 : 3, 'count') : (verb === 'ping' ? 4 : 1);
    const words = [`=address=${address}`, `=count=${count}`];
    if (opts.has('size')) words.push(`=size=${intIn(opts.get('size')!, 28, 1400, 'size')}`);
    if (verb === 'traceroute') words.push(`=max-hops=${opts.has('max-hops') ? intIn(opts.get('max-hops')!, 1, 20, 'max-hops') : 15}`);
    return { kind: 'api', verb, path: verb === 'ping' ? [] : ['tool'], apiPath: apiP, words, display: `${verb} ${address} count=${count}` };
  }

  // export: full menu paths from the positive list only (no abbreviations, no action menus, no root); only "hide-sensitive" (+ terse/verbose/compact); no file=.
  if (!ROS_EXPORT_PATHS.has(path.join(' '))) deny(`export ${path.length ? `/${path.join(' ')}` : 'without a menu path'} is refused: give the full menu path before "export", e.g. "/ip service export hide-sensitive"; positive list (${[...ROS_EXPORT_PATHS].map((p) => `/${p}`).join(', ')}).`);
  const allowed = new Set(['hide-sensitive', 'terse', 'verbose', 'compact']);
  for (const t of rest) if (!allowed.has(t)) deny(`export argument "${t}" is not allowed (only hide-sensitive, terse, verbose, compact; never file=).`);
  if (!rest.includes('hide-sensitive')) deny('export must use hide-sensitive.');
  const sshCommand = `${path.length ? `/${path.join(' ')} ` : '/'}export ${rest.join(' ')}`.replace('/ export', '/export');
  return { kind: 'export', path, display: sshCommand, sshCommand };
}

/** Value-free description of a plan for the audit log: path, verb and where-keys only (customer data stays out of logs). */
export function auditCommand(plan: RosPlan): string {
  if (plan.kind === 'export') return `/${plan.path.join(' ')} export`;
  const keys = plan.words.filter((w) => w.startsWith('?')).map((w) => w.slice(1).split('=')[0]!.replace(/^-/, '!'));
  return `${plan.path.length ? `/${plan.path.join(' ')} ` : ''}${plan.verb}${keys.length ? ` where ${keys.join(',')}` : ''}`;
}
