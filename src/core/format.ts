import { MASK, SCRIPT_KEYS, SECRET_KEY, maskInlineSecrets, maskMac, maskPiiCell } from './redact.js';
import type { Messages } from './messages.js';
import type { RosRow } from './types.js';

export const MAX_ROWS = 300;
const MAX_VALUE = 300;
const SECRET_PATH = /(^|\/)(snmp\/community)$/;

export interface FormatOptions { redactPii?: boolean; redactPppNames?: boolean; messages?: Pick<Messages, 'noRows' | 'noHops' | 'noFields'> }

/** Menus whose `name` column is a customer login (PPP user / PPPoE service name). */
const PPP_NAME_MENU = /^\/(?:ppp\/(?:active|secret)|interface\/pppoe-server)\//;

/** A name in a one-line summary: plain names stay bare, anything with spaces, dots, `;`, `=` or quotes is JSON-quoted so entries never run together. */
export const quoteName = (name: string): string => (/^[A-Za-z_][A-Za-z0-9_+-]*$/.test(name) ? name : JSON.stringify(name));

/** Menus whose rows describe customers (names, hosts, devices): with `redactPii` free-text columns there are masked too. */
export const CUSTOMER_MENU = /^\/(?:ppp\/(?:active|secret)|ip\/dhcp-server\/lease|ip\/hotspot|ip\/arp|queue\/simple|interface\/pppoe-server|interface\/(?:wireless|wifi)\/registration-table|log)\//;

/** Mask one row set by column name and by content. The result is safe to show and to return as structured data. */
export function maskRows(rows: RosRow[], apiPath: string, opts: FormatOptions = {}): RosRow[] {
  const maskName = SECRET_PATH.test(apiPath.replace(/\/print$/, ''));
  const customer = CUSTOMER_MENU.test(apiPath);
  return rows.map((row) => {
    const out: RosRow = {};
    for (const [k, v] of Object.entries(row)) {
      const secret = SECRET_KEY.test(k) || (maskName && k === 'name') || SCRIPT_KEYS.test(k);
      // SFP EEPROM dumps (hundreds of hex bytes) are useless to a model: reduce to a size.
      if (/^eeprom/i.test(k) && v.length > 40) { out[k] = `(${Math.floor(v.length / 2)} bytes dropped)`; continue; }
      let val = secret && v !== '' ? MASK : maskInlineSecrets(v);
      if (val !== MASK && val !== '' && opts.redactPii && opts.redactPppNames && k === 'name' && PPP_NAME_MENU.test(apiPath)) val = MASK;
      if (val !== MASK && opts.redactPii) val = customer ? maskPiiCell(k, val) : maskMac(val);
      if (val !== MASK && val.length > MAX_VALUE) val = `${val.slice(0, MAX_VALUE)}…(${val.length - MAX_VALUE} characters truncated)`;
      out[k] = val;
    }
    return out;
  });
}

export function formatRosRows(rows: RosRow[], apiPath: string, truncated: boolean, scanned?: number, tail?: number, opts: FormatOptions = {}): string {
  if (!rows.length) return opts.messages?.noRows ?? '(no rows)';
  const masked = maskRows(rows, apiPath, opts);
  const lines = masked.map((row, i) => (!Object.keys(row).length ? `${i} ${opts.messages?.noFields ?? '(no fields returned)'}` : `${i} ${Object.entries(row).map(([k, val]) => `${k}=${val === MASK ? val : /[\s"]/.test(val) ? JSON.stringify(val) : val}`).join(' ')}`));
  const note = tail && scanned !== undefined && scanned > rows.length
    ? `\n… (showing the ${rows.length} NEWEST of ${scanned}${truncated ? '+ read' : ''} entries; order old → new)`
    : truncated ? `\n… (limited to ${MAX_ROWS} rows / time)` : '';
  return `${lines.join('\n')}${note}`;
}

/** The traceroute API re-sends the whole hop table on each update, rows tagged with `.section` (broadcast number). Hops = rows of the LAST broadcast, in order. */
export function formatTraceroute(rows: RosRow[], messages?: Pick<Messages, 'noHops'>): string {
  if (!rows.length) return messages?.noHops ?? '(no hops)';
  const sections = new Map<string, RosRow[]>();
  for (const row of rows) { const key = row['.section'] ?? '0'; (sections.get(key) || sections.set(key, []).get(key)!).push(row); }
  const keys = [...sections.keys()];
  const last = keys.every((k) => /^\d+$/.test(k)) ? keys.sort((a, b) => Number(a) - Number(b))[keys.length - 1]! : keys[keys.length - 1]!;
  const hops = sections.get(last)!;
  return hops.map((r, i) => `${i + 1} ${r.address || '*'} loss=${r.loss ?? '?'}% sent=${r.sent ?? '?'} last=${r.last ?? '-'} avg=${r.avg ?? '-'}`).join('\n');
}
