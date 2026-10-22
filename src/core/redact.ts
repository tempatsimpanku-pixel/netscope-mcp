export const MASK = '[redacted]';

/** Key names that carry secrets (RouterOS attribute names, JSON keys, config words). */
export const SECRET_KEY = /^(?!public-key$)(?:[\w.-]*?(?:password|passwd|passphrase|secret|psk|token|community|key|credential)[\w-]*|(?:[\w.-]*[-_.])?(?:pin|pwd|pw|pass|auth)(?:[-_.][\w.-]*)?)$/i;
/** Keys whose value is a SCRIPT (secrets cannot be told apart from code): the whole value is masked. */
export const SCRIPT_KEY_PATTERN = '(?:source|script|run-after|on-(?:event|up|down|login|logout|error|failure|success|connect|disconnect|expire|lease|timeout)|[a-z]+(?:-[a-z]+)*-script)';
export const SCRIPT_KEYS = new RegExp(`^${SCRIPT_KEY_PATTERN}$`);

/** Value-inside-a-string pattern: `password=X`, `pass: X`, `secret=\"X\"` inside script/scheduler/netwatch/comment text (escaped quotes included). */
const INLINE_SECRET = /(?<![\w-])(?!public-key\b)((?:[\w-]*(?:password|passwd|passphrase|pass|secret|psk|community|key|token)[\w-]*)|(?:[\w-]*[-_])?(?:pin|pwd|pw|auth)(?:[-_][\w-]*)?)(\s*[=:]\s*)(\\?"(?:[^"\\]|\\.)*?\\?"|\\?"?[^\s";]+)/gi;

/** Free text (script bodies, comments, cell values): mask every secret-looking key/value pair inside it. */
export function maskInlineSecrets(text: string): string {
  return text.replace(INLINE_SECRET, (_all, key: string, sep: string) => `${key}${sep}${MASK}`);
}

/** Heuristic for a value that is a credential rather than a name: >= 10 chars with a digit, a lowercase and an uppercase letter. */
const looksLikeSecret = (v: string): boolean => v.length >= 10 && /\d/.test(v) && /[a-z]/.test(v) && /[A-Z]/.test(v);

/** Mask secret values in raw text output (RouterOS key=value / export, generic "password xxx" configs, JSON). */
export function redactText(raw: string): string {
  let section = '';
  let inPem = false;
  // Join RouterOS continuation lines ("\\" + newline) so multi-line string values are masked whole.
  return raw.replace(/\r/g, '').replace(/\\\n[ \t]*/g, '').split('\n').map((line) => {
    // PEM private-key blocks: the body is secret, the BEGIN/END markers are kept.
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line)) { inPem = !/-----END [A-Z ]*PRIVATE KEY-----/.test(line); return line.replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)?$/, (_m, b: string, e?: string) => (e ? `${b}${MASK}${e}` : b)); }
    if (inPem) { if (/-----END [A-Z ]*PRIVATE KEY-----/.test(line)) { inPem = false; return line; } return MASK; }
    const sec = /^\s*(\/[a-z0-9 /-]+?)\s*$/i.exec(line);
    if (sec) section = sec[1]!.toLowerCase();
    // JSON: "…password…": "x"
    let out = line.replace(/("[\w.-]*(?:password|passwd|passphrase|secret|psk|community|key|token|credential)[\w.-]*"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\s]+)/gi, `$1"${MASK}"`);
    // Script/scheduler/netwatch bodies: mask the whole value.
    out = out.replace(new RegExp(`(?<![\\w-])(${SCRIPT_KEY_PATTERN})=("(?:[^"\\\\]|\\\\.)*"|\\S+)`, 'g'), `$1=${MASK}`);
    // Secret pairs inside string values (source=, on-event=, comment=), then key=value / key="a b".
    out = maskInlineSecrets(out);
    out = out.replace(/([A-Za-z0-9_.-]+)=("[^"]*"|\S*)/g, (all, key: string) => (SECRET_KEY.test(key) ? `${key}=${MASK}` : all));
    // The community string IS the `name` of an snmp community row: by section, by the row's own columns, or (section unknown) on any bare `add`.
    const communityRow = /\/snmp community/.test(section) || /^\s*\/snmp community\b/.test(line) || /\b(?:read-access|write-access)=/.test(line) || /^\s*\/snmp\b/.test(section);
    if (communityRow) out = out.replace(/\bname=("[^"]*"|\S+)/g, (_a, v: string) => (v.startsWith('"') ? `name="${MASK}"` : `name=${MASK}`));
    // Section unknown (a chunk without its header): a credential-looking `name=` on an `add` row is masked, plain names are kept.
    else if (section === '' && /^\s*add\s/.test(line)) out = out.replace(/\bname=("([^"]*)"|(\S+))/g, (all, _v: string, q?: string, b?: string) => (looksLikeSecret(q ?? b ?? '') ? `name=${MASK}` : all));
    // Scripts: `:local mypw "x"` / `:global pass x`; free text: `pw is x`, `password: x`.
    out = out.replace(/(:(?:local|global|set)\s+\$?[\w-]*(?:pw|pwd|pass|passwd|password|secret|psk|key|token|community|credential)[\w-]*\s+)("(?:[^"\\]|\\.)*"|\S+)/gi, `$1${MASK}`);
    out = out.replace(/\b((?:pw|pwd|pass|passwd|password|passphrase|secret|psk|community|token|key)\s+(?:is|was|=|:)\s+)(?!\[redacted\])([^\s"';,]+)/gi, `$1${MASK}`);
    // Config-style text: a word containing password/passphrase/secret/psk/community/key/token masks the rest of the line.
    out = out.replace(/(^|[^A-Za-z0-9])([\w-]*(?:password|passphrase|secret|psk|community|key|token))\b([\s:'"]+)(?!\[redacted\]$)(\S.*)$/i, (_all, lead: string, k: string, sp: string) => `${lead}${k}${sp}${MASK}`);
    // Private keys (WireGuard/PKI): base64 of 43+ characters ending in "=" (44 for WireGuard).
    out = out.replace(/(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42,}={1,2}(?![A-Za-z0-9+/=])/g, MASK);
    return out;
  }).join('\n');
}

/** Remove exact credential values (password, community, user…) from any text about to leave the process. */
export function scrubExact(text: string, secrets: ReadonlyArray<string | undefined>): string {
  let out = text;
  for (const secret of secrets) if (secret && secret.length >= 3) out = out.split(secret).join(MASK);
  return out;
}

/** Error messages carry nothing but our own text. */
export function scrubMessage(message: string): string {
  // Keyword (+ attached characters) and the value that follows it ("password X", "community X", "key: X", "secret=X").
  return message.replace(/(?:password|passwd|passphrase|pass|pw|key|token|secret|community|psk)\S*(?:\s+(?:is|was)\b|\s*[=:])?(?:\s+("[^"]*"|'[^']*'|[^\s,;]+))?/gi, MASK).slice(0, 300);
}

/** Limit output and cut on a line boundary so the last line never dangles half-way. */
export function clip(text: string, limit = 12_000): string {
  const t = text.trim();
  if (t.length <= limit) return t;
  const nl = t.lastIndexOf('\n', limit);
  const cut = nl > limit * 0.5 ? nl : limit;
  const shown = t.slice(0, cut);
  return `${shown}\n… (truncated: ${shown.split('\n').length} of ${t.split('\n').length} lines shown; narrow with where/proplist or a sub-menu)`;
}

// ───────────────────────────── PII ─────────────────────────────

/** Columns that identify customers' equipment/people. With `redactPii` they are masked in row output. */
const PII_MAC_KEYS = /^(?:mac-address|caller-id|last-caller-id|active-mac-address|remote-id|client-id|src-mac-address|host-mac|bssid)$/i;
const PII_TEXT_KEYS = /^(?:host-name|comment|client-hostname|username|user)$/i;
const MAC_RE = /\b([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\b/g;

/** Keep the vendor prefix (first three octets), hide the device part. */
export function maskMac(text: string): string {
  return text.replace(MAC_RE, (_a, o1: string, sep: string, o2: string, o3: string) => `${o1}${sep}${o2}${sep}${o3}${sep}xx${sep}xx${sep}xx`);
}

/** Apply PII masking to one cell. */
export function maskPiiCell(key: string, value: string): string {
  if (PII_MAC_KEYS.test(key)) return maskMac(value);
  if (PII_TEXT_KEYS.test(key) && value !== '') return MASK;
  return maskMac(value);
}
