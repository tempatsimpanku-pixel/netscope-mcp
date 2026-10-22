/** RouterOS API wire format (length-prefixed words, zero-length word ends a sentence). */

export function encodeLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x4000) return Buffer.from([(n >> 8) | 0x80, n & 0xff]);
  if (n < 0x200000) return Buffer.from([(n >> 16) | 0xc0, (n >> 8) & 0xff, n & 0xff]);
  if (n < 0x10000000) return Buffer.from([(n >> 24) | 0xe0, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.from([0xf0, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

export function encodeSentence(words: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const w of words) { const b = Buffer.from(w, 'utf8'); parts.push(encodeLength(b.length), b); }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/** Take one sentence from the start of the buffer; null when it is not complete yet. */
export function decodeSentence(buf: Buffer): { words: string[]; used: number } | null {
  let pos = 0;
  const words: string[] = [];
  for (;;) {
    if (pos >= buf.length) return null;
    const b = buf[pos]!;
    let len: number; let head: number;
    if (b < 0x80) { len = b; head = 1; }
    else if (b < 0xc0) { if (pos + 2 > buf.length) return null; len = ((b & 0x3f) << 8) | buf[pos + 1]!; head = 2; }
    else if (b < 0xe0) { if (pos + 3 > buf.length) return null; len = ((b & 0x1f) << 16) | (buf[pos + 1]! << 8) | buf[pos + 2]!; head = 3; }
    else if (b < 0xf0) { if (pos + 4 > buf.length) return null; len = ((b & 0x0f) << 24) | (buf[pos + 1]! << 16) | (buf[pos + 2]! << 8) | buf[pos + 3]!; head = 4; }
    else { if (pos + 5 > buf.length) return null; len = buf.readUInt32BE(pos + 1); head = 5; }
    if (len === 0 && head === 1) return { words, used: pos + 1 };
    if (pos + head + len > buf.length) return null;
    words.push(buf.subarray(pos + head, pos + head + len).toString('utf8'));
    pos += head + len;
  }
}

/** Parse `=key=value` attribute words of a reply sentence. */
export function sentenceAttrs(words: string[]): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const w of words.slice(1)) { const m = /^=([^=]*)=(.*)$/s.exec(w); if (m) attrs[m[1]!] = m[2]!; }
  return attrs;
}
