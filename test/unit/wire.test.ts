import { describe, expect, it } from 'vitest';
import { decodeSentence, encodeLength, encodeSentence, sentenceAttrs } from '../../src/core/index.js';

describe('RouterOS API wire format', () => {
  it('round-trips word lengths across every encoding width', () => {
    for (const n of [1, 127, 128, 16383, 16384, 2097151, 2097152]) {
      const body = 'x'.repeat(n);
      expect(decodeSentence(encodeSentence([body, '=a=b']))?.words).toEqual([body, '=a=b']);
    }
    expect(encodeLength(300)).toEqual(Buffer.from([0x81, 0x2c]));
    expect(encodeLength(0x10000000)).toEqual(Buffer.from([0xf0, 0x10, 0, 0, 0]));
  });
  it('returns null for incomplete input and keeps leftover bytes accounted for', () => {
    expect(decodeSentence(encodeSentence(['!re']).subarray(0, 2))).toBeNull();
    const two = Buffer.concat([encodeSentence(['!re', '=a=1']), encodeSentence(['!done'])]);
    const first = decodeSentence(two)!;
    expect(first.words).toEqual(['!re', '=a=1']);
    expect(decodeSentence(two.subarray(first.used))?.words).toEqual(['!done']);
  });
  it('parses attribute words, keeping "=" inside values', () => {
    expect(sentenceAttrs(['!re', '=name=ether1', '=comment=a=b', 'ignored'])).toEqual({ name: 'ether1', comment: 'a=b' });
  });
});
