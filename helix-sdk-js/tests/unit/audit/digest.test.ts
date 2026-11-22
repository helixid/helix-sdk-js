// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { auditDigest, auditEventDigest, digestBytes, digestText, jsonDigest, keyedCommitmentValue, wtf8Bytes } from '../../../src/audit/digest.js';
import { CanonicalJsonError } from '../../../src/audit/canonical.js';
import { AUDIT_DIGEST_DOMAINS, type AuditProducerEvent } from '../../../src/audit/types.js';
import { canonicalize } from '../../../src/audit/canonical.js';

const hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const ch = (code: number): string => String.fromCharCode(code);

describe('digestBytes / digestText / wtf8Bytes', () => {
  it('digests raw bytes as sha256:<hex>', () => {
    const bytes = Uint8Array.from([1, 2, 3]);
    expect(digestBytes(bytes)).toBe(`sha256:${hex(bytes)}`);
    expect(digestBytes(new Uint8Array(0))).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('writes well-formed text as UTF-8 in one to four bytes', () => {
    expect([...wtf8Bytes('A')]).toEqual([0x41]);
    expect([...wtf8Bytes('é')]).toEqual([0xc3, 0xa9]);
    expect([...wtf8Bytes('€')]).toEqual([0xe2, 0x82, 0xac]);
    expect([...wtf8Bytes('😀')]).toEqual([0xf0, 0x9f, 0x98, 0x80]);
    expect([...wtf8Bytes('a€😀')]).toEqual([...Buffer.from('a€😀', 'utf8')]);
  });

  it('writes a lone surrogate as a three-byte code point (WTF-8), wherever it sits', () => {
    expect([...wtf8Bytes(ch(0xd800))]).toEqual([0xed, 0xa0, 0x80]);
    expect([...wtf8Bytes(`x${ch(0xdc00)}`)]).toEqual([0x78, 0xed, 0xb0, 0x80]);
    // A high surrogate followed by a non-low unit is still lone.
    expect([...wtf8Bytes(`${ch(0xd800)}A`)]).toEqual([0xed, 0xa0, 0x80, 0x41]);
    expect(digestText(`lone${ch(0xd800)}surrogate`)).toBe('sha256:5c9ceca03396ce46fa0d199bd5e390813f56bc18303771a73890ffdd7b5b45f0');
  });

  it('digestText digests the UTF-8 bytes', () => {
    expect(digestText('')).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(digestText('call-0001')).toBe(`sha256:${hex(Buffer.from('call-0001', 'utf8'))}`);
  });
});

describe('auditDigest', () => {
  it('is sha256 over UTF8(domain) || 0x00 || UTF8(JCS(value))', () => {
    const value = { b: 1, a: 'x' };
    const expected = hex(Buffer.concat([Buffer.from('org.kya-os.audit.event.v1\0', 'utf8'), Buffer.from(canonicalize(value), 'utf8')]));
    expect(auditDigest(AUDIT_DIGEST_DOMAINS.event, value)).toBe(`sha256:${expected}`);
    expect(auditDigest('other', value)).not.toBe(auditDigest(AUDIT_DIGEST_DOMAINS.event, value));
  });

  it('refuses an empty domain or one holding NUL, and a value with no canonical form', () => {
    expect(() => auditDigest('', {})).toThrow(TypeError);
    expect(() => auditDigest('a\0b', {})).toThrow('cannot contain NUL');
    expect(() => auditDigest('d', { a: undefined })).toThrow('Cannot canonicalize');
  });

  it('auditEventDigest uses the event domain', () => {
    const event = { eventType: 'tool.call.completed' } as unknown as AuditProducerEvent;
    expect(auditEventDigest(event)).toBe(auditDigest('org.kya-os.audit.event.v1', event));
  });
});

describe('jsonDigest', () => {
  it('digests the JSON wire form: undefined members dropped, non-finite numbers as null, no domain prefix', () => {
    expect(jsonDigest({ b: 1, a: undefined })).toBe(`sha256:${hex(Buffer.from('{"b":1}', 'utf8'))}`);
    expect(jsonDigest({ n: NaN })).toBe(jsonDigest({ n: null }));
    expect(jsonDigest([1, Infinity])).toBe(`sha256:${hex(Buffer.from('[1,null]', 'utf8'))}`);
    expect(jsonDigest({ a: 1 })).not.toBe(auditDigest(AUDIT_DIGEST_DOMAINS.event, { a: 1 }));
  });

  it('still refuses a string that is not well-formed Unicode', () => {
    expect(() => jsonDigest({ s: ch(0xd800) })).toThrow(CanonicalJsonError);
  });
});

describe('keyedCommitmentValue', () => {
  it('is HMAC-SHA256 under the key over the JCS of the value', () => {
    const key = Buffer.from('k'.repeat(32));
    const expected = createHmac('sha256', key).update('{"a":1,"b":"x"}', 'utf8').digest('hex');
    expect(keyedCommitmentValue(key, { b: 'x', a: 1 })).toBe(`sha256:${expected}`);
    expect(keyedCommitmentValue(key, 'user-9')).toBe(`sha256:${createHmac('sha256', key).update('"user-9"', 'utf8').digest('hex')}`);
    expect(keyedCommitmentValue(Buffer.from('other-key'), 'user-9')).not.toBe(keyedCommitmentValue(key, 'user-9'));
  });
});
