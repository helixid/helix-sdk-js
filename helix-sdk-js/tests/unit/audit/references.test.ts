// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import { auditDigest, digestText } from '../../../src/audit/digest.js';
import {
  MAX_CHAIN_DIGESTS,
  MAX_CREDENTIAL_NESTING,
  MAX_REFERENCE_LENGTH,
  UNKNOWN_DELEGATION_REF,
  UNSEEN_CODE_POINT_RANGES,
  credentialDigest,
  credentialShownId,
  credentialSignedForm,
  delegationChainDigest,
  delegationChainDigests,
  delegationRef,
  delegationReference,
  hasUnprintableCharacter,
  jsonTextNestingDepth,
  readSignatureBase64,
  sanitizeReference,
  valueNestingDepth,
} from '../../../src/audit/references.js';
import { AUDIT_DIGEST_DOMAINS } from '../../../src/audit/types.js';
import { auditEventsFixture, describeFixture, loadFixture } from './fixtures.js';

const ch = (code: number): string => String.fromCharCode(code);

/** SPEC appendix C.4 constants. */
const C4_ROOT = 'sha256:6fbe4c0f04413cb40ec3b3069bf7c73dc1b6a681765e95ac451672136328712e';
const C4_LEAF = 'sha256:d29d65862fce70137390bea2859696c7ad80ce88cede778fea1cab24d513eed1';
const C4_CHAIN = 'sha256:2df99ab7f9b80436dba945e0dfb7a37bd7b35400c82bbc72a5c2744f516eb788';

describeFixture('fixture references and delegation', () => {
  const fixture = auditEventsFixture();

  it('sanitizes every reference case as the fixture records it', () => {
    expect(fixture.references.length).toBeGreaterThanOrEqual(12);
    for (const { input, max_length, output } of fixture.references) {
      expect(max_length === undefined ? sanitizeReference(input) : sanitizeReference(input, max_length), JSON.stringify(input)).toBe(output);
    }
  });

  it('matches the vendored unseen code point ranges', () => {
    const vendored = loadFixture<unknown>('kya-os/conformance/unseen-code-points.json');
    const ranges = (Array.isArray(vendored) ? vendored : (vendored as { ranges: unknown }).ranges) as Array<unknown>;
    const asPairs = ranges.map((range) => {
      if (Array.isArray(range)) return [range[0], range[1]];
      const r = range as { start?: unknown; end?: unknown; first?: unknown; last?: unknown; from?: unknown; to?: unknown };
      return [r.start ?? r.first ?? r.from, r.end ?? r.last ?? r.to];
    });
    const toNumber = (value: unknown): number => (typeof value === 'number' ? value : parseInt(String(value).replace(/^U\+/i, ''), 16));
    expect(asPairs.map(([a, b]) => [toNumber(a), toNumber(b)])).toEqual(UNSEEN_CODE_POINT_RANGES.map(([a, b]) => [a, b]));
  });

  it('derives delegationRef and credentialDigest for every delegation case', () => {
    expect(fixture.delegation.length).toBeGreaterThanOrEqual(30);
    for (const { name, credential, delegation_ref, credential_digest } of fixture.delegation) {
      expect(delegationRef(credential), name).toBe(delegation_ref ?? undefined);
      expect(credentialDigest(credential), name).toBe(credential_digest ?? undefined);
    }
  });

  it('digests the chain root first and refuses an overlong or unsigned chain', () => {
    const { credentials, digests, chain_digest, too_long_chain_length } = fixture.delegation_chain;
    expect(delegationChainDigests(credentials)).toEqual(digests);
    expect(delegationChainDigest(digests as `sha256:${string}`[])).toBe(chain_digest);
    expect(delegationChainDigests(new Array<unknown>(too_long_chain_length).fill(credentials[0]))).toBeUndefined();
    expect(delegationChainDigests([credentials[0], { id: 'urn:uuid:unsigned' }])).toBeUndefined();
    expect(delegationChainDigests([])).toBeUndefined();
    expect(fixture.delegation_chain.too_long_chain_digests).toBeNull();
    expect(fixture.delegation_chain.unsigned_member_digests).toBeNull();
    // SPEC appendix C.4.
    expect(digests).toEqual([C4_ROOT, C4_LEAF]);
    expect(chain_digest).toBe(C4_CHAIN);
  });
});

describe('constants', () => {
  it('holds the SPEC bounds', () => {
    expect(MAX_REFERENCE_LENGTH).toBe(256);
    expect(MAX_CHAIN_DIGESTS).toBe(256);
    expect(MAX_CREDENTIAL_NESTING).toBe(64);
    expect(UNKNOWN_DELEGATION_REF).toBe('unknown');
    expect(delegationChainDigest([C4_ROOT, C4_LEAF])).toBe(C4_CHAIN);
    expect(auditDigest(AUDIT_DIGEST_DOMAINS.delegationChain, [C4_ROOT, C4_LEAF])).toBe(C4_CHAIN);
  });
});

describe('hasUnprintableCharacter', () => {
  it('sees control, format and ignorable code points, and lone surrogates', () => {
    expect(hasUnprintableCharacter('plain-ref')).toBe(false);
    expect(hasUnprintableCharacter('tab\there')).toBe(true);
    expect(hasUnprintableCharacter(`soft${ch(0xad)}hyphen`)).toBe(true);
    expect(hasUnprintableCharacter(`bom${ch(0xfeff)}`)).toBe(true);
    expect(hasUnprintableCharacter('emoji-😀')).toBe(false);
    // U+E0041 (tag character): a supplementary unseen code point written as a pair.
    expect(hasUnprintableCharacter('tag\u{e0041}')).toBe(true);
    expect(hasUnprintableCharacter(`high-at-end${ch(0xd800)}`)).toBe(true);
    expect(hasUnprintableCharacter(`high${ch(0xd800)}then-ascii`)).toBe(true);
    expect(hasUnprintableCharacter(`${ch(0xdc00)}low-first`)).toBe(true);
    // Beyond every range: printable.
    expect(hasUnprintableCharacter('\u{10ffff}')).toBe(false);
  });
});

describe('sanitizeReference', () => {
  it('keeps a printable reference within the bound and digests the rest', () => {
    expect(sanitizeReference('ok')).toBe('ok');
    expect(sanitizeReference('x'.repeat(256))).toBe('x'.repeat(256));
    expect(sanitizeReference('x'.repeat(257))).toBe(digestText('x'.repeat(257)));
    expect(sanitizeReference('')).toBe(digestText(''));
    expect(sanitizeReference('abcdef', 5)).toBe(digestText('abcdef'));
    expect(sanitizeReference('abcde', 5)).toBe('abcde');
    expect(sanitizeReference('a\u0000b')).toBe(digestText('a\u0000b'));
  });
});

describe('delegationReference', () => {
  it('digests an empty, overlong, unprintable, digest-shaped or "unknown" id', () => {
    expect(delegationReference('urn:uuid:1')).toBe('urn:uuid:1');
    expect(delegationReference('')).toBe(digestText(''));
    expect(delegationReference('x'.repeat(257))).toBe(digestText('x'.repeat(257)));
    expect(delegationReference('a\nb')).toBe(digestText('a\nb'));
    expect(delegationReference(`sha256:${'a'.repeat(64)}`)).toBe(digestText(`sha256:${'a'.repeat(64)}`));
    expect(delegationReference('unknown')).toBe(digestText('unknown'));
    expect(delegationReference('Unknown')).toBe('Unknown');
  });
});

describe('nesting depth', () => {
  it('counts JSON text nesting, ignoring brackets inside strings and escapes', () => {
    expect(jsonTextNestingDepth('{"a":[1,{"b":"[{\\"}"}]}')).toBe(3);
    expect(jsonTextNestingDepth('"just a string"')).toBe(0);
    expect(jsonTextNestingDepth('[[[]]]')).toBe(3);
    expect(jsonTextNestingDepth('[[],[]]')).toBe(2);
    expect(jsonTextNestingDepth('{"a":"\\\\"}')).toBe(1);
    expect(jsonTextNestingDepth('['.repeat(65) + ']'.repeat(65))).toBe(65);
    expect(jsonTextNestingDepth('['.repeat(200), 64)).toBe(65);
    expect(jsonTextNestingDepth('[[]]', 1)).toBe(2);
  });

  it('counts a parsed value iteratively', () => {
    expect(valueNestingDepth(1)).toBe(0);
    expect(valueNestingDepth(null)).toBe(0);
    expect(valueNestingDepth({})).toBe(1);
    expect(valueNestingDepth({ a: [{ b: 1 }] })).toBe(3);
    expect(valueNestingDepth([[[1]], { x: null }])).toBe(3);
    let deep: unknown = 1;
    for (let i = 0; i < 70; i += 1) deep = [deep];
    expect(valueNestingDepth(deep)).toBe(65);
    expect(valueNestingDepth(deep, 100)).toBe(70);
  });
});

describe('readSignatureBase64', () => {
  it('reads the JWS alphabet strictly and the proofValue alphabet loosely', () => {
    expect([...readSignatureBase64('AQID', true)!]).toEqual([1, 2, 3]);
    expect([...readSignatureBase64('AQI', true)!]).toEqual([1, 2]);
    expect([...readSignatureBase64('AQI=', true)!]).toEqual([1, 2]);
    expect(readSignatureBase64('AQ==', true)).toEqual(Uint8Array.from([1]));
    // Whitespace is skipped in both readings.
    expect([...readSignatureBase64(' AQ\nID\t', false)!]).toEqual([1, 2, 3]);
    // '+' and '/' belong to the standard alphabet only.
    expect(readSignatureBase64('+/+/', true)).toBeUndefined();
    expect([...readSignatureBase64('+/+/', false)!]).toEqual([0xfb, 0xff, 0xbf]);
    expect([...readSignatureBase64('-_-_', true)!]).toEqual([0xfb, 0xff, 0xbf]);
    // Characters outside both alphabets.
    expect(readSignatureBase64('AQ!D', false)).toBeUndefined();
    // Padding before data, an empty string, or a 1-mod-4 length.
    expect(readSignatureBase64('=AQID', false)).toBeUndefined();
    expect(readSignatureBase64('', false)).toBeUndefined();
    expect(readSignatureBase64('===', false)).toBeUndefined();
    expect(readSignatureBase64('AQIDA', false)).toBeUndefined();
    // JWS: padding must complete the last group exactly; loose: any amount after the data.
    expect(readSignatureBase64('AQI==', true)).toBeUndefined();
    expect(readSignatureBase64('AQID=', true)).toBeUndefined();
    expect([...readSignatureBase64('AQI===', false)!]).toEqual([1, 2]);
    expect([...readSignatureBase64('AQID=', false)!]).toEqual([1, 2, 3]);
  });
});

describe('credentialSignedForm / credentialShownId / credentialDigest', () => {
  const header = Buffer.from('{"alg":"EdDSA"}').toString('base64url');
  const payload = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

  it('reads a compact JWS as {jwt, signature} and refuses malformed ones', () => {
    const jwt = `${header}.${payload({ vc: { id: 'urn:uuid:a' } })}.AQID`;
    expect(credentialSignedForm(jwt)).toEqual({ jwt: jwt.slice(0, -5), signature: 'AQID' });
    expect(credentialSignedForm('a.b')).toBeUndefined();
    expect(credentialSignedForm(`.${payload({})}.AQID`)).toBeUndefined();
    expect(credentialSignedForm(`${header}..AQID`)).toBeUndefined();
    expect(credentialSignedForm(`${header}.not base64url!.AQID`)).toBeUndefined();
    expect(credentialSignedForm(`not-b64!.${payload({})}.AQID`)).toBeUndefined();
    expect(credentialSignedForm(`${header}.${payload({})}.`)).toBeUndefined();
    expect(credentialSignedForm(`${header}.${payload({})}.+/+/`)).toBeUndefined();
  });

  it('reads a credential object as {credential, signature} by the loose proofValue rule', () => {
    const credential = { id: 'urn:uuid:a', proof: { type: 'Ed25519Signature2020', proofValue: 'AQID' }, credentialSubject: { id: 'did:key:z1' } };
    expect(credentialSignedForm(credential)).toEqual({ credential: { id: 'urn:uuid:a', credentialSubject: { id: 'did:key:z1' } }, signature: 'AQID' });
    expect(credentialSignedForm(credential)).toEqual(credentialSignedForm({ ...credential, proof: { proofValue: 'AQID=' } }));
    expect(credentialSignedForm(42)).toBeUndefined();
    expect(credentialSignedForm(null)).toBeUndefined();
    expect(credentialSignedForm([credential])).toBeUndefined();
    expect(credentialSignedForm({ id: 'x' })).toBeUndefined();
    expect(credentialSignedForm({ id: 'x', proof: 'sig' })).toBeUndefined();
    expect(credentialSignedForm({ id: 'x', proof: {} })).toBeUndefined();
    expect(credentialSignedForm({ id: 'x', proof: { proofValue: '' } })).toBeUndefined();
    expect(credentialSignedForm({ id: 'x', proof: { proofValue: '!' } })).toBeUndefined();
    expect(credentialSignedForm({ id: 'x', proof: { proofValue: '=' } })).toBeUndefined();
    let deep: unknown = { proofValue: 'AQID' };
    for (let i = 0; i < 70; i += 1) deep = { nested: deep };
    expect(credentialSignedForm({ id: 'x', proof: { proofValue: 'AQID' }, deep })).toBeUndefined();
  });

  it('shows the id a credential presents: vc.id, then jti, then the delegation id', () => {
    expect(credentialShownId(`${header}.${payload({ vc: { id: 'urn:uuid:vc' }, jti: 'urn:uuid:jti' })}.AQID`)).toBe('urn:uuid:vc');
    expect(credentialShownId(`${header}.${payload({ vc: {}, jti: 'urn:uuid:jti' })}.AQID`)).toBe('urn:uuid:jti');
    expect(credentialShownId(`${header}.${payload({ vc: { credentialSubject: { delegation: { id: 'urn:uuid:del' } } } })}.AQID`)).toBe('urn:uuid:del');
    expect(credentialShownId(`${header}.${payload({ vc: { credentialSubject: { delegation: 'x' } } })}.AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}.${payload({ vc: { credentialSubject: 'x' } })}.AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}.${payload({ vc: {} })}.AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}.${payload({ jti: 'urn:uuid:jti' })}.AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}.${payload('text')}.AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}..AQID`)).toBeUndefined();
    expect(credentialShownId(`${header}.%%%.AQID`)).toBeUndefined();
    expect(credentialShownId('one.two')).toBeUndefined();
    expect(credentialShownId(`${header}.${Buffer.from('{').toString('base64url')}.AQID`)).toBeUndefined();
    expect(credentialShownId({ id: 'urn:uuid:obj' })).toBe('urn:uuid:obj');
    expect(credentialShownId({ credentialSubject: { delegation: { id: 'urn:uuid:nested' } } })).toBe('urn:uuid:nested');
    expect(credentialShownId({ credentialSubject: { delegation: { id: '' } } })).toBeUndefined();
    expect(credentialShownId({})).toBeUndefined();
    expect(credentialShownId('plain string')).toBeUndefined();
    expect(credentialShownId(7)).toBeUndefined();
    expect(credentialShownId(undefined)).toBeUndefined();
  });

  it('delegationRef wraps the shown id in delegationReference', () => {
    expect(delegationRef({ id: 'unknown' })).toBe(digestText('unknown'));
    expect(delegationRef({ id: 'urn:uuid:a' })).toBe('urn:uuid:a');
    expect(delegationRef({})).toBeUndefined();
  });

  it('credentialDigest is the delegation credential domain over the signed form', () => {
    const credential = { id: 'urn:uuid:a', proof: { proofValue: 'AQID' } };
    expect(credentialDigest(credential)).toBe(auditDigest(AUDIT_DIGEST_DOMAINS.delegationCredential, { credential: { id: 'urn:uuid:a' }, signature: 'AQID' }));
    expect(credentialDigest({ id: 'x' })).toBeUndefined();
    // A signed form with no canonical form (an unsafe integer) has no digest.
    expect(credentialDigest({ id: 'x', big: 2 ** 60, proof: { proofValue: 'AQID' } })).toBeUndefined();
  });

  it('credentialDigest lets an error that is not a canonicalization refusal through', () => {
    // A nested member enumerated twice: by the nesting walk, then by the canonicalizer, where it throws.
    let enumerations = 0;
    const flaky = new Proxy(
      { a: 1 },
      {
        ownKeys(target) {
          enumerations += 1;
          if (enumerations >= 2) throw new RangeError('enumerated too often');
          return Reflect.ownKeys(target);
        },
      },
    );
    expect(() => credentialDigest({ id: 'x', flaky, proof: { proofValue: 'AQID' } })).toThrow(RangeError);
  });
});
