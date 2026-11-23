// Copyright 2026 DgVerse LLP
// KYA-OS story F-2: the conformance pieces' refusals beyond the vectors.
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { EnvSigner, canonicalize, conformance, verifier } from '../../../../src/core/kyaos/index.js';
import { buildDIDDocument } from '../../../../src/core/did.js';
import { generateKeyPair } from '../../../../src/core/keys.js';

const adapter = new conformance.HelixConformanceAdapter({ now: () => Date.parse('2026-06-01T00:00:00Z') });
const keys = generateKeyPair();
const DID = 'did:web:issuer.example';
const document = buildDIDDocument(DID, keys.publicKey) as unknown as Record<string, unknown>;
const signer = new EnvSigner({ did: DID, envVar: 'K', env: { K: keys.privateKey } });

async function signLegacy(credential: Record<string, unknown>, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const signature = await signer.sign(new TextEncoder().encode(canonicalize(credential)));
  return { ...credential, proof: { type: 'Ed25519Signature2020', verificationMethod: `${DID}#key-1`, proofPurpose: 'assertionMethod', proofValue: Buffer.from(signature).toString('base64url'), ...extra } };
}

const delegation = (id: string, issuer: string, subject: string, extra: Record<string, unknown> = {}) => ({
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: `urn:uuid:${id}`,
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer,
  issuanceDate: '2026-01-01T00:00:00Z',
  credentialSubject: { id: subject, delegation: { id, issuerDid: issuer, subjectDid: subject, scopes: ['read'], constraints: { audience: 'did:web:server' }, status: 'active', ...extra } },
});

describe('runner', () => {
  it('records a thrown adapter as an error and refuses a duplicate id', async () => {
    const throwing = { ...adapter, name: 'x', resolveDidKey: async () => { throw new Error('boom'); } } as unknown as conformance.ConformanceAdapter;
    const report = await conformance.runConformance(throwing, [{ id: 'a', category: 'did-key-resolution', description: '', expected: 'pass', reason: '', input: {} }]);
    expect(report.results[0]).toMatchObject({ actual: 'error', ok: false });
    expect(conformance.formatReport(report)).toContain('RESULT: FAIL');
    const unknown = await conformance.runConformance(adapter, [{ id: 'b', category: 'other' as never, description: '', expected: 'fail', reason: '', input: {} }]);
    expect(unknown.results[0]!.actual).toBe('error');
    for (const category of ['audit-integrity', 'negotiation'] as const) {
      const outside = await conformance.runConformance(adapter, [{ id: category, category, description: '', expected: 'fail', reason: '', input: {} }]);
      expect(outside.allMatched).toBe(true);
    }
    const dir = mkdtempSync(join(tmpdir(), 'vectors-'));
    const file = { version: '1', category: 'did-key-resolution', vectors: [{ id: 'dup', category: 'did-key-resolution', description: '', expected: 'pass', reason: '', input: {} }] };
    writeFileSync(join(dir, 'a.json'), JSON.stringify(file));
    writeFileSync(join(dir, 'b.json'), JSON.stringify(file));
    expect(() => conformance.loadVectors(dir)).toThrow(/duplicate/);
    expect(conformance.loadVectors(dir, ['card-proof'])).toEqual([]);
  });
});

describe('adapter refusals', () => {
  it('fails closed on inputs that are not of their form', async () => {
    expect((await adapter.verifySignedProof({ proof: {}, now: 'x' as never, skewSeconds: 1 })).outcome).toBe('fail');
    expect((await adapter.verifySignedProof({ proof: 'x', now: 1, skewSeconds: 1 })).outcome).toBe('fail');
    expect((await adapter.verifySignedProof({ proof: { jws: 'a', meta: { did: 1 } }, didDocuments: {}, now: 1, skewSeconds: 1 })).outcome).toBe('fail');
    expect((await adapter.verifySignedProof({ proof: { jws: 'a', meta: { did: DID } }, didDocuments: { [DID]: document }, keyId: '#nope', now: 1, skewSeconds: 1 })).outcome).toBe('fail');
    expect((await adapter.resolveDidKey({ did: 'did:web:x' })).outcome).toBe('fail');
    expect((await adapter.resolveDidWeb({ did: 'did:key:z6Mk' })).outcome).toBe('fail');
    expect((await adapter.verifyCardProof({ proof: {}, request: { method: 'x' }, jwks: null as never, expectedAudience: DID, nowMs: 0, skewSeconds: 5 })).outcome).toBe('fail');
    expect((await adapter.verifyEntityCard({ card: { id: 'did:web:a', entityType: 'agent', name: 'a', responsibleParty: 'did:web:b' } })).detail).toContain('no delegation chain');
    expect((await adapter.verifyEntityCard({ card: null })).outcome).toBe('fail');
    expect((await adapter.verifyDelegationChain({ leaf: 'not.a.jwt', serverDid: 'did:web:server', didDocuments: {} })).outcome).toBe('fail');
    expect((await adapter.verifyDelegationChain({ leaf: null, ancestors: null as never, serverDid: 'did:web:server', didDocuments: {} })).outcome).toBe('fail');
  });
});

describe('legacy §6.2 reading', () => {
  it('verifies a signed delegation and refuses each broken rule', async () => {
    const docs = { [DID]: document };
    const root = await signLegacy(delegation('root', DID, DID));
    expect(conformance.legacyChainRefusal([root], 'did:web:server', docs, Date.now())).toBeUndefined();
    expect(conformance.legacyChainRefusal([root, root], 'did:web:server', docs, Date.now())).toMatch(/repeats/);
    expect(conformance.legacyChainRefusal([await signLegacy(delegation('r', DID, DID, { parentId: 'x' }))], 'did:web:server', docs, Date.now())).toMatch(/names a parent/);
    expect(conformance.legacyChainRefusal([root], 'did:web:other', docs, Date.now())).toMatch(/another audience/);
    const child = await signLegacy(delegation('child', DID, 'did:web:c', { parentId: 'root', scopes: ['write'] }));
    expect(conformance.legacyChainRefusal([root, child], 'did:web:server', docs, Date.now())).toMatch(/widens/);
    const orphan = await signLegacy(delegation('orphan', DID, 'did:web:c', { parentId: 'elsewhere' }));
    expect(conformance.legacyChainRefusal([root, orphan], 'did:web:server', docs, Date.now())).toMatch(/does not name its parent/);
    const stranger = await signLegacy(delegation('s', 'did:web:z', 'did:web:c', { parentId: 'root' }));
    expect(conformance.legacyChainRefusal([root, stranger], 'did:web:server', docs, Date.now())).toMatch(/not issued by its parent/);
    for (const [credential, pattern] of [
      [{ ...root, type: ['VerifiableCredential'] }, /not a DelegationCredential/],
      [{ ...root, credentialSubject: { ...(root['credentialSubject'] as object), extra: 1 } }, /more than id/],
      [{ ...root, credentialSubject: { id: DID, delegation: { id: 1 } } }, /malformed/],
      [await signLegacy(delegation('i', DID, DID, { status: 'revoked' })), /not active/],
      [{ ...root, issuer: 42 }, /no issuer/],
      [{ ...root, expirationDate: '2020-01-01T00:00:00Z' }, /expired/],
      [await signLegacy(delegation('n', DID, DID, { constraints: { notAfter: 1 } })), /notAfter/],
      [await signLegacy(delegation('b', DID, DID, { constraints: { notBefore: 9_999_999_999 } })), /notBefore/],
      ['not an object', /not a credential/],
    ] as const) {
      expect(conformance.legacyChainRefusal([credential], 'did:web:server', docs, Date.now()), String(pattern)).toMatch(pattern);
    }
  });

  it('refuses proofs whose key, type, purpose or signature does not hold', async () => {
    const docs = { [DID]: document };
    const base = delegation('root', DID, DID);
    expect(conformance.verifyLegacyProof(await signLegacy(base), docs)).toBeUndefined();
    expect(conformance.verifyLegacyProof('x', docs)).toMatch(/not a credential/);
    expect(conformance.verifyLegacyProof(base, docs)).toMatch(/no proof/);
    expect(conformance.verifyLegacyProof(await signLegacy(base, { type: 'Other' }), docs)).toMatch(/unsupported/);
    expect(conformance.verifyLegacyProof(await signLegacy(base, { proofPurpose: 'authentication' }), docs)).toMatch(/assertionMethod/);
    expect(conformance.verifyLegacyProof(await signLegacy(base, { verificationMethod: '' }), docs)).toMatch(/names no key/);
    expect(conformance.verifyLegacyProof(await signLegacy(base, { proofValue: '!!' }), docs)).toMatch(/no signature/);
    expect(conformance.verifyLegacyProof(await signLegacy({ ...base, issuer: { id: DID } }), docs)).toBeUndefined();
    expect(conformance.verifyLegacyProof({ ...(await signLegacy(base)), issuanceDate: '2026-02-01T00:00:00Z' }, docs)).toMatch(/does not verify/);
    expect(conformance.verifyLegacyProof({ ...(await signLegacy(base)), extra: 1n } as never, docs)).toMatch(/canonical/);
    expect(conformance.verifyLegacyProof(await signLegacy({ ...base, issuer: 7 } as never), docs)).toMatch(/no issuer/);
    expect(conformance.assertionKey(document, DID, 'key-1', true)).toBeDefined();
    expect(conformance.assertionKey({ ...document, assertionMethod: 'x' }, DID, undefined, false)).toBeUndefined();
    expect(conformance.assertionKey(document, DID, 7, true)).toBeUndefined();
    expect(conformance.assertionKey(document, DID, 'did:web:other#k', true)).toBeUndefined();
    expect(conformance.assertionKey(document, DID, DID, true)).toBeUndefined();
    const method = (document['verificationMethod'] as Record<string, unknown>[])[0]!;
    expect(conformance.assertionKey({ ...document, verificationMethod: [{ ...method, controller: 'did:web:x' }] }, DID, undefined, false)).toBeUndefined();
    expect(conformance.assertionKey({ ...document, verificationMethod: [{ ...method, publicKeyJwk: { kty: 'EC' } }] }, DID, undefined, false)).toBeUndefined();
    expect(conformance.issuerDid({ id: '' })).toBeUndefined();
  });

  it('verifies a VC-JWT and refuses its broken forms', async () => {
    const docs = { [DID]: document };
    const vc = delegation('jwt', DID, DID);
    const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const jwt = async (header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> => {
      const input = `${encode(header)}.${encode(payload)}`;
      return `${input}.${Buffer.from(await signer.sign(new TextEncoder().encode(input))).toString('base64url')}`;
    };
    const now = Date.now();
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA', kid: `${DID}#key-1` }, { iss: DID, vc }), docs, now)).toHaveProperty('credential');
    expect(conformance.verifyVcJwt('a.b', docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt('!!.!!.!!', docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(await jwt({ alg: 'ES256' }, { iss: DID, vc }), docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA', kid: '' }, { iss: DID, vc }), docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA' }, { iss: 'did:web:z', vc }), docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA' }, { iss: DID, vc, exp: 'soon' }), docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA' }, { iss: DID, vc, exp: 1 }), docs, now)).toMatchObject({ refusal: 'expired (exp)' });
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA' }, { iss: DID, vc, nbf: 9_999_999_999 }), docs, now)).toMatchObject({ refusal: 'not yet valid (nbf)' });
    expect(conformance.verifyVcJwt(await jwt({ alg: 'EdDSA', kid: '#nope' }, { iss: DID, vc }), docs, now)).toHaveProperty('refusal');
    const good = await jwt({ alg: 'EdDSA' }, { iss: DID, vc });
    expect(conformance.verifyVcJwt(`${good.slice(0, -2)}+/`, docs, now)).toHaveProperty('refusal');
    expect(conformance.verifyVcJwt(`${good.split('.').slice(0, 2).join('.')}.${Buffer.alloc(64).toString('base64url')}`, docs, now)).toMatchObject({ refusal: 'signature does not verify' });
  });
});

describe('status-list reading', () => {
  it('refuses mistaken configuration and reads keepers, windows and indexes', async () => {
    expect(() => conformance.statusConfiguration({ trustedRootIssuer: '' })).toThrow(/non-empty/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: 'x' as never })).toThrow(/does not map/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: 'x' as never } })).toThrow(/does not map/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: ['ftp://x'] } })).toThrow(/does not map/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: ['https://x.example/'] } })).toThrow(/followed by/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: ['https://X.example'] } })).toThrow(/lower case/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: ['https://x.example/a/'] } })).toThrow(/ends in/);
    expect(() => conformance.statusConfiguration({ statusListIssuers: { a: ['https://x.example/a'], b: ['https://x.example/a'] } })).toThrow(/two issuers/);
    const config = conformance.statusConfiguration({ statusListIssuers: { 'did:web:svc': ['https://svc.example'] } });
    expect(conformance.keeper('https://svc.example/list', 'did:web:o', config)).toEqual({ did: 'did:web:svc', unbound: false });
    expect(conformance.keeper('https://other.example/list', 'did:web:o', config)).toEqual({ did: 'did:web:o', unbound: true });
    expect(verifier.windowVerdict(undefined, '2026-01-01T00:00:00.123456789+05:00', Date.parse('2025-01-01T00:00:00Z'), 0)).toBe('inside');
    expect(verifier.windowVerdict('2026-01-01', undefined, 0, 0)).toBe('malformed');
    expect(verifier.isCalendarDateTime('2026-02-30T00:00:00Z')).toBe(false);
    expect(verifier.isCalendarDateTime('2026-02-28T00:00:00Z')).toBe(true);
    expect(verifier.isCalendarDateTime('2026-13-01T00:00:00Z')).toBe(false);
    expect(verifier.parseStatusListIndex(7)).toBeUndefined();
    expect(verifier.parseStatusListIndex('0'.repeat(10) + '7')).toBe(7);
    expect(verifier.parseStatusListIndex('99999999999999999')).toBeUndefined();
    expect(() => verifier.decodeStatusListBits('u!!')).toThrow(/GZIP/);
    expect(verifier.decodeStatusListBits(gzipSync(Buffer.alloc(2)).toString('base64url'))).toHaveLength(2);
    expect(await conformance.statusListRefusal({ credential: { credentialStatus: 'x' }, statusLists: {}, didDocuments: {}, serverDid: 's' }, 0)).toMatch(/credentialStatus/);
    expect(await conformance.statusListRefusal({ credential: { credentialStatus: {} }, statusLists: {}, didDocuments: {}, serverDid: 's' }, 0)).toMatch(/names no list/);
    expect(await conformance.statusListRefusal({ credential: null, statusLists: {}, didDocuments: {}, serverDid: 's' }, 0)).toMatch(/unreadable/);
    expect(
      await conformance.statusListRefusal(
        { credential: { issuer: 'did:web:o', credentialStatus: { statusListCredential: 'https://o.example/l' } }, statusLists: {}, didDocuments: {}, serverDid: 's' },
        0,
      ),
    ).toMatch(/no purpose/);
  });
});

describe('delegation binding', () => {
  it('digests, references and nesting as SPEC §7.8 reads them', () => {
    expect(conformance.credentialSignedForm('a..b')).toBeUndefined();
    expect(conformance.credentialSignedForm('a.b.!!')).toBeUndefined();
    expect(conformance.credentialSignedForm({ proof: 'x' })).toBeUndefined();
    expect(conformance.credentialSignedForm({ proof: { proofValue: 7 } })).toBeUndefined();
    expect(conformance.credentialDigest({ a: 1n, proof: { proofValue: 'AAAA' } } as never)).toBeUndefined();
    expect(conformance.chainDigest([])).toBeUndefined();
    expect(conformance.chainDigest([{ proof: { proofValue: '' } }])).toBeUndefined();
    expect(conformance.credentialShownId(42)).toBeUndefined();
    expect(conformance.credentialShownId('a.b')).toBeUndefined();
    expect(conformance.credentialShownId(`h.${Buffer.from([0xff]).toString('base64url')}.s`)).toBeUndefined();
    expect(conformance.credentialShownId(`h.${Buffer.from('﻿{}').toString('base64url')}.s`)).toBeUndefined();
    expect(conformance.credentialShownId(`h.${Buffer.from('{not json').toString('base64url')}.s`)).toBeUndefined();
    expect(conformance.credentialShownId(`h.${Buffer.from('{"vc":1}').toString('base64url')}.s`)).toBeUndefined();
    expect(conformance.credentialShownId(`h.${Buffer.from('{"vc":{},"jti":"j"}').toString('base64url')}.s`)).toBe('j');
    expect(conformance.delegationReference('x'.repeat(257))).toMatch(/^sha256:/);
    expect(conformance.delegationReference('a\ud800')).toMatch(/^sha256:/);
    expect(conformance.delegationReference('ok')).toBe('ok');
    expect(conformance.delegationRef({})).toBeUndefined();
    expect(conformance.hasUnprintableCharacter('😀')).toBe(false);
    expect(conformance.hasUnprintableCharacter('\udc00')).toBe(true);
    expect(conformance.hasUnprintableCharacter('󠀁')).toBe(true);
    expect(Buffer.from(conformance.wtf8Bytes('é€😀\ud800')).toString('hex')).toBe('c3a9e282acf09f9880eda080');
    expect(conformance.jsonTextNestingDepth('{"a":"[\\"]"}')).toBe(1);
    expect(conformance.jsonTextNestingDepth('['.repeat(70), 64)).toBe(65);
    expect(conformance.valueNestingDepth(7)).toBe(0);
    expect(conformance.readSignatureBase64('AA==', true)).toEqual(Uint8Array.from([0]));
    expect(conformance.readSignatureBase64('AA=', true)).toBeUndefined();
    expect(conformance.readSignatureBase64('A', true)).toBeUndefined();
    expect(conformance.readSignatureBase64('AA=A', false)).toBeUndefined();
    expect(conformance.readSignatureBase64('A A\n==', false)).toEqual(Uint8Array.from([0]));
  });
});
