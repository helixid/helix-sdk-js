// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// KYA-OS story F-2: the verifier's pieces on their own (request proof, status
// lists, DID resolution, schema evaluator, card, data integrity, attestations).

import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { EnvSigner, verifier } from '../../../../src/core/kyaos/index.js';
import { buildDIDDocument } from '../../../../src/core/did.js';
import { generateKeyPair } from '../../../../src/core/keys.js';
import { base58btcEncode } from '../../../../src/core/vp-crypto.js';

const keys = generateKeyPair();
const DID = 'did:web:agent.helix.test';
const signer = new EnvSigner({ did: DID, envVar: 'K', env: { K: keys.privateKey } });
const document = buildDIDDocument(DID, keys.publicKey) as unknown as verifier.DidResolver extends (did: string) => Promise<infer D> ? NonNullable<D> : never;
const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1' } } };
const AUDIENCE = 'did:web:orders.helix.test';
const NOW = Date.parse('2026-06-01T00:00:00Z');

describe('request proof', () => {
  it('mints a proof whose detached JWS verifies and whose requestHash binds the request minus _meta', async () => {
    const proof = await verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW, nonce: 'bm9uY2U' });
    expect(proof).toMatchObject({ prf: 'org.kya-os/proof.v1', alg: 'EdDSA', did: DID, kid: `${DID}#key-1`, audience: AUDIENCE, created: NOW / 1000, expires: NOW / 1000 + 60 });
    expect(proof.jws.split('.')[1]).toBe('');
    expect(verifier.verifyDetachedJws(proof, Buffer.from(keys.publicKey, 'hex'))).toBe(true);
    expect(verifier.requestHashContentDigest({ ...request, params: { ...request.params, _meta: { x: 1 } } })).toBe(proof.requestHash);
    expect(verifier.requestHashContentDigest({ method: 'tools/call' })).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
    expect(verifier.coveredRequest({ method: 'ping', params: 'raw' })).toEqual({ method: 'ping', params: 'raw' });
  });

  it('reads the proof from _meta under the canonical key before the legacy key, and the carried chain', () => {
    expect(verifier.readRequestProof({ 'org.kya-os/request-proof': { a: 1 }, 'org.kya-os/proof@1': { b: 2 } })).toEqual({ a: 1 });
    expect(verifier.readRequestProof({ 'org.kya-os/proof@1': { b: 2 } })).toEqual({ b: 2 });
    expect(verifier.readRequestProof({ 'org.kya-os/request-proof': null })).toBeUndefined();
    expect(verifier.readRequestProof('nope')).toBeUndefined();
    expect(verifier.readCarriedChain({ 'org.kya-os/delegation-chain': [1] })).toEqual([1]);
    expect(verifier.readCarriedChain({ 'org.kya-os/delegation-chain': null })).toBeUndefined();
    expect(verifier.readCarriedChain(undefined)).toBeUndefined();
  });

  it('parses only the §8.2 shape', async () => {
    const proof = await verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW, cnfJkt: 'abc' });
    expect(verifier.parseRequestProof(proof)).toBe(proof);
    const variants: Record<string, unknown>[] = [
      { ...proof, prf: 'org.kya-os/proof.v2' },
      { ...proof, alg: 'HS256' },
      { ...proof, did: 'not-a-did' },
      { ...proof, kid: 'did:web:x' },
      { ...proof, audience: 42 },
      { ...proof, nonce: 'has space' },
      { ...proof, created: 1.5 },
      { ...proof, expires: -1 },
      { ...proof, requestHash: '' },
      { ...proof, jws: '' },
      { ...proof, httpSig: '' },
      { ...proof, cnf: { jkt: 'abc', extra: 1 } },
      { ...proof, cnf: 'abc' },
    ];
    for (const variant of variants) expect(verifier.parseRequestProof(variant), JSON.stringify(variant)).toBeUndefined();
    expect(verifier.parseRequestProof(null)).toBeUndefined();
    expect(verifier.parseRequestProof({ ...proof, httpSig: 'sig' })).toBeDefined();
  });

  it('refuses a detached JWS whose header names another alg or kid, or that is not three strict segments', async () => {
    const proof = await verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW });
    const publicKey = Buffer.from(keys.publicKey, 'hex');
    const header = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const signature = proof.jws.split('.')[2]!;
    expect(verifier.verifyDetachedJws({ ...proof, jws: `${header({ alg: 'EdDSA', kid: 'did:web:other#k' })}..${signature}` }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, jws: `${header({ alg: 'ES256', kid: proof.kid })}..${signature}` }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, jws: `${proof.jws.split('.')[0]}.cGF5bG9hZA.${signature}` }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, jws: 'a..b' }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, jws: `bm90LWpzb24..${signature}` }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, jws: `${proof.jws.split('.')[0]}..${signature}=` }, publicKey)).toBe(false);
    expect(verifier.verifyDetachedJws(proof, new Uint8Array(32))).toBe(false);
    expect(verifier.verifyDetachedJws({ ...proof, nonce: 'other' }, publicKey)).toBe(false);
  });

  it('reports every window problem', () => {
    const base = { created: 1000, expires: 1060 } as verifier.RequestProof;
    expect(verifier.windowProblems(base, 1000, 5)).toEqual([]);
    expect(verifier.windowProblems({ ...base, expires: 1000 }, 1000, 5)).toEqual(['invalid_window']);
    expect(verifier.windowProblems({ ...base, expires: 1061 }, 1000, 5)).toEqual(['ttl_too_long']);
    expect(verifier.windowProblems(base, 990, 5)).toEqual(['created_in_future']);
    expect(verifier.windowProblems(base, 1070, 5)).toEqual(['expired']);
    expect(verifier.windowProblems(base, 1065, 5)).toEqual([]);
  });

  it('computes the RFC 7638 thumbprint over crv, kty, x', () => {
    // RFC 7638 §3.1 fixes the member order; the thumbprint is base64url of SHA-256 of that JSON.
    const jkt = verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' });
    expect(jkt).toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
    expect(verifier.didOfKid('did:web:a#k')).toBe('did:web:a');
    expect(verifier.didOfKid('did:web:a')).toBe('did:web:a');
  });
});

describe('status lists', () => {
  const bits = new Uint8Array(32);
  bits[1] = 0b0100_0000; // index 9 set
  const encoded = `u${gzipSync(bits).toString('base64url')}`;
  const entry = (index: string, extra: Partial<verifier.BitstringStatusEntry> = {}): verifier.BitstringStatusEntry => ({
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: index,
    statusListCredential: 'https://issuer.example/status/1',
    ...extra,
  });
  const read = (extra: Partial<verifier.StatusListRead> = {}): verifier.StatusListRead => ({ bits: verifier.decodeStatusListBits(encoded), ...extra });
  const options = { now: NOW };

  it('decodes a multibase or bare base64url GZIP list and reads bits MSB first', () => {
    expect(verifier.decodeStatusListBits(encoded)).toEqual(bits);
    expect(verifier.decodeStatusListBits(encoded.slice(1))).toEqual(bits);
    expect(verifier.readStatusBit(bits, 9)).toBe(1);
    expect(verifier.readStatusBit(bits, 8)).toBe(0);
    expect(verifier.readStatusBit(bits, 256)).toBeUndefined();
    expect(() => verifier.decodeStatusListBits(Buffer.from('not gzip').toString('base64url'))).toThrow(/GZIP/);
  });

  it('decodes a status-list credential, Bitstring v1.0 window first, VC 1.1 members as the fallback', () => {
    const list = {
      id: 'https://issuer.example/status/1',
      issuer: { id: 'did:web:issuer.example' },
      validFrom: '2026-01-01T00:00:00Z',
      expirationDate: '2027-01-01T00:00:00Z',
      credentialSubject: { statusPurpose: ['revocation', 'suspension'], encodedList: encoded },
    };
    expect(verifier.decodeStatusListCredential(list, { fresh: false })).toEqual({
      bits,
      issuer: 'did:web:issuer.example',
      statusPurpose: ['revocation', 'suspension'],
      id: 'https://issuer.example/status/1',
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2027-01-01T00:00:00Z',
      fresh: false,
    });
    expect(verifier.decodeStatusListCredential({ issuer: 'did:web:i', validUntil: 42, credentialSubject: { encodedList: encoded } })).toMatchObject({ validUntil: '', fresh: true });
    expect(() => verifier.decodeStatusListCredential(null)).toThrow(/object/);
    expect(() => verifier.decodeStatusListCredential({ credentialSubject: {} })).toThrow(/encodedList/);
  });

  it('parses only whole decimal indexes', () => {
    expect(verifier.parseStatusListIndex('0007')).toBe(7);
    expect(verifier.parseStatusListIndex('7')).toBe(7);
    expect(verifier.parseStatusListIndex(7)).toBeUndefined();
    expect(verifier.parseStatusListIndex('7.0')).toBeUndefined();
    expect(verifier.parseStatusListIndex(' 7')).toBeUndefined();
    expect(verifier.parseStatusListIndex('99999999999999999')).toBeUndefined();
  });

  it('holds an entry to the list by issuer, purpose, id, window and bit', () => {
    const issuer = 'did:web:issuer.example';
    expect(verifier.checkStatusEntry(entry('8'), issuer, read(), options)).toEqual({ ok: true, fresh: true });
    expect(verifier.checkStatusEntry(entry('9'), issuer, read(), options)).toMatchObject({ ok: false, code: 'status_revoked' });
    expect(verifier.checkStatusEntry({ ...entry('9'), statusPurpose: 'suspension' }, issuer, read(), options)).toMatchObject({ ok: false, code: 'status_revoked', message: /suspended/ });
    expect(verifier.checkStatusEntry(entry('8', { statusSize: 2 }), issuer, read(), options)).toMatchObject({ code: 'status_entry_malformed' });
    expect(verifier.checkStatusEntry(entry('x'), issuer, read(), options)).toMatchObject({ code: 'status_entry_malformed' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, undefined, options)).toMatchObject({ code: 'status_unavailable', fresh: true });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ issuer: 'did:web:other' }), options)).toMatchObject({ code: 'status_list_mismatch' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ statusPurpose: 'suspension' }), options)).toMatchObject({ code: 'status_list_mismatch' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ statusPurpose: ['suspension', 'revocation'] }), options)).toEqual({ ok: true, fresh: true });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ id: 'https://issuer.example/status/2' }), options)).toMatchObject({ code: 'status_list_mismatch' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ validUntil: '2026-03-01T00:00:00Z' }), options)).toMatchObject({ code: 'status_stale' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ validFrom: 'yesterday' }), options)).toMatchObject({ code: 'status_stale' });
    expect(verifier.checkStatusEntry(entry('8'), issuer, read({ fresh: false }), options)).toEqual({ ok: true, fresh: false });
    expect(verifier.checkStatusEntry(entry('4096'), issuer, read(), options)).toMatchObject({ code: 'status_entry_malformed' });
  });
});

describe('DID resolution', () => {
  it('resolves an Ed25519 did:key offline and nothing else', () => {
    const did = `did:key:${(verifier as unknown as { publicKeyOfDidKey: unknown }) && 'z6Mk'}`;
    expect(verifier.publicKeyOfDidKey(did)).toBeUndefined();
    expect(verifier.publicKeyOfDidKey('did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH')?.length).toBe(32);
    expect(verifier.publicKeyOfDidKey('did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVX!')).toBeUndefined();
    expect(verifier.publicKeyOfDidKey(`did:key:z6Mk${'1'.repeat(80)}`)).toBeUndefined();
    expect(verifier.publicKeyOfDidKey('did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc')).toBeUndefined();
    expect(verifier.publicKeyOfDidKey('did:web:example.com')).toBeUndefined();
    const doc = verifier.didKeyDocument('did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH')!;
    expect(doc.id).toBe('did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH');
    expect(doc.assertionMethod).toEqual([`${doc.id}#z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH`]);
    expect(verifier.didKeyDocument('did:web:x')).toBeUndefined();
  });

  it('derives did:web document URLs and refuses hosts or segments that are not one', () => {
    expect(verifier.didWebDocumentUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json');
    expect(verifier.didWebDocumentUrl('did:web:example.com%3A8443:agents:a1')).toBe('https://example.com:8443/agents/a1/did.json');
    expect(verifier.didWebDocumentUrl('did:web:example.com:..:x')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:example.com:a%2Fb')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:exa%2Fmple.com')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:%E0%A4%A')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:example.com:a%E0%A4%A')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:')).toBeUndefined();
    expect(verifier.didWebDocumentUrl('did:web:a:b:c:d')).toBe('https://a/b/c/d/did.json');
    expect(verifier.didWebDocumentUrl('did:key:z6Mk')).toBeUndefined();
  });

  it('resolves did:web through the injected fetch and refuses a substituted document', async () => {
    const served: Record<string, unknown> = { 'https://agent.helix.test/.well-known/did.json': document };
    const resolve = verifier.createDidResolver({
      fetch: async (url) => ({ ok: url in served, status: url in served ? 200 : 404, json: async () => served[url] }),
    });
    expect(await resolve(DID)).toEqual(document);
    expect(await resolve('did:web:other.helix.test')).toBeNull();
    expect(await resolve('did:web:bad host')).toBeNull();
    expect(await resolve('did:pkh:eip155:1:0xabc')).toBeNull();
    served['https://agent.helix.test/.well-known/did.json'] = { ...document, id: 'did:web:other' };
    expect(await resolve(DID)).toBeNull();
    const rewritten = verifier.createDidResolver({ fetch: async (url) => ({ ok: true, status: 200, json: async () => ({ ...document, id: url }) }), rewriteUrl: () => DID });
    expect((await rewritten(DID))?.id).toBe(DID);
    expect((await verifier.createDidResolver()('did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH'))?.id).toBeDefined();
  });

  it('lists the Ed25519 keys a document publishes, with their kids', async () => {
    const keysOf = verifier.ed25519KeysOf({
      id: DID,
      verificationMethod: [
        document.verificationMethod![0]!,
        { id: '#relative', controller: DID, publicKeyMultibase: document.verificationMethod![0]!.publicKeyMultibase },
        { id: `${DID}#broken`, controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'short' } },
        { id: `${DID}#none`, controller: DID },
        'not a method' as never,
      ],
    });
    expect(keysOf.map((key) => key.kid)).toEqual([`${DID}#key-1`, `${DID}#relative`]);
    const resolveKeys = verifier.createDidKeysResolver(async (did) => (did === DID ? document : null));
    expect((await resolveKeys(DID)).length).toBe(1);
    await expect(resolveKeys('did:web:other')).rejects.toThrow(/did not resolve/);
  });
});

describe('JSON schema evaluator additions', () => {
  it('evaluates maxLength, minimum and maximum, and refuses unknown keywords', () => {
    expect(verifier.validateJsonSchema({ type: 'string', maxLength: 2 }, 'abc')).toHaveLength(1);
    expect(verifier.validateJsonSchema({ type: 'number', minimum: 1, maximum: 3 }, 0)).toHaveLength(1);
    expect(verifier.validateJsonSchema({ type: 'number', minimum: 1, maximum: 3 }, 4)).toHaveLength(1);
    expect(verifier.validateJsonSchema({ type: 'integer', minimum: 1, maximum: 3 }, 2)).toEqual([]);
    expect(() => verifier.validateJsonSchema({ uniqueItems: true }, [])).toThrow(verifier.JsonSchemaError);
    expect(() => verifier.validateJsonSchema({ $ref: 'https://elsewhere' }, {})).toThrow(/local/);
    expect(() => verifier.validateJsonSchema({ $ref: '#/$defs/missing', $defs: {} }, {})).toThrow(/resolve/);
    expect(verifier.describeViolations([{ path: '$.a', message: 'm' }])).toBe('$.a: m');
    expect(verifier.deepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] })).toBe(true);
  });
});

describe('Entity Card', () => {
  it('accepts a card and refuses an unknown member', () => {
    const card = { id: 'did:web:example.com:agents:a', entityType: 'agent', name: 'A', capabilities: ['x'] };
    expect(verifier.validateEntityCard(card)).toEqual([]);
    expect(verifier.isEntityCard(card)).toBe(true);
    expect(verifier.validateEntityCard({ ...card, extra: 1 })[0]).toMatch(/extra/);
    expect(verifier.isEntityCard({ ...card, id: 'did:pkh:x' })).toBe(false);
  });
});

describe('data integrity and attestations', () => {
  const resolve: verifier.DidResolver = async (did) => (did === DID ? document : null);
  const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-01-01T00:00:00Z', verificationMethod: `${DID}#key-1`, proofPurpose: 'assertionMethod', proofValue: `z${base58btcEncode(Uint8Array.from({ length: 64 }, (_unused, index) => index + 1))}` };

  it('refuses each malformed proof for its reason', async () => {
    const doc = { issuer: DID, a: 1 };
    const reason = async (value: Record<string, unknown>): Promise<string> => {
      const verdict = await verifier.verifyDataIntegrity(value, resolve);
      return verdict.ok ? 'ok' : verdict.reason;
    };
    expect(await reason({ ...doc })).toBe('proof_missing');
    expect(await reason({ ...doc, proof: { ...proof, cryptosuite: 'other' } })).toBe('proof_unsupported');
    expect(await reason({ ...doc, proof: { ...proof, proofPurpose: 'authentication' } })).toBe('proof_purpose_mismatch');
    expect(await reason({ ...doc, proof: { ...proof, proofValue: 'abc' } })).toBe('proof_value_malformed');
    expect(await reason({ ...doc, proof: { ...proof, proofValue: 'z0OI' } })).toBe('proof_value_malformed');
    expect(await reason({ ...doc, proof: { ...proof, proofValue: 'z11' } })).toBe('proof_value_malformed');
    expect(await reason({ ...doc, proof: { ...proof, verificationMethod: 'nohash' } })).toBe('proof_method_malformed');
    expect(await reason({ ...doc, issuer: 'did:web:other', proof })).toBe('proof_issuer_mismatch');
    expect(await reason({ ...doc, issuer: { id: 'did:web:other' }, proof })).toBe('proof_issuer_mismatch');
    expect(await reason({ ...doc, '@context': ['a'], proof: { ...proof, '@context': ['b'] } })).toBe('proof_context_mismatch');
    expect(await reason({ ...doc, proof: { ...proof, verificationMethod: 'did:web:unknown#k' }, issuer: 'did:web:unknown' })).toBe('did_unresolved');
    const throwing = async (): Promise<never> => { throw new Error('down'); };
    expect((await verifier.verifyDataIntegrity({ ...doc, proof }, throwing)) as { reason: string }).toMatchObject({ reason: 'did_unresolved' });
    expect(await reason({ ...doc, proof: { ...proof, verificationMethod: `${DID}#key-9` } })).toBe('key_rejected');
    expect(await reason({ ...doc, proof, bad: 1n as never })).toBe('document_not_canonical');
    expect(await reason({ ...doc, proof })).toBe('signature_invalid');
    expect(verifier.issuerOf(42)).toBeUndefined();
  });

  it('verifies a signed hop and an attestation from the fixtures through checkCapabilities', async () => {
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
      id: 'urn:uuid:1',
      type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
      issuer: DID,
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-12-31T00:00:00Z',
      credentialSubject: { id: 'did:web:subject', capability: 'read:orders' },
      credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '1', statusListCredential: 'https://issuer.example/status/1' },
    };
    // Sign through the same construction the verifier checks.
    const config = { type: proof.type, cryptosuite: proof.cryptosuite, created: proof.created, verificationMethod: proof.verificationMethod, proofPurpose: proof.proofPurpose, '@context': vc['@context'] };
    const signature = await signer.sign(verifier.hashData(config, vc));
    const signed = { ...vc, proof: { type: proof.type, cryptosuite: proof.cryptosuite, created: proof.created, verificationMethod: proof.verificationMethod, proofPurpose: proof.proofPurpose, proofValue: `z${base58btcEncode(signature)}` } };
    const bits = new Uint8Array(32);
    const fetchStatusList: verifier.FetchStatusList = async () => ({ bits, fresh: true });
    const options = { subjectDid: 'did:web:subject', now: NOW, fetchStatusList };
    expect((await verifier.verifyDataIntegrity(signed, resolve)).ok).toBe(true);
    const check = await verifier.checkCapabilities([{ name: 'read:orders', attestations: [{ vc: signed }] }, 'bare', { name: 'write', attestations: [{ vc: { ...signed, credentialSubject: { ...signed.credentialSubject, capability: 'write' } } }] }], resolve, options);
    expect(check).toEqual({ verified: ['read:orders'], unverified: ['bare', 'write'], fresh: true, refusals: { write: 'signature_invalid' } });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, subjectDid: 'did:web:other' })).toMatchObject({ reason: 'subject_mismatch' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, capability: 'other' })).toMatchObject({ reason: 'capability_mismatch' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, trustedIssuers: ['did:web:other'] })).toMatchObject({ reason: 'issuer_untrusted' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, now: Date.parse('2027-06-01T00:00:00Z') })).toMatchObject({ reason: 'credential_expired' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, fetchStatusList: undefined })).toMatchObject({ reason: 'status_seam_missing' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, fetchStatusList: async () => { throw new Error('down'); } })).toMatchObject({ reason: 'status_unavailable' });
    expect(await verifier.verifyCapabilityAttestation(signed, resolve, { ...options, fetchStatusList: async () => undefined })).toMatchObject({ reason: 'status_unavailable' });
    expect(await verifier.verifyCapabilityAttestation({ ...signed, extra: 1 }, resolve, options)).toMatchObject({ reason: 'schema_invalid' });
    expect(verifier.capabilityName('x')).toBe('x');
    expect(verifier.capabilityName({ name: 'y', attestations: [] })).toBe('y');
    expect(verifier.deriveConformanceLevel({ verified: ['a'], unverified: [] }, false)).toBe('L2');
  });

  it('ports the chain helpers: decimals, caveats, invoker', () => {
    expect(verifier.decimalLte('1.50', '1.5')).toBe(true);
    expect(verifier.decimalLte('1.51', '1.5')).toBe(false);
    expect(verifier.decimalLte('x', '1')).toBe(false);
    expect(verifier.caveatNarrows({ type: 'MaxAmount', limit: '1' }, { type: 'MaxAmount', limit: '1', currency: 'USD' })).toBe(true);
    expect(verifier.caveatNarrows({ type: 'MaxAmount', limit: '1', currency: 'EUR' }, { type: 'MaxAmount', limit: '1', currency: 'USD' })).toBe(false);
    expect(verifier.caveatNarrows({ type: 'ValidUntil', date: '2026-01-01T00:00:00Z' }, { type: 'ValidUntil' })).toBe(false);
    expect(verifier.caveatNarrows({ type: 'Region', regions: ['EU'] }, { type: 'Region', regions: ['EU'] })).toBe(true);
    expect(verifier.caveatNarrows({ type: 'A' }, { type: 'B' })).toBe(false);
    expect(verifier.invokerOf({ credentialSubject: { controller: 'did:web:c' } as never })).toBe('did:web:c');
    expect(verifier.isDelegationHop({})).toBe(false);
    expect(verifier.isTrustedIssuer('did:web:a', '*')).toBe(true);
    expect(verifier.isTrustedIssuer('did:web:a', 'nope' as never)).toBe(false);
    expect(verifier.clockSkewMs(-1)).toBeUndefined();
    expect(verifier.clockSkewMs('x')).toBeUndefined();
    expect(verifier.windowVerdict(undefined, undefined, 0, -1)).toBe('skew_invalid');
    expect(verifier.windowVerdict('bad', undefined, 0)).toBe('malformed');
    expect(verifier.evaluateDelegationChain([], {})).toMatchObject({ code: 'chain_invalid' });
    expect(verifier.evaluateDelegationChain([{}], { maxChainLength: 0 })).toMatchObject({ code: 'configuration_error' });
    expect(verifier.evaluateDelegationChain([{}], { maxClockSkewMs: -5 })).toMatchObject({ code: 'configuration_error' });
    expect(verifier.attestedCapabilities(['a', { credentialSubject: { capability: 'a' } }, 'b'])).toEqual(['a', 'b']);
  });
});

describe('verify() edge cases beyond the fixtures', () => {
  it('refuses a verifier without an audience, with a bad chain bound, and a seam that is not a function', async () => {
    const seams: verifier.VerifierSeams = { clock: () => NOW, resolveDid: async () => null, resolveDidKeys: async () => [], nonceStore: { insert: async () => true } };
    const noAudience = await verifier.verify({ proof: {} }, seams, { expectedAudience: '' });
    expect(noAudience.reasons).toEqual(['configuration_error']);
    const badBound = await verifier.verify({ proof: {} }, seams, { expectedAudience: AUDIENCE, maxChainLength: 0 });
    expect(badBound.reasons).toEqual(['configuration_error']);
    const notFunctions = await verifier.verify({ proof: {} }, { ...seams, nonceStore: {} as never }, { expectedAudience: AUDIENCE });
    expect(notFunctions.reasons).toEqual(['nonce_seam_missing']);
  });

  it('handles a null proof and a request whose params cannot be canonicalized', async () => {
    const seams: verifier.VerifierSeams = { clock: () => NOW, resolveDid: async () => null, resolveDidKeys: async () => [], nonceStore: { insert: async () => true } };
    expect((await verifier.verify({ proof: null }, seams, { expectedAudience: AUDIENCE })).reasons).toEqual(['proof_missing']);
    const proof = await verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW });
    // §11.2 (story C-C): the key is resolved (step 3) before requestHash is recomputed (step 6).
    expect((await verifier.verify({ proof, request }, seams, { expectedAudience: AUDIENCE })).reasons).toEqual(['did_unresolved']);
    const resolving = { ...seams, resolveDid: async () => document, resolveDidKeys: async () => verifier.ed25519KeysOf(document) };
    const result = await verifier.verify({ proof, request: { method: 'x', params: { n: 1n as never } } }, resolving, { expectedAudience: AUDIENCE });
    expect(result.reasons).toEqual(['request_hash_mismatch']);
  });

  it('answers a bad key in the membership list without failing closed on the good one', async () => {
    const seams: verifier.VerifierSeams = {
      clock: () => NOW,
      resolveDid: async () => document,
      resolveDidKeys: async () => [{ kty: 'OKP', crv: 'Ed25519', x: 'short' } as never, ...verifier.ed25519KeysOf(document)],
      nonceStore: { insert: async () => true },
    };
    const proof = await verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW });
    const result = await verifier.verify({ proof, request }, seams, { expectedAudience: AUDIENCE });
    expect(result).toMatchObject({ ok: true, level: 'L1', proofAssurance: 'L3-minus', effectiveScopes: [] });
    expect(verifier.isPlainObject({})).toBe(true);
    expect(verifier.isPlainObject([])).toBe(false);
  });
});
