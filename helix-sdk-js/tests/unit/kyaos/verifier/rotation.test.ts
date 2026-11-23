// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** KYA-OS story C-E points 2 and 3, verifier side: key validity by kid and created, the last-seen sequence, the jwks.json projection. */

import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import { EnvSigner, JwsReasons, keyValidityProblem, proofTime, signJws, verifier, verifyJwsByKid, type JwsDidDocument } from '../../../../src/core/kyaos/index.js';
import { base58btcEncode } from '../../../../src/core/vp-crypto.js';
import { generateKeyPair } from '../../../../src/index.js';

const DID = 'did:web:agent.helix.test:agents:0a1b';
const AUDIENCE = 'did:web:orders.helix.test';
const oldKeys = generateKeyPair();
const newKeys = generateKeyPair();
const oldSigner = new EnvSigner({ did: DID, kid: 'key-1', envVar: 'K', env: { K: oldKeys.privateKey } });
const newSigner = new EnvSigner({ did: DID, kid: 'key-2', envVar: 'K', env: { K: newKeys.privateKey } });
const x = (hex: string): string => Buffer.from(hex, 'hex').toString('base64url');

function method(fragment: string, publicKeyHex: string, extra: Record<string, unknown> = {}) {
  return { id: `${DID}#${fragment}`, type: 'Ed25519VerificationKey2020', controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: x(publicKeyHex) }, ...extra };
}

/** key-2 current, key-1 superseded until `until` (and revoked at `revoked`). */
function rotated(until: string, revoked?: string, sequence = 2): JwsDidDocument {
  const ids = [`${DID}#key-2`, `${DID}#key-1`];
  return {
    id: DID,
    verificationMethod: [method('key-2', newKeys.publicKey), method('key-1', oldKeys.publicKey, { validUntil: until, ...(revoked ? { revoked } : {}) })],
    authentication: ids,
    assertionMethod: ids,
    rotationSequence: sequence,
    updated: '2026-06-01T10:00:00Z',
  };
}

/** An eddsa-jcs-2022 proof over `document` by the key `fragment` of DID. */
async function signDi(document: Record<string, unknown>, privateKeyHex: string, fragment: string, created: string) {
  const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created, verificationMethod: `${DID}#${fragment}`, proofPurpose: 'assertionMethod' };
  const signature = await ed25519.signAsync(verifier.hashData(proof, document), Buffer.from(privateKeyHex, 'hex').subarray(-32));
  return { ...document, proof: { ...proof, proofValue: `z${base58btcEncode(signature)}` } };
}

const resolverOf = (document: unknown) => async (): Promise<JwsDidDocument> => document as JwsDidDocument;
const NOW = Date.parse('2026-06-01T12:00:00Z');

describe('key validity (C-E point 3)', () => {
  it('reads the same rules as helix-core', () => {
    const at = Date.parse('2026-06-01T10:00:00Z');
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-06-02T00:00:00Z' }, at)).toBeUndefined();
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-05-31T00:00:00Z' }, at)).toMatchObject({ reason: 'key_superseded' });
    expect(keyValidityProblem({ id: 'k', validFrom: '2026-06-02T00:00:00Z' }, at)).toMatchObject({ reason: 'key_superseded' });
    expect(keyValidityProblem({ id: 'k', revoked: '2026-06-02T00:00:00Z' }, at)).toMatchObject({ reason: 'key_revoked' });
    expect(keyValidityProblem({ id: 'k', validUntil: 'soon' }, at)).toMatchObject({ reason: 'key_validity_malformed' });
    expect(keyValidityProblem({ validUntil: '2026-05-31T00:00:00Z' }, undefined, at)).toMatchObject({ message: expect.stringContaining('the key') });
    expect(proofTime(1)).toBe(1000);
    expect(proofTime('x')).toBeUndefined();
  });

  it('a Data Integrity proof made before rotation verifies after it; the old key signing later, or a revoked key, is refused', async () => {
    const before = await signDi({ issuer: DID, n: 1 }, oldKeys.privateKey, 'key-1', '2026-06-01T09:00:00Z');
    const after = await signDi({ issuer: DID, n: 2 }, oldKeys.privateKey, 'key-1', '2026-06-03T09:00:00Z');
    const resolve = resolverOf(rotated('2026-06-02T10:00:00Z'));
    expect(await verifier.verifyDataIntegrity(before, resolve)).toMatchObject({ ok: true, verificationMethod: `${DID}#key-1` });
    expect(await verifier.verifyDataIntegrity(after, resolve)).toMatchObject({ ok: false, reason: 'key_superseded' });
    expect(await verifier.verifyDataIntegrity(before, resolverOf(rotated('2026-06-01T09:30:00Z', '2026-06-01T09:30:00Z')))).toMatchObject({ ok: false, reason: 'key_revoked' });
  });

  it('a JWS is checked at its iat, the time given, or now', async () => {
    const resolve = resolverOf(rotated('2026-06-02T10:00:00Z'));
    const early = await signJws({ iss: DID, iat: Date.parse('2026-06-01T09:00:00Z') / 1000 }, oldSigner);
    const late = await signJws({ iss: DID, iat: Date.parse('2026-06-03T09:00:00Z') / 1000 }, oldSigner);
    expect((await verifyJwsByKid(early, resolve)).kid).toBe(`${DID}#key-1`);
    await expect(verifyJwsByKid(late, resolve)).rejects.toMatchObject({ reason: JwsReasons.KEY_SUPERSEDED });
    expect((await verifyJwsByKid(late, resolve, { at: Date.parse('2026-06-01T00:00:00Z') })).did).toBe(DID);
    await expect(verifyJwsByKid(await signJws({ iss: DID }, oldSigner), resolve, { now: Date.parse('2026-06-03T00:00:00Z') })).rejects.toMatchObject({ reason: JwsReasons.KEY_SUPERSEDED });
    await expect(verifyJwsByKid(early, resolverOf(rotated('2026-06-02T10:00:00Z', '2026-06-01T09:30:00Z')))).rejects.toMatchObject({ reason: JwsReasons.KEY_REVOKED });
    const malformed = rotated('2026-06-02T10:00:00Z');
    (malformed.verificationMethod![1] as Record<string, unknown>)['validUntil'] = 'soon';
    await expect(verifyJwsByKid(early, resolverOf(malformed))).rejects.toMatchObject({ reason: JwsReasons.KEY_VALIDITY_MALFORMED });
  });
});

describe('request proofs across a rotation (C-E done-when)', () => {
  const request = { method: 'tools/call', params: { name: 't', arguments: {} } };
  const seams = (document: JwsDidDocument, clock = NOW): verifier.RequestProofSeams => ({
    clock: () => clock,
    resolveDid: async () => document,
    resolveDidKeys: async () => verifier.ed25519KeysOf(document),
    nonceStore: { insert: async () => true },
  });
  const run = (proof: unknown, document: JwsDidDocument, clock = NOW) => verifier.verifyRequestProof(proof, request, seams(document, clock), { expectedAudience: AUDIENCE });

  it('the old key signs during the overlap; after its validUntil only the new key does; a revoked key never', async () => {
    const document = rotated('2026-06-01T12:30:00Z');
    expect(await run(await verifier.signRequestProof(request, oldSigner, { audience: AUDIENCE, now: NOW }), document)).toMatchObject({ ok: true });
    expect(await run(await verifier.signRequestProof(request, newSigner, { audience: AUDIENCE, now: NOW }), document)).toMatchObject({ ok: true });
    const later = NOW + 3_600_000;
    expect((await run(await verifier.signRequestProof(request, oldSigner, { audience: AUDIENCE, now: later }), document, later)).reasons).toEqual(['key_superseded']);
    expect(await run(await verifier.signRequestProof(request, newSigner, { audience: AUDIENCE, now: later }), document, later)).toMatchObject({ ok: true });
    const compromised = rotated('2026-06-01T11:00:00Z', '2026-06-01T11:00:00Z', 3);
    expect((await run(await verifier.signRequestProof(request, oldSigner, { audience: AUDIENCE, now: NOW - 7_200_000 }), compromised, NOW - 7_200_000)).reasons).toEqual(['key_revoked']);
    const malformed = rotated('later');
    expect((await run(await verifier.signRequestProof(request, oldSigner, { audience: AUDIENCE, now: NOW }), malformed)).reasons).toEqual(['key_validity_malformed']);
  });

  it('a resolver that already saw a newer document refuses the older one as stale', async () => {
    const served = [rotated('2026-06-02T00:00:00Z', undefined, 3), rotated('2026-06-02T00:00:00Z', undefined, 2)];
    const resolveDid = verifier.createDidResolver({ fetch: async () => ({ ok: true, status: 200, json: async () => served.shift() }) });
    const proof = await verifier.signRequestProof(request, newSigner, { audience: AUDIENCE, now: NOW });
    const check = (): ReturnType<typeof verifier.verifyRequestProof> =>
      verifier.verifyRequestProof(proof, request, { ...seams(rotated('2026-06-02T00:00:00Z')), resolveDid }, { expectedAudience: AUDIENCE });
    expect(await check()).toMatchObject({ ok: true });
    expect((await check()).reasons).toEqual(['did_document_stale']);
  });
});

describe('the last-seen sequence and the jwks.json projection (C-E point 2)', () => {
  it('a resolver with a shared guard refuses a lower sequence than another resolver saw', async () => {
    const guard = new verifier.RotationSequenceGuard();
    const a = verifier.createDidResolver({ sequenceGuard: guard, fetch: async () => ({ ok: true, status: 200, json: async () => rotated('2026-06-02T00:00:00Z', undefined, 4) }) });
    const b = verifier.createDidResolver({ sequenceGuard: guard, fetch: async () => ({ ok: true, status: 200, json: async () => rotated('2026-06-02T00:00:00Z', undefined, 3) }) });
    expect(await a(DID)).toMatchObject({ rotationSequence: 4 });
    await expect(b(DID)).rejects.toBeInstanceOf(verifier.StaleDidDocumentError);
    await expect(b(DID)).rejects.toMatchObject({ reason: verifier.DID_DOCUMENT_STALE, sequence: 3, lastSeen: 4 });
    const guarded = verifier.guardedResolver(async () => null);
    expect(await guarded(DID)).toBeNull();
  });

  it('projects and reads a JWKS under the same guard', async () => {
    const guard = new verifier.RotationSequenceGuard(new verifier.MemoryRotationSequenceStore(1));
    const jwks = verifier.projectJwks(rotated('2026-06-02T00:00:00Z', '2026-06-01T11:00:00Z', 5) as never);
    expect(jwks).toMatchObject({ rotationSequence: 5, keys: [{ kid: `${DID}#key-2`, use: 'sig', alg: 'EdDSA' }, { kid: `${DID}#key-1`, revoked: '2026-06-01T11:00:00Z' }] });
    expect((await verifier.readJwks(DID, jwks, guard)).map((key) => key.kid)).toEqual([`${DID}#key-2`, `${DID}#key-1`]);
    await expect(verifier.readJwks(DID, { ...jwks, rotationSequence: 4 }, guard)).rejects.toThrow(/lower than 5/);
    await expect(verifier.readJwks(DID, {}, guard)).rejects.toThrow(/not a JWK Set/);
    expect(verifier.rotationSequenceOf({ rotationSequence: 0 })).toBeUndefined();
    expect(verifier.projectJwks({ id: DID, verificationMethod: [{ id: '#x', publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: 'a' } }] })).toEqual({ keys: [] });
  });
});

describe('rotation edges (C-E)', () => {
  it('projects relative ids and validFrom, skips methods without a usable Ed25519 key, and leaves out a missing version', () => {
    const projected = verifier.projectJwks({
      id: DID,
      verificationMethod: [
        { id: '#key-3', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: x(newKeys.publicKey) }, validFrom: '2026-06-01T00:00:00Z' },
        { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'a' } },
        { id: '#nokey' },
        { id: '#ec', publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a' } },
      ],
    });
    expect(projected).toEqual({ keys: [{ kty: 'OKP', crv: 'Ed25519', x: x(newKeys.publicKey), kid: `${DID}#key-3`, use: 'sig', alg: 'EdDSA', validFrom: '2026-06-01T00:00:00Z' }] });
    expect(verifier.projectJwks({ id: DID })).toEqual({ keys: [] });
  });

  it('reads only the DID\'s own Ed25519 keys from a JWKS', async () => {
    const own = { kty: 'OKP', crv: 'Ed25519', x: 'a', kid: `${DID}#key-1` };
    const keys = await verifier.readJwks(DID, { keys: [own, { ...own, kid: 'did:web:other#k' }, { ...own, crv: 'X25519' }, { ...own, kty: 'EC' }, { ...own, x: 1 }, { ...own, kid: 1 }, null, 'junk'] }, new verifier.RotationSequenceGuard());
    expect(keys).toEqual([own]);
    await expect(verifier.readJwks(DID, null, new verifier.RotationSequenceGuard())).rejects.toThrow(/not a JWK Set/);
  });

  it('refuses a document that drops the sequence once one was seen; keeps the highest; evicts the oldest DID', async () => {
    const guard = new verifier.RotationSequenceGuard();
    expect(await guard.check(DID, { rotationSequence: 2 })).toBeUndefined();
    expect((await guard.check(DID, {}))?.message).toMatch(/carries no rotationSequence/);
    expect(await guard.check('did:web:unversioned.example', null)).toBeUndefined();
    const store = new verifier.MemoryRotationSequenceStore(1);
    store.raise('a', 3);
    store.raise('a', 2);
    expect(store.get('a')).toBe(3);
    store.raise('b', 1);
    expect(store.get('a')).toBeUndefined();
    const guarded = verifier.guardedResolver(async () => ({ id: DID, rotationSequence: 1 }), guard);
    await expect(guarded(DID)).rejects.toBeInstanceOf(verifier.StaleDidDocumentError);
    expect(await verifier.guardedResolver(async () => undefined)(DID)).toBeUndefined();
  });

  it('reads a validFrom after the proof as superseded, and a bool or negative proof time as none', () => {
    expect(keyValidityProblem({ id: 'k', validFrom: '2026-06-02T00:00:00Z' }, undefined, Date.parse('2026-06-01T00:00:00Z'))).toMatchObject({ reason: 'key_superseded' });
    expect(proofTime(-5)).toBeUndefined();
    expect(proofTime(Number.NaN)).toBeUndefined();
    expect(proofTime('2026-13-45T00:00:00Z')).toBeUndefined();
    expect(proofTime('2026-06-01T00:00:00.5+05:30')).toBe(Date.parse('2026-06-01T00:00:00.5+05:30'));
  });
});
