// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS story C-C, the agent side: mintRequestProof, requestHashContentDigest,
 * attachChain and withRequestProof; what they produce verifies in the local
 * verifier, and none of it carries private key material (stories rule 7).
 */

import { describe, expect, it } from 'vitest';
import { buildDIDDocument, generateKeyPair } from '../../../src/index.js';
import {
  DELEGATION_CHAIN_META_KEY,
  EnvSigner,
  REQUEST_PROOF_META_KEY,
  RequestProofError,
  attachChain,
  mintRequestProof,
  requestHashContentDigest,
  toProofRequest,
  verifier,
  withRequestProof,
  type Signer,
} from '../../../src/core/kyaos/index.js';

const keys = generateKeyPair();
const DID = 'did:web:agent.helix.test';
const AUDIENCE = 'did:web:orders.helix.test';
const NOW = Date.parse('2026-06-01T00:00:00Z');
const signer = new EnvSigner({ did: DID, envVar: 'K', env: { K: keys.privateKey } });
const document = buildDIDDocument(DID, keys.publicKey) as never;
const seams = (): verifier.VerifierSeams => {
  const seen = new Set<string>();
  return {
    clock: () => NOW,
    resolveDid: async () => document,
    resolveDidKeys: async () => verifier.ed25519KeysOf(document),
    nonceStore: { insert: async (nonce, did) => !seen.has(`${did}|${nonce}`) && Boolean(seen.add(`${did}|${nonce}`)) },
  };
};
const hop = { id: 'urn:zcap:x', proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'assertionMethod', proofValue: 'z' } };
const toolCall = { name: 'lookup_order', arguments: { orderId: 'ORD-1' } };

describe('requestHashContentDigest', () => {
  it('is sha-256=:<base64>: over the JCS of {method, params} with params._meta removed', () => {
    const digest = requestHashContentDigest(toolCall);
    expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/]{43}=:$/);
    expect(requestHashContentDigest({ ...toolCall, _meta: { progressToken: 1 } })).toBe(digest);
    expect(requestHashContentDigest({ method: 'tools/call', params: { arguments: { orderId: 'ORD-1' }, name: 'lookup_order' } })).toBe(digest);
    expect(requestHashContentDigest({ ...toolCall, arguments: { orderId: 'ORD-2' } })).not.toBe(digest);
    expect(requestHashContentDigest({ method: 'ping' })).toBe(verifier.requestHashContentDigest({ method: 'ping' }));
  });

  it('turns a tool call into its tools/call request and refuses one without a name', () => {
    expect(toProofRequest({ name: 't' })).toEqual({ method: 'tools/call', params: { name: 't' } });
    expect(toProofRequest({ name: 't', _meta: { a: 1 } })).toEqual({ method: 'tools/call', params: { name: 't', _meta: { a: 1 } } });
    const request = { method: 'resources/read', params: { uri: 'x' } };
    expect(toProofRequest(request)).toBe(request);
    expect(() => toProofRequest({ name: '' })).toThrow(RequestProofError);
  });
});

describe('mintRequestProof', () => {
  it('mints an org.kya-os/proof.v1 the verifier accepts: EdDSA, kid of did, the audience, a 128-bit nonce, ≤ 60 s', async () => {
    const proof = await mintRequestProof(toolCall, signer, { audience: AUDIENCE, now: NOW });
    expect(proof).toMatchObject({ prf: 'org.kya-os/proof.v1', alg: 'EdDSA', did: DID, kid: `${DID}#key-1`, audience: AUDIENCE, requestHash: requestHashContentDigest(toolCall) });
    expect(Buffer.from(proof.nonce, 'base64url')).toHaveLength(16);
    expect(proof.expires - proof.created).toBe(60);
    expect(proof.jws).toMatch(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
    expect(proof.cnf).toBeUndefined();
    const verdict = await verifier.verifyRequestProof(proof, toProofRequest(toolCall), seams(), { expectedAudience: AUDIENCE });
    expect(verdict).toMatchObject({ ok: true, did: DID, assurance: 'L3-minus' });
  });

  it('mints a fresh nonce per call and carries cnf.jkt when given', async () => {
    const jkt = verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(keys.publicKey, 'hex').toString('base64url') });
    const first = await mintRequestProof(toolCall, signer, { audience: AUDIENCE, cnfJkt: jkt });
    const second = await mintRequestProof(toolCall, signer, { audience: AUDIENCE, cnfJkt: jkt });
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.cnf).toEqual({ jkt });
    const fused = await verifier.verifyRequestProof(first, toProofRequest(toolCall), { ...seams(), clock: () => first.created * 1000 }, { expectedAudience: AUDIENCE, tokenCnfJkt: jkt });
    expect(fused).toMatchObject({ ok: true, assurance: 'L3' });
  });

  it('refuses an audience that is not a DID, a lifetime outside 1..60 s, a short nonce and a malformed cnfJkt', async () => {
    await expect(mintRequestProof(toolCall, signer, { audience: 'https://orders.example' })).rejects.toThrow(/audience/);
    await expect(mintRequestProof(toolCall, signer, { audience: AUDIENCE, ttlSeconds: 61 })).rejects.toThrow(/ttlSeconds/);
    await expect(mintRequestProof(toolCall, signer, { audience: AUDIENCE, ttlSeconds: 0 })).rejects.toThrow(/ttlSeconds/);
    await expect(mintRequestProof(toolCall, signer, { audience: AUDIENCE, ttlSeconds: 1.5 })).rejects.toThrow(/ttlSeconds/);
    await expect(mintRequestProof(toolCall, signer, { audience: AUDIENCE, nonce: 'short' })).rejects.toThrow(/nonce/);
    await expect(mintRequestProof(toolCall, signer, { audience: AUDIENCE, cnfJkt: 'x' })).rejects.toThrow(/cnfJkt/);
    const fixed = await mintRequestProof(toolCall, signer, { audience: AUDIENCE, ttlSeconds: 10, nonce: 'A'.repeat(22), now: NOW });
    expect(fixed).toMatchObject({ nonce: 'A'.repeat(22), expires: fixed.created + 10 });
  });
});

describe('attachChain', () => {
  it('puts the chain root to leaf under org.kya-os/delegation-chain, as a copy', () => {
    const hops = [hop, { ...hop, id: 'urn:zcap:y' }];
    const meta = attachChain(hops);
    expect(Object.keys(meta)).toEqual([DELEGATION_CHAIN_META_KEY]);
    expect(meta[DELEGATION_CHAIN_META_KEY]).toEqual(hops);
    expect(meta[DELEGATION_CHAIN_META_KEY]).not.toBe(hops);
  });

  it('refuses an empty chain, more than 10 hops, and a hop without its own eddsa-jcs-2022 assertion proof', () => {
    expect(() => attachChain([])).toThrow(/non-empty/);
    expect(() => attachChain('x' as never)).toThrow(/non-empty/);
    expect(() => attachChain(Array.from({ length: 11 }, () => hop))).toThrow(/at most 10/);
    expect(() => attachChain([{ id: 'x' }])).toThrow(/hop 0/);
    expect(() => attachChain([hop, { ...hop, proof: { ...hop.proof, cryptosuite: 'ecdsa-rdfc-2019' } }])).toThrow(/hop 1/);
    expect(() => attachChain([{ ...hop, proof: { ...hop.proof, proofPurpose: 'authentication' } }])).toThrow(/hop 0/);
    expect(() => attachChain([{ ...hop, proof: { ...hop.proof, type: 'Ed25519Signature2020' } }])).toThrow(/hop 0/);
    expect(() => attachChain([null])).toThrow(/hop 0/);
  });
});

describe('withRequestProof', () => {
  it('returns the request with the proof and the chain in params._meta, keeping other members, and it verifies as sent', async () => {
    const sent = await withRequestProof({ ...toolCall, _meta: { progressToken: 'p' } }, signer, { audience: AUDIENCE, chain: [hop], now: NOW });
    const meta = (sent.params as { _meta: Record<string, unknown> })._meta;
    expect(meta['progressToken']).toBe('p');
    expect(meta[DELEGATION_CHAIN_META_KEY]).toEqual([hop]);
    const proof = verifier.readRequestProof(meta);
    expect(proof).toBe(meta[REQUEST_PROOF_META_KEY]);
    expect(await verifier.verifyRequestProof(proof, sent, seams(), { expectedAudience: AUDIENCE })).toMatchObject({ ok: true });
  });

  it('signs a request without params as sent, with params carrying only _meta', async () => {
    const sent = await withRequestProof({ method: 'tools/list' }, signer, { audience: AUDIENCE, now: NOW });
    expect(Object.keys(sent.params as object)).toEqual(['_meta']);
    const proof = verifier.readRequestProof((sent.params as { _meta: unknown })._meta);
    expect(await verifier.verifyRequestProof(proof, sent, seams(), { expectedAudience: AUDIENCE })).toMatchObject({ ok: true });
    expect((await withRequestProof({ method: 'm', params: { _meta: 'not-an-object' } }, signer, { audience: AUDIENCE })).params).toMatchObject({ _meta: { [REQUEST_PROOF_META_KEY]: expect.any(Object) } });
  });

  it('refuses array params, which cannot carry _meta, and a bad chain before signing', async () => {
    let signed = 0;
    const counting: Signer = { did: DID, kid: 'key-1', sign: async (data) => { signed += 1; return signer.sign(data); } };
    await expect(withRequestProof({ method: 'm', params: [1, 2] }, counting, { audience: AUDIENCE })).rejects.toThrow(/params must be an object/);
    await expect(withRequestProof(toolCall, counting, { audience: AUDIENCE, chain: [] })).rejects.toThrow(/non-empty/);
    expect(signed).toBe(0);
  });
});

describe('self-custody (stories rule 7)', () => {
  it('no request the SDK builds carries the private key, in any encoding', async () => {
    const sent = await withRequestProof(toolCall, signer, { audience: AUDIENCE, chain: [hop] });
    const text = JSON.stringify(sent);
    const secret = Buffer.from(keys.privateKey, 'hex');
    for (const encoding of [keys.privateKey, keys.privateKey.toUpperCase(), secret.toString('base64'), secret.toString('base64url')]) {
      expect(text).not.toContain(encoding);
    }
    expect(text).not.toMatch(/"d"\s*:/);
    // The signer itself serialises to its DID and kid only.
    expect(JSON.stringify(signer)).not.toContain(keys.privateKey);
  });
});
