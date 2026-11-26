// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** KYA-OS story C-C: verifyRequestProof on its own, each step's seam and refusal. */

import { describe, expect, it } from 'vitest';
import { EnvSigner, verifier } from '../../../../src/core/kyaos/index.js';
import { buildDIDDocument, generateKeyPair } from '../../../../src/index.js';

const keys = generateKeyPair();
const DID = 'did:web:agent.helix.test';
const AUDIENCE = 'did:web:orders.helix.test';
const NOW = Date.parse('2026-06-01T00:00:00Z');
const signer = new EnvSigner({ did: DID, envVar: 'K', env: { K: keys.privateKey } });
const document = buildDIDDocument(DID, keys.publicKey) as never;
const request = { method: 'tools/call', params: { name: 't', arguments: { a: 1 } } };
const seams = (overrides: Partial<verifier.RequestProofSeams> = {}): verifier.RequestProofSeams => ({
  clock: () => NOW,
  resolveDid: async () => document,
  resolveDidKeys: async () => verifier.ed25519KeysOf(document),
  nonceStore: { insert: async () => true },
  ...overrides,
});
const mint = (options: Partial<verifier.SignRequestProofOptions> = {}): Promise<verifier.RequestProof> =>
  verifier.signRequestProof(request, signer, { audience: AUDIENCE, now: NOW, ...options });
const run = async (proof: unknown, overrides: Partial<verifier.RequestProofSeams> = {}, options: Partial<verifier.RequestProofOptions> = {}, req: verifier.ProofRequest | undefined = request) =>
  verifier.verifyRequestProof(proof, req, seams(overrides), { expectedAudience: AUDIENCE, ...options });

describe('verifyRequestProof', () => {
  it('accepts a good proof with its DID, L3-minus and the parsed proof', async () => {
    const proof = await mint();
    expect(await run(proof)).toEqual({ ok: true, reasons: [], messages: [], did: DID, assurance: 'L3-minus', proof, warnings: [] });
  });

  it('fails closed on missing seams at the step that needs them', async () => {
    const proof = await mint();
    expect((await run(proof, { clock: undefined })).reasons).toEqual(['clock_seam_missing']);
    expect((await run(proof, { resolveDid: undefined })).reasons).toEqual(['did_resolver_missing']);
    expect((await run(proof, { resolveDidKeys: undefined })).reasons).toEqual(['did_membership_unverifiable']);
    expect((await run(proof, { nonceStore: undefined })).reasons).toEqual(['nonce_seam_missing']);
    expect((await run(proof, { nonceStore: {} as never })).reasons).toEqual(['nonce_seam_missing']);
    expect((await run(proof, {}, { expectedAudience: 'orders' })).reasons).toEqual(['configuration_error']);
  });

  it('refuses each binding with its own code', async () => {
    const proof = await mint();
    expect((await run(undefined)).reasons).toEqual(['proof_missing']);
    expect((await run(null)).reasons).toEqual(['proof_missing']);
    expect((await run({ ...proof, extra: 1 })).reasons).toEqual(['malformed_proof']);
    expect((await run({ ...proof, kid: 'did:web:x#key-1' })).reasons).toEqual(['kid_did_mismatch']);
    expect((await run({ ...proof, alg: 'ES256' })).reasons).toEqual(['alg_unsupported']);
    expect((await run(proof, { resolveDid: async () => null })).reasons).toEqual(['did_unresolved']);
    expect((await run(proof, { resolveDid: async () => { throw new Error('down'); } })).reasons).toEqual(['did_unresolved']);
    expect((await run({ ...proof, kid: `${DID}#key-9` })).reasons).toEqual(['key_unresolvable']);
    expect((await run(proof, { resolveDidKeys: async () => { throw new Error('down'); } })).reasons).toEqual(['did_keys_unresolvable']);
    expect((await run(proof, { resolveDidKeys: async () => [{ kty: 'OKP', crv: 'Ed25519', x: undefined } as never] })).reasons).toEqual(['kid_not_in_did_document']);
    expect((await run(proof, {}, { expectedAudience: 'did:web:other' })).reasons).toEqual(['audience_mismatch']);
    expect((await verifier.verifyRequestProof(proof, undefined, seams(), { expectedAudience: AUDIENCE })).reasons).toEqual(['request_missing']);
    expect((await run(proof, {}, {}, { method: 'x', params: { n: 1n as never } })).reasons).toEqual(['request_hash_mismatch']);
    expect((await run(await mint({ ttlSeconds: 0 }))).reasons).toEqual(['invalid_window']);
    expect((await run(await mint({ ttlSeconds: 61, now: NOW - 200_000 }))).reasons).toEqual(['ttl_too_long', 'expired']);
    expect((await run(proof, { nonceStore: { insert: async () => false } })).reasons).toEqual(['nonce_replayed']);
    expect((await run(proof, { nonceStore: { insert: async () => { throw new Error('redis down'); } } })).reasons).toEqual(['nonce_store_unavailable']);
    expect((await run({ ...proof, jws: proof.jws.replace(/..$/, 'AA') })).reasons).toEqual(['invalid_signature']);
  });

  it('keeps the nonce until expires + skew + 1 s, for the proof\'s did', async () => {
    const inserted: unknown[] = [];
    const proof = await mint();
    await run(proof, { nonceStore: { insert: async (...args) => Boolean(inserted.push(args)) } }, { skewSeconds: 7 });
    expect(inserted).toEqual([[proof.nonce, DID, (proof.expires + 8) * 1000]]);
  });

  it('runs the cnf fusion last', async () => {
    const jkt = verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(keys.publicKey, 'hex').toString('base64url') });
    expect(await run(await mint({ cnfJkt: jkt }), {}, { tokenCnfJkt: jkt })).toMatchObject({ ok: true, assurance: 'L3', warnings: [] });
    expect(await run(await mint({ cnfJkt: jkt }))).toMatchObject({ ok: true, assurance: 'L3-minus', warnings: [verifier.CNF_PRESENT_BUT_TOKEN_UNFUSED] });
    expect((await run(await mint({ cnfJkt: 'A'.repeat(43) }))).reasons).toEqual(['cnf_key_mismatch']);
    expect((await run(await mint(), {}, { tokenCnfJkt: jkt })).reasons).toEqual(['cnf_required_by_token']);
    expect((await run(await mint({ cnfJkt: jkt }), {}, { tokenCnfJkt: 'B'.repeat(43) })).reasons).toEqual(['cnf_token_mismatch']);
  });
});
