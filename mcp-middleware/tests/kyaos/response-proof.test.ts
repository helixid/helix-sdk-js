// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the server's detached response proof (L2.11, L2.12) and the self-custody invariant (rule 7).
import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import { RESPONSE_PROOF_META_KEY, attachResponseProof, buildResponseProof, type ProofMeta } from '../../src/kyaos/index.js';
import { NOW, SERVER, keys, resolveDid, signer } from './helpers.js';

const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } };
const body = { content: [{ type: 'text', text: 'ok' }] };

function meta(outcome: kyaos.ProofOutcome, extra: Partial<ProofMeta> = {}): ProofMeta {
  return {
    did: SERVER,
    kid: `${SERVER}#key-1`,
    ts: Math.floor(NOW / 1000),
    nonce: kyaos.generateNonce(),
    audience: SERVER,
    sessionId: 'kyaos_11111111-2222-4333-8444-555555555555',
    requestHash: kyaos.hashRequest(request),
    ...(kyaos.outcomeHasResponse(outcome) ? { responseHash: kyaos.hashResponse(body, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE), prf: kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE } : {}),
    outcome,
    ...extra,
  };
}

describe('buildResponseProof', () => {
  it('signs the canonical claims of the meta through the Signer; the SDK verifies it against the server DID', async () => {
    const proof = await buildResponseProof(meta('allowed', { clientDid: 'did:key:z6Mkagent' }), signer);
    expect(proof.meta).toEqual(meta('allowed', { nonce: proof.meta.nonce, clientDid: 'did:key:z6Mkagent' }));
    expect(proof.jws).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(Buffer.from(proof.jws.split('.')[1]!, 'base64url').toString('utf8')).toBe(kyaos.proofPayload(proof.meta));
    expect(kyaos.readJwsHeader(proof.jws)).toEqual({ alg: 'EdDSA', kid: `${SERVER}#key-1` });
    const verified = await kyaos.verifyResponseProof(attachResponseProof(body, proof), SERVER, resolveDid as never, { request, now: NOW });
    expect(verified.outcome).toBe('allowed');
    expect(verified.meta.clientDid).toBe('did:key:z6Mkagent');
  });

  it('carries responseHash on allowed and needs_authorization only', async () => {
    for (const outcome of ['allowed', 'needs_authorization'] as const) {
      const proof = await buildResponseProof(meta(outcome), signer);
      expect(proof.meta.responseHash, outcome).toBeDefined();
      expect((await kyaos.verifyDetachedProof(proof, { resolveDid: resolveDid as never }, { now: NOW })).outcome).toBe(outcome);
      const { responseHash: _r, ...withoutHash } = meta(outcome);
      await expect(buildResponseProof(withoutHash, signer), outcome).rejects.toThrow('must carry responseHash');
    }
    for (const outcome of ['denied', 'step_up_required'] as const) {
      const proof = await buildResponseProof(meta(outcome, { reason: 'insufficient scope' }), signer);
      expect(proof.meta).not.toHaveProperty('responseHash');
      expect((await kyaos.verifyDetachedProof(proof, { resolveDid: resolveDid as never }, { now: NOW })).outcome).toBe(outcome);
      await expect(buildResponseProof(meta(outcome, { responseHash: kyaos.hashResponse(body) }), signer), outcome).rejects.toThrow('no responseHash');
    }
    // An absent outcome is allowed.
    const { outcome: _o, ...implicit } = meta('allowed');
    expect((await buildResponseProof(implicit, signer)).meta.outcome).toBeUndefined();
  });

  it('refuses meta that names another signer or key, or that is malformed', async () => {
    await expect(buildResponseProof(meta('allowed', { did: 'did:web:other.example' }), signer)).rejects.toThrow('the signer is');
    await expect(buildResponseProof(meta('allowed', { kid: `${SERVER}#key-2` }), signer)).rejects.toThrow('the signer is');
    await expect(buildResponseProof(meta('allowed', { requestHash: 'nope' }), signer)).rejects.toMatchObject({ code: 'RESPONSE_PROOF_INVALID' });
    const hashKid = { did: SERVER, kid: '#key-1', sign: (d: Uint8Array) => signer.sign(d) };
    expect((await buildResponseProof(meta('allowed'), hashKid)).meta.kid).toBe(`${SERVER}#key-1`);
  });

  it('self-custody invariant: only the signing input reaches the Signer and the private key appears nowhere', async () => {
    const seen: Uint8Array[] = [];
    const spy: kyaos.Signer = {
      did: SERVER,
      kid: 'key-1',
      sign: async (data) => {
        seen.push(data);
        return signer.sign(data);
      },
    };
    const proof = await buildResponseProof(meta('allowed'), spy);
    expect(seen).toHaveLength(1);
    expect(Buffer.from(seen[0]!).toString('utf8')).toBe(proof.jws.split('.').slice(0, 2).join('.'));
    const leaks = [keys.privateKey, Buffer.from(keys.privateKey, 'hex').toString('base64url'), Buffer.from(keys.privateKey, 'hex').toString('base64')];
    for (const leak of leaks) {
      expect(JSON.stringify(proof)).not.toContain(leak);
      expect(JSON.stringify(signer)).not.toContain(leak);
      expect(JSON.stringify(attachResponseProof(body, proof))).not.toContain(leak);
    }
    expect(Object.keys(signer)).toEqual(['did', 'kid']);
  });
});

describe('attachResponseProof', () => {
  it('puts the proof at _meta["org.kya-os/response-proof"] and keeps the result and other _meta members', async () => {
    const proof = await buildResponseProof(meta('allowed'), signer);
    expect(RESPONSE_PROOF_META_KEY).toBe('org.kya-os/response-proof');
    expect(attachResponseProof(body, proof)).toEqual({ ...body, _meta: { [RESPONSE_PROOF_META_KEY]: proof } });
    const withMeta = { ...body, _meta: { traceparent: 't', [RESPONSE_PROOF_META_KEY]: 'stale' } };
    expect(attachResponseProof(withMeta, proof)._meta).toEqual({ traceparent: 't', [RESPONSE_PROOF_META_KEY]: proof });
    expect(attachResponseProof({ ...body, _meta: 'not an object' }, proof)._meta).toEqual({ [RESPONSE_PROOF_META_KEY]: proof });
    expect(attachResponseProof({ ...body, _meta: ['x'] }, proof)._meta).toEqual({ [RESPONSE_PROOF_META_KEY]: proof });
  });
});
