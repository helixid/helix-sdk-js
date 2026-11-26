// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the client side of the detached response proof (L2.11 to L2.13, L2.17).
import { describe, expect, it } from 'vitest';
import {
  EnvSigner,
  LEGACY_RESPONSE_PROOF_META_KEYS,
  PROOF_OUTCOMES,
  ProofReasons,
  REQUEST_PROOF_META_KEY,
  RESPONSE_PROOF_ENVELOPE_PROFILE,
  RESPONSE_PROOF_META_KEY,
  canonicalize,
  hashRequest,
  hashResponse,
  outcomeHasResponse,
  proofClaims,
  proofPayload,
  publicKeyHexToJwk,
  readResponseProof,
  signJws,
  validateProofMeta,
  verifyDetachedProof,
  verifyResponseProof,
  type DetachedProof,
  type ProofMeta,
  type ProofOutcome,
} from '../../../src/core/kyaos/index.js';
import { InvalidJWSError, ResponseProofError, kyaos, type IDidResolver } from '../../../src/index.js';
import { buildDIDDocument } from '../../../src/core/did.js';
import { generateKeyPair } from '../../../src/core/keys.js';

const SERVER = 'did:web:orders.example';
const keys = generateKeyPair();
const otherKeys = generateKeyPair();
const signer = new EnvSigner({ did: SERVER, envVar: 'K', env: { K: keys.privateKey } });
const document = buildDIDDocument(SERVER, keys.publicKey);
const resolveDid = async (did: string) => (did === SERVER ? document : null);
const jwk = publicKeyHexToJwk(keys.publicKey, `${SERVER}#key-1`);
const NOW = 1_750_000_000_000;

const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001', _kyaos_session: 'kyaos_x' }, _meta: { traceparent: 't' } } };
const body = { content: [{ type: 'text', text: '{"id":"ORD-1001"}' }], structuredContent: { id: 'ORD-1001' } };

function metaFor(outcome: ProofOutcome | undefined, extra: Partial<ProofMeta> = {}): ProofMeta {
  const meta: ProofMeta = {
    did: SERVER,
    kid: `${SERVER}#key-1`,
    ts: Math.floor(NOW / 1000),
    nonce: 'b6VZmm9hXn-otOETBkvlvQ',
    audience: SERVER,
    sessionId: 'kyaos_11111111-2222-4333-8444-555555555555',
    requestHash: hashRequest(request),
    ...(outcome === undefined || outcomeHasResponse(outcome) ? { responseHash: hashResponse(body, RESPONSE_PROOF_ENVELOPE_PROFILE) } : {}),
    ...(outcome !== undefined ? { outcome } : {}),
    prf: RESPONSE_PROOF_ENVELOPE_PROFILE,
    ...extra,
  };
  return meta;
}

/** A proof signed the way the middleware signs: the canonical claims as the payload text. */
async function proofFor(meta: ProofMeta, by = signer): Promise<DetachedProof> {
  return { jws: await signJws(proofPayload(meta), by), meta };
}

const withProof = (proof: DetachedProof, key: string = RESPONSE_PROOF_META_KEY, extraMeta: Record<string, unknown> = {}) => ({
  ...body,
  _meta: { [key]: proof, ...extraMeta },
});

async function reasonOf(run: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof ResponseProofError || error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
  throw new Error('expected a refusal');
}

describe('proof claims and payload', () => {
  it('writes iss and sub from did, aud from audience, drops kid and undefined members, keeps the rest', () => {
    const meta = metaFor('denied', { reason: 'nope', clientDid: 'did:key:z6Mkagent', scopeId: 's', delegationRef: 'urn:uuid:1', delegationChainDigest: `sha256:${'a'.repeat(64)}` });
    expect(proofClaims(meta)).toEqual({
      iss: SERVER,
      sub: SERVER,
      aud: SERVER,
      ts: meta.ts,
      nonce: meta.nonce,
      sessionId: meta.sessionId,
      requestHash: meta.requestHash,
      outcome: 'denied',
      reason: 'nope',
      clientDid: 'did:key:z6Mkagent',
      scopeId: 's',
      delegationRef: 'urn:uuid:1',
      delegationChainDigest: `sha256:${'a'.repeat(64)}`,
      prf: RESPONSE_PROOF_ENVELOPE_PROFILE,
    });
    expect(proofClaims({ ...metaFor(undefined), responseHash: undefined })).not.toHaveProperty('responseHash');
    expect(proofPayload(meta)).toBe(canonicalize(proofClaims(meta)));
    expect(proofPayload(meta).startsWith('{"aud":')).toBe(true);
  });

  it('outcomeHasResponse: allowed and needs_authorization carry a body, denied and step_up_required do not', () => {
    expect(PROOF_OUTCOMES).toEqual(['allowed', 'denied', 'step_up_required', 'needs_authorization']);
    expect(outcomeHasResponse('allowed')).toBe(true);
    expect(outcomeHasResponse('needs_authorization')).toBe(true);
    expect(outcomeHasResponse('denied')).toBe(false);
    expect(outcomeHasResponse('step_up_required')).toBe(false);
  });
});

describe('validateProofMeta (detached-proof schema)', () => {
  it('accepts every documented member and returns the meta typed', () => {
    const meta = metaFor('allowed', { reason: 'r', clientDid: 'did:key:x', scopeId: 's', delegationRef: 'd', delegationChainDigest: `sha256:${'0'.repeat(64)}` });
    expect(validateProofMeta(meta)).toBe(meta);
    expect(validateProofMeta(metaFor(undefined))).toBeDefined();
  });

  const digest = `sha256:${'f'.repeat(64)}`;
  const refusals: [name: string, patch: unknown, reason: string][] = [
    ['not an object', 'meta', ProofReasons.META_INVALID],
    ['an unknown member', { ...metaFor(undefined), extra: 1 }, ProofReasons.META_INVALID],
    ['a non-DID did', { ...metaFor(undefined), did: 'orders' }, ProofReasons.META_INVALID],
    ['a non-string did', { ...metaFor(undefined), did: 7 }, ProofReasons.META_INVALID],
    ['an empty kid', { ...metaFor(undefined), kid: '' }, ProofReasons.META_INVALID],
    ['a missing kid', { ...metaFor(undefined), kid: undefined }, ProofReasons.META_INVALID],
    ['a zero ts', { ...metaFor(undefined), ts: 0 }, ProofReasons.META_INVALID],
    ['a fractional ts', { ...metaFor(undefined), ts: 1.5 }, ProofReasons.META_INVALID],
    ['a string ts', { ...metaFor(undefined), ts: '1' }, ProofReasons.META_INVALID],
    ['an empty nonce', { ...metaFor(undefined), nonce: '' }, ProofReasons.META_INVALID],
    ['a missing audience', { ...metaFor(undefined), audience: undefined }, ProofReasons.META_INVALID],
    ['a numeric sessionId', { ...metaFor(undefined), sessionId: 1 }, ProofReasons.META_INVALID],
    ['a malformed requestHash', { ...metaFor(undefined), requestHash: 'sha256:short' }, ProofReasons.META_INVALID],
    ['a missing requestHash', { ...metaFor(undefined), requestHash: undefined }, ProofReasons.META_INVALID],
    ['a malformed responseHash', { ...metaFor(undefined), responseHash: 'md5:x' }, ProofReasons.META_INVALID],
    ['an upper-case responseHash', { ...metaFor(undefined), responseHash: `sha256:${'A'.repeat(64)}` }, ProofReasons.META_INVALID],
    ['a malformed delegationChainDigest', { ...metaFor(undefined), delegationChainDigest: 'x' }, ProofReasons.META_INVALID],
    ['an unknown outcome', { ...metaFor(undefined), outcome: 'maybe' }, ProofReasons.META_INVALID],
    ['a non-string reason', { ...metaFor(undefined), reason: 1 }, ProofReasons.META_INVALID],
    ['a non-string clientDid', { ...metaFor(undefined), clientDid: {} }, ProofReasons.META_INVALID],
    ['an unknown profile', { ...metaFor(undefined), prf: 'org.example/unknown-profile.v9' }, ProofReasons.PROFILE_UNKNOWN],
    ['a non-string profile', { ...metaFor(undefined), prf: 1 }, ProofReasons.PROFILE_UNKNOWN],
  ];
  it.each(refusals)('refuses %s', async (_name, value, reason) => {
    expect(await reasonOf(() => validateProofMeta(value))).toBe(reason);
    expect(digest).toMatch(/^sha256:/);
  });
});

describe('readResponseProof (L2.17)', () => {
  it('reads org.kya-os/response-proof first, then the 1.x keys, ignoring everything else in _meta', async () => {
    const proof = await proofFor(metaFor(undefined));
    const other = await proofFor(metaFor('denied'));
    expect(LEGACY_RESPONSE_PROOF_META_KEYS).toEqual(['org.kya-os/proof', 'proof']);
    expect(readResponseProof({ [RESPONSE_PROOF_META_KEY]: proof, 'org.kya-os/proof': other, proof: other })).toEqual(proof);
    expect(readResponseProof({ 'org.kya-os/proof': proof, proof: other })).toEqual(proof);
    expect(readResponseProof({ proof })).toEqual(proof);
    expect(readResponseProof({ [RESPONSE_PROOF_META_KEY]: null, proof })).toEqual(proof);
    expect(
      readResponseProof({
        [RESPONSE_PROOF_META_KEY]: proof,
        'io.modelcontextprotocol/trace': 'x',
        traceparent: '00-1-2-01',
        tracestate: 'a=b',
        baggage: 'k=v',
        'x-helix-vp': 'gone',
        [REQUEST_PROOF_META_KEY]: { jws: 'not.a.response-proof', meta: {} },
      }),
    ).toEqual(proof);
  });

  it('returns undefined with no proof, and never reads the request proof as one', async () => {
    expect(readResponseProof(undefined)).toBeUndefined();
    expect(readResponseProof('meta')).toBeUndefined();
    expect(readResponseProof({})).toBeUndefined();
    expect(readResponseProof({ traceparent: 't' })).toBeUndefined();
    expect(readResponseProof({ [REQUEST_PROOF_META_KEY]: await proofFor(metaFor(undefined)) })).toBeUndefined();
  });

  it('refuses a present but malformed proof value', async () => {
    const proof = await proofFor(metaFor(undefined));
    expect(await reasonOf(() => readResponseProof({ [RESPONSE_PROOF_META_KEY]: 'jws' }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => readResponseProof({ [RESPONSE_PROOF_META_KEY]: { jws: proof.jws } }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => readResponseProof({ [RESPONSE_PROOF_META_KEY]: { meta: proof.meta } }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => readResponseProof({ [RESPONSE_PROOF_META_KEY]: { ...proof, extra: 1 } }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => readResponseProof({ proof: { jws: proof.jws, meta: { did: 'x' } } }))).toBe(ProofReasons.META_INVALID);
  });
});

describe('verifyDetachedProof (L2.11, L2.12)', () => {
  it('verifies by JWK and by DID resolution, returning the outcome', async () => {
    const proof = await proofFor(metaFor(undefined));
    const byJwk = await verifyDetachedProof(proof, { jwk }, { now: NOW });
    expect(byJwk).toEqual({ meta: proof.meta, outcome: 'allowed', did: SERVER, kid: `${SERVER}#key-1`, profile: RESPONSE_PROOF_ENVELOPE_PROFILE });
    const byDid = await verifyDetachedProof(proof, { resolveDid }, { now: NOW, expectedDid: SERVER });
    expect(byDid).toEqual(byJwk);
    const denied = await proofFor(metaFor('denied', { reason: 'insufficient scope' }));
    expect((await verifyDetachedProof(denied, { jwk }, { now: NOW })).outcome).toBe('denied');
    const bodyProfile = await proofFor({ ...metaFor('needs_authorization'), prf: undefined } as ProofMeta);
    expect((await verifyDetachedProof(bodyProfile, { jwk }, { now: NOW })).profile).toBeUndefined();
  });

  it('accepts an IDidResolver as well as a resolver function (cross-border: only the resolver is consulted)', async () => {
    const proof = await proofFor(metaFor(undefined));
    const calls: string[] = [];
    const resolver: IDidResolver = {
      resolve: async (did) => {
        calls.push(did);
        return { didDocument: document, didResolutionMetadata: {}, didDocumentMetadata: {} };
      },
    };
    expect((await verifyDetachedProof(proof, { resolveDid: resolver }, { now: NOW })).did).toBe(SERVER);
    expect(calls).toEqual([SERVER]);
    const empty: IDidResolver = { resolve: async () => ({ didDocument: null, didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {} }) };
    expect(await reasonOf(() => verifyDetachedProof(proof, { resolveDid: empty }, { now: NOW }))).toBe('jws_did_unresolved');
  });

  it('refuses a proof that is not {jws, meta}', async () => {
    expect(await reasonOf(() => verifyDetachedProof('x' as never, { jwk }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => verifyDetachedProof({ meta: metaFor(undefined) } as never, { jwk }))).toBe(ProofReasons.MALFORMED);
    expect(await reasonOf(() => verifyDetachedProof({ jws: 'a.b.c', meta: 'm' } as never, { jwk }))).toBe(ProofReasons.META_INVALID);
  });

  it('refuses a signer other than expected, before resolving', async () => {
    const proof = await proofFor(metaFor(undefined));
    let resolved = false;
    const reason = await reasonOf(() =>
      verifyDetachedProof(
        proof,
        {
          resolveDid: async () => {
            resolved = true;
            return document;
          },
        },
        { now: NOW, expectedDid: 'did:web:other.example' },
      ),
    );
    expect(reason).toBe(ProofReasons.SIGNER_MISMATCH);
    expect(resolved).toBe(false);
  });

  it('refuses the JWS layer refusals with their own reasons: wrong key, tampered signature, kid not the meta kid', async () => {
    const proof = await proofFor(metaFor(undefined));
    expect(await reasonOf(() => verifyDetachedProof(proof, { jwk: publicKeyHexToJwk(otherKeys.publicKey) }, { now: NOW }))).toBe('jws_signature_invalid');
    const [h, p, s] = proof.jws.split('.') as [string, string, string];
    const flipped = `${h}.${p}.${s.startsWith('A') ? 'B' : 'A'}${s.slice(1)}`;
    expect(await reasonOf(() => verifyDetachedProof({ ...proof, jws: flipped }, { jwk }, { now: NOW }))).toBe('jws_signature_invalid');
    const otherKid = await proofFor(metaFor(undefined, { kid: `${SERVER}#key-2` }));
    expect(await reasonOf(() => verifyDetachedProof(otherKid, { jwk }, { now: NOW }))).toBe('jws_kid_mismatch');
    const foreign = new EnvSigner({ did: 'did:web:other.example', envVar: 'K', env: { K: otherKeys.privateKey } });
    const foreignProof = await proofFor(metaFor(undefined), foreign);
    expect(await reasonOf(() => verifyDetachedProof(foreignProof, { jwk }, { now: NOW }))).toBe('jws_kid_mismatch');
    expect(await reasonOf(() => verifyDetachedProof(foreignProof, { resolveDid }, { now: NOW }))).toBe('jws_kid_did_mismatch');
  });

  it('refuses meta that is not what was signed (tampered meta, stripped prf, altered nonce or session)', async () => {
    const proof = await proofFor(metaFor(undefined));
    const tampered = (patch: Partial<ProofMeta>): DetachedProof => ({ jws: proof.jws, meta: { ...proof.meta, ...patch } });
    expect(await reasonOf(() => verifyDetachedProof(tampered({ requestHash: `sha256:${'de'.repeat(32)}` }), { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
    const { prf: _prf, ...stripped } = proof.meta;
    expect(await reasonOf(() => verifyDetachedProof({ jws: proof.jws, meta: stripped }, { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
    expect(await reasonOf(() => verifyDetachedProof(tampered({ nonce: 'nonce-other' }), { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
    expect(await reasonOf(() => verifyDetachedProof(tampered({ sessionId: 'sess_other' }), { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
    expect(await reasonOf(() => verifyDetachedProof(tampered({ outcome: 'allowed' }), { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
    // A payload that is the right claims but not canonical is not what a conformant server signs.
    const uncanonical = { jws: await signJws(JSON.stringify({ ...proofClaims(proof.meta) }).replace('{"aud"', '{ "aud"'), signer), meta: proof.meta };
    expect(await reasonOf(() => verifyDetachedProof(uncanonical, { jwk }, { now: NOW }))).toBe(ProofReasons.PAYLOAD_MISMATCH);
  });

  it('refuses a ts outside the skew window, inclusive at the edges, default skew 120 s and Date.now()', async () => {
    const meta = metaFor(undefined);
    const proof = await proofFor(meta);
    const second = 1000;
    expect((await verifyDetachedProof(proof, { jwk }, { now: NOW + 120 * second })).outcome).toBe('allowed');
    expect((await verifyDetachedProof(proof, { jwk }, { now: NOW - 120 * second })).outcome).toBe('allowed');
    expect(await reasonOf(() => verifyDetachedProof(proof, { jwk }, { now: NOW + 121 * second }))).toBe(ProofReasons.TIMESTAMP_SKEW);
    expect(await reasonOf(() => verifyDetachedProof(proof, { jwk }, { now: NOW - 121 * second }))).toBe(ProofReasons.TIMESTAMP_SKEW);
    expect((await verifyDetachedProof(proof, { jwk }, { now: NOW + 300 * second, skewSeconds: 300 })).outcome).toBe('allowed');
    expect(await reasonOf(() => verifyDetachedProof(proof, { jwk }, { now: NOW + 31 * second, skewSeconds: 30 }))).toBe(ProofReasons.TIMESTAMP_SKEW);
    // No `now`: the wall clock, which is far from the fixed NOW.
    expect(await reasonOf(() => verifyDetachedProof(proof, { jwk }))).toBe(ProofReasons.TIMESTAMP_SKEW);
    const fresh = await proofFor(metaFor(undefined, { ts: Math.floor(Date.now() / 1000) }));
    expect((await verifyDetachedProof(fresh, { jwk })).outcome).toBe('allowed');
  });

  it('requires responseHash on allowed and needs_authorization, refuses it on denied and step_up_required', async () => {
    const noHash = await proofFor({ ...metaFor(undefined), responseHash: undefined } as ProofMeta);
    expect(await reasonOf(() => verifyDetachedProof(noHash, { jwk }, { now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_MISSING);
    const noHashNeeds = await proofFor({ ...metaFor('needs_authorization'), responseHash: undefined } as ProofMeta);
    expect(await reasonOf(() => verifyDetachedProof(noHashNeeds, { jwk }, { now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_MISSING);
    const deniedWithHash = await proofFor(metaFor('denied', { responseHash: hashResponse(body) }));
    expect(await reasonOf(() => verifyDetachedProof(deniedWithHash, { jwk }, { now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_UNEXPECTED);
    const stepUpWithHash = await proofFor(metaFor('step_up_required', { responseHash: hashResponse(body) }));
    expect(await reasonOf(() => verifyDetachedProof(stepUpWithHash, { jwk }, { now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_UNEXPECTED);
    expect((await verifyDetachedProof(await proofFor(metaFor('step_up_required')), { jwk }, { now: NOW })).outcome).toBe('step_up_required');
    expect((await verifyDetachedProof(await proofFor(metaFor('needs_authorization')), { jwk }, { now: NOW })).outcome).toBe('needs_authorization');
  });
});

describe('verifyResponseProof (L2.13: recompute both hashes)', () => {
  it('verifies a proof carried in the response against the server DID, recomputing both hashes', async () => {
    const proof = await proofFor(metaFor(undefined));
    const verified = await verifyResponseProof(withProof(proof), SERVER, resolveDid, { request, now: NOW });
    expect(verified).toEqual({
      meta: proof.meta,
      outcome: 'allowed',
      did: SERVER,
      kid: `${SERVER}#key-1`,
      profile: RESPONSE_PROOF_ENVELOPE_PROFILE,
      requestHash: proof.meta.requestHash,
      responseHash: proof.meta.responseHash,
    });
    expect(kyaos.verifyResponseProof).toBe(verifyResponseProof);
  });

  it('ignores every other _meta key and the 1.x keys still work (L2.17)', async () => {
    const proof = await proofFor(metaFor(undefined));
    const noisy = withProof(proof, RESPONSE_PROOF_META_KEY, { 'io.modelcontextprotocol/trace': 'x', traceparent: 't', tracestate: 's', baggage: 'b', 'x-helix-vp': 'gone', [REQUEST_PROOF_META_KEY]: { jws: 'x', meta: {} } });
    expect((await verifyResponseProof(noisy, SERVER, resolveDid, { request, now: NOW })).outcome).toBe('allowed');
    expect((await verifyResponseProof(withProof(proof, 'org.kya-os/proof'), SERVER, resolveDid, { request, now: NOW })).outcome).toBe('allowed');
    expect((await verifyResponseProof(withProof(proof, 'proof'), SERVER, resolveDid, { request, now: NOW })).outcome).toBe('allowed');
  });

  it('refuses a response with no proof, or a proof for another server', async () => {
    expect(await reasonOf(() => verifyResponseProof(body, SERVER, resolveDid, { request, now: NOW }))).toBe(ProofReasons.MISSING);
    expect(await reasonOf(() => verifyResponseProof({ ...body, _meta: { traceparent: 't' } }, SERVER, resolveDid, { request, now: NOW }))).toBe(ProofReasons.MISSING);
    expect(await reasonOf(() => verifyResponseProof(null, SERVER, resolveDid, { request, now: NOW }))).toBe(ProofReasons.MISSING);
    const proof = await proofFor(metaFor(undefined));
    expect(await reasonOf(() => verifyResponseProof(withProof(proof), 'did:web:other.example', resolveDid, { request, now: NOW }))).toBe(ProofReasons.SIGNER_MISMATCH);
  });

  it('a swapped request fails with request_hash_mismatch, a swapped body with response_hash_mismatch', async () => {
    const proof = await proofFor(metaFor(undefined));
    const otherRequest = { method: 'tools/call', params: { name: 'refund_order', arguments: { orderId: 'ORD-1001' } } };
    expect(await reasonOf(() => verifyResponseProof(withProof(proof), SERVER, resolveDid, { request: otherRequest, now: NOW }))).toBe(ProofReasons.REQUEST_HASH_MISMATCH);
    const swapped = { ...withProof(proof), structuredContent: { id: 'ORD-9999' } };
    expect(await reasonOf(() => verifyResponseProof(swapped, SERVER, resolveDid, { request, now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_MISMATCH);
    const swappedText = { ...withProof(proof), content: [{ type: 'text', text: 'something else' }] };
    expect(await reasonOf(() => verifyResponseProof(swappedText, SERVER, resolveDid, { request, now: NOW }))).toBe(ProofReasons.RESPONSE_HASH_MISMATCH);
    // The request the client sent carried control arguments and _meta; neither is covered, so they may differ freely.
    const bare = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } };
    expect((await verifyResponseProof(withProof(proof), SERVER, resolveDid, { request: bare, now: NOW })).outcome).toBe('allowed');
  });

  it('a denied proof binds the request only; a body-profile proof given out of band hashes the body as received', async () => {
    const denied = await proofFor(metaFor('denied', { reason: 'insufficient scope' }));
    const verified = await verifyResponseProof({ error: 'insufficient_scope' }, SERVER, resolveDid, { request, now: NOW, proof: denied });
    expect(verified.outcome).toBe('denied');
    expect(verified.responseHash).toBeUndefined();
    expect(verified.meta.reason).toBe('insufficient scope');
    const data = [{ type: 'text', text: 'released r-1' }];
    const bodyProof = await proofFor({ ...metaFor(undefined), prf: undefined, responseHash: hashResponse(data) } as ProofMeta);
    expect((await verifyResponseProof(data, SERVER, resolveDid, { request, now: NOW, proof: bodyProof })).responseHash).toBe(hashResponse(data));
    expect(await reasonOf(() => verifyResponseProof([...data, { type: 'text', text: 'extra' }], SERVER, resolveDid, { request, now: NOW, proof: bodyProof }))).toBe(
      ProofReasons.RESPONSE_HASH_MISMATCH,
    );
  });

  it('exposes the reason on the error object and as details', async () => {
    try {
      await verifyResponseProof(body, SERVER, resolveDid, { request, now: NOW });
      throw new Error('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(ResponseProofError);
      const refused = error as ResponseProofError;
      expect(refused.code).toBe('RESPONSE_PROOF_INVALID');
      expect(refused.name).toBe('ResponseProofError');
      expect(refused.details).toEqual({ reason: ProofReasons.MISSING });
      expect(new ResponseProofError('x').message).toBe('Response proof is invalid');
    }
  });
});
