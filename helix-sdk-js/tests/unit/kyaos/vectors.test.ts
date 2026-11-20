// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  EnvSigner,
  ProofReasons,
  canonicalize,
  hashJson,
  hashRequest,
  hashResponse,
  publicKeyHexToJwk,
  signJws,
  verifyDetachedProof,
  verifyJws,
  verifyJwsByKid,
  verifyResponseProof,
  type DidResolver,
  type Ed25519PublicJwk,
  type JwsPayload,
} from '../../../src/core/kyaos/index.js';
import { InvalidJWSError, ResponseProofError } from '../../../src/index.js';
import { coreFixturesDir, fixtureSkipReason, haveCoreFixtures, jwsPayload, loadFixture, vectors, vectorsDir } from './fixtures.js';

/**
 * KYA-OS story L2-A: the SDK's own `jcs`, `jws`, `signer` and response-proof
 * code against helix-core's fixtures (stories rule 24): the vendored
 * conformance suite (`fixtures/kya-os`, pinned at a4d7f61) and the
 * cross-language `fixtures/kya-os-helix/{jcs,jws}.json` the JS reference
 * generates. Read from the sibling helix-core checkout or
 * `HELIX_CORE_FIXTURES_DIR`.
 */

if (!haveCoreFixtures) console.warn(`[kyaos vectors] skipped: ${fixtureSkipReason}`);

const describeWithFixtures = describe.skipIf(!haveCoreFixtures);

describeWithFixtures('vendored suite pin (fixtures/kya-os)', () => {
  it('holds suite 1.10.0 at the pinned vector set hash, file for file', () => {
    const manifest = loadFixture<{ suiteVersion: string; vectorSetHash: string; vectorCount: number; files: [string, string][] }>('kya-os/conformance/SUITE-MANIFEST.json');
    const names = readdirSync(vectorsDir).filter((name) => name.endsWith('.json')).sort();
    let count = 0;
    const files = names.map((name) => {
      const bytes = readFileSync(join(vectorsDir, name));
      count += (JSON.parse(bytes.toString('utf8')) as { vectors: unknown[] }).vectors.length;
      return [name, createHash('sha256').update(bytes).digest('hex')];
    });
    expect(files).toEqual(manifest.files);
    expect(count).toBe(manifest.vectorCount);
    expect(manifest.suiteVersion).toBe('1.10.0');
    const vectorSetHash = `sha256:${createHash('sha256').update(canonicalize(files), 'utf8').digest('hex')}`;
    expect(vectorSetHash).toBe('sha256:6dd5e3dd0526b0fb7e7e3ea9e76b63a3acd0651aeb36ee03ea1f820bb15ebed0');
    expect(vectorSetHash).toBe(manifest.vectorSetHash);
  });
});

describeWithFixtures('JCS vectors (L1-B, through the SDK copy)', () => {
  it('canonicalizes the audit-integrity canonicalization vectors and every eventCanonical', () => {
    const all = vectors('audit-integrity.json');
    const checked = all.filter((vector) => vector.input['canonicalization']);
    expect(checked.length).toBeGreaterThan(0);
    for (const vector of checked) {
      const { value, canonical } = vector.input['canonicalization'] as { value: unknown; canonical: string };
      expect(canonicalize(value) === canonical, vector.id).toBe(vector.expected === 'pass');
    }
    for (const vector of all) {
      expect(canonicalize(vector.input['event']), vector.id).toBe(vector.input['eventCanonical']);
    }
  });

  it('re-derives every vector of fixtures/kya-os-helix/jcs.json', () => {
    const file = loadFixture<{ vectors: { name: string; input: unknown; canonical: string; hash: string }[] }>('kya-os-helix/jcs.json');
    expect(file.vectors.length).toBeGreaterThanOrEqual(14);
    for (const vector of file.vectors) {
      expect(canonicalize(vector.input), vector.name).toBe(vector.canonical);
      expect(hashJson(vector.input), vector.name).toBe(vector.hash);
    }
  });

  /** The vectors whose refusal is the hash part itself: the request or response no longer hashes to the proof. */
  const HASH_FAILURES = ['signed-proof/envelope-tampered-structured-content', 'signed-proof/delegation-proof-request-hash-altered', 'signed-proof/delegation-proof-request-substituted'];

  it('recomputes requestHash and responseHash of the signed-proof vectors with hashRequest / hashResponse', () => {
    const checked = vectors('signed-proof.json').filter((vector) => vector.input['expected']?.request);
    expect(checked.length).toBeGreaterThan(30);
    const disagreeing: string[] = [];
    for (const vector of checked) {
      const { proof, expected } = vector.input as {
        proof: { jws: string; meta: { requestHash: string; responseHash?: string } };
        expected: { request: { method: string; params?: Record<string, unknown> }; response?: { data: unknown } };
      };
      const profile = jwsPayload(proof.jws)['prf'] as string | undefined;
      let agree = hashRequest(expected.request) === proof.meta.requestHash;
      if (expected.response) agree &&= hashResponse(expected.response.data, profile) === proof.meta.responseHash;
      else expect(proof.meta.responseHash, vector.id).toBeUndefined();
      if (!agree) disagreeing.push(vector.id);
      if (vector.expected === 'pass') expect(agree, `${vector.id}: hashes must agree on a pass vector`).toBe(true);
    }
    expect(disagreeing.sort()).toEqual([...HASH_FAILURES].sort());
  });
});

interface JwsFixtures {
  keys: Record<'signer' | 'other', { private_key_hex: string; public_key_hex: string; did: string; kid_fragment: string; kid: string; public_key_jwk: Ed25519PublicJwk; did_document: Record<string, unknown> }>;
  vectors: { name: string; signer: 'signer' | 'other'; payload: { json: unknown } | { text: string } | { bytes_hex: string }; header_extra?: Record<string, unknown>; header: Record<string, unknown>; jws: string }[];
  rejections: { name: string; jws: string; verify_with: { key: 'signer' | 'other'; kid: boolean }; expected_did?: string; reason: string; by_kid_reason?: string | null }[];
}

async function reasonOf(run: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof InvalidJWSError || error instanceof ResponseProofError) return error.reason;
    throw error;
  }
  return 'verified';
}

describeWithFixtures('JWS fixtures (L1-C, through the SDK copy): fixtures/kya-os-helix/jws.json', () => {
  const fixtures = haveCoreFixtures ? loadFixture<JwsFixtures>('kya-os-helix/jws.json') : ({ keys: {}, vectors: [], rejections: [] } as unknown as JwsFixtures);
  const resolver: DidResolver = async (did) => (Object.values(fixtures.keys).find((key) => key.did === did)?.did_document as never) ?? null;
  const jwkFor = (key: 'signer' | 'other', withKid: boolean): Ed25519PublicJwk =>
    publicKeyHexToJwk(fixtures.keys[key].public_key_hex, withKid ? fixtures.keys[key].kid : undefined);

  it('records the test keys consistently', () => {
    for (const key of Object.values(fixtures.keys)) {
      expect(key.kid).toBe(`${key.did}#${key.kid_fragment}`);
      expect(key.public_key_jwk).toEqual(publicKeyHexToJwk(key.public_key_hex, key.kid));
      expect(key.did_document['id']).toBe(key.did);
      expect(new EnvSigner({ did: key.did, kid: key.kid_fragment, envVar: 'K', env: { K: key.private_key_hex } }).publicKeyHex()).toBe(key.public_key_hex);
    }
  });

  it('re-signs every vector to the same bytes and verifies it by JWK and by kid', async () => {
    expect(fixtures.vectors.length).toBeGreaterThan(5);
    for (const vector of fixtures.vectors) {
      const key = fixtures.keys[vector.signer];
      const signer = new EnvSigner({ did: key.did, kid: key.kid_fragment, envVar: 'K', env: { K: key.private_key_hex } });
      const payload: JwsPayload =
        'json' in vector.payload ? (vector.payload.json as JwsPayload) : 'text' in vector.payload ? vector.payload.text : new Uint8Array(Buffer.from(vector.payload.bytes_hex, 'hex'));
      expect(await signJws(payload, signer, vector.header_extra ? { header: vector.header_extra } : {}), vector.name).toBe(vector.jws);
      const byJwk = verifyJws(vector.jws, jwkFor(vector.signer, true));
      expect(byJwk.header, vector.name).toEqual(vector.header);
      expect(byJwk.did).toBe(key.did);
      const byKid = await verifyJwsByKid(vector.jws, resolver);
      expect(byKid.payloadBytes).toEqual(byJwk.payloadBytes);
      if ('json' in vector.payload) expect(byKid.payload).toEqual(vector.payload.json);
      if ('text' in vector.payload) expect(Buffer.from(byKid.payloadBytes).toString('utf8')).toBe(vector.payload.text);
      if ('bytes_hex' in vector.payload) expect(Buffer.from(byKid.payloadBytes).toString('hex')).toBe(vector.payload.bytes_hex);
    }
  });

  it('refuses every rejection for the recorded reason, by JWK and by kid', async () => {
    expect(fixtures.rejections.length).toBeGreaterThan(15);
    for (const rejection of fixtures.rejections) {
      const options = rejection.expected_did === undefined ? {} : { expectedDid: rejection.expected_did };
      const jwk = jwkFor(rejection.verify_with.key, rejection.verify_with.kid);
      expect(await reasonOf(() => verifyJws(rejection.jws, jwk, options)), rejection.name).toBe(rejection.reason);
      if (rejection.by_kid_reason === null) {
        expect((await verifyJwsByKid(rejection.jws, resolver, options)).did, rejection.name).toBe(fixtures.keys.signer.did);
      } else {
        expect(await reasonOf(() => verifyJwsByKid(rejection.jws, resolver, options)), rejection.name).toBe(rejection.by_kid_reason ?? rejection.reason);
      }
    }
  });
});

/**
 * Fail vectors this layer cannot see: their refusal is the delegation chain's
 * (F-2 verifier, C-C holder-of-key proof), so the proof itself verifies here
 * with the outcome the server signed.
 */
const DELEGATION_LAYER = new Set([
  'signed-proof/delegation-chain-refused-outcome-unstated',
  'signed-proof/delegation-chain-substituted',
  'signed-proof/delegation-chain-unbound',
  'signed-proof/delegation-chain-no-signed-form',
  'signed-proof/delegation-ref-substituted',
  'signed-proof/delegation-chain-nested-past-bound',
  'signed-proof/delegation-chain-number-read-as-binary64',
]);

/** What this layer says about each fail vector it does see. */
const EXPECTED_REFUSALS: Record<string, string> = {
  'signed-proof/tampered-signature': 'jws_signature_invalid',
  'signed-proof/tampered-meta': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/wrong-key': 'jws_kid_mismatch',
  'signed-proof/timestamp-skew-exceeded': ProofReasons.TIMESTAMP_SKEW,
  'signed-proof/envelope-tampered-structured-content': ProofReasons.RESPONSE_HASH_MISMATCH,
  'signed-proof/prf-stripped-downgrade': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/unknown-profile': ProofReasons.PROFILE_UNKNOWN,
  'signed-proof/delegation-chain-digest-stripped': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/delegation-proof-signature-stray-character': 'jws_malformed',
  'signed-proof/delegation-proof-signature-stray-characters': 'jws_malformed',
  'signed-proof/delegation-proof-signature-base64': 'jws_malformed',
  'signed-proof/delegation-proof-signature-white-space': 'jws_malformed',
  'signed-proof/delegation-proof-signature-padded': 'jws_malformed',
  'signed-proof/delegation-proof-fourth-segment': 'jws_malformed',
  'signed-proof/delegation-proof-header-non-ascii': 'jws_malformed',
  'signed-proof/delegation-proof-request-hash-altered': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/delegation-proof-nonce-altered': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/delegation-proof-session-altered': ProofReasons.PAYLOAD_MISMATCH,
  'signed-proof/delegation-proof-request-substituted': ProofReasons.REQUEST_HASH_MISMATCH,
  'signed-proof/delegation-proof-header-algorithm': 'jws_alg_unsupported',
  'signed-proof/delegation-proof-header-key': 'jws_kid_mismatch',
  'signed-proof/delegation-proof-signer-of-another-did': 'jws_kid_did_mismatch',
};

describeWithFixtures('signed-proof vectors through the response-proof verifier (L2.11 to L2.13, L2.17)', () => {
  const all = haveCoreFixtures ? vectors('signed-proof.json') : [];

  it('is the whole category', () => {
    expect(all.length).toBe(52);
    expect(Object.keys(EXPECTED_REFUSALS).length + DELEGATION_LAYER.size).toBe(all.filter((v) => v.expected === 'fail').length);
  });

  for (const vector of all) {
    it(`${vector.id} (${vector.expected})`, async () => {
      const { proof, publicKeyJwk, now, skewSeconds, expected } = vector.input as {
        proof: { jws: string; meta: Record<string, unknown> };
        publicKeyJwk: Ed25519PublicJwk;
        now: number;
        skewSeconds: number;
        expected?: { request: { method: string; params?: Record<string, unknown> }; response?: { data: unknown } };
      };
      const did = proof.meta['did'] as string;
      const resolveDid: DidResolver = async (wanted) =>
        wanted === did ? { id: did, verificationMethod: [{ id: proof.meta['kid'] as string, controller: did, publicKeyJwk }], assertionMethod: [proof.meta['kid'] as string] } : null;
      const options = { now: now * 1000, skewSeconds };
      const verdict = await reasonOf(async () => {
        const detached = await verifyDetachedProof(proof as never, { jwk: publicKeyJwk }, options);
        if (!expected) return detached;
        // Through the resolver and with both hashes recomputed, as the SDK does for a real call.
        const response = expected.response?.data;
        return verifyResponseProof(response, did, resolveDid, { request: expected.request, proof: proof as never, ...options });
      });
      if (vector.expected === 'pass' || DELEGATION_LAYER.has(vector.id)) {
        expect(verdict, vector.reason).toBe('verified');
      } else {
        expect(verdict, vector.reason).toBe(EXPECTED_REFUSALS[vector.id]);
      }
    });
  }

  it('reports the signed outcome on the refused-chain vectors, which is what the delegation layer then judges', async () => {
    const refused = all.find((v) => v.id === 'signed-proof/delegation-chain-refused')!;
    const { proof, publicKeyJwk, now, skewSeconds } = refused.input;
    const verified = await verifyDetachedProof(proof, { jwk: publicKeyJwk }, { now: now * 1000, skewSeconds });
    expect(verified.outcome).toBe('denied');
    expect(verified.meta.responseHash).toBeUndefined();
  });
});

describeWithFixtures('signed-proof-key-relationship vectors through verifyJwsByKid', () => {
  const NO_KID_VECTORS = new Set(['signed-proof/key-relationship-first-usable', 'signed-proof/key-relationship-first-unusable']);
  it('agrees with every vector (the two no-keyId vectors select a usable key by the header kid)', async () => {
    const all = vectors('signed-proof-key-relationship.json');
    expect(all.length).toBe(10);
    for (const vector of all) {
      const { proof, didDocuments, keyId } = vector.input as { proof: { jws: string; meta: { did: string } }; didDocuments: Record<string, unknown>; keyId?: string };
      const resolver: DidResolver = async (did) => (didDocuments[did] as never) ?? null;
      const verdict = await reasonOf(() => verifyJwsByKid(proof.jws, resolver, { ...(keyId ? { expectedKid: keyId } : {}), expectedDid: proof.meta.did }));
      if (vector.expected === 'pass' || NO_KID_VECTORS.has(vector.id)) expect(verdict, vector.id).toBe('verified');
      else expect(verdict, vector.id).not.toBe('verified');
    }
  });
});

describe('fixture location', () => {
  it('is the sibling helix-core checkout unless HELIX_CORE_FIXTURES_DIR says otherwise', () => {
    expect(coreFixturesDir.endsWith('fixtures')).toBe(true);
    expect(fixtureSkipReason).toContain('HELIX_CORE_FIXTURES_DIR');
  });
});
