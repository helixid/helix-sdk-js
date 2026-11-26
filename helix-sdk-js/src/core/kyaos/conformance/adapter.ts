// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The SDK's KYA-OS `ConformanceAdapter` (story F-2): every method answers a
 * vector with the SDK's own code, fail-closed (any error is `fail`, nothing
 * throws).
 *
 * - `signed-proof`: the response-proof verifier of story L2-A, then the
 *   SPEC §7.8 delegation binding (outcome, chain digest, delegationRef).
 * - `delegation-chain`, `status-list`: the §6.2 readings in ./legacy.ts and
 *   ./status-list.ts (the vectors are written in the earlier profile).
 * - `did-key-resolution`, `did-web-resolution`: the verifier's resolvers.
 * - `card-proof`: the local verifier itself (`kyaos.verifier.verify`), with
 *   seams built from the vector's JWKS.
 * - `entity-card`: the strict card schema, the revocation rule (a card that
 *   declares `revocation` is refused without a checker), and the
 *   accountability JOIN recomputed over the vector's chain with the
 *   verifier's chain rules.
 *
 * `audit-integrity` and `negotiation` are outside story F-2's categories.
 */

import { hashRequest, hashResponse } from '../hash.js';
import { verifyDetachedProof } from '../response-proof.js';
import type { Ed25519PublicJwk } from '../jws.js';
import { evaluateDelegationChainRules } from '../verifier/credentials.js';
import { validateEntityCard } from '../verifier/card.js';
import { createDidResolver, didKeyDocument, ed25519KeysOf } from '../verifier/resolve.js';
import { didOfKid } from '../verifier/request-proof.js';
import { verify } from '../verifier/verify.js';
import { chainDigest, delegationRef } from './delegation-binding.js';
import { assertionKey, legacyChainRefusal, verifyVcJwt } from './legacy.js';
import { statusListRefusal } from './status-list.js';
import type {
  AdapterResult,
  CardProofInput,
  ConformanceAdapter,
  DelegationChainInput,
  DidResolutionInput,
  EntityCardInput,
  SignedProofInput,
  StatusListInput,
} from './types.js';

const PASS: AdapterResult = { outcome: 'pass' };
const fail = (detail: string): AdapterResult => ({ outcome: 'fail', detail });
const message = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** Whether a resolved document publishes a usable Ed25519 key in its first verification method. */
function usableDocument(document: unknown, did: string): boolean {
  if (!isObject(document) || document['id'] !== did) return false;
  return ed25519KeysOf(document as never).length > 0;
}

export interface HelixConformanceAdapterOptions {
  /** Epoch ms the time-bound checks of the §6.2 categories read; default `Date.now()`. */
  now?: (() => number) | undefined;
}

export class HelixConformanceAdapter implements ConformanceAdapter {
  readonly name = '@helixid/sdk-js kyaos (story F-2)';
  readonly #now: () => number;

  constructor(options: HelixConformanceAdapterOptions = {}) {
    this.#now = options.now ?? Date.now;
  }

  async verifySignedProof(input: SignedProofInput): Promise<AdapterResult> {
    try {
      if (typeof input.now !== 'number' || typeof input.skewSeconds !== 'number') return fail('now and skewSeconds are numbers');
      const proof = input.proof as { jws?: unknown; meta?: Record<string, unknown> };
      if (!isObject(proof) || !isObject(proof.meta)) return fail('not a detached proof');
      let jwk: Ed25519PublicJwk;
      if (input.didDocuments !== undefined) {
        const did = proof.meta['did'];
        if (typeof did !== 'string') return fail('meta.did is not a DID');
        const named = 'keyId' in input;
        const key = assertionKey(input.didDocuments[did], did, named ? input.keyId : undefined, named);
        if (key === undefined) return fail('no assertionMethod key of the signer');
        const document = input.didDocuments[did] as { assertionMethod?: unknown[] };
        const first = document.assertionMethod?.[0];
        const kid = named ? (String(input.keyId).startsWith('#') ? `${did}${String(input.keyId)}` : String(input.keyId)) : isObject(first) ? String(first['id']) : String(first);
        jwk = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key).toString('base64url'), kid: kid.startsWith('#') ? `${did}${kid}` : kid };
      } else {
        jwk = input.publicKeyJwk as Ed25519PublicJwk;
      }
      const verified = await verifyDetachedProof(proof as never, { jwk }, { now: input.now * 1000, skewSeconds: input.skewSeconds });
      const expected = input.expected;
      if (expected === undefined) return PASS;
      if (!isObject(expected)) return fail('expected is not an object');
      const meta = verified.meta;
      const held = 'response' in expected && expected.response !== undefined ? hashResponse(expected.response.data, meta.prf) : undefined;
      if (hashRequest(expected.request as never) !== meta.requestHash) return fail('requestHash does not bind the request held');
      const chain = expected.delegationChain ?? undefined;
      const required = expected.outcome ?? (chain !== undefined ? 'allowed' : undefined);
      if (required !== undefined && (meta.outcome ?? 'allowed') !== required) return fail(`the proof states ${meta.outcome ?? 'allowed'}, not ${required}`);
      if ((meta.responseHash !== undefined) !== (held !== undefined)) return fail('the proof binds a response exactly when one is held');
      if (meta.responseHash !== undefined && meta.responseHash !== held) return fail('responseHash does not bind the response held');
      if (chain === undefined) return PASS;
      if (meta.delegationChainDigest === undefined) return fail('the proof binds no chain');
      const digest = chainDigest(chain);
      if (digest === undefined) return fail('the chain has no signed form');
      if (digest !== meta.delegationChainDigest) return fail('delegationChainDigest is not the chain held');
      if ((meta.delegationRef || undefined) !== delegationRef(chain[chain.length - 1])) return fail('delegationRef does not name the presented credential');
      return PASS;
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async verifyDelegationChain(input: DelegationChainInput): Promise<AdapterResult> {
    try {
      const now = this.#now();
      const verified = new Set<unknown>();
      let leaf: unknown = input.leaf;
      if (typeof leaf === 'string') {
        const read = verifyVcJwt(leaf, input.didDocuments, now);
        if ('refusal' in read) return fail(read.refusal);
        leaf = read.credential;
        verified.add(leaf);
      }
      const refusal = legacyChainRefusal([...(input.ancestors ?? []), leaf], input.serverDid, input.didDocuments, now, verified);
      return refusal === undefined ? PASS : fail(refusal);
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async verifyStatusList(input: StatusListInput): Promise<AdapterResult> {
    const refusal = await statusListRefusal(input, this.#now());
    return refusal === undefined ? PASS : fail(refusal);
  }

  async resolveDidKey(input: DidResolutionInput): Promise<AdapterResult> {
    try {
      if (typeof input.did !== 'string' || !input.did.startsWith('did:key:')) return fail('not a did:key');
      const document = didKeyDocument(input.did);
      return usableDocument(document, input.did) ? PASS : fail('no usable Ed25519 verification method');
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async resolveDidWeb(input: DidResolutionInput): Promise<AdapterResult> {
    try {
      const resolve = createDidResolver({
        fetch: async () => {
          const found = input.didDocument !== undefined;
          return { ok: found, status: found ? 200 : 404, json: async (): Promise<unknown> => (found ? input.didDocument : null) };
        },
      });
      if (typeof input.did !== 'string' || !input.did.startsWith('did:web:')) return fail('not a did:web');
      const document = await resolve(input.did);
      return usableDocument(document, input.did) ? PASS : fail('no usable, id-matched document');
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async verifyCardProof(input: CardProofInput): Promise<AdapterResult> {
    try {
      const keys = input.jwks.keys.filter((key) => typeof key.kid === 'string');
      const documentOf = (did: string): Record<string, unknown> | null => {
        const own = keys.filter((key) => didOfKid(key.kid!) === did);
        if (own.length === 0) return null;
        const methods = own.map((key) => ({ id: key.kid!, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: key.kty, crv: key.crv, x: key.x } }));
        return { id: did, verificationMethod: methods, assertionMethod: methods.map((method) => method.id) };
      };
      const used = new Set<string>();
      const result = await verify(
        { proof: input.proof, request: input.request },
        {
          clock: () => input.nowMs,
          resolveDid: async (did) => documentOf(did) as never,
          resolveDidKeys: async (did) => keys.filter((key) => didOfKid(key.kid!) === did) as Ed25519PublicJwk[],
          ...(input.omitNonceSeam
            ? {}
            : {
                nonceStore: {
                  insert: async (nonce: string, did: string | undefined): Promise<boolean> => {
                    const key = `${did ?? ''}|${nonce}`;
                    if (used.has(key)) return false;
                    used.add(key);
                    return true;
                  },
                },
              }),
        },
        {
          expectedAudience: input.expectedAudience,
          skewSeconds: input.skewSeconds,
          ...(input.tokenCnfJkt === undefined ? {} : { tokenCnfJkt: input.tokenCnfJkt }),
        },
      );
      return result.ok ? PASS : fail(result.reasons.join(', '));
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async verifyEntityCard(input: EntityCardInput): Promise<AdapterResult> {
    try {
      const problems = validateEntityCard(input.card);
      if (problems.length > 0) return fail(`malformed card: ${problems.join('; ')}`);
      const card = input.card as { responsibleParty?: string; revocation?: unknown };
      if (card.responsibleParty !== undefined) {
        const accountability = input.accountability;
        if (accountability === undefined) return fail('responsibleParty with no delegation chain to recompute it over');
        // The chain's proofs are placeholders in these vectors (no adapter method verifies a hop proof
        // here; CONFORMANCE.md): the structure, attenuation and JOIN are recomputed, the proof shape is not.
        const rules = evaluateDelegationChainRules(accountability.chain, {
          resourceOwner: accountability.resourceOwner,
          ...(accountability.resource === undefined ? {} : { resource: accountability.resource }),
          ...(accountability.now === undefined ? {} : { now: accountability.now }),
          proofShape: 'any',
        });
        if (!rules.ok) return fail(`accountability: ${rules.reasons.join('; ')}`);
        if (card.responsibleParty !== rules.responsibleParty) return fail('responsibleParty is not the root issuer');
        if (accountability.proofDid !== undefined && rules.leafInvoker !== accountability.proofDid) return fail('the leaf invoker is not the proof DID');
      }
      // A card that declares revocation is refused when there is nothing to check it with (SPEC-ENTITY-CARD §10.3).
      if (card.revocation !== undefined) return fail('configuration_error: revocation declared with no status-list checker');
      return PASS;
    } catch (error) {
      return fail(`refused: ${message(error)}`);
    }
  }

  async verifyAuditIntegrity(): Promise<AdapterResult> {
    return fail('audit-integrity is outside story F-2 (story A-1 runs it)');
  }

  async evaluateNegotiation(): Promise<AdapterResult> {
    return fail('negotiation is outside story F-2');
  }
}

