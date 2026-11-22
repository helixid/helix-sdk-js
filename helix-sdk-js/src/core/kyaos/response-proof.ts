// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS detached response proofs, the client's side (story L2-A; conformance
 * L2.11 to L2.13, L2.17; schema `detached-proof.json`).
 *
 * A proof is `{jws, meta}`: `meta` is the ProofMeta in the clear and `jws`
 * is an EdDSA compact JWS whose payload is the RFC 8785 canonical JSON of
 * the same facts written as claims (`iss` and `sub` the signer's DID, `aud`
 * the audience, the rest under their own names). {@link verifyDetachedProof}
 * checks the signature against the signer's DID document, that the payload
 * is exactly what `meta` says, that `ts` is fresh and that `responseHash` is
 * present exactly when the outcome carries a response. {@link
 * verifyResponseProof} then recomputes `requestHash` from the request the
 * client sent and `responseHash` from the result it received: a signature
 * proves the proof is the server's, only the recompute proves the body in
 * hand is the one the server signed.
 *
 * Reads `_meta["org.kya-os/response-proof"]` and, through 1.x, the prior
 * keys `org.kya-os/proof` and bare `proof`, first present wins; every other
 * `_meta` key is ignored and never a reason to refuse (L2.17).
 *
 * Cross-border rule: the only input besides the proof, request and response
 * is the DID document the injected resolver returns.
 */

import { ResponseProofError } from '../HelixError.js';
import type { IDidResolver } from '../../resolver/IDidResolver.js';
import { hashRequest, hashResponse, RESPONSE_PROOF_ENVELOPE_PROFILE, type CoveredRequestInput } from './hash.js';
import { canonicalize } from './jcs.js';
import { verifyJws, verifyJwsByKid, type DidResolver, type Ed25519PublicJwk, type JwsDidDocument } from './jws.js';
import { DEFAULT_CLOCK_SKEW_SECONDS, withinSkew } from './handshake.js';

export const RESPONSE_PROOF_META_KEY = 'org.kya-os/response-proof';
/** Keys a 1.x verifier also reads, after the current one, in this order. */
export const LEGACY_RESPONSE_PROOF_META_KEYS = ['org.kya-os/proof', 'proof'] as const;
/** The holder-of-key request proof (SPEC-ENTITY-CARD §8.1): a separate profile, never read as a response proof. */
export const REQUEST_PROOF_META_KEY = 'org.kya-os/request-proof';

export const PROOF_OUTCOMES = ['allowed', 'denied', 'step_up_required', 'needs_authorization'] as const;
export type ProofOutcome = (typeof PROOF_OUTCOMES)[number];

/** Why a response proof was refused; carried as `ResponseProofError.reason`, mirrored in helix-sdk-py. */
export const ProofReasons = {
  MISSING: 'proof_missing',
  MALFORMED: 'proof_malformed',
  META_INVALID: 'proof_meta_invalid',
  PROFILE_UNKNOWN: 'proof_profile_unknown',
  SIGNER_MISMATCH: 'proof_signer_mismatch',
  PAYLOAD_MISMATCH: 'proof_payload_mismatch',
  TIMESTAMP_SKEW: 'proof_timestamp_skew',
  RESPONSE_HASH_MISSING: 'response_hash_missing',
  RESPONSE_HASH_UNEXPECTED: 'response_hash_unexpected',
  REQUEST_HASH_MISMATCH: 'request_hash_mismatch',
  RESPONSE_HASH_MISMATCH: 'response_hash_mismatch',
} as const;

export type ProofReason = (typeof ProofReasons)[keyof typeof ProofReasons];

export interface ProofMeta {
  did: string;
  kid: string;
  /** Unix seconds. */
  ts: number;
  nonce: string;
  audience: string;
  sessionId: string;
  requestHash: string;
  /** Present on `allowed` and `needs_authorization`, absent on `denied` and `step_up_required`. */
  responseHash?: string;
  /** Absent means `allowed`. */
  outcome?: ProofOutcome;
  reason?: string;
  clientDid?: string;
  scopeId?: string;
  delegationRef?: string;
  delegationChainDigest?: string;
  /** Response-proof profile; absent is the body profile. */
  prf?: typeof RESPONSE_PROOF_ENVELOPE_PROFILE;
}

export interface DetachedProof {
  jws: string;
  meta: ProofMeta;
}

export interface VerifiedProof {
  meta: ProofMeta;
  /** `meta.outcome`, `allowed` when absent. */
  outcome: ProofOutcome;
  did: string;
  kid: string;
  /** `meta.prf`, undefined for the body profile. */
  profile: string | undefined;
}

export interface VerifyProofOptions {
  /** Milliseconds since the epoch; default `Date.now()`. */
  now?: number;
  /** Default 120, the server's advertised `clockSkewSeconds` when known. */
  skewSeconds?: number;
  /** The DID the proof must be signed by, when the caller knows it. */
  expectedDid?: string;
}

/** The key to verify with: one public JWK, or a resolver for the signer's DID document. */
export type ProofKeySource = { jwk: Ed25519PublicJwk } | { resolveDid: DidResolver | IDidResolver };

export interface VerifyResponseProofOptions extends VerifyProofOptions {
  /** The request the client sent, as a JSON-RPC `{method, params}`: `requestHash` is recomputed from it. */
  request: CoveredRequestInput;
  /** A proof carried outside the response; default: read from `response._meta`. */
  proof?: DetachedProof;
}

export interface VerifiedResponseProof extends VerifiedProof {
  requestHash: string;
  responseHash: string | undefined;
}

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const DID = /^did:[a-z0-9]+:.+$/;
const META_MEMBERS = new Set([
  'did', 'kid', 'ts', 'nonce', 'audience', 'sessionId', 'requestHash', 'responseHash',
  'outcome', 'reason', 'clientDid', 'scopeId', 'delegationRef', 'delegationChainDigest', 'prf',
]);
const OPTIONAL_STRINGS = ['reason', 'clientDid', 'scopeId', 'delegationRef'] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const refuse = (reason: ProofReason, message: string): never => {
  throw new ResponseProofError(reason, message);
};

/** Whether proofs with this outcome carry a response body, and so a `responseHash`. */
export function outcomeHasResponse(outcome: ProofOutcome): boolean {
  return outcome === 'allowed' || outcome === 'needs_authorization';
}

/**
 * The claims a server signs for `meta`, as the detached-proof vectors write
 * them: `iss` and `sub` are the signer's DID, `aud` the audience, everything
 * else keeps its name; `kid` lives in the JWS header only.
 */
export function proofClaims(meta: ProofMeta): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(meta)) {
    if (value === undefined || name === 'kid') continue;
    if (name === 'did') {
      claims['iss'] = value;
      claims['sub'] = value;
    } else if (name === 'audience') {
      claims['aud'] = value;
    } else {
      claims[name] = value;
    }
  }
  return claims;
}

/** The exact payload text a proof over `meta` is signed over: canonical JSON of {@link proofClaims}. */
export function proofPayload(meta: ProofMeta): string {
  return canonicalize(proofClaims(meta));
}

/** Checks `meta` against the ProofMeta schema; returns it typed. */
export function validateProofMeta(value: unknown): ProofMeta {
  if (!isRecord(value)) return refuse(ProofReasons.META_INVALID, 'proof meta must be an object');
  for (const name of Object.keys(value)) {
    if (!META_MEMBERS.has(name)) return refuse(ProofReasons.META_INVALID, `proof meta has an unknown member ${name}`);
  }
  const { did, kid, ts, nonce, audience, sessionId, requestHash, responseHash, outcome, prf, delegationChainDigest } = value;
  if (!DID.test(String(did)) || typeof did !== 'string') return refuse(ProofReasons.META_INVALID, 'proof meta did must be a DID');
  if (typeof kid !== 'string' || kid.length === 0) return refuse(ProofReasons.META_INVALID, 'proof meta kid must be a non-empty string');
  if (typeof ts !== 'number' || !Number.isInteger(ts) || ts < 1) return refuse(ProofReasons.META_INVALID, 'proof meta ts must be a positive integer');
  for (const [name, member] of [['nonce', nonce], ['audience', audience], ['sessionId', sessionId]] as const) {
    if (typeof member !== 'string' || member.length === 0) return refuse(ProofReasons.META_INVALID, `proof meta ${name} must be a non-empty string`);
  }
  if (typeof requestHash !== 'string' || !SHA256.test(requestHash)) return refuse(ProofReasons.META_INVALID, 'proof meta requestHash must be sha256:<hex>');
  if (responseHash !== undefined && (typeof responseHash !== 'string' || !SHA256.test(responseHash))) {
    return refuse(ProofReasons.META_INVALID, 'proof meta responseHash must be sha256:<hex>');
  }
  if (delegationChainDigest !== undefined && (typeof delegationChainDigest !== 'string' || !SHA256.test(delegationChainDigest))) {
    return refuse(ProofReasons.META_INVALID, 'proof meta delegationChainDigest must be sha256:<hex>');
  }
  if (outcome !== undefined && !PROOF_OUTCOMES.includes(outcome as ProofOutcome)) {
    return refuse(ProofReasons.META_INVALID, `proof meta outcome must be one of ${PROOF_OUTCOMES.join(', ')}`);
  }
  for (const name of OPTIONAL_STRINGS) {
    if (value[name] !== undefined && typeof value[name] !== 'string') return refuse(ProofReasons.META_INVALID, `proof meta ${name} must be a string`);
  }
  // An unknown profile is never verified under weaker, body-only semantics (SPEC §7.3).
  if (prf !== undefined && prf !== RESPONSE_PROOF_ENVELOPE_PROFILE) {
    return refuse(ProofReasons.PROFILE_UNKNOWN, `proof profile ${String(prf)} is not known`);
  }
  return value as unknown as ProofMeta;
}

/**
 * The response proof in a result's `_meta`, or undefined when there is none.
 * Reads the current key, then the two 1.x keys; a present-but-malformed
 * value is refused, every other `_meta` member is ignored.
 */
export function readResponseProof(meta: unknown): DetachedProof | undefined {
  if (!isRecord(meta)) return undefined;
  for (const key of [RESPONSE_PROOF_META_KEY, ...LEGACY_RESPONSE_PROOF_META_KEYS]) {
    const candidate = meta[key];
    if (candidate === undefined || candidate === null) continue;
    if (!isRecord(candidate) || typeof candidate['jws'] !== 'string' || !isRecord(candidate['meta'])) {
      return refuse(ProofReasons.MALFORMED, `_meta["${key}"] must be {jws, meta}`);
    }
    for (const name of Object.keys(candidate)) {
      if (name !== 'jws' && name !== 'meta') return refuse(ProofReasons.MALFORMED, `_meta["${key}"] has an unknown member ${name}`);
    }
    return { jws: candidate['jws'], meta: validateProofMeta(candidate['meta']) };
  }
  return undefined;
}

function asDidResolver(source: DidResolver | IDidResolver): DidResolver {
  if (typeof source === 'function') return source;
  return async (did: string): Promise<JwsDidDocument | null> =>
    (await source.resolve(did)).didDocument as unknown as JwsDidDocument | null;
}

/**
 * Verifies a detached proof on its own: `meta` is well formed, the JWS is
 * the signer's (by the JWK given, or the assertion method `meta.kid` names
 * in the resolved DID document of `meta.did`), its payload is exactly the
 * canonical claims of `meta`, `ts` is within the skew and `responseHash` is
 * present exactly when the outcome carries a response. Throws
 * `ResponseProofError` (or `InvalidJWSError` from the JWS layer).
 */
export async function verifyDetachedProof(
  proof: DetachedProof,
  key: ProofKeySource,
  options: VerifyProofOptions = {},
): Promise<VerifiedProof> {
  if (!isRecord(proof) || typeof proof.jws !== 'string') return refuse(ProofReasons.MALFORMED, 'proof must be {jws, meta}');
  const meta = validateProofMeta(proof.meta);
  if (options.expectedDid !== undefined && options.expectedDid !== meta.did) {
    return refuse(ProofReasons.SIGNER_MISMATCH, `proof is signed by ${meta.did}, not ${options.expectedDid}`);
  }
  const jwsOptions = { expectedKid: meta.kid, expectedDid: meta.did };
  const verification =
    'jwk' in key ? verifyJws(proof.jws, key.jwk, jwsOptions) : await verifyJwsByKid(proof.jws, asDidResolver(key.resolveDid), jwsOptions);
  if (Buffer.from(verification.payloadBytes).toString('utf8') !== proofPayload(meta)) {
    return refuse(ProofReasons.PAYLOAD_MISMATCH, 'the signed payload is not the canonical form of the proof meta');
  }
  const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
  if (!withinSkew(meta.ts, nowSeconds, options.skewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS)) {
    return refuse(ProofReasons.TIMESTAMP_SKEW, `proof ts ${meta.ts} is outside the skew window around ${nowSeconds}`);
  }
  const outcome = meta.outcome ?? 'allowed';
  if (outcomeHasResponse(outcome) && meta.responseHash === undefined) {
    return refuse(ProofReasons.RESPONSE_HASH_MISSING, `a ${outcome} proof must carry responseHash`);
  }
  if (!outcomeHasResponse(outcome) && meta.responseHash !== undefined) {
    return refuse(ProofReasons.RESPONSE_HASH_UNEXPECTED, `a ${outcome} proof carries no response and so no responseHash`);
  }
  return { meta, outcome, did: verification.did, kid: verification.kid, profile: meta.prf };
}

/**
 * Verifies the proof on `response` against `serverDid`, recomputing
 * `requestHash` from `options.request` and `responseHash` from `response`
 * (minus its top-level `_meta` under the envelope profile). A swapped
 * request or response body fails with `request_hash_mismatch` /
 * `response_hash_mismatch`; a missing proof with `proof_missing`.
 */
export async function verifyResponseProof(
  response: unknown,
  serverDid: string,
  resolveDid: DidResolver | IDidResolver,
  options: VerifyResponseProofOptions,
): Promise<VerifiedResponseProof> {
  const proof = options.proof ?? readResponseProof(isRecord(response) ? response['_meta'] : undefined);
  if (proof === undefined) return refuse(ProofReasons.MISSING, `the response carries no _meta["${RESPONSE_PROOF_META_KEY}"]`);
  const verified = await verifyDetachedProof(proof, { resolveDid }, { ...options, expectedDid: serverDid });
  const requestHash = hashRequest(options.request);
  if (requestHash !== verified.meta.requestHash) {
    return refuse(ProofReasons.REQUEST_HASH_MISMATCH, 'the proof does not bind the request that was sent');
  }
  let responseHash: string | undefined;
  if (verified.meta.responseHash !== undefined) {
    responseHash = hashResponse(response, verified.profile);
    if (responseHash !== verified.meta.responseHash) {
      return refuse(ProofReasons.RESPONSE_HASH_MISMATCH, 'the proof does not bind the response that was received');
    }
  }
  return { ...verified, requestHash, responseHash };
}
