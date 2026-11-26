// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The per-request holder-of-key proof `org.kya-os/proof.v1`
 * (SPEC-ENTITY-CARD.md §8): the shape, the `requestHash` binding
 * (`sha-256=:<base64>:` over the JCS of `{method, params}` with
 * `params._meta` removed), the covered claims the detached JWS signs, the
 * RFC 7638 thumbprint the DID-membership check compares, and the window
 * rules. `verify()` runs them in the §11.2 order; this module holds each
 * pure piece so the SDK's minter (story C-C) and the verifier derive the
 * signing input from one place.
 */

import { randomBytes } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../jcs.js';
import { base64UrlDecodeStrict, base64UrlEncode, type Ed25519PublicJwk } from '../jws.js';

/** Where the proof rides: `_meta["org.kya-os/request-proof"]`. */
export const REQUEST_PROOF_META_KEY = 'org.kya-os/request-proof';
/** The earlier carrier key, read for one major version (§8.1); the canonical key wins when both exist. */
export const LEGACY_REQUEST_PROOF_META_KEY = 'org.kya-os/proof@1';
/** Where a request carries its delegation chain, root to leaf (§10.5). */
export const DELEGATION_CHAIN_META_KEY = 'org.kya-os/delegation-chain';

export const PROOF_PROFILE_V1 = 'org.kya-os/proof.v1';
export const LEGACY_PROOF_PROFILE = 'org.kya-os/proof@1';

/** `expires - created` may not exceed this many seconds (§8.2). */
export const MAX_PROOF_TTL_SECONDS = 60;
/** Default clock skew, in seconds, on the created/expires window (§8.2). */
export const DEFAULT_PROOF_SKEW_SECONDS = 5;

export interface RequestProof {
  prf: typeof PROOF_PROFILE_V1 | typeof LEGACY_PROOF_PROFILE;
  alg: 'EdDSA' | 'ES256';
  did: string;
  kid: string;
  audience: string;
  nonce: string;
  /** Epoch seconds. */
  created: number;
  expires: number;
  requestHash: string;
  cnf?: { jkt: string };
  jws: string;
  httpSig?: string;
}

/** The request a proof binds: a JSON-RPC `{method, params}`. */
export interface ProofRequest {
  method: string;
  params?: unknown;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const DID = /^did:[a-z0-9]+:.+$/;
const KID = /^did:[a-z0-9]+:.+#.+$/;
const MEMBERS = new Set(['prf', 'alg', 'did', 'kid', 'audience', 'nonce', 'created', 'expires', 'requestHash', 'cnf', 'jws', 'httpSig']);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The proof as `_meta` carries it: under the canonical key, else the legacy
 * key; `undefined` when neither is present. The value is returned as is;
 * {@link parseRequestProof} judges its shape.
 */
export function readRequestProof(meta: unknown): unknown {
  if (!isRecord(meta)) return undefined;
  const canonical = meta[REQUEST_PROOF_META_KEY];
  if (canonical !== undefined && canonical !== null) return canonical;
  const legacy = meta[LEGACY_REQUEST_PROOF_META_KEY];
  return legacy === null ? undefined : legacy;
}

/** The carried chain in `_meta`, as is; `undefined` when the request carries none. */
export function readCarriedChain(meta: unknown): unknown {
  if (!isRecord(meta)) return undefined;
  const chain = meta[DELEGATION_CHAIN_META_KEY];
  return chain === null ? undefined : chain;
}

/** Checks `value` against the §8.2 object; the proof typed, or undefined when it is not one. */
export function parseRequestProof(value: unknown): RequestProof | undefined {
  if (!isRecord(value)) return undefined;
  for (const name of Object.keys(value)) if (!MEMBERS.has(name)) return undefined;
  const { prf, alg, did, kid, audience, nonce, created, expires, requestHash, cnf, jws, httpSig } = value;
  if (prf !== PROOF_PROFILE_V1 && prf !== LEGACY_PROOF_PROFILE) return undefined;
  if (alg !== 'EdDSA' && alg !== 'ES256') return undefined;
  if (typeof did !== 'string' || !DID.test(did)) return undefined;
  if (typeof kid !== 'string' || !KID.test(kid)) return undefined;
  if (typeof audience !== 'string' || !DID.test(audience)) return undefined;
  if (typeof nonce !== 'string' || !BASE64URL.test(nonce)) return undefined;
  if (typeof created !== 'number' || !Number.isInteger(created) || created < 0) return undefined;
  if (typeof expires !== 'number' || !Number.isInteger(expires) || expires < 0) return undefined;
  if (typeof requestHash !== 'string' || requestHash.length === 0) return undefined;
  if (typeof jws !== 'string' || jws.length === 0) return undefined;
  if (httpSig !== undefined && (typeof httpSig !== 'string' || httpSig.length === 0)) return undefined;
  if (cnf !== undefined) {
    if (!isRecord(cnf) || Object.keys(cnf).length !== 1 || typeof cnf['jkt'] !== 'string' || !BASE64URL.test(cnf['jkt'])) return undefined;
  }
  return value as unknown as RequestProof;
}

/** The §8.3 covered request: `{method, params}` with `params._meta` removed; `{method}` alone when there are no params. */
export function coveredRequest(request: ProofRequest): Record<string, unknown> {
  const params = request.params;
  if (params === undefined) return { method: request.method };
  if (!isRecord(params) || !('_meta' in params)) return { method: request.method, params };
  const rest: Record<string, unknown> = { ...params };
  delete rest['_meta'];
  return { method: request.method, params: rest };
}

/** `sha-256=:<base64>:` (RFC 9421 Content-Digest form) over the JCS of the covered request. */
export function requestHashContentDigest(request: ProofRequest): string {
  const digest = sha256(utf8ToBytes(canonicalize(coveredRequest(request))));
  return `sha-256=:${Buffer.from(digest).toString('base64')}:`;
}

/** The covered claims (§8.4): every member but the two signatures, in the order the profile lists them. */
export function coveredClaims(proof: RequestProof): Record<string, unknown> {
  return {
    prf: proof.prf,
    alg: proof.alg,
    did: proof.did,
    kid: proof.kid,
    audience: proof.audience,
    nonce: proof.nonce,
    created: proof.created,
    expires: proof.expires,
    requestHash: proof.requestHash,
    ...(proof.cnf ? { cnf: { jkt: proof.cnf.jkt } } : {}),
  };
}

/** The JCS bytes of the covered claims: the detached JWS payload. */
export function coveredClaimsBytes(proof: RequestProof): Uint8Array {
  return utf8ToBytes(canonicalize(coveredClaims(proof)));
}

/** RFC 7638 thumbprint of an Ed25519 public JWK: SHA-256 of `{"crv","kty","x"}` in that order, base64url. */
export function jwkThumbprint(jwk: Pick<Ed25519PublicJwk, 'crv' | 'kty' | 'x'>): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return base64UrlEncode(sha256(utf8ToBytes(canonical)));
}

/** The DID part of a `<did>#<fragment>` key id. */
export function didOfKid(kid: string): string {
  const hash = kid.indexOf('#');
  return hash === -1 ? kid : kid.slice(0, hash);
}

/**
 * Verifies the detached JWS (`<protected>..<signature>`) over the recomputed
 * covered claims: the protected header must name the proof's `alg` and
 * `kid`, every segment is strict base64url, and the Ed25519 signature must
 * hold under `publicKey`. Only `EdDSA` is verified here; an `ES256` proof
 * is refused by the caller before this (the Helix profile signs Ed25519).
 */
export function verifyDetachedJws(proof: RequestProof, publicKey: Uint8Array): boolean {
  const parts = proof.jws.split('.');
  if (parts.length !== 3 || parts[1] !== '') return false;
  const [protectedB64, , signatureB64] = parts as [string, string, string];
  const headerBytes = base64UrlDecodeStrict(protectedB64);
  const signature = base64UrlDecodeStrict(signatureB64);
  if (headerBytes === undefined || signature === undefined || signature.length !== 64 || protectedB64.length === 0) return false;
  let header: unknown;
  try {
    header = JSON.parse(Buffer.from(headerBytes).toString('utf8'));
  } catch {
    return false;
  }
  if (!isRecord(header) || header['alg'] !== proof.alg || header['kid'] !== proof.kid) return false;
  const signingInput = utf8ToBytes(`${protectedB64}.${base64UrlEncode(coveredClaimsBytes(proof))}`);
  try {
    return ed25519.verify(signature, signingInput, publicKey);
  } catch {
    return false;
  }
}

export type WindowProblem = 'invalid_window' | 'ttl_too_long' | 'created_in_future' | 'expired';

/** Every way the proof's window fails at `nowSeconds` with `skewSeconds` tolerance (§11.2 step 7). */
export function windowProblems(proof: RequestProof, nowSeconds: number, skewSeconds: number, maxTtlSeconds = MAX_PROOF_TTL_SECONDS): WindowProblem[] {
  const problems: WindowProblem[] = [];
  if (proof.expires <= proof.created) problems.push('invalid_window');
  if (proof.expires - proof.created > maxTtlSeconds) problems.push('ttl_too_long');
  if (proof.created > nowSeconds + skewSeconds) problems.push('created_in_future');
  if (proof.expires < nowSeconds - skewSeconds) problems.push('expired');
  return problems;
}

export interface SignRequestProofOptions {
  /** The recipient's DID (from its card), what the verifier checks as `expectedAudience`. */
  audience: string;
  /** Epoch ms of `created`; default the signer's clock, `Date.now()`. */
  now?: number | undefined;
  /** Lifetime in seconds, at most 60; default 60. */
  ttlSeconds?: number | undefined;
  /** A base64url nonce, 128 bits; default fresh random bytes. */
  nonce?: string | undefined;
  /** The RFC 7638 thumbprint to carry as `cnf.jkt`; default none (L3-minus). */
  cnfJkt?: string | undefined;
  /** `org.kya-os/proof.v1` (default) or the legacy profile id, for verifiers of the earlier draft. */
  profile?: typeof PROOF_PROFILE_V1 | typeof LEGACY_PROOF_PROFILE | undefined;
}

/**
 * Mints an `org.kya-os/proof.v1` for `request`, signed by `signer` as a
 * detached EdDSA JWS over the covered claims (§8.4). The fixture generator,
 * the sample agent and the tests mint through this; story C-C's SDK minter
 * wraps it per call.
 */
export async function signRequestProof(
  request: ProofRequest,
  signer: { did: string; kid: string; sign(data: Uint8Array): Promise<Uint8Array> },
  options: SignRequestProofOptions,
): Promise<RequestProof> {
  const created = Math.floor((options.now ?? Date.now()) / 1000);
  const ttl = options.ttlSeconds ?? MAX_PROOF_TTL_SECONDS;
  const kid = `${signer.did}#${signer.kid.replace(/^#/, '')}`;
  const claims: RequestProof = {
    prf: options.profile ?? PROOF_PROFILE_V1,
    alg: 'EdDSA',
    did: signer.did,
    kid,
    audience: options.audience,
    nonce: options.nonce ?? base64UrlEncode(randomBytes(16)),
    created,
    expires: created + ttl,
    requestHash: requestHashContentDigest(request),
    ...(options.cnfJkt === undefined ? {} : { cnf: { jkt: options.cnfJkt } }),
    jws: '',
  };
  const protectedHeader = base64UrlEncode(JSON.stringify({ alg: 'EdDSA', kid }));
  const signingInput = utf8ToBytes(`${protectedHeader}.${base64UrlEncode(coveredClaimsBytes(claims))}`);
  const signature = await signer.sign(signingInput);
  return { ...claims, jws: `${protectedHeader}..${base64UrlEncode(signature)}` };
}
