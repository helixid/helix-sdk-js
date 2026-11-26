// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Verification of the per-request holder-of-key proof `org.kya-os/proof.v1`
 * (KYA-OS story C-C, SPEC-ENTITY-CARD.md §11.2), in the exact order the
 * spec gives, stopping at the first broken binding:
 *
 *  1. schema (`malformed_proof`);
 *  2. `kid` names a key of `did` (`kid_did_mismatch`);
 *  3. the signing key resolved from `did`'s document (`key_unresolvable`;
 *     a document older than one already seen, `did_document_stale`), and
 *     (story C-E) valid at `created`: never `revoked` (`key_revoked`), not
 *     past its `validUntil` (`key_superseded`);
 *  4. its RFC 7638 thumbprint is among the keys the DID publishes
 *     (`kid_not_in_did_document`; no `resolveDidKeys` seam fails closed with
 *     `did_membership_unverifiable`);
 *  5. `audience` is this verifier (`audience_mismatch`);
 *  6. `requestHash` recomputes over the request (`request_hash_mismatch`);
 *  7. the window, with ±5 s skew by default (`invalid_window`,
 *     `ttl_too_long`, `created_in_future`, `expired`);
 *  8. the nonce is unseen for `did` in the replay store (`nonce_replayed`;
 *     no store fails closed with `nonce_seam_missing`);
 *  9. the detached JWS over the recomputed covered claims
 *     (`invalid_signature`);
 * 10. the `cnf` fusion (§8.6): `L3` when the token's `cnf.jkt`, the proof's
 *     and the key's thumbprint agree, `L3-minus` without a token `cnf`.
 *
 * A proof under the legacy carrier key `org.kya-os/proof@1`, or with the
 * legacy `prf`, verifies the same way (`readRequestProof`, `parseRequestProof`).
 * Pure: everything external comes through the seams, and a missing seam is
 * refused at the step that needs it, never skipped.
 */

import { InvalidJWSError } from '../../HelixError.js';
import { base64UrlDecodeStrict, selectAssertionMethod, verificationMethodToJwk, type DidResolver, type Ed25519PublicJwk } from '../jws.js';
import { ReasonCodes, type ReasonCode } from './codes.js';
import { keyValidityProblem, type KeyValidityReason } from '../key-validity.js';
import { StaleDidDocumentError } from './rotation.js';

const KEY_VALIDITY_CODES: Record<KeyValidityReason, ReasonCode> = {
  key_revoked: ReasonCodes.KEY_REVOKED,
  key_superseded: ReasonCodes.KEY_SUPERSEDED,
  key_validity_malformed: ReasonCodes.KEY_VALIDITY_MALFORMED,
};
import {
  DEFAULT_PROOF_SKEW_SECONDS,
  MAX_PROOF_TTL_SECONDS,
  didOfKid,
  jwkThumbprint,
  parseRequestProof,
  requestHashContentDigest,
  verifyDetachedJws,
  windowProblems,
  type ProofRequest,
  type RequestProof,
} from './request-proof.js';

/** `L3` on a full `cnf` fusion, `L3-minus` without a token `cnf` (§8.6). */
export type ProofAssurance = 'L3' | 'L3-minus';

/** The local replay store: one atomic conditional insert, the middleware's `NonceStore` shape. */
export interface NonceStoreSeam {
  insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean>;
}

/** The seams §11.2 reads: the caller's DID document and keys, the replay store and the time. */
export interface RequestProofSeams {
  resolveDid?: DidResolver | undefined;
  resolveDidKeys?: ((did: string) => Promise<Ed25519PublicJwk[]> | Ed25519PublicJwk[]) | undefined;
  nonceStore?: NonceStoreSeam | undefined;
  /** Milliseconds since the epoch. */
  clock?: (() => number) | undefined;
}

export interface RequestProofOptions {
  /** This verifier's own DID: the proof's `audience` must equal it. */
  expectedAudience: string;
  /** Clock skew on the window, in seconds; default 5. */
  skewSeconds?: number | undefined;
  /** The longest lifetime accepted, in seconds; default 60. */
  maxTtlSeconds?: number | undefined;
  /** The access token's RFC 9449 `cnf.jkt`; absent means L3-minus. */
  tokenCnfJkt?: string | undefined;
}

export interface RequestProofVerification {
  ok: boolean;
  /** The reason codes of the step that failed; empty iff `ok`. */
  reasons: ReasonCode[];
  messages: string[];
  /** The accountable principal, once every binding held. */
  did?: string | undefined;
  assurance?: ProofAssurance | undefined;
  /** The parsed proof, once step 1 passed. */
  proof?: RequestProof | undefined;
  /** Non-fatal diagnostics: `cnf_present_but_token_unfused` (§8.6). */
  warnings: string[];
}

/** The non-fatal diagnostic of §8.6: the proof carries `cnf` but no token `cnf` was given to fuse it with. */
export const CNF_PRESENT_BUT_TOKEN_UNFUSED = 'cnf_present_but_token_unfused';

function refusedAt(code: ReasonCode, message: string, proof?: RequestProof, extra: { reasons?: ReasonCode[]; messages?: string[] } = {}): RequestProofVerification {
  return {
    ok: false,
    reasons: extra.reasons ?? [code],
    messages: extra.messages ?? [message],
    ...(proof === undefined ? {} : { proof }),
    warnings: [],
  };
}

interface ResolvedKey {
  jwk: Ed25519PublicJwk;
  publicKey: Uint8Array;
}

/**
 * Verifies one request proof against `request` in the §11.2 order. Never
 * throws for a bad proof or a failing seam: each is a reason code.
 */
export async function verifyRequestProof(
  value: unknown,
  request: ProofRequest | undefined,
  seams: RequestProofSeams,
  options: RequestProofOptions,
): Promise<RequestProofVerification> {
  if (typeof seams.clock !== 'function') return refusedAt(ReasonCodes.CLOCK_SEAM_MISSING, 'no clock seam: the window cannot be checked');
  if (typeof options.expectedAudience !== 'string' || !options.expectedAudience.startsWith('did:')) {
    return refusedAt(ReasonCodes.CONFIGURATION_ERROR, 'expectedAudience must be this verifier\'s DID');
  }
  if (value === undefined || value === null) return refusedAt(ReasonCodes.PROOF_MISSING, 'the request carries no org.kya-os/request-proof');

  // 1. Schema.
  const proof = parseRequestProof(value);
  if (proof === undefined) return refusedAt(ReasonCodes.MALFORMED_PROOF, 'the request proof is not an org.kya-os/proof.v1 object');

  // 2. kid ⇄ did.
  if (didOfKid(proof.kid) !== proof.did) return refusedAt(ReasonCodes.KID_DID_MISMATCH, 'kid does not belong to did', proof);

  // 3. The signing key, from did's document (CID §3.3 assertion rule); only EdDSA keys are read.
  if (typeof seams.resolveDid !== 'function') return refusedAt(ReasonCodes.DID_RESOLVER_MISSING, 'no resolveDid seam: the signing key cannot be read', proof);
  if (proof.alg !== 'EdDSA') return refusedAt(ReasonCodes.ALG_UNSUPPORTED, `proof alg ${proof.alg} is not EdDSA`, proof);
  let key: ResolvedKey;
  try {
    const document = await seams.resolveDid(proof.did);
    if (document === null || document === undefined) return refusedAt(ReasonCodes.DID_UNRESOLVED, `${proof.did} did not resolve`, proof);
    let method: ReturnType<typeof selectAssertionMethod>;
    try {
      method = selectAssertionMethod(document, proof.did, proof.kid);
      const jwk = verificationMethodToJwk(method);
      key = { jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: proof.kid }, publicKey: base64UrlDecodeStrict(jwk.x)! };
    } catch (error) {
      const reason = error instanceof InvalidJWSError ? `${error.reason}: ` : '';
      return refusedAt(ReasonCodes.KEY_UNRESOLVABLE, `${reason}${(error as Error).message}`, proof);
    }
    // 3b. Story C-E point 3: the key kid names was valid when the proof was created (a revoked key never is).
    const validity = keyValidityProblem(method, proof.created * 1000, seams.clock());
    if (validity) return refusedAt(KEY_VALIDITY_CODES[validity.reason], validity.message, proof);
  } catch (error) {
    if (error instanceof StaleDidDocumentError) return refusedAt(ReasonCodes.DID_DOCUMENT_STALE, error.message, proof);
    return refusedAt(ReasonCodes.DID_UNRESOLVED, `could not resolve ${proof.did}: ${(error as Error).message}`, proof);
  }

  // 4. DID membership: the key's RFC 7638 thumbprint is one the DID publishes.
  if (typeof seams.resolveDidKeys !== 'function') {
    return refusedAt(ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE, 'no resolveDidKeys seam: the key cannot be shown to belong to the DID', proof);
  }
  let published: Ed25519PublicJwk[];
  try {
    published = await seams.resolveDidKeys(proof.did);
  } catch (error) {
    return refusedAt(ReasonCodes.DID_KEYS_UNRESOLVABLE, `could not list the keys of ${proof.did}: ${(error as Error).message}`, proof);
  }
  const keyJkt = jwkThumbprint(key.jwk);
  const listed = published.some((jwk) => {
    try {
      return jwkThumbprint(jwk) === keyJkt;
    } catch {
      return false;
    }
  });
  if (!listed) return refusedAt(ReasonCodes.KID_NOT_IN_DID_DOCUMENT, `${proof.kid} is not a key ${proof.did} publishes`, proof);

  // 5. Audience.
  if (proof.audience !== options.expectedAudience) {
    return refusedAt(ReasonCodes.AUDIENCE_MISMATCH, `audience ${proof.audience} is not this verifier (${options.expectedAudience})`, proof);
  }

  // 6. requestHash, recomputed with params._meta stripped (§8.3).
  if (request === undefined) return refusedAt(ReasonCodes.REQUEST_MISSING, 'no request to recompute requestHash from', proof);
  let computed: string | undefined;
  try {
    computed = requestHashContentDigest(request);
  } catch {
    computed = undefined;
  }
  if (computed !== proof.requestHash) return refusedAt(ReasonCodes.REQUEST_HASH_MISMATCH, 'requestHash does not recompute from the request', proof);

  // 7. Window: every way it fails, as one step.
  const skewSeconds = options.skewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;
  const nowSeconds = Math.floor(seams.clock() / 1000);
  const problems = windowProblems(proof, nowSeconds, skewSeconds, options.maxTtlSeconds ?? MAX_PROOF_TTL_SECONDS);
  if (problems.length > 0) {
    const reasons = problems.map((problem) => ReasonCodes[problem.toUpperCase() as 'INVALID_WINDOW' | 'TTL_TOO_LONG' | 'CREATED_IN_FUTURE' | 'EXPIRED']);
    return refusedAt(reasons[0]!, '', proof, { reasons, messages: problems.map((problem) => `proof window: ${problem}`) });
  }

  // 8. Replay: the nonce unseen for did, kept until expires + skew + 1 s.
  if (seams.nonceStore === undefined || typeof seams.nonceStore.insert !== 'function') {
    return refusedAt(ReasonCodes.NONCE_SEAM_MISSING, 'no nonceStore seam: there is no replay defense to run', proof);
  }
  try {
    if (!(await seams.nonceStore.insert(proof.nonce, proof.did, (proof.expires + skewSeconds + 1) * 1000))) {
      return refusedAt(ReasonCodes.NONCE_REPLAYED, `nonce ${proof.nonce} was already used by ${proof.did}`, proof);
    }
  } catch (error) {
    return refusedAt(ReasonCodes.NONCE_STORE_UNAVAILABLE, `the nonce store could not answer: ${(error as Error).message}`, proof);
  }

  // 9. The detached JWS over the recomputed covered claims.
  if (!verifyDetachedJws(proof, key.publicKey)) {
    return refusedAt(ReasonCodes.INVALID_SIGNATURE, 'the detached JWS does not verify over the covered claims', proof);
  }

  // 10. cnf fusion.
  const warnings: string[] = [];
  if (proof.cnf !== undefined && proof.cnf.jkt !== keyJkt) {
    return refusedAt(ReasonCodes.CNF_KEY_MISMATCH, 'cnf.jkt is not the thumbprint of the signing key', proof);
  }
  let assurance: ProofAssurance;
  if (options.tokenCnfJkt === undefined) {
    if (proof.cnf !== undefined) warnings.push(CNF_PRESENT_BUT_TOKEN_UNFUSED);
    assurance = 'L3-minus';
  } else if (proof.cnf === undefined) {
    return refusedAt(ReasonCodes.CNF_REQUIRED_BY_TOKEN, 'the token is sender-constrained but the proof carries no cnf', proof);
  } else if (proof.cnf.jkt !== options.tokenCnfJkt) {
    return refusedAt(ReasonCodes.CNF_TOKEN_MISMATCH, 'cnf.jkt is not the token cnf.jkt', proof);
  } else {
    assurance = 'L3';
  }
  return { ok: true, reasons: [], messages: [], did: proof.did, assurance, proof, warnings };
}
