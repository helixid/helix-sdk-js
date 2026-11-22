// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * W3C Data Integrity `eddsa-jcs-2022`, the verify side, as the KYA-OS
 * reference verifies delegation hops, attestations and status lists
 * (SPEC.md §6.10):
 *
 * - proof options = the proof without `proofValue`, carrying the document's
 *   `@context`; the unsecured document = the document without `proof`;
 * - hash data = SHA-256(RFC 8785 canonical proof options) followed by
 *   SHA-256(RFC 8785 canonical unsecured document);
 * - signature = Ed25519 over the hash data; `proofValue` = `z` + base58btc.
 *
 * Verifying reads the issuer's DID document through an injected resolver
 * and picks the verification method `proof.verificationMethod` names only
 * when the document lists it under `assertionMethod` exactly once and the
 * issuer controls it (CID §3.3, the same rule the JWS verifier applies).
 * Cross-border rule (stories rule 4): nothing here reads a Helix database.
 *
 * Ported from helix-core `src/core/credentials/data-integrity.ts` (story F-1)
 * for story F-2 (stories rule 24); the verify half only, since the SDK's
 * issuers sign through helix-core or the SDK's own signer elsewhere.
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { InvalidJWSError } from '../../HelixError.js';
import { base58btcDecode } from '../../vp-crypto.js';
import { canonicalize } from '../jcs.js';
import { JwsReasons, base64UrlDecodeStrict, selectAssertionMethod, verificationMethodToJwk, type DidResolver } from '../jws.js';

export type { DidResolver } from '../jws.js';

/** Why a proof was refused; the same strings helix-core and helix-sdk-py use. */
export const DataIntegrityReasons = {
  PROOF_MISSING: 'proof_missing',
  PROOF_UNSUPPORTED: 'proof_unsupported',
  PROOF_PURPOSE_MISMATCH: 'proof_purpose_mismatch',
  PROOF_VALUE_MALFORMED: 'proof_value_malformed',
  PROOF_METHOD_MALFORMED: 'proof_method_malformed',
  PROOF_ISSUER_MISMATCH: 'proof_issuer_mismatch',
  PROOF_CONTEXT_MISMATCH: 'proof_context_mismatch',
  DOCUMENT_NOT_CANONICAL: 'document_not_canonical',
  DID_UNRESOLVED: 'did_unresolved',
  KEY_REJECTED: 'key_rejected',
  SIGNATURE_INVALID: 'signature_invalid',
} as const;

export type DataIntegrityReason = (typeof DataIntegrityReasons)[keyof typeof DataIntegrityReasons];

export type ProofVerification =
  | { ok: true; issuer: string; verificationMethod: string }
  | { ok: false; reason: DataIntegrityReason; message: string };

const ED25519_SIGNATURE_LENGTH = 64;

/** The DID a document names as its issuer: a string or an `{ id }` object. */
export function issuerOf(issuer: unknown): string | undefined {
  if (typeof issuer === 'string' && issuer.startsWith('did:')) return issuer;
  if (issuer !== null && typeof issuer === 'object') {
    const id = (issuer as { id?: unknown }).id;
    if (typeof id === 'string' && id.startsWith('did:')) return id;
  }
  return undefined;
}

function digest(value: unknown): Uint8Array {
  return sha256(utf8ToBytes(canonicalize(value)));
}

/** SHA-256(canonical proof options) || SHA-256(canonical unsecured document). */
export function hashData(proofOptions: Record<string, unknown>, unsecured: Record<string, unknown>): Uint8Array {
  const proofHash = digest(proofOptions);
  const documentHash = digest(unsecured);
  const data = new Uint8Array(proofHash.length + documentHash.length);
  data.set(proofHash, 0);
  data.set(documentHash, proofHash.length);
  return data;
}

function refused(reason: DataIntegrityReason, message: string): ProofVerification {
  return { ok: false, reason, message };
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function isPrefix(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, index) => canonicalize(entry) === canonicalize(whole[index]));
}

/**
 * Verifies the one `eddsa-jcs-2022` proof on `document` against the key its
 * issuer's DID document lists for `assertionMethod`. Never throws for a bad
 * document or proof: every refusal is a `{ ok: false, reason }` the caller
 * can relay. A resolver that throws is `did_unresolved`.
 */
export async function verifyDataIntegrity(
  document: Record<string, unknown>,
  resolveDid: DidResolver,
  options: { proofPurpose?: 'assertionMethod' } = {},
): Promise<ProofVerification> {
  const purpose = options.proofPurpose ?? 'assertionMethod';
  const proof = document['proof'];
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    return refused(DataIntegrityReasons.PROOF_MISSING, 'document carries no single proof object');
  }
  const members = proof as Record<string, unknown>;
  if (members['type'] !== 'DataIntegrityProof' || members['cryptosuite'] !== 'eddsa-jcs-2022') {
    return refused(DataIntegrityReasons.PROOF_UNSUPPORTED, 'proof is not DataIntegrityProof / eddsa-jcs-2022');
  }
  if (members['proofPurpose'] !== purpose) {
    return refused(DataIntegrityReasons.PROOF_PURPOSE_MISMATCH, `proofPurpose is not ${purpose}`);
  }
  const proofValue = members['proofValue'];
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z') || proofValue.length < 2) {
    return refused(DataIntegrityReasons.PROOF_VALUE_MALFORMED, 'proofValue is not a base58btc multibase string');
  }
  let signature: Uint8Array;
  try {
    signature = base58btcDecode(proofValue.slice(1));
  } catch {
    return refused(DataIntegrityReasons.PROOF_VALUE_MALFORMED, 'proofValue is not base58btc');
  }
  if (signature.length !== ED25519_SIGNATURE_LENGTH) {
    return refused(DataIntegrityReasons.PROOF_VALUE_MALFORMED, 'proofValue is not a 64-byte Ed25519 signature');
  }
  const verificationMethod = members['verificationMethod'];
  if (typeof verificationMethod !== 'string' || !verificationMethod.includes('#')) {
    return refused(DataIntegrityReasons.PROOF_METHOD_MALFORMED, 'verificationMethod is not a DID URL');
  }
  const issuer = issuerOf(document['issuer']);
  const did = verificationMethod.slice(0, verificationMethod.indexOf('#'));
  if (issuer === undefined || did !== issuer) {
    return refused(DataIntegrityReasons.PROOF_ISSUER_MISMATCH, 'verificationMethod does not belong to the issuer');
  }

  const unsecured: Record<string, unknown> = { ...document };
  delete unsecured['proof'];
  const config: Record<string, unknown> = { ...members };
  delete config['proofValue'];
  if (config['@context'] !== undefined) {
    // The proof may name its own @context only as a prefix of the document's.
    if (!isPrefix(contexts(document['@context']), contexts(config['@context']))) {
      return refused(DataIntegrityReasons.PROOF_CONTEXT_MISMATCH, 'proof @context is not a prefix of the document @context');
    }
    unsecured['@context'] = config['@context'];
  }
  if (unsecured['@context'] !== undefined) config['@context'] = unsecured['@context'];

  let resolved: Awaited<ReturnType<DidResolver>>;
  try {
    resolved = await resolveDid(did);
  } catch (error) {
    return refused(DataIntegrityReasons.DID_UNRESOLVED, `could not resolve ${did}: ${(error as Error).message}`);
  }
  if (resolved === null || resolved === undefined) {
    return refused(DataIntegrityReasons.DID_UNRESOLVED, `could not resolve ${did}`);
  }
  let publicKey: Uint8Array;
  try {
    const method = selectAssertionMethod(resolved, did, verificationMethod);
    publicKey = base64UrlDecodeStrict(verificationMethodToJwk(method).x)!;
  } catch (error: unknown) {
    const reason = error instanceof InvalidJWSError ? error.reason : JwsReasons.KEY_UNSUPPORTED;
    return refused(DataIntegrityReasons.KEY_REJECTED, `${reason}: ${(error as Error).message}`);
  }
  let data: Uint8Array;
  try {
    data = hashData(config, unsecured);
  } catch (error) {
    return refused(DataIntegrityReasons.DOCUMENT_NOT_CANONICAL, (error as Error).message);
  }
  // noble answers false, never throws, for a signature or key that is no point.
  if (!ed25519.verify(signature, data, publicKey)) {
    return refused(DataIntegrityReasons.SIGNATURE_INVALID, 'proofValue does not verify');
  }
  return { ok: true, issuer, verificationMethod };
}
