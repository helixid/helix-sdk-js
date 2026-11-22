// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { kyaos } from '@helixid/sdk-js';

/**
 * The server's side of the KYA-OS detached response proof (story L2-A;
 * conformance L2.11, L2.12). `buildResponseProof` signs the RFC 8785
 * canonical JSON of the ProofMeta's claims (`iss`/`sub` the server DID,
 * `aud` the audience, the rest by name) as an EdDSA compact JWS through the
 * service Signer, and returns `{jws, meta}`. The Signer is the only thing
 * that touches the private key: this module hands it bytes and takes back a
 * signature (self-custody invariant, stories rule 7).
 */

export type ProofMeta = kyaos.ProofMeta;
export type DetachedProof = kyaos.DetachedProof;
export type ProofOutcome = kyaos.ProofOutcome;

export const RESPONSE_PROOF_META_KEY = kyaos.RESPONSE_PROOF_META_KEY;

/**
 * Signs `meta` with `signer`, whose DID and kid must be the ones `meta`
 * names. `responseHash` must be present on `allowed` and
 * `needs_authorization` and absent on `denied` and `step_up_required`.
 */
export async function buildResponseProof(meta: ProofMeta, signer: kyaos.Signer): Promise<DetachedProof> {
  const validated = kyaos.validateProofMeta(meta);
  if (validated.did !== signer.did || validated.kid !== `${signer.did}#${signer.kid.replace(/^#/, '')}`) {
    throw new Error(`buildResponseProof: meta names ${validated.did} / ${validated.kid}, the signer is ${signer.did}#${signer.kid}`);
  }
  const outcome = validated.outcome ?? 'allowed';
  if (kyaos.outcomeHasResponse(outcome) && validated.responseHash === undefined) {
    throw new Error(`buildResponseProof: a ${outcome} proof must carry responseHash`);
  }
  if (!kyaos.outcomeHasResponse(outcome) && validated.responseHash !== undefined) {
    throw new Error(`buildResponseProof: a ${outcome} proof carries no response and so no responseHash`);
  }
  const jws = await kyaos.signJws(kyaos.proofPayload(validated), signer);
  return { jws, meta: validated };
}

/** `result` with `proof` at `_meta["org.kya-os/response-proof"]`; other `_meta` members are kept. */
export function attachResponseProof<T extends Record<string, unknown>>(result: T, proof: DetachedProof): T & { _meta: Record<string, unknown> } {
  const existing = result['_meta'];
  const meta = typeof existing === 'object' && existing !== null && !Array.isArray(existing) ? (existing as Record<string, unknown>) : {};
  return { ...result, _meta: { ...meta, [RESPONSE_PROOF_META_KEY]: proof } };
}
