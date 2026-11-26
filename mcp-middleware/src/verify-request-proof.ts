// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The per-request holder-of-key proof check (KYA-OS story C-C point 4),
 * through the local verifier of story F-2: the proof a tool call carries in
 * `_meta["org.kya-os/request-proof"]` (or the legacy `org.kya-os/proof@1`,
 * the canonical key winning when both exist) is verified in the exact
 * SPEC-ENTITY-CARD.md §11.2 order with the verifier's own seams: schema,
 * `kid` to DID, the key resolved and its thumbprint present in the DID
 * document, audience equal to this service's DID, `requestHash`
 * recomputed, the window with ±5 s skew, the nonce unseen in the L2-A
 * replay store, the signature, the `cnf` fusion. A missing DID-keys seam or
 * nonce store fails closed.
 *
 * The guard runs the same check inside `verify()` together with the chain
 * and the card; this export is for hosts that verify a proof on its own.
 * It consumes the nonce, so a proof verified here is spent.
 */

import { kyaos } from '@helixid/sdk-js';
import { requestOf, type LocalVerifier, type LocalVerifierCall } from './verify-locally.js';

export interface VerifyRequestProofOptions {
  /** The access token's `cnf.jkt`, for the L3 fusion; absent means L3-minus. */
  tokenCnfJkt?: string | undefined;
  /** Clock skew on the window, seconds; default 5. */
  skewSeconds?: number | undefined;
}

/** Verifies the request proof of one tool call with `verifier`'s seams; the audience is the verifier's service DID. */
export function verifyRequestProof(
  verifier: LocalVerifier,
  call: LocalVerifierCall,
  options: VerifyRequestProofOptions = {},
): Promise<kyaos.verifier.RequestProofVerification> {
  return kyaos.verifier.verifyRequestProof(kyaos.verifier.readRequestProof(call._meta), requestOf(call), verifier.seams, {
    expectedAudience: verifier.serviceDid,
    ...(options.tokenCnfJkt === undefined ? {} : { tokenCnfJkt: options.tokenCnfJkt }),
    ...(options.skewSeconds === undefined ? {} : { skewSeconds: options.skewSeconds }),
  });
}
