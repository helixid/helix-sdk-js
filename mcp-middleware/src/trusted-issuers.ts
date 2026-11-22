// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story C-B point 4: the middleware's trusted-issuer allowlist for
 * capability attestations. `'*'` (the shipped default, stories rule 9)
 * trusts every issuer; a list such as `[helixIssuerDid]` trusts those DIDs
 * only, and an attestation from any other issuer is `unverified`. A
 * restrictive default is a phase 4 discussion.
 */

import { kyaos } from '@helixid/sdk-js';
import { DEFAULT_TRUSTED_ISSUERS, type TrustedIssuers } from './credentials.js';

/**
 * Whether `issuerDid` may back a capability under `setting`. Pure: no I/O, no
 * defaults beyond `'*'`. The local verifier's rule (`kyaos.verifier.isTrustedIssuer`,
 * story F-2), so the middleware and the verifier never disagree.
 */
export function isTrustedIssuer(issuerDid: string, setting: TrustedIssuers = DEFAULT_TRUSTED_ISSUERS): boolean {
  return kyaos.verifier.isTrustedIssuer(issuerDid, setting);
}

/** How a verifier reports an attestation from `issuerDid`: `verified` only when the issuer is trusted. */
export function attestationTrust(issuerDid: string, setting: TrustedIssuers = DEFAULT_TRUSTED_ISSUERS): 'verified' | 'unverified' {
  return isTrustedIssuer(issuerDid, setting) ? 'verified' : 'unverified';
}
