// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Capability attestations and the Entity Card level (stories F-1, C-B;
 * SPEC-ENTITY-CARD.md §9): one `CapabilityAttestationCredential` per
 * capability, verified on schema, subject (the card id), capability name,
 * trusted issuer, window, proof and status; a card's capabilities sorted
 * into verified and unverified; the level recomputed from that, never read
 * off the card.
 *
 * Ported from helix-core `src/core/credentials/{attestation,card-level}.ts`
 * for story F-2 (stories rule 24), with the status read going through the
 * verifier's `fetchStatusList` seam instead of a pre-fetched list.
 */

import { ReasonCodes } from './codes.js';
import {
  credentialSchemaViolations,
  describeViolations,
  isTrustedIssuer,
  windowVerdict,
  type SignedCapabilityAttestation,
  type TrustedIssuers,
} from './credentials.js';
import { verifyDataIntegrity, type DidResolver } from './data-integrity.js';
import { revocationCheckerOf, type RevocationChecker } from './revocation.js';
import type { FetchStatusList, StatusListRead } from './status.js';

export type ConformanceLevel = 'L1' | 'L2' | 'L3';

export interface CardCapabilityObject {
  name: string;
  attestations: { vc: unknown }[];
}

export type CardCapability = string | CardCapabilityObject;

export interface CapabilityCheck {
  verified: string[];
  unverified: string[];
}

/** The name of a capability entry, whichever form it takes. */
export function capabilityName(capability: CardCapability): string {
  return typeof capability === 'string' ? capability : capability.name;
}

export type AttestationVerification =
  | { ok: true; credential: SignedCapabilityAttestation; capability: string; issuer: string; fresh: boolean }
  | { ok: false; reason: string; message: string };

export interface VerifyAttestationOptions {
  /** The card id / agent DID the attestation must name. */
  subjectDid?: string | undefined;
  /** The capability name it must attest. */
  capability?: string | undefined;
  /** Default `'*'`: an unlisted issuer is `issuer_untrusted`. */
  trustedIssuers?: TrustedIssuers | undefined;
  /** Epoch ms. */
  now: number;
  maxClockSkewMs?: number | undefined;
  /** Reads the status list the entry names; without it (and without `checkRevocation`) the attestation is refused `status_seam_missing`. */
  fetchStatusList?: FetchStatusList | undefined;
  /** The revocation check (story L3-C), in place of a bare `fetchStatusList` read: cached, keeper-aware. */
  checkRevocation?: RevocationChecker | undefined;
  /** The scopes the request touches, which pick the status cache TTL. */
  scopes?: readonly string[] | undefined;
  /** The lists read live during this verification (see `RevocationContext.reads`). */
  reads?: Map<string, StatusListRead> | undefined;
  /** Read each list live, past the status cache (see `RevocationContext.live`). */
  liveStatus?: boolean | undefined;
}

/**
 * Schema, subject, capability name, trusted issuer, window, proof and status
 * of a capability attestation, in that order. Every refusal is a reason the
 * caller can relay; nothing throws.
 */
export async function verifyCapabilityAttestation(
  value: unknown,
  resolveDid: DidResolver,
  options: VerifyAttestationOptions,
): Promise<AttestationVerification> {
  const violations = credentialSchemaViolations('attestation', value);
  if (violations.length > 0) {
    return { ok: false, reason: 'schema_invalid', message: describeViolations(violations) };
  }
  const credential = value as SignedCapabilityAttestation;
  const subject = credential.credentialSubject;
  if (options.subjectDid !== undefined && subject.id !== options.subjectDid) {
    return { ok: false, reason: 'subject_mismatch', message: 'credentialSubject.id is not the card id' };
  }
  if (options.capability !== undefined && subject.capability !== options.capability) {
    return { ok: false, reason: 'capability_mismatch', message: 'credentialSubject.capability is not the declared capability' };
  }
  if (!isTrustedIssuer(credential.issuer, options.trustedIssuers ?? '*')) {
    return { ok: false, reason: ReasonCodes.ISSUER_UNTRUSTED, message: `${credential.issuer} is not a trusted issuer` };
  }
  const window = windowVerdict(credential.validFrom, credential.validUntil, options.now, options.maxClockSkewMs);
  if (window !== 'inside') {
    return { ok: false, reason: `credential_${window}`, message: `credential is ${window.replace(/_/g, ' ')}` };
  }
  const proof = await verifyDataIntegrity(credential as unknown as Record<string, unknown>, resolveDid);
  if (!proof.ok) return proof;
  const checker =
    options.checkRevocation ?? (options.fetchStatusList === undefined ? undefined : revocationCheckerOf(options.fetchStatusList, options.maxClockSkewMs));
  if (checker === undefined) {
    return { ok: false, reason: ReasonCodes.STATUS_SEAM_MISSING, message: 'no fetchStatusList seam to read the attestation status with' };
  }
  let status;
  try {
    status = await checker(credential, { now: options.now, scopes: options.scopes, reads: options.reads, ...(options.liveStatus === true ? { live: true } : {}) });
  } catch (error) {
    return { ok: false, reason: ReasonCodes.STATUS_UNAVAILABLE, message: `the revocation check failed: ${(error as Error).message}` };
  }
  if (status.revoked) return { ok: false, reason: status.code ?? ReasonCodes.STATUS_REVOKED, message: status.message ?? 'revoked' };
  return { ok: true, credential, capability: subject.capability, issuer: credential.issuer, fresh: status.fresh };
}

export interface CheckCapabilitiesOptions extends Omit<VerifyAttestationOptions, 'capability'> {
  subjectDid: string;
}

export interface CapabilityCheckResult extends CapabilityCheck {
  /** False when any verified attestation's status came from a cached read. */
  fresh: boolean;
  /** Why each unverified attested capability failed, by name: the first attestation's reason. */
  refusals: Record<string, string>;
}

/**
 * Sorts a card's capabilities into verified (every attested name with at
 * least one attestation that verifies) and unverified (bare strings, and
 * attested names none of whose attestations verify).
 */
export async function checkCapabilities(
  capabilities: readonly CardCapability[],
  resolveDid: DidResolver,
  options: CheckCapabilitiesOptions,
): Promise<CapabilityCheckResult> {
  const verified: string[] = [];
  const unverified: string[] = [];
  const refusals: Record<string, string> = {};
  let fresh = true;
  for (const capability of capabilities) {
    if (typeof capability === 'string') {
      unverified.push(capability);
      continue;
    }
    let holds = false;
    for (const attestation of capability.attestations) {
      const verdict = await verifyCapabilityAttestation(attestation.vc, resolveDid, { ...options, capability: capability.name });
      if (verdict.ok) {
        holds = true;
        fresh &&= verdict.fresh;
        break;
      }
      refusals[capability.name] ??= verdict.reason;
    }
    (holds ? verified : unverified).push(capability.name);
  }
  return { verified, unverified, fresh, refusals };
}

/** The §9.4 proof floor: a boolean, or a proof verdict whose `ok` says whether it held. */
export type ProofFloor = boolean | { ok: boolean } | undefined;

/**
 * SPEC-ENTITY-CARD.md §9.4, `deriveConformanceLevel(check, proofFloor,
 * revocationFresh)`: L1 unless every declared capability is attested and
 * verified; L3 only with the proof floor and a fresh revocation read;
 * otherwise L2. Fail-closed: a missing artifact demotes, never errors open.
 * L3-minus (§8.6) satisfies the proof floor; whether it satisfies a tool's
 * L3 minimum is the caller's policy (story C-C, `l3MinusSatisfiesL3`).
 */
export function deriveConformanceLevel(check: CapabilityCheck, proofFloor: ProofFloor = false, revocationFresh = true): ConformanceLevel {
  const allAttested = check.verified.length > 0 && check.unverified.length === 0;
  if (!allAttested) return 'L1';
  const floor = typeof proofFloor === 'object' && proofFloor !== null ? proofFloor.ok === true : proofFloor === true;
  if (floor && revocationFresh) return 'L3';
  return 'L2';
}
