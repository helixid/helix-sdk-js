// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The delegation proof JWT (KYA-OS story L3-D point 3, SPEC.md §8.2, L3.23)
 * and the chain string (§8.3, L3.24).
 *
 * The forwarding service signs, with its own Signer (EdDSA, `kid` its DID's
 * key): `iss` its DID, `sub` the Responsible Party (the issuer of the
 * chain's root hop, whoever that is on this journey: the account on an
 * owner-rooted chain, the user's did:key on a consent chain), `aud` the
 * target host, `iat`, `exp` = `iat` + 60 s, a fresh `jti`, `delegation_id`
 * (the leaf capability's id), `delegation_chain` (the chain string) and
 * `scope` (comma-separated).
 */

import { randomUUID } from 'node:crypto';
import { kyaos } from '@helixid/sdk-js';

/** The proof's lifetime: §8.2 fixes `exp` at `iat` + 60 s. */
export const DELEGATION_PROOF_TTL_SECONDS = 60;
export const DELEGATION_PROOF_TYP = 'JWT';

export interface DelegationProofClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  delegation_id: string;
  delegation_chain: string;
  scope: string;
}

export interface MintDelegationProofInput {
  /** The Responsible Party: the issuer of the chain's root hop. */
  sub: string;
  /** The target host (`new URL(target).host`). */
  aud: string;
  delegation_id: string;
  delegation_chain: string;
  /** The scopes forwarded, joined with commas; or the list. */
  scope: string | readonly string[];
  /** The forwarding service's DID; must be the signer's. Default the signer's DID. */
  iss?: string | undefined;
  /** Default a fresh `urn:uuid`. */
  jti?: string | undefined;
  /** Milliseconds since the epoch; default `Date.now()`. */
  now?: number | undefined;
}

/** Mints the §8.2 delegation proof JWT, signed by the forwarding service's `signer`. */
export async function mintDelegationProofJwt(input: MintDelegationProofInput, signer: kyaos.Signer): Promise<string> {
  const iss = input.iss ?? signer.did;
  if (iss !== signer.did) throw new Error('mintDelegationProofJwt: iss must be the signer\'s DID');
  for (const [name, value] of Object.entries({ sub: input.sub, aud: input.aud, delegation_id: input.delegation_id, delegation_chain: input.delegation_chain })) {
    if (typeof value !== 'string' || value.length === 0) throw new Error(`mintDelegationProofJwt: ${name} must be a non-empty string`);
  }
  const iat = Math.floor((input.now ?? Date.now()) / 1000);
  const claims: DelegationProofClaims = {
    iss,
    sub: input.sub,
    aud: input.aud,
    iat,
    exp: iat + DELEGATION_PROOF_TTL_SECONDS,
    jti: input.jti ?? `urn:uuid:${randomUUID()}`,
    delegation_id: input.delegation_id,
    delegation_chain: input.delegation_chain,
    scope: typeof input.scope === 'string' ? input.scope : input.scope.join(','),
  };
  return kyaos.signJws(claims as unknown as Record<string, unknown>, signer, { header: { typ: DELEGATION_PROOF_TYP } });
}

/** The §8.3 chain string of one delegation: `<vcId>><delegationId>`, or the one id it has. */
export function chainStringOf(delegation: { vcId?: string | undefined; id?: string | undefined }): string {
  const { vcId, id } = delegation;
  if (!id && !vcId) return '';
  if (!vcId) return id!;
  if (!id) return vcId;
  return `${vcId}>${id}`;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The chain string of a Helix chain, root first: each hop's VC `id` and its
 * capability id (`credentialSubject.id`), the hops joined with `>`, as
 * multi-hop chain strings concatenate (L3.24).
 */
export function buildChainString(chain: readonly unknown[]): string {
  return chain
    .map((hop) => {
      if (!isRecord(hop)) return '';
      const subject = isRecord(hop['credentialSubject']) ? hop['credentialSubject'] : {};
      return chainStringOf({
        vcId: typeof hop['id'] === 'string' ? hop['id'] : undefined,
        id: typeof subject['id'] === 'string' ? subject['id'] : undefined,
      });
    })
    .filter((part) => part.length > 0)
    .join('>');
}

/** The leaf capability's id: the `delegation_id` the proof names. */
export function delegationIdOf(chain: readonly unknown[]): string | undefined {
  const leaf = chain[chain.length - 1];
  if (!isRecord(leaf) || !isRecord(leaf['credentialSubject'])) return undefined;
  const id = leaf['credentialSubject']['id'];
  return typeof id === 'string' && id.length > 0 ? id : undefined;
}

export type DelegationProofFailure =
  | 'delegation_proof_malformed'
  | 'delegation_proof_invalid'
  | 'delegation_proof_audience'
  | 'delegation_proof_expired'
  | 'delegation_proof_not_yet_valid'
  | 'delegation_proof_lifetime';

export type DelegationProofVerification =
  | { ok: true; claims: DelegationProofClaims; kid: string }
  | { ok: false; reason: DelegationProofFailure; message: string; iss?: string | undefined };

export interface VerifyDelegationProofOptions {
  /** How the `iss` DID resolves: the local verifier's `seams.resolveDid`. */
  resolveDid: kyaos.DidResolver;
  /** This service's own host or hosts; `aud` must be one of them. */
  audience: string | readonly string[];
  /** Milliseconds since the epoch. */
  now: number;
  /** Clock skew on `iat` and `exp`, seconds; default 5. */
  skewSeconds?: number | undefined;
}

const CLAIM_STRINGS = ['iss', 'sub', 'aud', 'jti', 'delegation_id', 'delegation_chain', 'scope'] as const;

/**
 * Verifies a delegation proof JWT: EdDSA under the assertion key its `kid`
 * names in the `iss` DID's document, `aud` one of this service's hosts, and
 * the window (`iat` not ahead, `exp` not past, both ± skew, `exp - iat` at
 * most 60 s). The jti, `sub` and the chain claims are the caller's to hold
 * against the chain and the replay store.
 */
export async function verifyDelegationProofJwt(jwt: string, options: VerifyDelegationProofOptions): Promise<DelegationProofVerification> {
  let verified: kyaos.JwsVerification;
  try {
    verified = await kyaos.verifyJwsByKid(jwt, options.resolveDid);
  } catch (error) {
    const { reason, message } = error as { reason?: unknown; message: string };
    if (reason === kyaos.JwsReasons.MALFORMED || reason === kyaos.JwsReasons.HEADER_INVALID) {
      return { ok: false, reason: 'delegation_proof_malformed', message };
    }
    return { ok: false, reason: 'delegation_proof_invalid', message };
  }
  const payload = verified.payload;
  if (!isRecord(payload) || (verified.header['typ'] !== undefined && verified.header['typ'] !== DELEGATION_PROOF_TYP)) {
    return { ok: false, reason: 'delegation_proof_malformed', message: 'the proof is not a JWT with a JSON claims set' };
  }
  for (const name of CLAIM_STRINGS) {
    if (typeof payload[name] !== 'string' || (name !== 'scope' && (payload[name] as string).length === 0)) {
      return { ok: false, reason: 'delegation_proof_malformed', message: `claim ${name} is not a non-empty string`, iss: verified.did };
    }
  }
  for (const name of ['iat', 'exp'] as const) {
    if (typeof payload[name] !== 'number' || !Number.isInteger(payload[name])) {
      return { ok: false, reason: 'delegation_proof_malformed', message: `claim ${name} is not an integer`, iss: verified.did };
    }
  }
  const claims = payload as unknown as DelegationProofClaims;
  const audiences = typeof options.audience === 'string' ? [options.audience] : options.audience;
  if (!audiences.includes(claims.aud)) {
    return { ok: false, reason: 'delegation_proof_audience', message: `aud ${claims.aud} is not this service's host`, iss: claims.iss };
  }
  const skew = options.skewSeconds ?? 5;
  const now = Math.floor(options.now / 1000);
  if (claims.exp - claims.iat > DELEGATION_PROOF_TTL_SECONDS || claims.exp <= claims.iat) {
    return { ok: false, reason: 'delegation_proof_lifetime', message: `the proof lives ${claims.exp - claims.iat} s; at most ${DELEGATION_PROOF_TTL_SECONDS} s`, iss: claims.iss };
  }
  if (now > claims.exp + skew) return { ok: false, reason: 'delegation_proof_expired', message: 'the proof has expired', iss: claims.iss };
  if (claims.iat > now + skew) return { ok: false, reason: 'delegation_proof_not_yet_valid', message: 'the proof is issued in the future', iss: claims.iss };
  return { ok: true, claims, kid: verified.kid };
}

/** The scope claim as a list: comma-separated, trimmed, empty entries dropped. */
export function scopeList(scope: string): string[] {
  return [...new Set(scope.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0))];
}
