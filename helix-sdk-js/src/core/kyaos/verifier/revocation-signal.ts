// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The revocation signal (KYA-OS story L3-C point 7; SPEC.md §6.5.2 "honor
 * explicit revocation signals immediately"): one Security Event Token
 * (RFC 8417) per revoked credential, signed by the Helix issuer, carrying
 * only the credential id.
 *
 * Shape: a compact EdDSA JWS, header `{alg: "EdDSA", kid, typ:
 * "secevent+jwt"}`, payload `{iss, iat, jti, aud?, events: {
 * "<REVOCATION_EVENT_TYPE>": { subject: { format: "uri", uri: "<credential
 * id>" } } }}` (subject identifier per RFC 9493). No `exp`, no `sub`: a SET
 * states that something happened, it authorises nothing.
 *
 * A verifier honours a signal only when its `iss` is one of the issuers it
 * trusts for signals and the signature verifies under that issuer's
 * `assertionMethod` key; anything else is ignored (and reported by the
 * caller). The signal is a cache hint: it deletes cached verdicts, it never
 * revokes anything by itself. Authority still comes from the chain and the
 * list.
 */

import { randomUUID } from 'node:crypto';
import { InvalidJWSError } from '../../HelixError.js';
import { readJwsHeader, signJws, verifyJwsByKid, type DidResolver } from '../jws.js';
import type { Signer } from '../signer.js';

/** The event type of a revoked credential (a Helix-defined URI; KYA-OS names none). */
export const REVOCATION_EVENT_TYPE = 'https://helixid.io/secevent/credential-revoked';
/** RFC 8417 §2.3. */
export const SECEVENT_JWT_TYP = 'secevent+jwt';
/** RFC 8935 §2: the media type a pushed SET is sent with. */
export const SECEVENT_JWT_MEDIA_TYPE = 'application/secevent+jwt';
/** How old a signal may be and still be honoured, by default (a replayed old signal only deletes a cache entry, but there is no use for it). */
export const DEFAULT_SIGNAL_MAX_AGE_SECONDS = 24 * 60 * 60;

export interface RevocationSignal {
  jti: string;
  iss: string;
  /** Seconds since the epoch. */
  iat: number;
  aud?: string | string[] | undefined;
  /** The revoked credential's id. */
  credentialId: string;
}

export interface SignRevocationSignalInput {
  credentialId: string;
  /** Default a fresh `urn:uuid`. */
  jti?: string | undefined;
  /** Seconds since the epoch; default now. */
  iat?: number | undefined;
  aud?: string | string[] | undefined;
}

/** The SET for one revoked credential, signed by `signer` (the Helix issuer). */
export async function signRevocationSignal(input: SignRevocationSignalInput, signer: Signer): Promise<string> {
  if (typeof input.credentialId !== 'string' || input.credentialId.length === 0) throw new TypeError('credentialId must be a non-empty string');
  const payload: Record<string, unknown> = {
    iss: signer.did,
    iat: input.iat ?? Math.floor(Date.now() / 1000),
    jti: input.jti ?? `urn:uuid:${randomUUID()}`,
    ...(input.aud === undefined ? {} : { aud: input.aud }),
    events: { [REVOCATION_EVENT_TYPE]: { subject: { format: 'uri', uri: input.credentialId } } },
  };
  return signJws(payload, signer, { header: { typ: SECEVENT_JWT_TYP } });
}

export const SignalReasons = {
  MALFORMED: 'signal_malformed',
  UNKNOWN_ISSUER: 'signal_unknown_issuer',
  BAD_SIGNATURE: 'signal_bad_signature',
  WRONG_EVENT: 'signal_wrong_event',
  STALE: 'signal_stale',
} as const;

export type SignalReason = (typeof SignalReasons)[keyof typeof SignalReasons];

export type SignalVerification = { ok: true; signal: RevocationSignal } | { ok: false; reason: SignalReason; message: string };

export interface VerifyRevocationSignalOptions {
  /** The issuer DIDs whose signals are honoured (the Helix issuer of the deployment the service listens to). */
  trustedIssuers: readonly string[];
  /** How a trusted issuer's DID resolves, for its key. */
  resolveDid: DidResolver;
  /** Milliseconds since the epoch; default `Date.now`. */
  now?: number | undefined;
  /** Oldest `iat` honoured, seconds; default 24 h. */
  maxAgeSeconds?: number | undefined;
  /** Clock tolerance on `iat` in the future, seconds; default 300. */
  skewSeconds?: number | undefined;
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function payloadOf(set: string): Record<string, unknown> | undefined {
  const segment = set.split('.')[1];
  if (segment === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verifies a revocation SET: its shape, an issuer on the trusted list
 * (checked before anything is resolved), the `kid` of that issuer, the
 * signature under its `assertionMethod` key, a known event type naming one
 * credential by URI, and an `iat` neither in the future nor too old.
 */
export async function verifyRevocationSignal(set: unknown, options: VerifyRevocationSignalOptions): Promise<SignalVerification> {
  const refuse = (reason: SignalReason, message: string): SignalVerification => ({ ok: false, reason, message });
  if (typeof set !== 'string' || set.split('.').length !== 3) return refuse(SignalReasons.MALFORMED, 'a SET is a compact JWS');
  let typ: unknown;
  try {
    typ = readJwsHeader(set).typ;
  } catch (error) {
    return refuse(SignalReasons.MALFORMED, (error as Error).message);
  }
  if (typ !== SECEVENT_JWT_TYP) return refuse(SignalReasons.MALFORMED, `typ is not ${SECEVENT_JWT_TYP}`);
  const claims = payloadOf(set);
  if (claims === undefined) return refuse(SignalReasons.MALFORMED, 'the SET payload is not a JSON object');
  const iss = claims['iss'];
  if (typeof iss !== 'string' || !iss.startsWith('did:')) return refuse(SignalReasons.MALFORMED, 'iss is not a DID');
  if (!options.trustedIssuers.includes(iss)) return refuse(SignalReasons.UNKNOWN_ISSUER, `${iss} is not an issuer whose signals are honoured`);
  try {
    await verifyJwsByKid(set, options.resolveDid, { expectedDid: iss });
  } catch (error) {
    const reason = error instanceof InvalidJWSError ? `${error.reason}: ` : '';
    return refuse(SignalReasons.BAD_SIGNATURE, `${reason}${(error as Error).message}`);
  }
  const iat = claims['iat'];
  const jti = claims['jti'];
  if (typeof iat !== 'number' || !Number.isInteger(iat) || typeof jti !== 'string' || jti.length === 0) {
    return refuse(SignalReasons.MALFORMED, 'iat and jti are required');
  }
  const events = claims['events'];
  const event = isObject(events) ? events[REVOCATION_EVENT_TYPE] : undefined;
  if (!isObject(events) || Object.keys(events).length !== 1 || !isObject(event)) {
    return refuse(SignalReasons.WRONG_EVENT, `the SET carries no single ${REVOCATION_EVENT_TYPE} event`);
  }
  const subject = event['subject'];
  if (!isObject(subject) || subject['format'] !== 'uri' || typeof subject['uri'] !== 'string' || subject['uri'].length === 0) {
    return refuse(SignalReasons.WRONG_EVENT, 'the event subject is not a credential id (format uri)');
  }
  const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
  if (iat > nowSeconds + (options.skewSeconds ?? 300)) return refuse(SignalReasons.STALE, 'iat is in the future');
  if (iat < nowSeconds - (options.maxAgeSeconds ?? DEFAULT_SIGNAL_MAX_AGE_SECONDS)) return refuse(SignalReasons.STALE, 'the SET is older than the signals honoured');
  const aud = claims['aud'];
  return {
    ok: true,
    signal: {
      jti,
      iss,
      iat,
      ...(typeof aud === 'string' || Array.isArray(aud) ? { aud: aud as string | string[] } : {}),
      credentialId: subject['uri'],
    },
  };
}
