// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The client's side of the signed `needs_authorization` challenge and the
 * resume flow (KYA-OS story L3-E; SPEC §9.2, §9.3, §11.1 "consent-URL
 * substitution").
 *
 * A service that lacks the authority for a call answers with a challenge
 * `{error: "needs_authorization", message, authorizationUrl, resumeToken,
 * expiresAt, scopes, display?}` as the tool result (`structuredContent`, and
 * the same JSON as text), signed per L2-A with `outcome: needs_authorization`
 * and a `responseHash` over the whole result. {@link handleNeedsAuthorization}
 * verifies that proof against the service DID, recomputing both hashes,
 * BEFORE it reads the challenge: a signature alone proves the proof is the
 * service's, only the recompute proves the `authorizationUrl` in hand is the
 * one the service signed. An intermediary that swaps the URL and leaves the
 * signature intact is refused with `response_hash_mismatch`, and nothing of
 * the challenge is surfaced.
 *
 * The user is then sent to `authorizationUrl`; the consent page issues the
 * root DelegationCredential (story L3-H). {@link retryWithResume} retries
 * the same call with the `resumeToken` and that credential as the
 * `_kyaos_resume` and `_kyaos_delegation` control arguments (SPEC §7.3's
 * `_kyaos*` channel: stripped by the server before the tool and never part
 * of the covered request), and verifies the proof on the answer.
 *
 * Cross-border rule: the only input besides the response, the request and
 * the challenge is the DID document the injected resolver returns.
 */

import { NeedsAuthorizationError } from '../HelixError.js';
import type { IDidResolver } from '../../resolver/IDidResolver.js';
import type { CoveredRequestInput } from './hash.js';
import type { DidResolver } from './jws.js';
import { verifyResponseProof, type VerifiedResponseProof, type VerifyProofOptions } from './response-proof.js';

export const NEEDS_AUTHORIZATION = 'needs_authorization';
/** Control argument carrying the resume token on a retry. */
export const RESUME_CONTROL_ARGUMENT = '_kyaos_resume';
/** Control argument carrying the new DelegationCredential on a retry. */
export const DELEGATION_CONTROL_ARGUMENT = '_kyaos_delegation';
export const DISPLAY_HINTS = ['link', 'qr', 'code'] as const;
export type DisplayHint = (typeof DISPLAY_HINTS)[number];

/** SPEC §9.2 `display`: how a client may present the authorization step. */
export interface NeedsAuthorizationDisplay {
  title?: string;
  hint?: DisplayHint[];
  authorizationCode?: string;
  qrUrl?: string;
}

/** SPEC §9.2 `NeedsAuthorizationError`: the challenge a service answers with. */
export interface NeedsAuthorizationChallenge {
  error: typeof NEEDS_AUTHORIZATION;
  message: string;
  /** Where the user can grant the authorization; trusted only after the proof verified. */
  authorizationUrl: string;
  /** Opaque; sent back on the retry. */
  resumeToken: string;
  /** Unix seconds at which `resumeToken` expires. */
  expiresAt: number;
  scopes: string[];
  display?: NeedsAuthorizationDisplay;
}

/** Why a challenge was refused; carried as `NeedsAuthorizationError.reason`, mirrored in helix-sdk-py. */
export const ChallengeReasons = {
  /** The proof verified, but its outcome is not `needs_authorization`: the response is not a challenge. */
  OUTCOME_MISMATCH: 'challenge_outcome_mismatch',
  MISSING: 'challenge_missing',
  MALFORMED: 'challenge_malformed',
  URL_INVALID: 'authorization_url_invalid',
  EXPIRED: 'challenge_expired',
} as const;
export type ChallengeReason = (typeof ChallengeReasons)[keyof typeof ChallengeReasons];

export interface HandledChallenge {
  challenge: NeedsAuthorizationChallenge;
  /** The verified proof: `outcome` is `needs_authorization`, `responseHash` the hash of the whole response. */
  proof: VerifiedResponseProof;
}

export interface HandleNeedsAuthorizationOptions extends VerifyProofOptions {
  /** The request the client sent, as a JSON-RPC `{method, params}`. */
  request: CoveredRequestInput;
}

/** The tool-call params a retry is built from. */
export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown> | undefined;
  _meta?: Record<string, unknown> | undefined;
}

export interface RetryWithResumeOptions {
  /** The call to retry: the same tool and arguments as the challenged call. */
  call: ToolCallParams;
  /** Sends a `tools/call` with these params and resolves the result body (the JSON-RPC `result`). */
  send: (params: ToolCallParams) => Promise<unknown>;
  /** When given with `resolveDid`, the answer's proof is verified against this DID and the retried request. */
  serviceDid?: string | undefined;
  resolveDid?: DidResolver | IDidResolver | undefined;
  now?: number | undefined;
  skewSeconds?: number | undefined;
}

export interface RetriedCall {
  /** The params that were sent: the call plus the two control arguments. */
  params: ToolCallParams;
  response: unknown;
  /** Present when `serviceDid` and `resolveDid` were given. */
  proof?: VerifiedResponseProof | undefined;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const refuse = (reason: ChallengeReason, message: string): never => {
  throw new NeedsAuthorizationError(reason, message);
};

/** The challenge a response carries: at its top level, or as its `structuredContent`; undefined when neither looks like one. */
export function findChallenge(response: unknown): unknown {
  if (!isRecord(response)) return undefined;
  if (response['error'] === NEEDS_AUTHORIZATION) return response;
  const structured = response['structuredContent'];
  if (isRecord(structured) && structured['error'] === NEEDS_AUTHORIZATION) return structured;
  return undefined;
}

/** Whether `response` looks like a needs_authorization challenge (its shape only; nothing is verified). */
export function isNeedsAuthorization(response: unknown): boolean {
  return findChallenge(response) !== undefined;
}

const isStringArray = (value: unknown): value is string[] => Array.isArray(value) && value.every((s) => typeof s === 'string');

/**
 * Reads and checks the challenge's shape (SPEC §9.2), without any proof
 * check: `authorizationUrl` must be an absolute http(s) URL, `expiresAt`
 * a Unix-seconds integer still in the future, `scopes` strings, `display`
 * well formed. Prefer {@link handleNeedsAuthorization}, which verifies first.
 */
export function readChallenge(response: unknown, options: { now?: number | undefined } = {}): NeedsAuthorizationChallenge {
  const found = findChallenge(response);
  if (found === undefined) return refuse(ChallengeReasons.MISSING, 'the response is not a needs_authorization challenge');
  const challenge = found as Record<string, unknown>;
  const { message, authorizationUrl, resumeToken, expiresAt, scopes, display } = challenge;
  if (typeof message !== 'string') return refuse(ChallengeReasons.MALFORMED, 'challenge message must be a string');
  if (typeof authorizationUrl !== 'string' || authorizationUrl.length === 0) return refuse(ChallengeReasons.URL_INVALID, 'challenge authorizationUrl must be a string');
  let url: URL;
  try {
    url = new URL(authorizationUrl);
  } catch {
    return refuse(ChallengeReasons.URL_INVALID, 'challenge authorizationUrl must be an absolute URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return refuse(ChallengeReasons.URL_INVALID, `challenge authorizationUrl must be http(s), not ${url.protocol}`);
  if (typeof resumeToken !== 'string' || resumeToken.length === 0) return refuse(ChallengeReasons.MALFORMED, 'challenge resumeToken must be a non-empty string');
  if (typeof expiresAt !== 'number' || !Number.isInteger(expiresAt) || expiresAt < 1) return refuse(ChallengeReasons.MALFORMED, 'challenge expiresAt must be Unix seconds');
  if (!isStringArray(scopes)) return refuse(ChallengeReasons.MALFORMED, 'challenge scopes must be an array of strings');
  let shown: NeedsAuthorizationDisplay | undefined;
  if (display !== undefined) {
    if (!isRecord(display)) return refuse(ChallengeReasons.MALFORMED, 'challenge display must be an object');
    shown = {};
    for (const name of ['title', 'authorizationCode', 'qrUrl'] as const) {
      const value = display[name];
      if (value === undefined) continue;
      if (typeof value !== 'string') return refuse(ChallengeReasons.MALFORMED, `challenge display.${name} must be a string`);
      shown[name] = value;
    }
    const hint = display['hint'];
    if (hint !== undefined) {
      if (!isStringArray(hint) || !hint.every((h) => (DISPLAY_HINTS as readonly string[]).includes(h))) {
        return refuse(ChallengeReasons.MALFORMED, `challenge display.hint must list ${DISPLAY_HINTS.join(', ')}`);
      }
      shown.hint = hint as DisplayHint[];
    }
  }
  const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
  if (expiresAt <= nowSeconds) return refuse(ChallengeReasons.EXPIRED, `the challenge expired at ${expiresAt} (now ${nowSeconds})`);
  return {
    error: NEEDS_AUTHORIZATION,
    message,
    authorizationUrl,
    resumeToken,
    expiresAt,
    scopes: [...scopes],
    ...(shown !== undefined ? { display: shown } : {}),
  };
}

/**
 * Verifies the challenge's proof against `serviceDid` (signature, signer,
 * `outcome: needs_authorization`, `requestHash` recomputed from the request
 * sent, `responseHash` recomputed over the whole response received), then
 * reads the challenge. Throws `ResponseProofError` (a tampered
 * `authorizationUrl` is `response_hash_mismatch`), `InvalidJWSError`, or
 * `NeedsAuthorizationError` for a verified response that is not a
 * well-formed, unexpired challenge. Only a returned `authorizationUrl` is
 * safe to show.
 */
export async function handleNeedsAuthorization(
  response: unknown,
  serviceDid: string,
  resolveDid: DidResolver | IDidResolver,
  options: HandleNeedsAuthorizationOptions,
): Promise<HandledChallenge> {
  const proof = await verifyResponseProof(response, serviceDid, resolveDid, options);
  if (proof.outcome !== NEEDS_AUTHORIZATION) {
    return refuse(ChallengeReasons.OUTCOME_MISMATCH, `the proof's outcome is ${proof.outcome}, not needs_authorization`);
  }
  const challenge = readChallenge(response, { now: options.now });
  return { challenge, proof };
}

/** `params` with the resume token and the credential as control arguments; nothing else changes. */
export function withResume(params: ToolCallParams, resumeToken: string, credential: unknown): ToolCallParams {
  if (typeof resumeToken !== 'string' || resumeToken.length === 0) throw new TypeError('withResume: resumeToken must be a non-empty string');
  if (credential === undefined || credential === null) throw new TypeError('withResume: the retry must carry the DelegationCredential');
  return {
    ...params,
    arguments: { ...(params.arguments ?? {}), [RESUME_CONTROL_ARGUMENT]: resumeToken, [DELEGATION_CONTROL_ARGUMENT]: credential },
  };
}

/**
 * Retries `options.call` with `resumeToken` and the new DelegationCredential
 * `hop`, through `options.send`. With `serviceDid` and `resolveDid` the
 * answer's proof is verified against the request that was sent (the control
 * arguments are not part of the covered request), so a swapped answer or a
 * second challenge with a bad proof is refused here.
 */
export async function retryWithResume(resumeToken: string, hop: unknown, options: RetryWithResumeOptions): Promise<RetriedCall> {
  const params = withResume(options.call, resumeToken, hop);
  const response = await options.send(params);
  if (options.serviceDid === undefined || options.resolveDid === undefined) return { params, response };
  const proof = await verifyResponseProof(response, options.serviceDid, options.resolveDid, {
    request: { method: 'tools/call', params: params as unknown as Record<string, unknown> },
    ...(options.now !== undefined ? { now: options.now } : {}),
    ...(options.skewSeconds !== undefined ? { skewSeconds: options.skewSeconds } : {}),
  });
  return { params, response, proof };
}
