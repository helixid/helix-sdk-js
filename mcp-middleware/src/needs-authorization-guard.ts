// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { AuthorizedCaller } from './middleware.js';
import type { NeedsAuthorization, NeedsAuthorizationError } from './needs-authorization.js';
import type { MCPToolCall } from './types.js';

/**
 * How the guard (`helixidMCPMiddleware`) uses the L3-E layer, kept out of
 * middleware.ts so that file only gains two calls. The agent a challenge or
 * a retry is bound to is the caller's DID (HelixID callers) or OAuth
 * subject (OAuth callers): whatever identified the caller.
 */

export const callerId = (caller: AuthorizedCaller): string | undefined => caller.agentDid ?? caller.oauthSubject;

/**
 * When the call carries `_kyaos_resume`: consumes the token, checks the
 * binding and verifies the credential, then resolves the caller with the
 * scopes the credential grants added. Throws `ResumeRefusedError`.
 * Undefined for an ordinary call, or when the layer is not configured.
 */
export async function resumeRetry(
  layer: NeedsAuthorization | undefined,
  caller: AuthorizedCaller,
  toolCall: MCPToolCall,
  toolName: string | undefined,
  required: string[],
): Promise<AuthorizedCaller | undefined> {
  if (layer === undefined) return undefined;
  const retry = layer.readRetry(toolCall);
  if (retry === undefined) return undefined;
  const agentDid = callerId(caller) ?? '';
  const granted = await layer.authorizeRetry(retry.resumeToken, retry.credential, { agentDid, tool: toolName ?? '', scopes: required });
  return { ...caller, scopes: [...new Set([...caller.scopes, ...granted.scopes])] };
}

/** The challenge for an identified caller lacking `required`; undefined when the layer is not configured or the caller has no identity to bind to. */
export async function challengeFor(
  layer: NeedsAuthorization | undefined,
  caller: AuthorizedCaller,
  toolName: string | undefined,
  required: string[],
): Promise<NeedsAuthorizationError | undefined> {
  const agentDid = callerId(caller);
  if (layer === undefined || agentDid === undefined || toolName === undefined) return undefined;
  return layer.challenge({
    agentDid,
    tool: toolName,
    scopes: required,
    missing: required.filter((scope) => !caller.scopes.includes(scope)),
    authMethod: caller.authMethod,
    effectiveScopes: caller.scopes,
    oauthSubject: caller.oauthSubject,
    level: caller.level,
    fresh: caller.fresh,
  });
}

/**
 * Helix error codes that refuse a consent request because of the caller, not
 * the service: the agent is not attested for the scope (or for any scope the
 * request names), or Helix does not know it as an agent it may ask consent for.
 */
export const CALLER_CONSENT_REFUSALS: ReadonlySet<string> = new Set(['CONSENT_GRANT_SCOPE_NOT_ALLOWED', 'CONSENT_NO_GRANTABLE_SCOPES', 'DID_NOT_FOUND']);

/** What a failed consent request (thrown while building the challenge) means for the call. */
export type ConsentFailure = { kind: 'refused'; helixCode: string; message: string } | { kind: 'unavailable'; message: string };

/**
 * Sorts an error thrown while the challenge's consent request was made at
 * Helix (a `ConsentFlowError`, matched by its code):
 * - `refused`: Helix refused it because of the caller (CALLER_CONSENT_REFUSALS);
 * - `unavailable`: Helix could not be reached, or failed (5xx, 408, 429, or no usable answer);
 * - undefined: anything else (the service's own setup, say), left to the host as a server error.
 */
export function consentFailureOf(error: unknown): ConsentFailure | undefined {
  const e = error as { code?: unknown; reason?: unknown; httpStatus?: unknown; helixCode?: unknown; message?: unknown } | null;
  if (e === null || typeof e !== 'object' || e.code !== 'CONSENT_FLOW_FAILED') return undefined;
  const message = typeof e.message === 'string' ? e.message : 'consent flow failed';
  const status = typeof e.httpStatus === 'number' ? e.httpStatus : 0;
  if (e.reason === 'consent_unreachable' || status >= 500 || status === 408 || status === 429) return { kind: 'unavailable', message };
  if (e.reason === 'consent_request_refused' && typeof e.helixCode === 'string' && CALLER_CONSENT_REFUSALS.has(e.helixCode)) {
    return { kind: 'refused', helixCode: e.helixCode, message };
  }
  return undefined;
}
