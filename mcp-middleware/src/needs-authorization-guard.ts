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
    vpId: caller.vpId,
  });
}
