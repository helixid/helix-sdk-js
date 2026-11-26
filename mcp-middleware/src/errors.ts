// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { InsufficientScopeError } from '@helixid/sdk-js';

export type MCPAuthErrorCode =
  | 'CREDENTIAL_CONFLICT'
  | 'OAUTH_TOKEN_INVALID'
  | 'TOOL_NOT_PERMITTED'
  | 'RESOURCE_NOT_PERMITTED'
  | 'PROMPT_NOT_PERMITTED';

const STATUS: Record<MCPAuthErrorCode, number> = {
  CREDENTIAL_CONFLICT: 400,
  OAUTH_TOKEN_INVALID: 401,
  TOOL_NOT_PERMITTED: 403,
  RESOURCE_NOT_PERMITTED: 403,
  PROMPT_NOT_PERMITTED: 403,
};

/**
 * Errors raised by the middleware itself. `@helixid/sdk-js` error codes are a
 * closed union, so these new cases live here; insufficient scope still uses
 * the sdk-js error (INSUFFICIENT_SCOPE) so existing handlers keep working.
 */
export class MCPAuthError extends Error {
  public readonly code: MCPAuthErrorCode;
  public readonly httpStatus: number;

  constructor(code: MCPAuthErrorCode, message: string) {
    super(message);
    this.name = 'MCPAuthError';
    this.code = code;
    this.httpStatus = STATUS[code];
  }
}

export type ProofErrorCode = 'PROOF_MISSING' | 'PROOF_INVALID' | 'PROOF_LEVEL_INSUFFICIENT';

/**
 * A KYA-OS request proof that is absent, or that the local verifier refused
 * (story F-2). `reasons` carries the verifier's reason codes
 * (`nonce_replayed`, `audience_mismatch`, `attenuation_violation`, ...), so a
 * host can answer or log the refusal without parsing the message.
 */
export class ProofError extends Error {
  public readonly code: ProofErrorCode;
  public readonly httpStatus = 401;
  public readonly reasons: readonly string[];

  constructor(code: ProofErrorCode, message: string, reasons: readonly string[] = []) {
    super(message);
    this.name = 'ProofError';
    this.code = code;
    this.reasons = reasons;
  }
}

/**
 * A verified call whose derived Card level is below the tool's minimum
 * (story C-C point 7; SPEC-ENTITY-CARD.md D.2 `proof_level_insufficient`):
 * a chain without a proof for an L3 tool, say, or a stale status list that
 * demoted the call to L2. Raised after the scope check passed. Carries the
 * level the call came to (`derivedLevel`, `L3-minus` for an unfused L3) and
 * the one the tool demands.
 */
export class LevelError extends ProofError {
  public readonly derivedLevel: string;
  public readonly requiredLevel: string;

  constructor(derivedLevel: string, requiredLevel: string) {
    super('PROOF_LEVEL_INSUFFICIENT', `This tool needs Card level ${requiredLevel}; the call came to ${derivedLevel}`, ['proof_level_insufficient']);
    this.name = 'LevelError';
    this.derivedLevel = derivedLevel;
    this.requiredLevel = requiredLevel;
  }
}

/**
 * INSUFFICIENT_SCOPE with the missing scope as a field, so the 403 challenge
 * can carry it as the RFC 6750 `scope` attribute. The sdk-js error only has
 * it in the message; the code stays INSUFFICIENT_SCOPE for existing handlers.
 */
export class ToolScopeError extends InsufficientScopeError {
  /** The first scope the caller lacked (what the audit row records). */
  public readonly requiredScope: string;
  /** Everything the tool requires: what the RFC 6750 `scope` challenge lists, so one retry can fix it. */
  public readonly requiredScopes: readonly string[];

  /** `message` replaces the default "Required scope: …" (a refused consent request says why, say). */
  constructor(requiredScope: string, requiredScopes: readonly string[] = [requiredScope], message?: string) {
    super(requiredScope);
    this.requiredScope = requiredScope;
    this.requiredScopes = requiredScopes;
    if (message !== undefined) this.message = message;
  }
}

/**
 * The authorization server could not be reached or gave an unusable answer
 * (JWKS or introspection). A fault on the server side, not a bad credential:
 * `toHttpErrorResponse` leaves it unmapped so the host answers 5xx, never 401.
 */
export class AuthorizationServerUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationServerUnavailableError';
  }
}
