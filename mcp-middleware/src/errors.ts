// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { InsufficientScopeError } from '@helixid/sdk-js';

export type MCPAuthErrorCode =
  | 'CREDENTIAL_CONFLICT'
  | 'OAUTH_TOKEN_INVALID'
  | 'TOOL_NOT_PERMITTED';

const STATUS: Record<MCPAuthErrorCode, number> = {
  CREDENTIAL_CONFLICT: 400,
  OAUTH_TOKEN_INVALID: 401,
  TOOL_NOT_PERMITTED: 403,
};

/**
 * Errors raised by the middleware itself. `@helixid/sdk-js` error codes are a
 * closed union, so these new cases live here; missing/invalid VPs and
 * insufficient scope still use the sdk-js errors (VP_MISSING,
 * VP_VERIFICATION_FAILED, INSUFFICIENT_SCOPE) so existing handlers keep working.
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

  constructor(requiredScope: string, requiredScopes: readonly string[] = [requiredScope]) {
    super(requiredScope);
    this.requiredScope = requiredScope;
    this.requiredScopes = requiredScopes;
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
