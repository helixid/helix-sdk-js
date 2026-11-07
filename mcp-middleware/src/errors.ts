// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

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
