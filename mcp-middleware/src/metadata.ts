// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

export interface ProtectedResourceMetadataInput {
  /** This MCP server's resource identifier (its URL). */
  resource: string;
  /** Issuer URLs of the authorization servers that mint tokens for this resource. */
  authorizationServers?: string[];
  scopesSupported?: string[];
  resourceName?: string;
  resourceDocumentation?: string;
}

/** RFC 9728 Protected Resource Metadata document. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
  bearer_methods_supported: string[];
  resource_name?: string;
  resource_documentation?: string;
}

/**
 * Where RFC 9728 §3.1 says the metadata lives: `/.well-known/oauth-protected-resource`
 * inserted between the host and the resource's path.
 */
export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource);
  const path = url.pathname === '/' ? '' : url.pathname;
  return `${url.origin}/.well-known/oauth-protected-resource${path}`;
}

/** Builds the JSON body to serve at `protectedResourceMetadataUrl(resource)`. */
export function buildProtectedResourceMetadata(input: ProtectedResourceMetadataInput): ProtectedResourceMetadata {
  return {
    resource: input.resource,
    ...(input.authorizationServers ? { authorization_servers: input.authorizationServers } : {}),
    ...(input.scopesSupported ? { scopes_supported: input.scopesSupported } : {}),
    bearer_methods_supported: ['header'],
    ...(input.resourceName ? { resource_name: input.resourceName } : {}),
    ...(input.resourceDocumentation ? { resource_documentation: input.resourceDocumentation } : {}),
  };
}

export interface HttpErrorResponse {
  status: number;
  headers: { 'WWW-Authenticate': string };
  body: {
    error: string;
    error_description: string;
    /** PROOF_LEVEL_INSUFFICIENT (story C-C): the level the call came to and the one the tool demands. */
    derivedLevel?: string;
    requiredLevel?: string;
    _meta?: Record<string, unknown>;
    [member: string]: unknown;
  };
}

export interface HttpErrorOptions {
  /** URL from `protectedResourceMetadataUrl()`; advertised in every challenge. */
  resourceMetadataUrl: string;
  /** The KYA-OS `denied` proof of this refusal (story L2-A), carried in the body as `_meta["org.kya-os/response-proof"]`. */
  proof?: { jws: string; meta: object } | undefined;
}

// RFC 6750 §3: error_description and scope are limited to %x20-21 / %x23-5B / %x5D-7E.
const quote = (value: string): string => `"${value.replace(/[^\x20-\x21\x23-\x5B\x5D-\x7E]/g, ' ')}"`;

function challenge(scheme: 'Bearer' | 'KyaOS', params: Array<[string, string]>): string {
  return `${scheme} ${params.map(([k, v]) => `${k}=${quote(v)}`).join(', ')}`;
}

// Only errors that describe the *caller's* credentials map to HTTP auth
// responses. Anything else (e.g. the middleware's own API key being rejected)
// is a server fault and must not be reported to the caller as a 401.
const MAPPED: Record<string, { status: number; error: string }> = {
  // KYA-OS request proofs (story F-2): absent, or refused by the local verifier.
  PROOF_MISSING: { status: 401, error: '' },
  PROOF_INVALID: { status: 401, error: 'invalid_token' },
  // Story C-C: verified, but below the tool's minimum Card level (RFC 9470's step-up error).
  PROOF_LEVEL_INSUFFICIENT: { status: 401, error: 'insufficient_user_authentication' },
  OAUTH_TOKEN_INVALID: { status: 401, error: 'invalid_token' },
  CREDENTIAL_CONFLICT: { status: 400, error: 'invalid_request' },
  INSUFFICIENT_SCOPE: { status: 403, error: 'insufficient_scope' },
  TOOL_NOT_PERMITTED: { status: 403, error: 'insufficient_scope' },
  // KYA-OS session layer (story L2-A): a session id that is unknown, expired, malformed or another agent's.
  KYAOS_REJECTED: { status: 400, error: 'invalid_request' },
  // KYA-OS story L3-E: the challenge (hosts without the signing runtime answer it here, unsigned) and a refused retry.
  NEEDS_AUTHORIZATION: { status: 403, error: 'needs_authorization' },
  RESUME_REFUSED: { status: 403, error: 'insufficient_scope' },
};

/**
 * Turns an error thrown by the middleware into an HTTP auth response: 401 with
 * `WWW-Authenticate` challenges for both `Bearer` and `KyaOS` (each pointing
 * at the RFC 9728 metadata), 400 for ambiguous credentials, 403 for scope
 * failures. Returns undefined for errors that are not the caller's fault, so
 * the host can handle them as server errors.
 */
export function toHttpErrorResponse(error: unknown, options: HttpErrorOptions): HttpErrorResponse | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  const mapped = typeof code === 'string' && Object.hasOwn(MAPPED, code) ? MAPPED[code] : undefined;
  if (!mapped) return undefined;
  const message = error instanceof Error ? error.message : 'Unauthorized';
  const e = error as { requiredScope?: unknown; requiredScopes?: unknown; derivedLevel?: unknown; requiredLevel?: unknown } | null;
  const required = Array.isArray(e?.requiredScopes)
    ? e.requiredScopes.filter((x): x is string => typeof x === 'string')
    : typeof e?.requiredScope === 'string'
      ? [e.requiredScope]
      : [];
  const params: Array<[string, string]> = [
    ...(mapped.error ? ([['error', mapped.error], ['error_description', message]] as Array<[string, string]>) : []),
    // RFC 6750 §3: the scopes the resource requires, so a client can ask its
    // authorization server for them and retry once. Only when the error names them.
    ...(mapped.error === 'insufficient_scope' && required.length > 0
      ? ([['scope', required.join(' ')]] as Array<[string, string]>)
      : []),
    ['resource_metadata', options.resourceMetadataUrl],
  ];
  return {
    status: mapped.status,
    headers: { 'WWW-Authenticate': `${challenge('Bearer', params)}, ${challenge('KyaOS', params)}` },
    body: {
      error: mapped.error || 'unauthorized',
      error_description: message,
      ...(typeof e?.derivedLevel === 'string' ? { derivedLevel: e.derivedLevel } : {}),
      ...(typeof e?.requiredLevel === 'string' ? { requiredLevel: e.requiredLevel } : {}),
      ...(code === 'NEEDS_AUTHORIZATION' ? (error as { challenge?: Record<string, unknown> }).challenge : {}),
      ...(options.proof ? { _meta: { 'org.kya-os/response-proof': options.proof } } : {}),
    },
  };
}
