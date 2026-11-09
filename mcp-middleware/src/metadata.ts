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
  body: { error: string; error_description: string };
}

export interface HttpErrorOptions {
  /** URL from `protectedResourceMetadataUrl()`; advertised in every challenge. */
  resourceMetadataUrl: string;
}

const quote = (value: string): string => `"${value.replace(/["\\\r\n]/g, ' ')}"`;

function challenge(scheme: 'Bearer' | 'HelixVP', params: Array<[string, string]>): string {
  return `${scheme} ${params.map(([k, v]) => `${k}=${quote(v)}`).join(', ')}`;
}

// Only errors that describe the *caller's* credentials map to HTTP auth
// responses. Anything else (e.g. the middleware's own API key being rejected)
// is a server fault and must not be reported to the caller as a 401.
const MAPPED: Record<string, { status: number; error: string }> = {
  VP_MISSING: { status: 401, error: '' },
  VP_INVALID_STRUCTURE: { status: 401, error: 'invalid_token' },
  VP_VERIFICATION_FAILED: { status: 401, error: 'invalid_token' },
  OAUTH_TOKEN_INVALID: { status: 401, error: 'invalid_token' },
  CREDENTIAL_CONFLICT: { status: 400, error: 'invalid_request' },
  INSUFFICIENT_SCOPE: { status: 403, error: 'insufficient_scope' },
  TOOL_NOT_PERMITTED: { status: 403, error: 'insufficient_scope' },
};

/**
 * Turns an error thrown by the middleware into an HTTP auth response: 401 with
 * `WWW-Authenticate` challenges for both `Bearer` and `HelixVP` (each pointing
 * at the RFC 9728 metadata), 400 for ambiguous credentials, 403 for scope
 * failures. Returns undefined for errors that are not the caller's fault, so
 * the host can handle them as server errors.
 */
export function toHttpErrorResponse(error: unknown, options: HttpErrorOptions): HttpErrorResponse | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  const mapped = typeof code === 'string' && Object.hasOwn(MAPPED, code) ? MAPPED[code] : undefined;
  if (!mapped) return undefined;
  const message = error instanceof Error ? error.message : 'Unauthorized';
  const requiredScope = (error as { requiredScope?: unknown } | null)?.requiredScope;
  const params: Array<[string, string]> = [
    ...(mapped.error ? ([['error', mapped.error], ['error_description', message]] as Array<[string, string]>) : []),
    // RFC 6750 §3: the scope the credential lacked, so a client can ask its
    // authorization server for it and retry. Only when the error names one.
    ...(mapped.error === 'insufficient_scope' && typeof requiredScope === 'string'
      ? ([['scope', requiredScope]] as Array<[string, string]>)
      : []),
    ['resource_metadata', options.resourceMetadataUrl],
  ];
  return {
    status: mapped.status,
    headers: { 'WWW-Authenticate': `${challenge('Bearer', params)}, ${challenge('HelixVP', params)}` },
    body: { error: mapped.error || 'unauthorized', error_description: message },
  };
}
