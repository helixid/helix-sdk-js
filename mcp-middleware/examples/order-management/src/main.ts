// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/* eslint-disable no-console -- command-line entry point: startup and error output is the point */

import { HelixClient } from '@helixid/sdk-js';
import {
  createHelixAuditSink,
  type AuthResult,
  type MCPMiddlewareOptions,
  type OAuthIntrospectionOptions,
  type OAuthIssuerOptions,
} from '@helixid/mcp-middleware';
import { createOrderServer } from './app.js';

/**
 * Configuration (environment):
 *   PORT, HOST            listen address (default 3700 on 127.0.0.1)
 *   MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
 *   HELIX_API_URL         HelixID API to verify VPs and write audit events. Required whenever
 *   HELIX_API_KEY         HELIX_API_KEY is set: there is deliberately no default URL.
 *   SERVICE_DID           this server's DID: VPs for other services are rejected
 *   OAUTH_ISSUER          OAuth door, one authorization server: its issuer, plus either
 *   OAUTH_JWKS_URI          its jwks_uri (JWT access tokens; aud must be MCP_RESOURCE), or
 *   OAUTH_INTROSPECTION_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET
 *                           its RFC 7662 introspection endpoint and this server's client credentials (opaque tokens)
 *   OAUTH_ISSUERS         several authorization servers: a JSON array of
 *                         { issuer, jwksUri?, introspection?: { endpoint, clientId, clientSecret } }
 *   DEMO_MODE=1           local demo only: accept the fixed bearer tokens below instead of an
 *                         authorization server. Refused unless HOST is loopback.
 */
const DEMO_TOKENS: Record<string, AuthResult> = {
  'demo-reader': { sub: 'demo-reader', scopes: ['orders:read'] },
  'demo-admin': { sub: 'demo-admin', scopes: ['orders:read', 'orders:admin'] },
};

function fail(message: string): never {
  console.error(`order-management: ${message}`);
  process.exit(1);
}

const env = process.env;
const port = Number(env['PORT'] ?? 3700);
const host = env['HOST'] ?? '127.0.0.1';
const resource = env['MCP_RESOURCE'] ?? `http://localhost:${port}/mcp`;
const apiUrl = env['HELIX_API_URL'];
const apiKey = env['HELIX_API_KEY'];
const serviceDid = env['SERVICE_DID'];
const demo = env['DEMO_MODE'] === '1';

if (apiKey && !apiUrl) {
  // HelixClient given only an API key talks to the hosted production API.
  fail('HELIX_API_KEY is set but HELIX_API_URL is not; set HELIX_API_URL explicitly (e.g. a local server)');
}
if (demo && !['127.0.0.1', 'localhost', '::1'].includes(host)) {
  fail('DEMO_MODE accepts fixed tokens and is only allowed on a loopback HOST');
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
const asString = (value: unknown): string | undefined => (typeof value === 'string' && value.length > 0 ? value : undefined);

/** Refuses keys this sample does not pass through, so a misspelt or unsupported option fails loudly instead of silently changing behaviour. */
function onlyKeys(raw: Record<string, unknown>, allowed: readonly string[], where: string): void {
  const unknown = Object.keys(raw).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) fail(`${where}: unknown key(s) ${unknown.join(', ')}; allowed: ${allowed.join(', ')}`);
}

function introspectionOf(raw: Record<string, unknown> | undefined, where: string): OAuthIntrospectionOptions | undefined {
  if (!raw) return undefined;
  onlyKeys(raw, ['endpoint', 'clientId', 'clientSecret', 'cacheTtlMs', 'allowMissingAudience'], `${where}.introspection`);
  const endpoint = asString(raw['endpoint']);
  const clientId = asString(raw['clientId']);
  const clientSecret = asString(raw['clientSecret']);
  if (!endpoint || !clientId || !clientSecret) fail(`${where}: introspection needs endpoint, clientId and clientSecret`);
  const cacheTtlMs = raw['cacheTtlMs'];
  const allowMissingAudience = raw['allowMissingAudience'];
  if (cacheTtlMs !== undefined && (typeof cacheTtlMs !== 'number' || cacheTtlMs < 0)) fail(`${where}: cacheTtlMs must be a non-negative number`);
  if (allowMissingAudience !== undefined && typeof allowMissingAudience !== 'boolean') fail(`${where}: allowMissingAudience must be a boolean`);
  return {
    endpoint,
    clientId,
    clientSecret,
    ...(typeof cacheTtlMs === 'number' ? { cacheTtlMs } : {}),
    ...(typeof allowMissingAudience === 'boolean' ? { allowMissingAudience } : {}),
  };
}

/** The trusted authorization servers, from OAUTH_ISSUERS (several) and/or OAUTH_ISSUER (one). The audience is always this server. */
function oauthIssuersFromEnv(): OAuthIssuerOptions[] {
  const issuers: OAuthIssuerOptions[] = [];

  if (env['OAUTH_ISSUERS']) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(env['OAUTH_ISSUERS']);
    } catch {
      fail('OAUTH_ISSUERS is not valid JSON');
    }
    if (!Array.isArray(parsed)) fail('OAUTH_ISSUERS must be a JSON array');
    parsed.forEach((item, i) => {
      const where = `OAUTH_ISSUERS[${i}]`;
      const entry = asRecord(item) ?? fail(`${where}: expected an object`);
      onlyKeys(entry, ['issuer', 'jwksUri', 'introspection', 'requireAccessTokenType'], where);
      const issuer = asString(entry['issuer']) ?? fail(`${where}: issuer is required`);
      const jwksUri = asString(entry['jwksUri']);
      const introspection = introspectionOf(asRecord(entry['introspection']), where);
      if (!jwksUri && !introspection) fail(`${where}: needs jwksUri, introspection, or both`);
      const requireAccessTokenType = entry['requireAccessTokenType'];
      if (requireAccessTokenType !== undefined && typeof requireAccessTokenType !== 'boolean') fail(`${where}: requireAccessTokenType must be a boolean`);
      issuers.push({
        issuer,
        audience: resource,
        ...(jwksUri ? { jwksUri } : {}),
        ...(introspection ? { introspection } : {}),
        ...(typeof requireAccessTokenType === 'boolean' ? { requireAccessTokenType } : {}),
      });
    });
  }

  const clientVars = Boolean(env['OAUTH_CLIENT_ID'] || env['OAUTH_CLIENT_SECRET']);
  if (env['OAUTH_ISSUER']) {
    const jwksUri = env['OAUTH_JWKS_URI'];
    const introspectionUrl = env['OAUTH_INTROSPECTION_URL'];
    if (!jwksUri && !introspectionUrl) {
      fail('OAUTH_ISSUER needs OAUTH_JWKS_URI (JWT access tokens) or OAUTH_INTROSPECTION_URL + OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET (opaque tokens)');
    }
    if (clientVars && !introspectionUrl) {
      // Otherwise the server would quietly start JWKS-only while the operator believes introspection is on.
      fail('OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET are only used with OAUTH_INTROSPECTION_URL');
    }
    const introspection = introspectionUrl
      ? introspectionOf({ endpoint: introspectionUrl, clientId: env['OAUTH_CLIENT_ID'], clientSecret: env['OAUTH_CLIENT_SECRET'] }, 'OAUTH_INTROSPECTION_URL')
      : undefined;
    issuers.push({
      issuer: env['OAUTH_ISSUER'],
      audience: resource,
      ...(jwksUri ? { jwksUri } : {}),
      ...(introspection ? { introspection } : {}),
    });
  } else if (env['OAUTH_JWKS_URI'] || env['OAUTH_INTROSPECTION_URL'] || clientVars) {
    fail('OAUTH_JWKS_URI / OAUTH_INTROSPECTION_URL / OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET need OAUTH_ISSUER');
  }

  return issuers;
}

const issuers = oauthIssuersFromEnv();
if (demo && issuers.length > 0) {
  fail('use either DEMO_MODE or OAUTH_ISSUER / OAUTH_ISSUERS, not both');
}

const auth: Omit<MCPMiddlewareOptions, 'toolScopes' | 'requiredScopes'> = {
  ...(serviceDid ? { expectedTargetService: serviceDid, serviceDid } : {}),
  onAuditError: (error) => console.error('audit write failed:', error),
};
if (apiUrl) {
  auth.client = new HelixClient(apiUrl, apiKey ? { apiKey } : {});
  if (apiKey) {
    auth.auditSink = createHelixAuditSink({ baseUrl: apiUrl, apiKey, ...(serviceDid ? { serviceDid } : {}) });
  }
}
if (demo) {
  auth.validateOAuthToken = async (token): Promise<AuthResult> => {
    const result = Object.hasOwn(DEMO_TOKENS, token) ? DEMO_TOKENS[token] : undefined;
    if (!result) throw new Error('unknown demo token');
    return result;
  };
} else if (issuers.length > 0) {
  auth.oauth = issuers;
}
if (!auth.client && !auth.validateOAuthToken && !auth.oauth) {
  fail('no way to authenticate callers: set HELIX_API_URL (HelixID VPs), OAUTH_ISSUER / OAUTH_ISSUERS, or DEMO_MODE=1');
}

const server = createOrderServer({
  resource,
  ...(issuers.length > 0 ? { authorizationServers: issuers.map((i) => i.issuer) } : {}),
  auth,
  onServerError: (error) => console.error('server error:', error),
});
server.listen(port, host, () => {
  const modes = issuers.map((i) => `${i.issuer} (${[i.jwksUri && 'jwks', i.introspection && 'introspection'].filter(Boolean).join('+')})`);
  console.log(`order-management MCP server on ${resource}`);
  console.log(`  HelixID VPs: ${auth.client ? `verified via ${apiUrl}` : 'off (set HELIX_API_URL)'}`);
  console.log(`  OAuth:       ${demo ? 'DEMO tokens demo-reader, demo-admin' : modes.length ? modes.join(', ') : 'off'}`);
  console.log(`  Audit:       ${auth.auditSink ? `${apiUrl}/v1/audit-log/events` : 'off (set HELIX_API_URL + HELIX_API_KEY)'}`);
});
