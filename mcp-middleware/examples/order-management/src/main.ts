// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/* eslint-disable no-console -- command-line entry point: startup and error output is the point */

import { HelixClient } from '@helixid/sdk-js';
import { createHelixAuditSink, type AuthResult, type MCPMiddlewareOptions } from '@helixid/mcp-middleware';
import { createOrderServer } from './app.js';

/**
 * Configuration (environment):
 *   PORT, HOST            listen address (default 3700 on 127.0.0.1)
 *   MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp)
 *   HELIX_API_URL         HelixID API to verify VPs and write audit events. Required whenever
 *   HELIX_API_KEY         HELIX_API_KEY is set: there is deliberately no default URL.
 *   SERVICE_DID           this server's DID: VPs for other services are rejected
 *   OAUTH_ISSUER          OAuth door: authorization server issuer ...
 *   OAUTH_JWKS_URI        ... and its jwks_uri (tokens must have aud = MCP_RESOURCE)
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
if (demo && (env['OAUTH_ISSUER'] || env['OAUTH_JWKS_URI'])) {
  fail('use either DEMO_MODE or OAUTH_ISSUER/OAUTH_JWKS_URI, not both');
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
} else if (env['OAUTH_ISSUER'] && env['OAUTH_JWKS_URI']) {
  auth.oauth = { issuer: env['OAUTH_ISSUER'], audience: resource, jwksUri: env['OAUTH_JWKS_URI'] };
}
if (!auth.client && !auth.validateOAuthToken && !auth.oauth) {
  fail('no way to authenticate callers: set HELIX_API_URL (HelixID VPs), OAUTH_ISSUER + OAUTH_JWKS_URI, or DEMO_MODE=1');
}

const server = createOrderServer({
  resource,
  ...(env['OAUTH_ISSUER'] ? { authorizationServers: [env['OAUTH_ISSUER']] } : {}),
  auth,
  onServerError: (error) => console.error('server error:', error),
});
server.listen(port, host, () => {
  console.log(`order-management MCP server on ${resource}`);
  console.log(`  HelixID VPs: ${auth.client ? `verified via ${apiUrl}` : 'off (set HELIX_API_URL)'}`);
  console.log(`  OAuth:       ${demo ? 'DEMO tokens demo-reader, demo-admin' : auth.oauth ? env['OAUTH_ISSUER'] : 'off'}`);
  console.log(`  Audit:       ${auth.auditSink ? `${apiUrl}/v1/audit-log/events` : 'off (set HELIX_API_URL + HELIX_API_KEY)'}`);
});
