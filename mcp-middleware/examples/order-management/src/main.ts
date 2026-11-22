// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/* eslint-disable no-console -- command-line entry point: startup and error output is the point */

import { HelixClient, kyaos } from '@helixid/sdk-js';
import {
  createHelixAuditSink,
  createKyaOs,
  createWellKnownMcp,
  type AuthResult,
  type KyaOsRuntime,
  type MCPMiddlewareOptions,
  type OAuthIntrospectionOptions,
  type OAuthIssuerOptions,
  type WellKnownMcp,
  auth0,
  entra,
  keycloak,
  okta,
} from '@helixid/mcp-middleware';
import { createOrderServer } from './app.js';

/**
 * Configuration (environment):
 *   PORT, HOST            listen address (default 3700 on 127.0.0.1)
 *   MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
 *   HELIX_API_URL         HelixID API to verify VPs and write audit events. Required whenever
 *   HELIX_API_KEY         HELIX_API_KEY is set: there is deliberately no default URL.
 *   SERVICE_DID           this server's DID: VPs for other services are rejected
 *   OAUTH_ISSUER          OAuth door, one authorization server. The issuer alone is enough: its keys are
 *                         read from its metadata (aud must be MCP_RESOURCE). Optional:
 *   OAUTH_JWKS_URI          its jwks_uri, to skip discovery
 *   OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET
 *                           this server's client credentials: tokens are introspected (RFC 7662, opaque tokens)
 *   OAUTH_INTROSPECTION_URL its introspection endpoint, to skip discovery
 *   OAUTH_ISSUERS         several authorization servers: a JSON array of provider presets
 *                         { provider: "entra", tenantId, audience } | { provider: "auth0", domain }
 *                         | { provider: "okta", domain, authorizationServerId?, introspection? }
 *                         | { provider: "keycloak", baseUrl, realm, introspection? }
 *                         or custom { issuer, jwksUri?, introspection?: { clientId, clientSecret, endpoint? } }
 *   DEMO_MODE=1           local demo only: accept the fixed bearer tokens below instead of an
 *                         authorization server. Refused unless HOST is loopback.
 *   SERVICE_SIGNING_KEY   KYA-OS (story L2-A): this server's Ed25519 private key (hex), the key
 *                         SERVICE_DID's document lists as key-1. Turns on the _kyaos_handshake tool,
 *                         sessions and a server-signed proof on every tool call outcome. Optional:
 *   KYAOS_PUBLIC_ORIGIN     the origin agents connect to, accepted as handshake audience next to the
 *                           DID (default: the origin of MCP_RESOURCE)
 *   KYAOS_CLOCK_SKEW_SECONDS  30 to 600 (default 120)
 *   KYAOS_SESSIONS=0        no sessions: the handshake is refused, calls are proven without one
 *   KYAOS_SESSION_TTL_MINUTES idle TTL (default 30; fractions allowed)
 *   KYAOS_NONCE_STORE       the replay store: memory (default, this instance only), redis or dynamo,
 *                           read by @helixid/mcp-middleware itself (nonceStoreFromEnv); with it:
 *                           redis: KYAOS_REDIS_URL, KYAOS_NONCE_KEY_PREFIX
 *                           dynamo: KYAOS_DYNAMO_TABLE, KYAOS_DYNAMO_KEY_ATTRIBUTE, KYAOS_DYNAMO_TTL_ATTRIBUTE,
 *                                   KYAOS_DYNAMO_REGION, KYAOS_DYNAMO_ENDPOINT (AWS credentials: the SDK's chain)
 *                           See .env.example.
 *   WELL_KNOWN_MCP        KYA-OS discovery (story L1-D): GET /.well-known/mcp is served whenever SERVICE_DID
 *                         is a did:web or did:key (the document's serverDid), with endpoints at
 *                         KYAOS_PUBLIC_ORIGIN (default: the origin of MCP_RESOURCE) and the KYA-OS values
 *                         above. 0 turns the route off (404); 1 makes a SERVICE_DID the document cannot
 *                         carry a startup error instead of a notice. Optional:
 *   STATUS_LIST_CREDENTIAL  URL of this server's status list credential, advertised in the document
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

/**
 * Introspection settings. `endpoint` may be left out of a custom entry (it is
 * then read from the issuer's metadata) and is not accepted on a provider
 * preset (the preset knows it).
 */
function introspectionOf(
  raw: Record<string, unknown> | undefined,
  where: string,
  endpoint: 'optional' | 'derived',
): OAuthIntrospectionOptions | undefined {
  if (!raw) return undefined;
  const keys = ['clientId', 'clientSecret', 'cacheTtlMs', 'allowMissingAudience', ...(endpoint === 'optional' ? ['endpoint'] : [])];
  onlyKeys(raw, keys, `${where}.introspection`);
  const clientId = asString(raw['clientId']);
  const clientSecret = asString(raw['clientSecret']);
  if (!clientId || !clientSecret) fail(`${where}: introspection needs clientId and clientSecret`);
  const url = asString(raw['endpoint']);
  const cacheTtlMs = raw['cacheTtlMs'];
  const allowMissingAudience = raw['allowMissingAudience'];
  if (cacheTtlMs !== undefined && (typeof cacheTtlMs !== 'number' || cacheTtlMs < 0)) fail(`${where}: cacheTtlMs must be a non-negative number`);
  if (allowMissingAudience !== undefined && typeof allowMissingAudience !== 'boolean') fail(`${where}: allowMissingAudience must be a boolean`);
  return {
    clientId,
    clientSecret,
    ...(url ? { endpoint: url } : {}),
    ...(typeof cacheTtlMs === 'number' ? { cacheTtlMs } : {}),
    ...(typeof allowMissingAudience === 'boolean' ? { allowMissingAudience } : {}),
  };
}

/** One OAUTH_ISSUERS entry: a provider preset (`provider` + what that provider needs) or a custom issuer. */
function issuerFromEntry(entry: Record<string, unknown>, where: string): OAuthIssuerOptions {
  const need = (key: string): string => asString(entry[key]) ?? fail(`${where}: ${key} is required`);
  const flag = (key: string): boolean => {
    const value = entry[key];
    if (value !== undefined && typeof value !== 'boolean') fail(`${where}: ${key} must be a boolean`);
    return value === true;
  };
  // Tokens must name this server. Entra is the exception: its v2.0 tokens carry the API's client ID in aud.
  const audience = asString(entry['audience']) ?? resource;
  const provider = entry['provider'];
  try {
    switch (provider) {
      case 'entra':
        onlyKeys(entry, ['provider', 'tenantId', 'audience'], where);
        if (!asString(entry['audience'])) fail(`${where}: entra needs audience (the API's application ID; Entra puts that in aud, not the URL)`);
        return entra({ tenantId: need('tenantId'), audience });
      case 'auth0':
        onlyKeys(entry, ['provider', 'domain', 'audience'], where);
        return auth0({ domain: need('domain'), audience });
      case 'okta': {
        onlyKeys(entry, ['provider', 'domain', 'authorizationServerId', 'audience', 'introspection', 'introspectJwts'], where);
        const introspection = introspectionOf(asRecord(entry['introspection']), where, 'derived');
        const serverId = asString(entry['authorizationServerId']);
        return okta({
          domain: need('domain'),
          audience,
          ...(serverId ? { authorizationServerId: serverId } : {}),
          ...(introspection ? { introspection } : {}),
          ...(flag('introspectJwts') ? { introspectJwts: true } : {}),
        });
      }
      case 'keycloak': {
        onlyKeys(entry, ['provider', 'baseUrl', 'realm', 'audience', 'introspection', 'introspectJwts'], where);
        const introspection = introspectionOf(asRecord(entry['introspection']), where, 'derived');
        return keycloak({
          baseUrl: need('baseUrl'),
          realm: need('realm'),
          audience,
          ...(introspection ? { introspection } : {}),
          ...(flag('introspectJwts') ? { introspectJwts: true } : {}),
        });
      }
      case undefined: {
        onlyKeys(entry, ['issuer', 'jwksUri', 'introspection', 'introspectJwts', 'requireAccessTokenType', 'audience'], where);
        const jwksUri = asString(entry['jwksUri']);
        const introspection = introspectionOf(asRecord(entry['introspection']), where, 'optional');
        const requireAccessTokenType = entry['requireAccessTokenType'];
        if (requireAccessTokenType !== undefined && typeof requireAccessTokenType !== 'boolean') fail(`${where}: requireAccessTokenType must be a boolean`);
        return {
          issuer: need('issuer'),
          audience,
          ...(jwksUri ? { jwksUri } : {}),
          ...(introspection ? { introspection } : {}),
          ...(typeof requireAccessTokenType === 'boolean' ? { requireAccessTokenType } : {}),
          ...(flag('introspectJwts') ? { introspectJwts: true } : {}),
        };
      }
      default:
        return fail(`${where}: unknown provider ${JSON.stringify(provider)}; use entra, auth0, okta, keycloak, or leave it out and give issuer`);
    }
  } catch (error) {
    return fail(`${where}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** The trusted authorization servers, from OAUTH_ISSUERS (several) and/or OAUTH_ISSUER (one). */
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
      issuers.push(issuerFromEntry(asRecord(item) ?? fail(`${where}: expected an object`), where));
    });
  }

  const clientId = env['OAUTH_CLIENT_ID'];
  const clientSecret = env['OAUTH_CLIENT_SECRET'];
  const jwksUri = env['OAUTH_JWKS_URI'];
  const introspectionUrl = env['OAUTH_INTROSPECTION_URL'];
  if (env['OAUTH_ISSUER']) {
    if (Boolean(clientId) !== Boolean(clientSecret)) fail('OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET go together');
    if (introspectionUrl && !clientId) fail('OAUTH_INTROSPECTION_URL needs OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET');
    // Only the issuer: its keys come from its metadata. With client credentials:
    // tokens are introspected, at OAUTH_INTROSPECTION_URL or the metadata's endpoint.
    issuers.push({
      issuer: env['OAUTH_ISSUER'],
      audience: resource,
      ...(jwksUri ? { jwksUri } : {}),
      ...(clientId && clientSecret
        ? { introspection: { clientId, clientSecret, ...(introspectionUrl ? { endpoint: introspectionUrl } : {}) } }
        : {}),
    });
  } else if (jwksUri || introspectionUrl || clientId || clientSecret) {
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

/** A positive number from an optional variable; `integer` demands a whole one. */
function numberFromEnv(name: string, integer: boolean): number | undefined {
  const raw = env[name];
  if (!raw) return undefined;
  const value = Number(raw);
  if (!(value > 0) || !Number.isFinite(value) || (integer && !Number.isInteger(value))) {
    fail(`${name} must be a positive ${integer ? 'integer' : 'number'}`);
  }
  return value;
}

let kyaOs: KyaOsRuntime | undefined;
if (env['SERVICE_SIGNING_KEY']) {
  if (!serviceDid) fail('SERVICE_SIGNING_KEY needs SERVICE_DID (the DID whose document lists the key)');
  const skew = numberFromEnv('KYAOS_CLOCK_SKEW_SECONDS', true);
  const ttlMinutes = numberFromEnv('KYAOS_SESSION_TTL_MINUTES', false);
  try {
    kyaOs = createKyaOs({
      // The key is read from the environment at every signature; the server never holds it.
      signer: new kyaos.EnvSigner({ did: serviceDid, envVar: 'SERVICE_SIGNING_KEY' }),
      publicOrigin: env['KYAOS_PUBLIC_ORIGIN'] || new URL(resource).origin,
      ...(skew !== undefined ? { clockSkewSeconds: skew } : {}),
      session: { enabled: env['KYAOS_SESSIONS'] !== '0', ...(ttlMinutes !== undefined ? { ttlMinutes } : {}) },
      toolsEndpoint: resource,
    });
  } catch (error) {
    fail(`KYA-OS: ${error instanceof Error ? error.message : String(error)}`);
  }
} else if (env['KYAOS_NONCE_STORE'] || env['KYAOS_PUBLIC_ORIGIN'] || env['KYAOS_CLOCK_SKEW_SECONDS'] || env['KYAOS_SESSIONS'] || env['KYAOS_SESSION_TTL_MINUTES']) {
  fail('KYAOS_* settings need SERVICE_SIGNING_KEY');
}

if (kyaOs) {
  // redis and dynamo load their client package in the background: a missing one stops the server here, not at the first call.
  try {
    await kyaOs.ready();
  } catch (error) {
    fail(`KYA-OS: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** The discovery document (story L1-D): built once, validated against the schema, or the reason it is off. */
let wellKnown: WellKnownMcp | undefined;
let wellKnownOff: string | undefined;
const wellKnownSetting = env['WELL_KNOWN_MCP'];
if (wellKnownSetting === '0') {
  wellKnown = createWellKnownMcp({ enabled: false });
  wellKnownOff = 'off (WELL_KNOWN_MCP=0): 404';
} else if (!serviceDid) {
  wellKnownOff = 'off (set SERVICE_DID)';
} else if (!/^did:(web|key):/.test(serviceDid) && wellKnownSetting !== '1') {
  wellKnownOff = `off (SERVICE_DID ${serviceDid} is not a did:web or did:key, which the document's serverDid must be; WELL_KNOWN_MCP=1 makes this an error)`;
} else {
  try {
    wellKnown = createWellKnownMcp({
      publicOrigin: env['KYAOS_PUBLIC_ORIGIN'] || new URL(resource).origin,
      serverDid: serviceDid,
      toolsEndpoint: new URL(resource).pathname,
      ...(kyaOs ? { kyaos: kyaOs.describe() } : {}),
      ...(env['STATUS_LIST_CREDENTIAL'] ? { statusListCredential: env['STATUS_LIST_CREDENTIAL'] } : {}),
    });
  } catch (error) {
    fail(`/.well-known/mcp: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const server = createOrderServer({
  resource,
  ...(issuers.length > 0 ? { authorizationServers: issuers.map((i) => i.issuer) } : {}),
  auth,
  ...(kyaOs ? { kyaos: kyaOs } : {}),
  ...(wellKnown ? { wellKnown } : {}),
  onServerError: (error) => console.error('server error:', error),
});
server.listen(port, host, () => {
  const modes = issuers.map((i) => {
    const how = [(i.jwksUri || !i.introspection) && 'jwks', i.introspection && 'introspection'].filter(Boolean).join('+');
    const discovered = (!i.jwksUri && !i.introspection) || (i.introspection && !i.introspection.endpoint);
    return `${i.issuer} (${how}${discovered ? ', endpoints from its metadata' : ''})`;
  });
  console.log(`order-management MCP server on ${resource}`);
  console.log(`  HelixID VPs: ${auth.client ? `verified via ${apiUrl}` : 'off (set HELIX_API_URL)'}`);
  console.log(`  OAuth:       ${demo ? 'DEMO tokens demo-reader, demo-admin' : modes.length ? modes.join(', ') : 'off'}`);
  console.log(`  Audit:       ${auth.auditSink ? `${apiUrl}/v1/audit-log/events` : 'off (set HELIX_API_URL + HELIX_API_KEY)'}`);
  console.log(
    `  KYA-OS:      ${
      kyaOs
        ? `proofs by ${kyaOs.serverDid}, sessions ${kyaOs.sessionsEnabled ? 'on' : 'off'}, skew ${kyaOs.clockSkewSeconds} s (replay store: the line above)`
        : 'off (set SERVICE_SIGNING_KEY)'
    }`,
  );
  const document = wellKnown?.document;
  console.log(
    `  Discovery:   ${
      document
        ? `${new URL(document.endpoints.tools).origin}/.well-known/mcp, serverDid ${document.serverDid}, skew ${document.clockSkewSeconds} s, handshake ${document.endpoints.handshake ? 'advertised' : 'absent'} (route the path at that origin to this server: see mcp-middleware/docs/well-known.md)`
        : wellKnownOff
    }`,
  );
});
