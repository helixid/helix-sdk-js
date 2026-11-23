// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/* eslint-disable no-console -- command-line entry point: startup and error output is the point */

import { appendFileSync, readFileSync } from 'node:fs';
import { kyaos } from '@helixid/sdk-js';
import type { AuditDeliverySink } from '@helixid/sdk-js';
import {
  RedisStatusCacheStore,
  type RedisStatusCacheClient,
  createHelixAuditDelivery,
  createRevocationSignalClient,
  type RevocationSignalClient,
  createKyaOs,
  createMcpAuditTrail,
  createLocalVerifier,
  createNeedsAuthorization,
  type AuditSink,
  type AuthResult,
  type KyaOsRuntime,
  type McpAuditTrail,
  type MCPMiddlewareOptions,
  type OAuthIntrospectionOptions,
  type OAuthIssuerOptions,
  auth0,
  entra,
  keycloak,
  okta,
} from '@helixid/mcp-middleware';
import { createOrderServer } from './app.js';
import { demoRetryAuthorizer } from './demo-authorizer.js';
import { TOOL_SCOPES } from './orders.js';
import { describeWellKnown, wellKnownFromEnv, type WellKnownFromEnv } from './well-known-env.js';

/**
 * Configuration (environment):
 *   PORT, HOST            listen address (default 3700 on 127.0.0.1)
 *   MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
 *   HELIX_API_URL         HelixID API the audit trail writes to. Required whenever HELIX_API_KEY is
 *   HELIX_API_KEY         set: there is deliberately no default URL. Never on the request path. The key
 *                         turns on the audit trail (KYA-OS typed events to the recorder, POST /v1/audit/submissions),
 *                         which names this server as its producer, so it also needs SERVICE_DID.
 *   AUDIT_INCLUDE_TOOL_NAMES=1
 *                         record tool names in audit events (withheld by default: often sensitive)
 *   AUDIT_DELIVERY        required (default): each event's recorder receipt is obtained before the call
 *                         goes on; buffered: events go to a durable outbox (AUDIT_OUTBOX_DIR) and are
 *                         delivered in the background; best-effort: only with AUDIT_ACCEPT_AAP1=1
 *   AUDIT_OUTBOX_DIR      buffered delivery's durable outbox directory (AUDIT_OUTBOX=memory asks for the
 *                         ephemeral one, which buffered delivery refuses at startup)
 *   SERVICE_DID           this server's DID: the KYA-OS door (story F-2). Every tool call that carries
 *                         a request proof in _meta["org.kya-os/request-proof"] (and its delegation chain
 *                         in _meta["org.kya-os/delegation-chain"]) is verified in-process against this
 *                         DID as audience and resource, from public DID documents, status lists and the
 *                         agent's Entity Card alone. Optional:
 *   KYAOS_TRUSTED_ISSUERS   comma-separated attestation issuers, or * (default: allow all)
 *   KYAOS_TRUSTED_ROOTS     comma-separated DIDs the root hop may be issued by (default: any)
 *   KYAOS_MAX_CHAIN_LENGTH  longest carried chain read (default 10)
 *   KYAOS_CARDS_FILE        JSON file mapping agent DIDs to their Entity Cards (local config, read before
 *                           the card is fetched from the agent's DID document)
 *   KYAOS_ALLOW_LOOPBACK_HTTP=1  development only: read DID documents, cards and status lists over
 *                           http on loopback hosts
 *   Revocation (story L3-C): every status list's proof is verified before a bit is read; lists and
 *   verdicts are cached (in KYAOS_REDIS_URL when set, shared by every instance):
 *   KYAOS_STATUS_CACHE_TTL      seconds a list or verdict is cached (default 300)
 *   KYAOS_HIGH_PRIVILEGE_SCOPES comma-separated scopes whose reads are cached at most
 *   KYAOS_HIGH_PRIVILEGE_TTL      seconds (default 60, at most 60)
 *   KYAOS_MAX_STALE_SECONDS     seconds a list may be served past its validUntil from the cache (default 60)
 *   KYAOS_STATUS_LIST_ISSUERS   JSON object: issuer DID -> status-list URLs or https origins it keeps
 *   KYAOS_SIGNAL_ISSUERS        comma-separated DIDs whose revocation signals (RFC 8417 SETs) are honoured;
 *                               needed by either of:
 *   KYAOS_REVOCATION_EVENTS_URL   Helix's SSE endpoint (<api>/v1/events/revocations): one outbound
 *                                 connection, reconnecting on drop
 *   KYAOS_REVOCATION_WEBHOOK_PATH a path on this server that receives pushed SETs (RFC 8935)
 *   KYAOS_VERIFICATION_LOG      1: print each verification (level, fresh, reasons) and each revocation signal
 *                               as one JSON line; a file path: append them there as JSON lines instead
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
 *   PUBLIC_ORIGIN         KYA-OS story C-A: serve this server's did.json and card.json (its did:web is
 *                         derived from the origin and MCP path). Optional with it:
 *   SERVICE_NAME            the card's display name (default "Order Management (HelixID sample)")
 *   SERVICE_PUBLIC_KEY_JWK  the service key's public JWK, {"kty":"OKP","crv":"Ed25519","x":...}
 *   SERVICE_KID             its verification-method fragment (default key-1)
 *   SERVICE_RESPONSIBLE_PARTY  the accountable org DID, when there is one
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
 *   KYAOS_REDIS_URL         also the status cache's Redis (story L3-C), whatever KYAOS_NONCE_STORE says: lists
 *                           and verdicts shared by every instance; without it the cache is in memory
 *   KYAOS_AUTHORIZATION_URL KYA-OS (story L3-E): the consent page a caller without the authority for a
 *                         tool is sent to. Turns on the signed needs_authorization challenge and the
 *                         resume flow; the resume-token store follows KYAOS_NONCE_STORE (Redis on
 *                         KYAOS_REDIS_URL, key prefix KYAOS_RESUME_KEY_PREFIX, when the replay store is
 *                         Redis; memory otherwise), chosen by @helixid/mcp-middleware itself. In
 *                         DEMO_MODE the retry's DelegationCredential is checked structurally only (see
 *                         demo-authorizer.ts); outside it every retry is refused until a verifier
 *                         (stories F-2, L3-H) is wired in. Optional:
 *   KYAOS_RESUME_TTL_SECONDS  resume-token lifetime (default 600)
 *   AUDIT_LOG_FILE        append every audit event as one JSON line to this file, next to (or instead
 *                         of) the HelixID audit sink; for local runs and the e2e suite
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
  // Agents with a DID as subject, for the needs_authorization flow (story L3-E): read only until a delegation grants more.
  'demo-agent': { sub: 'did:key:z6MkdemoAgentOrdersRead', scopes: ['orders:read'] },
  'demo-agent-2': { sub: 'did:key:z6MkdemoAgentTwoOrdersRead', scopes: ['orders:read'] },
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
  // An audit sink given only an API key would talk to the hosted production API.
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
let audit: McpAuditTrail | undefined;
if (apiUrl && apiKey) {
  // The audit trail is the only thing that talks to the Helix API, and never on the request path.
  if (!serviceDid) fail('HELIX_API_KEY turns on the audit trail, whose events name this server: set SERVICE_DID');
  // A-2: delivery to the HelixID recorder (POST /v1/audit/submissions).
  const delivery = env['AUDIT_DELIVERY'] || 'required';
  if (delivery !== 'required' && delivery !== 'buffered' && delivery !== 'best-effort') {
    fail(`AUDIT_DELIVERY must be required, buffered or best-effort (got ${delivery})`);
  }
  let reporter: AuditDeliverySink;
  try {
    reporter = createHelixAuditDelivery({
      baseUrl: apiUrl,
      apiKey,
      delivery,
      ...(env['AUDIT_OUTBOX'] === 'memory' ? { outbox: 'memory' as const } : {}),
      ...(env['AUDIT_OUTBOX_DIR'] ? { outboxDir: env['AUDIT_OUTBOX_DIR'] } : {}),
      acceptAap1: env['AUDIT_ACCEPT_AAP1'] === '1',
      onDeliveryFailure: (error) => console.error('audit delivery failed:', error instanceof Error ? error.message : error),
    });
  } catch (error) {
    fail(`audit delivery refused: ${error instanceof Error ? error.message : String(error)}`);
  }
  audit = createMcpAuditTrail({ reporter, serviceDid, includeToolNames: env['AUDIT_INCLUDE_TOOL_NAMES'] === '1' });
  // The guard's decisions and the call lifecycle share one trail (one source, one sequence).
  auth.auditSink = audit.toolAuditSink();
}
const auditLogFile = env['AUDIT_LOG_FILE'];
if (auditLogFile) {
  const helixSink = auth.auditSink;
  const fileSink: AuditSink = (event) => appendFileSync(auditLogFile, `${JSON.stringify(event)}\n`);
  auth.auditSink = helixSink ? async (event): Promise<void> => (fileSink(event), helixSink(event)) : fileSink;
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
if (!serviceDid && !auth.validateOAuthToken && !auth.oauth) {
  fail('no way to authenticate callers: set SERVICE_DID (KYA-OS request proofs), OAUTH_ISSUER / OAUTH_ISSUERS, or DEMO_MODE=1');
}

const publicOrigin = env['PUBLIC_ORIGIN'];
let identity: Parameters<typeof createOrderServer>[0]['identity'];
if (publicOrigin) {
  let publicKeyJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string } | undefined;
  if (env['SERVICE_PUBLIC_KEY_JWK']) {
    try {
      publicKeyJwk = JSON.parse(env['SERVICE_PUBLIC_KEY_JWK']) as { kty: 'OKP'; crv: 'Ed25519'; x: string };
    } catch {
      fail('SERVICE_PUBLIC_KEY_JWK is not valid JSON');
    }
  }
  identity = {
    publicOrigin,
    path: new URL(resource).pathname,
    ...(serviceDid ? { did: serviceDid } : {}),
    card: {
      name: env['SERVICE_NAME'] ?? 'Order Management (HelixID sample)',
      capabilities: ['tools/list', 'tools/call', ...Object.keys(TOOL_SCOPES)],
      ...(publicKeyJwk ? { publicKeyJwk, kid: env['SERVICE_KID'] ?? 'key-1' } : {}),
      ...(env['SERVICE_RESPONSIBLE_PARTY'] ? { responsibleParty: env['SERVICE_RESPONSIBLE_PARTY'] } : {}),
    },
  };
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
const redisUrl = env['KYAOS_REDIS_URL'];
if (redisUrl && !serviceDid) fail('KYAOS_REDIS_URL needs SERVICE_DID');
// The status cache's Redis (story L3-C): an ioredis client of its own. The replay store's comes from nonceStoreFromEnv (story L2-A).
let statusCacheRedis: (RedisStatusCacheClient & { quit(): Promise<unknown> }) | undefined;
if (redisUrl) {
  const { Redis } = await import('ioredis');
  const client = new Redis(redisUrl);
  // Without a listener ioredis prints its own unhandled-error line; ours carries no URL.
  client.on('error', (error: Error) => console.warn(`status cache: redis error: ${error.message}`));
  statusCacheRedis = client as unknown as RedisStatusCacheClient & { quit(): Promise<unknown> };
}
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

const authorizationUrl = env['KYAOS_AUTHORIZATION_URL'];
if (authorizationUrl) {
  if (!serviceDid) fail('KYAOS_AUTHORIZATION_URL needs SERVICE_DID (the challenge binds the token to this service)');
  const ttlSeconds = numberFromEnv('KYAOS_RESUME_TTL_SECONDS', false);
  try {
    auth.needsAuthorization = createNeedsAuthorization({
      // The consent page, with the binding in its query so the page knows what to show (the token stays out of the URL).
      authorizationUrl: (c) => {
        const url = new URL(authorizationUrl);
        url.searchParams.set('agent', c.agentDid);
        url.searchParams.set('tool', c.tool);
        url.searchParams.set('scope', c.scopes.join(' '));
        return url.toString();
      },
      ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
      ...(demo ? { authorizer: demoRetryAuthorizer(serviceDid) } : {}),
      ...(auth.auditSink ? { auditSink: auth.auditSink } : {}),
      onAuditError: (error) => console.error('audit write failed:', error),
      serviceDid,
    });
  } catch (error) {
    fail(`KYA-OS needs_authorization: ${error instanceof Error ? error.message : String(error)}`);
  }
} else if (env['KYAOS_RESUME_TTL_SECONDS']) {
  fail('KYAOS_RESUME_TTL_SECONDS needs KYAOS_AUTHORIZATION_URL');
}

if (kyaOs) {
  // redis and dynamo load their client package in the background: a missing one stops the server here, not at the first call.
  try {
    await kyaOs.ready();
  } catch (error) {
    fail(`KYA-OS: ${error instanceof Error ? error.message : String(error)}`);
  }
}
if (auth.needsAuthorization) {
  // The resume-token store follows the replay store; a Redis one loads ioredis in the background, like it.
  try {
    await auth.needsAuthorization.ready();
  } catch (error) {
    fail(`KYA-OS needs_authorization: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** A comma-separated list of DIDs, or undefined when the variable is unset or `*`. */
function didList(name: string): string[] | undefined {
  const raw = env[name]?.trim();
  if (!raw || raw === '*') return undefined;
  const dids = raw.split(',').map((did) => did.trim()).filter((did) => did.length > 0);
  if (dids.some((did) => !did.startsWith('did:'))) fail(`${name} must list DIDs`);
  return dids;
}

/** A non-negative number of seconds from an optional variable. */
function secondsFromEnv(name: string): number | undefined {
  const raw = env[name];
  if (raw === undefined || raw === '') return undefined;
  const value = Number(raw);
  if (!(value >= 0) || !Number.isFinite(value)) fail(`${name} must be a non-negative number of seconds`);
  return value;
}

/** A JSON object from an optional variable. */
function jsonFromEnv(name: string): Record<string, string[]> | undefined {
  const raw = env[name];
  if (!raw) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (asRecord(parsed) === undefined) fail(`${name} must be a JSON object`);
    return parsed as Record<string, string[]>;
  } catch {
    return fail(`${name} is not valid JSON`);
  }
}

let revocationSignals: RevocationSignalClient | undefined;
const revocationWebhookPath = env['KYAOS_REVOCATION_WEBHOOK_PATH'];
const L3C_SETTINGS = [
  'KYAOS_STATUS_CACHE_TTL',
  'KYAOS_HIGH_PRIVILEGE_SCOPES',
  'KYAOS_HIGH_PRIVILEGE_TTL',
  'KYAOS_MAX_STALE_SECONDS',
  'KYAOS_STATUS_LIST_ISSUERS',
  'KYAOS_SIGNAL_ISSUERS',
  'KYAOS_REVOCATION_EVENTS_URL',
  'KYAOS_REVOCATION_WEBHOOK_PATH',
  'KYAOS_VERIFICATION_LOG',
];

// The KYA-OS door (story F-2): every request proof is verified here, in-process, with the Helix API never asked.
if (serviceDid) {
  const trustedIssuers = didList('KYAOS_TRUSTED_ISSUERS');
  const trustedRootIssuers = didList('KYAOS_TRUSTED_ROOTS');
  const maxChainLength = numberFromEnv('KYAOS_MAX_CHAIN_LENGTH', true);
  let cards: Record<string, unknown> | undefined;
  if (env['KYAOS_CARDS_FILE']) {
    try {
      cards = JSON.parse(readFileSync(env['KYAOS_CARDS_FILE'], 'utf8')) as Record<string, unknown>;
    } catch (error) {
      fail(`KYAOS_CARDS_FILE: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const highPrivilegeScopes = env['KYAOS_HIGH_PRIVILEGE_SCOPES']?.split(',').map((scope) => scope.trim()).filter((scope) => scope.length > 0);
  const statusCacheTtl = numberFromEnv('KYAOS_STATUS_CACHE_TTL', false);
  const highPrivilegeTtl = numberFromEnv('KYAOS_HIGH_PRIVILEGE_TTL', false);
  const maxStaleSeconds = secondsFromEnv('KYAOS_MAX_STALE_SECONDS');
  const statusListIssuers = jsonFromEnv('KYAOS_STATUS_LIST_ISSUERS');
  const verificationLog = env['KYAOS_VERIFICATION_LOG'] || undefined;
  /** One JSON line per verification or signal: on stdout, or appended to the file KYAOS_VERIFICATION_LOG names. */
  const logEvent = (kind: string, report: unknown): void => {
    if (verificationLog === '1') console.log(`[kya-os] ${kind} ${JSON.stringify(report)}`);
    else if (verificationLog !== undefined) appendFileSync(verificationLog, `${JSON.stringify({ kind, ...(report as object) })}\n`);
  };
  let statusCache: kyaos.verifier.StatusCache;
  try {
    statusCache = new kyaos.verifier.StatusCache({
      ...(statusCacheTtl === undefined ? {} : { statusCacheTtl }),
      ...(highPrivilegeTtl === undefined ? {} : { highPrivilegeTtl }),
      ...(highPrivilegeScopes === undefined ? {} : { highPrivilegeScopes }),
      ...(maxStaleSeconds === undefined ? {} : { maxStaleSeconds }),
      // Shared by every instance next to the replay store: one signal's delete is seen by all.
      ...(statusCacheRedis ? { store: new RedisStatusCacheStore({ client: statusCacheRedis }) } : {}),
    });
  } catch (error) {
    fail(`status cache: ${error instanceof Error ? error.message : String(error)}`);
  }
  const localVerifier = createLocalVerifier({
    serviceDid,
    statusCache,
    ...(statusListIssuers === undefined ? {} : { statusListIssuers }),
    ...(verificationLog ? { reportVerification: (report): void => logEvent('verification', report) } : {}),
    ...(trustedIssuers === undefined ? {} : { trustedIssuers }),
    ...(trustedRootIssuers === undefined ? {} : { trustedRootIssuers }),
    ...(maxChainLength === undefined ? {} : { maxChainLength }),
    ...(cards === undefined ? {} : { cards }),
    allowLoopbackHttp: env['KYAOS_ALLOW_LOOPBACK_HTTP'] === '1',
    catalog: [...new Set(Object.values(TOOL_SCOPES).flat())],
    // One replay store for the handshake, the response proofs and the request proofs.
    ...(kyaOs ? { nonceStore: kyaOs.nonceStore } : {}),
    // Story A-1 connects the audit trail here; until then each verification is logged once as unrecorded.
    log: (message) => console.warn(message),
  });
  auth.verifier = localVerifier;
  const eventsUrl = env['KYAOS_REVOCATION_EVENTS_URL'];
  const signalIssuers = didList('KYAOS_SIGNAL_ISSUERS');
  if (eventsUrl || revocationWebhookPath) {
    if (signalIssuers === undefined) fail('KYAOS_REVOCATION_EVENTS_URL / KYAOS_REVOCATION_WEBHOOK_PATH need KYAOS_SIGNAL_ISSUERS (the Helix issuer DID)');
    if (revocationWebhookPath !== undefined && !revocationWebhookPath.startsWith('/')) fail('KYAOS_REVOCATION_WEBHOOK_PATH must be a path');
    revocationSignals = createRevocationSignalClient(localVerifier, {
      ...(eventsUrl ? { eventsUrl } : {}),
      trustedIssuers: signalIssuers,
      // Every signal, honoured or ignored, is one line: the sample's audit of the signal channel.
      onSignal: (report) => {
        console.log(`[kya-os] revocation-signal ${JSON.stringify(report)}`);
        logEvent('revocation-signal', report);
      },
      onConnectionChange: (connected, error) => {
        console.log(`[kya-os] revocation-events ${connected ? 'connected' : 'disconnected'}${error ? `: ${error instanceof Error ? error.message : String(error)}` : ''}`);
        logEvent('revocation-events', { connected, ...(error ? { error: error instanceof Error ? error.message : String(error) } : {}) });
      },
    });
    if (eventsUrl) revocationSignals.start();
  } else if (signalIssuers !== undefined) {
    fail('KYAOS_SIGNAL_ISSUERS needs KYAOS_REVOCATION_EVENTS_URL or KYAOS_REVOCATION_WEBHOOK_PATH');
  }
} else if (
  ['KYAOS_TRUSTED_ISSUERS', 'KYAOS_TRUSTED_ROOTS', 'KYAOS_MAX_CHAIN_LENGTH', 'KYAOS_CARDS_FILE', ...L3C_SETTINGS].some((name) => env[name])
) {
  fail('KYAOS_TRUSTED_ISSUERS / KYAOS_TRUSTED_ROOTS / KYAOS_MAX_CHAIN_LENGTH / KYAOS_CARDS_FILE and the revocation settings need SERVICE_DID');
}

/** The discovery document (story L1-D): built once, validated against the schema, or the reason it is off. */
let discovery: WellKnownFromEnv = { wellKnown: undefined, off: undefined };
try {
  discovery = wellKnownFromEnv(env, resource, serviceDid, kyaOs);
} catch (error) {
  fail(`/.well-known/mcp: ${error instanceof Error ? error.message : String(error)}`);
}
const wellKnown = discovery.wellKnown;

const server = createOrderServer({
  resource,
  ...(identity ? { identity } : {}),
  ...(issuers.length > 0 ? { authorizationServers: issuers.map((i) => i.issuer) } : {}),
  auth,
  ...(audit ? { audit } : {}),
  ...(kyaOs ? { kyaos: kyaOs } : {}),
  ...(revocationSignals && revocationWebhookPath ? { revocationWebhook: { path: revocationWebhookPath, handle: revocationSignals.webhookHandler() } } : {}),
  ...(wellKnown ? { wellKnown } : {}),
  onServerError: (error) => console.error('server error:', error),
});
process.once('SIGTERM', () => {
  void revocationSignals?.stop();
  void statusCacheRedis?.quit();
  server.close();
});
server.listen(port, host, () => {
  const modes = issuers.map((i) => {
    const how = [(i.jwksUri || !i.introspection) && 'jwks', i.introspection && 'introspection'].filter(Boolean).join('+');
    const discovered = (!i.jwksUri && !i.introspection) || (i.introspection && !i.introspection.endpoint);
    return `${i.issuer} (${how}${discovered ? ', endpoints from its metadata' : ''})`;
  });
  console.log(`order-management MCP server on ${resource}`);
  console.log(
    `  KYA-OS proofs: ${
      auth.verifier
        ? `verified in-process for ${serviceDid}, trusted issuers ${env['KYAOS_TRUSTED_ISSUERS'] || '*'}, chain length <= ${env['KYAOS_MAX_CHAIN_LENGTH'] || 10}`
        : 'off (set SERVICE_DID)'
    }`,
  );
  if (auth.verifier) {
    console.log(
      `  Revocation:  list proofs verified, cache ${redisUrl ? `redis ${redisUrl}` : 'in memory'}, signals ${
        revocationSignals ? [env['KYAOS_REVOCATION_EVENTS_URL'] && `SSE ${env['KYAOS_REVOCATION_EVENTS_URL']}`, revocationWebhookPath && `webhook ${revocationWebhookPath}`].filter(Boolean).join(' + ') : 'off'
      }`,
    );
  }
  console.log(`  OAuth:       ${demo ? 'DEMO tokens demo-reader, demo-admin, demo-agent, demo-agent-2' : modes.length ? modes.join(', ') : 'off'}`);
  console.log(
    `  Audit:       ${
      [
        audit
          ? `${apiUrl}/v1/audit/submissions (KYA-OS recorder, ${env['AUDIT_DELIVERY'] || 'required'} delivery; tool names ${audit.includeToolNames ? 'recorded' : 'withheld'})`
          : '',
        auditLogFile ? `file ${auditLogFile}` : '',
      ]
        .filter(Boolean)
        .join(' + ') || 'off (set HELIX_API_URL + HELIX_API_KEY + SERVICE_DID, or AUDIT_LOG_FILE)'
    }`,
  );
  console.log(`  Identity:    ${identity ? `${identity.publicOrigin}${new URL(resource).pathname.replace(/\/$/, '')}/{did,card}.json` : 'off (set PUBLIC_ORIGIN)'}`);
  console.log(
    `  Consent:     ${
      authorizationUrl
        ? `needs_authorization challenges to ${authorizationUrl}, resume tokens ${env['KYAOS_NONCE_STORE']?.trim().toLowerCase() === 'redis' ? 'in redis (KYAOS_REDIS_URL)' : 'in memory'}, retries ${demo ? 'checked structurally (DEMO_MODE, no signature verification)' : 'refused until a verifier is wired in'}`
        : 'off (set KYAOS_AUTHORIZATION_URL)'
    }`,
  );
  console.log(
    `  KYA-OS:      ${
      kyaOs
        ? `proofs by ${kyaOs.serverDid}, sessions ${kyaOs.sessionsEnabled ? 'on' : 'off'}, skew ${kyaOs.clockSkewSeconds} s (replay store: the line above)`
        : 'off (set SERVICE_SIGNING_KEY)'
    }`,
  );
  console.log(`  Discovery:   ${describeWellKnown(discovery)}`);
});
