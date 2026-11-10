// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import {
  constants,
  createHash,
  createPublicKey,
  verify as cryptoVerify,
  type JsonWebKey as NodeJwk,
  type KeyObject,
} from 'node:crypto';
import { AuthorizationServerUnavailableError, MCPAuthError } from './errors.js';

/** The outcome of validating an OAuth access token. */
export interface AuthResult {
  /** The token's subject (`sub`). Logged as the caller identity in audit events. */
  sub: string;
  /** Granted scopes, compared against per-tool scopes. */
  scopes?: string[];
  clientId?: string;
  claims?: Record<string, unknown>;
}

/** RFC 7662 token introspection: how to ask the issuer whether an opaque (or JWT) token is active. */
export interface OAuthIntrospectionOptions {
  /**
   * The authorization server's `introspection_endpoint`. https only (http allowed
   * for loopback). Omit it to have `createOAuthValidator` read it from the
   * issuer's metadata document (RFC 8414 / OpenID Connect discovery).
   */
  endpoint?: string;
  /** This resource server's client credentials at the authorization server (HTTP Basic, RFC 6749 §2.3.1). */
  clientId: string;
  clientSecret: string;
  /** How long a positive answer is reused before asking again. Default 60 s; never past the token's `exp`. 0 disables. */
  cacheTtlMs?: number;
  /**
   * Accept an active token whose introspection response has no `aud`. Off by
   * default: without an audience there is no proof the token was minted for
   * this server (RFC 8707), so it is refused.
   */
  allowMissingAudience?: boolean;
}

/**
 * One trusted authorization server. Validate its tokens by JWKS (`jwksUri`),
 * by introspection (`introspection`), or both: a JWT is checked against the
 * keys when `jwksUri` is set, otherwise introspected; a token that is not a
 * JWT can only be introspected.
 */
export interface OAuthIssuerOptions {
  /** Expected `iss`. Must match the token's claim exactly (Auth0 issuers end in `/`, Okta's do not). */
  issuer: string;
  /** Expected `aud`: this MCP server's resource identifier (RFC 8707 / RFC 9728). */
  audience: string | string[];
  /**
   * The authorization server's `jwks_uri`. https only (http allowed for loopback).
   * With neither `jwksUri` nor `introspection`, `createOAuthValidator` reads it
   * from the issuer's metadata document, so `{ issuer, audience }` is enough.
   */
  jwksUri?: string;
  introspection?: OAuthIntrospectionOptions;
  /**
   * With both `jwksUri` and `introspection`: after a JWT's signature and claims
   * check out, also introspect it, so a token revoked at the authorization
   * server is refused before it expires. Costs one (cached) round trip per
   * token. Off by default: a JWT is then verified by its keys alone.
   */
  introspectJwts?: boolean;
  /**
   * Claims that carry the granted scopes; all listed are merged. Default
   * `['scope', 'scp']`. Microsoft Entra puts app permissions in `roles`.
   */
  scopeClaims?: string[];
  /** Allowed JWS algorithms. Default: RS/PS/ES 256-512 and EdDSA. `none` and HS* are never accepted. */
  algorithms?: string[];
  /** Allowed clock skew for exp/nbf. Default 30. */
  clockToleranceSeconds?: number;
  /** How long fetched keys are trusted. Default 10 minutes. */
  jwksCacheTtlMs?: number;
  /** Minimum gap between refetches triggered by an unknown `kid`. Default 30 seconds. */
  jwksRefetchCooldownMs?: number;
  /**
   * Require the JWT header `typ` to be `at+jwt` (RFC 9068), so an ID token
   * with a matching audience is not accepted as an access token. Off by
   * default: not every authorization server sets it.
   */
  requireAccessTokenType?: boolean;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

/** A single issuer validated by JWKS: the original `oauth` option shape, still accepted. */
export type OAuthJwtOptions = OAuthIssuerOptions & { jwksUri: string };

/** The `oauth` option: one trusted issuer, or several (an agent on Auth0 and another on Okta can share one MCP server). */
export type OAuthOptions = OAuthIssuerOptions | OAuthIssuerOptions[];

interface Alg {
  hash: string | null;
  kty: 'RSA' | 'EC' | 'OKP';
  crv?: string;
  pss?: boolean;
}

const ALGS: Record<string, Alg> = {
  RS256: { hash: 'sha256', kty: 'RSA' },
  RS384: { hash: 'sha384', kty: 'RSA' },
  RS512: { hash: 'sha512', kty: 'RSA' },
  PS256: { hash: 'sha256', kty: 'RSA', pss: true },
  PS384: { hash: 'sha384', kty: 'RSA', pss: true },
  PS512: { hash: 'sha512', kty: 'RSA', pss: true },
  ES256: { hash: 'sha256', kty: 'EC', crv: 'P-256' },
  ES384: { hash: 'sha384', kty: 'EC', crv: 'P-384' },
  ES512: { hash: 'sha512', kty: 'EC', crv: 'P-521' },
  EdDSA: { hash: null, kty: 'OKP', crv: 'Ed25519' },
};

type Jwk = NodeJwk & { kid?: string; use?: string; alg?: string };

const invalid = (reason: string): MCPAuthError => new MCPAuthError('OAUTH_TOKEN_INVALID', reason);

function decodeSegment(segment: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw invalid('Malformed token');
}

function assertHttpsOrLoopback(uri: string, what: string): void {
  const url = new URL(uri);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error(`${what} must use https (http is allowed only for localhost)`);
  }
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** Expired introspection cache entries are swept when the cache reaches this many entries, so one-token-per-call workloads cannot grow it without bound. */
const CACHE_SWEEP_AT = 1_000;

const DEFAULT_SCOPE_CLAIMS = ['scope', 'scp'];

function parseScopes(claims: Record<string, unknown>, scopeClaims: string[] = DEFAULT_SCOPE_CLAIMS): string[] {
  const scopes = new Set<string>();
  for (const name of scopeClaims) {
    const value = claims[name];
    const items = typeof value === 'string' ? value.split(' ') : Array.isArray(value) ? value : [];
    for (const item of items) if (typeof item === 'string' && item.length > 0) scopes.add(item);
  }
  return [...scopes];
}

function audienceMatches(aud: unknown, audiences: string[]): boolean {
  const tokenAud = Array.isArray(aud) ? aud : [aud];
  return tokenAud.some((a) => typeof a === 'string' && audiences.includes(a));
}

/**
 * Thrown when an issuer confirmed the token is genuine and active but its
 * claims do not fit this server (wrong audience, expired, ...). Distinct from
 * "not active" so the multi-issuer dispatcher stops there: the token is real
 * and belongs to that issuer, so no other issuer should be shown it.
 */
class ActiveTokenRejectedError extends MCPAuthError {}

/** The common claim checks, after the token is known to be genuine (signature verified, or introspected as active). */
function checkStandardClaims(
  claims: Record<string, unknown>,
  options: {
    issuer: string;
    audiences: string[];
    tolerance: number;
    requireExp: boolean;
    requireAud: boolean;
    /** RFC 7662 makes `sub` optional: a client-credentials token may carry only `client_id`. */
    subFromClientId?: boolean;
    scopeClaims?: string[] | undefined;
  },
): AuthResult {
  const now = nowSeconds();
  const exp = claims['exp'];
  if (exp !== undefined || options.requireExp) {
    if (typeof exp !== 'number' || exp + options.tolerance < now) throw invalid('Token expired');
  }
  const nbf = claims['nbf'];
  if (nbf !== undefined && (typeof nbf !== 'number' || nbf - options.tolerance > now)) {
    throw invalid('Token not yet valid');
  }
  const iss = claims['iss'];
  if (iss !== undefined && iss !== options.issuer) throw invalid('Unexpected token issuer');
  const aud = claims['aud'];
  if (aud === undefined) {
    if (options.requireAud) throw invalid('Token has no audience');
  } else if (!audienceMatches(aud, options.audiences)) {
    throw invalid('Token audience does not match this server');
  }
  const clientId = claims['client_id'] ?? claims['azp'];
  const rawSub = claims['sub'];
  const sub =
    typeof rawSub === 'string' && rawSub.length > 0
      ? rawSub
      : options.subFromClientId && typeof clientId === 'string' && clientId.length > 0
        ? clientId
        : undefined;
  if (sub === undefined) throw invalid('Token has no subject');
  return {
    sub,
    scopes: parseScopes(claims, options.scopeClaims),
    ...(typeof clientId === 'string' ? { clientId } : {}),
    claims,
  };
}

/**
 * Default OAuth 2.1 access-token validator for JWT access tokens: verifies the
 * signature against the authorization server's JWKS (cached, refetched on key
 * rotation) and checks issuer, audience, expiry and not-before. For opaque
 * tokens use `createIntrospectionValidator`; for several issuers,
 * `createOAuthValidator`.
 */
export function createJwtValidator(options: OAuthJwtOptions): (token: string) => Promise<AuthResult> {
  assertHttpsOrLoopback(options.jwksUri, 'jwksUri');
  const allowed = new Set(options.algorithms ?? Object.keys(ALGS));
  for (const alg of allowed) {
    if (!(alg in ALGS)) throw new Error(`Unsupported algorithm: ${alg}`);
  }
  const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
  const tolerance = options.clockToleranceSeconds ?? 30;
  const ttl = options.jwksCacheTtlMs ?? 10 * 60_000;
  const cooldown = options.jwksRefetchCooldownMs ?? 30_000;
  const doFetch = options.fetch ?? fetch;

  let keys: Jwk[] = [];
  let fetchedAt = 0;
  let inflight: Promise<void> | undefined;

  const refresh = (): Promise<void> => {
    inflight ??= (async (): Promise<void> => {
      try {
        const res = await doFetch(options.jwksUri, {
          headers: { accept: 'application/json' },
          signal: AbortSignal.timeout(5_000),
        });
        if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
        const body = (await res.json()) as { keys?: unknown };
        if (!Array.isArray(body.keys)) throw new Error('JWKS response has no keys array');
        keys = body.keys.filter((k): k is Jwk => typeof k === 'object' && k !== null);
        fetchedAt = Date.now();
      } finally {
        inflight = undefined;
      }
    })();
    return inflight;
  };

  const select = (kid: string | undefined, alg: string, spec: Alg): Jwk[] =>
    keys.filter(
      (k) =>
        k.kty === spec.kty &&
        (spec.crv === undefined || k.crv === spec.crv) &&
        (k.use === undefined || k.use === 'sig') &&
        (k.alg === undefined || k.alg === alg) &&
        (kid === undefined || k.kid === kid),
    );

  const findKey = async (kid: string | undefined, alg: string, spec: Alg): Promise<Jwk> => {
    try {
      if (Date.now() - fetchedAt > ttl) await refresh();
      let candidates = select(kid, alg, spec);
      if (candidates.length === 0 && Date.now() - fetchedAt >= cooldown) {
        await refresh(); // unknown kid: the issuer may have rotated keys
        candidates = select(kid, alg, spec);
      }
      // Without a kid, only accept an unambiguous key.
      if (candidates.length !== 1) throw invalid('No matching signing key');
      return candidates[0] as Jwk;
    } catch (err) {
      if (err instanceof MCPAuthError) throw err;
      // The authorization server, not the caller, is the problem: never a 401.
      throw new AuthorizationServerUnavailableError(
        `Signing keys could not be retrieved from ${options.jwksUri}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  return async (token: string): Promise<AuthResult> => {
    const parts = token.split('.');
    if (parts.length !== 3) throw invalid('Not a JWT');
    const [h, p, s] = parts as [string, string, string];
    const header = decodeSegment(h);
    const alg = header['alg'];
    if (typeof alg !== 'string' || !allowed.has(alg)) throw invalid('Unsupported token algorithm');
    if ('crit' in header) throw invalid('Unsupported critical header');
    if (options.requireAccessTokenType) {
      const typ = typeof header['typ'] === 'string' ? header['typ'].toLowerCase() : '';
      if (typ !== 'at+jwt' && typ !== 'application/at+jwt') throw invalid('Not an access token (typ)');
    }
    const spec = ALGS[alg] as Alg;
    const kid = typeof header['kid'] === 'string' ? header['kid'] : undefined;

    const jwk = await findKey(kid, alg, spec);
    let key: KeyObject;
    let ok: boolean;
    try {
      key = createPublicKey({ key: jwk, format: 'jwk' });
      const data = Buffer.from(`${h}.${p}`);
      const sig = Buffer.from(s, 'base64url');
      ok = cryptoVerify(
        spec.hash,
        data,
        spec.kty === 'RSA'
          ? spec.pss
            ? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
            : { key, padding: constants.RSA_PKCS1_PADDING }
          : spec.kty === 'EC'
            ? { key, dsaEncoding: 'ieee-p1363' }
            : key,
        sig,
      );
    } catch {
      throw invalid('Token signature could not be verified');
    }
    if (!ok) throw invalid('Invalid token signature');

    const claims = decodeSegment(p);
    if (claims['iss'] === undefined) throw invalid('Unexpected token issuer');
    return checkStandardClaims(claims, {
      issuer: options.issuer,
      audiences,
      tolerance,
      requireExp: true,
      requireAud: true,
      scopeClaims: options.scopeClaims,
    });
  };
}

/**
 * RFC 7662 token introspection: asks the authorization server whether the
 * token is active and reads the subject, scopes, audience and expiry from
 * its answer. The way to accept opaque tokens (Okta's org authorization
 * server, Auth0 without an API audience, Keycloak with opaque tokens on).
 * Positive answers are cached briefly; "not active" and failures are not.
 * An unreachable or misbehaving authorization server throws
 * `AuthorizationServerUnavailableError`, which `toHttpErrorResponse` leaves
 * unmapped: the caller's token was not shown to be bad.
 */
export function createIntrospectionValidator(
  options: OAuthIssuerOptions & { introspection: OAuthIntrospectionOptions },
): (token: string) => Promise<AuthResult> {
  const { endpoint, clientId, clientSecret } = options.introspection;
  if (!endpoint) {
    throw new Error('introspection.endpoint is required here; createOAuthValidator can discover it from the issuer');
  }
  assertHttpsOrLoopback(endpoint, 'introspection endpoint');
  const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
  const tolerance = options.clockToleranceSeconds ?? 30;
  const ttl = options.introspection.cacheTtlMs ?? 60_000;
  const requireAud = !options.introspection.allowMissingAudience;
  const doFetch = options.fetch ?? fetch;
  // RFC 6749 §2.3.1: apply application/x-www-form-urlencoded to the id and
  // secret before Basic-encoding them (space -> '+', '!*'()' encoded; not quite encodeURIComponent).
  const formEncode = (value: string): string => new URLSearchParams({ v: value }).toString().slice(2);
  const basic = Buffer.from(`${formEncode(clientId)}:${formEncode(clientSecret)}`).toString('base64');

  const cache = new Map<string, { result: AuthResult; expiresAt: number }>();
  const keyOf = (token: string): string => createHash('sha256').update(token).digest('base64url');
  const unavailable = (detail: string): AuthorizationServerUnavailableError =>
    new AuthorizationServerUnavailableError(`Token introspection at ${endpoint} failed: ${detail}`);

  return async (token: string): Promise<AuthResult> => {
    const key = keyOf(token);
    const hit = cache.get(key);
    if (hit !== undefined) {
      if (hit.expiresAt > Date.now()) return hit.result;
      cache.delete(key);
    }

    let res: Response;
    try {
      res = await doFetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          authorization: `Basic ${basic}`,
        },
        body: new URLSearchParams({ token, token_type_hint: 'access_token' }).toString(),
        signal: AbortSignal.timeout(5_000),
      });
    } catch (err) {
      throw unavailable(err instanceof Error ? err.message : String(err));
    }
    if (!res.ok) throw unavailable(`HTTP ${res.status}`);
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw unavailable('response is not JSON');
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body) || typeof (body as { active?: unknown }).active !== 'boolean') {
      throw unavailable('response has no boolean "active"');
    }
    const claims = body as Record<string, unknown>;
    if (claims['active'] !== true) throw invalid('Token is not active');

    // From here on the issuer has vouched for the token: a failure means it
    // is a real token that does not fit this server, never "unknown token".
    let result: AuthResult;
    try {
      // RFC 7662 lets an issuer report a refresh token as active; only access tokens may be bearers here.
      const tokenType = claims['token_type'];
      if (typeof tokenType === 'string' && !['bearer', 'access_token'].includes(tokenType.toLowerCase())) {
        throw invalid('Not an access token (token_type)');
      }
      result = checkStandardClaims(claims, {
        issuer: options.issuer,
        audiences,
        tolerance,
        requireExp: false,
        requireAud,
        subFromClientId: true,
        scopeClaims: options.scopeClaims,
      });
    } catch (err) {
      if (err instanceof MCPAuthError) throw new ActiveTokenRejectedError(err.code, err.message);
      throw err;
    }
    if (ttl > 0) {
      const exp = claims['exp'];
      const untilExp = typeof exp === 'number' ? exp * 1000 : Number.POSITIVE_INFINITY;
      if (cache.size >= CACHE_SWEEP_AT) {
        const now = Date.now();
        for (const [k, v] of cache) if (v.expiresAt <= now) cache.delete(k);
      }
      cache.set(key, { result, expiresAt: Math.min(Date.now() + ttl, untilExp) });
    }
    return result;
  };
}

/** Enough of a JWT to route it: three segments and a JSON header naming an algorithm. */
function peekJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const header = decodeSegment(parts[0] as string);
    if (typeof header['alg'] !== 'string') return undefined;
    return { header, payload: decodeSegment(parts[1] as string) };
  } catch {
    return undefined;
  }
}

type Validator = (token: string) => Promise<AuthResult>;

/**
 * Fetches the issuer's metadata: OpenID Connect discovery first (what Auth0,
 * Okta, Entra and Keycloak all serve), then the two RFC 8414 forms. The
 * document must name the same issuer (RFC 8414 §3.3), or a server could
 * answer for an issuer it is not.
 */
async function discoverMetadata(issuer: string, doFetch: typeof fetch): Promise<Record<string, unknown>> {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/+$/, '');
  const base = `${url.origin}${path}`;
  const candidates = [
    `${base}/.well-known/openid-configuration`,
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    ...(path ? [`${base}/.well-known/oauth-authorization-server`] : []),
  ];
  let last = 'no metadata document found';
  for (const candidate of candidates) {
    try {
      const res = await doFetch(candidate, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(5_000) });
      if (!res.ok) {
        last = `${candidate}: HTTP ${res.status}`;
        continue;
      }
      const body: unknown = await res.json();
      if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        last = `${candidate}: not a JSON object`;
        continue;
      }
      const metadata = body as Record<string, unknown>;
      if (metadata['issuer'] !== issuer) {
        throw new AuthorizationServerUnavailableError(
          `Metadata at ${candidate} is for issuer ${String(metadata['issuer'])}, not ${issuer}`,
        );
      }
      return metadata;
    } catch (err) {
      if (err instanceof AuthorizationServerUnavailableError) throw err;
      last = `${candidate}: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
  throw new AuthorizationServerUnavailableError(`Authorization server metadata for ${issuer} could not be retrieved (${last})`);
}

/**
 * One issuer's validators. What the entry asks for decides the mode: `jwksUri`
 * (or nothing at all) means JWTs are verified against its keys; `introspection`
 * means tokens are introspected. A URL the entry leaves out is read from the
 * issuer's metadata on first use and kept; a failed lookup is retried on the
 * next token.
 */
function issuerValidators(entry: OAuthIssuerOptions): { jwt?: Validator; introspect?: Validator } {
  const introspection = entry.introspection;
  const wantsJwt = entry.jwksUri !== undefined || introspection === undefined;
  if (entry.introspectJwts && !(entry.jwksUri && introspection)) {
    throw new Error(`oauth: issuer ${entry.issuer} sets introspectJwts, which needs both jwksUri and introspection`);
  }
  const needsDiscovery = (wantsJwt && !entry.jwksUri) || (introspection !== undefined && !introspection.endpoint);
  if (needsDiscovery) assertHttpsOrLoopback(entry.issuer, 'issuer (for metadata discovery)');

  const build = (metadata: Record<string, unknown>): { jwt?: Validator; introspect?: Validator } => {
    const fromMetadata = (name: string): string => {
      const value = metadata[name];
      if (typeof value !== 'string' || value.length === 0) {
        throw new AuthorizationServerUnavailableError(`Metadata for ${entry.issuer} has no ${name}`);
      }
      return value;
    };
    try {
      const byKeys = wantsJwt ? createJwtValidator({ ...entry, jwksUri: entry.jwksUri ?? fromMetadata('jwks_uri') }) : undefined;
      const introspect = introspection
        ? createIntrospectionValidator({
            ...entry,
            introspection: { ...introspection, endpoint: introspection.endpoint ?? fromMetadata('introspection_endpoint') },
          })
        : undefined;
      const jwt =
        byKeys && introspect && entry.introspectJwts
          ? async (token: string): Promise<AuthResult> => {
              const result = await byKeys(token); // cheap and offline first
              await introspect(token); // then: is it still active at the issuer?
              return result;
            }
          : byKeys;
      return { ...(jwt ? { jwt } : {}), ...(introspect ? { introspect } : {}) };
    } catch (err) {
      // Without discovery a bad URL is the operator's typo: fail at construction.
      if (!needsDiscovery || err instanceof AuthorizationServerUnavailableError) throw err;
      throw new AuthorizationServerUnavailableError(
        `Metadata for ${entry.issuer} is unusable: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  let built = needsDiscovery ? undefined : build({});
  let inflight: Promise<{ jwt?: Validator; introspect?: Validator }> | undefined;
  const ready = (): Promise<{ jwt?: Validator; introspect?: Validator }> => {
    if (built) return Promise.resolve(built);
    inflight ??= discoverMetadata(entry.issuer, entry.fetch ?? fetch)
      .then((metadata) => (built = build(metadata)))
      .finally(() => {
        inflight = undefined;
      });
    return inflight;
  };

  return {
    ...(wantsJwt ? { jwt: async (token: string) => ((await ready()).jwt as Validator)(token) } : {}),
    ...(introspection ? { introspect: async (token: string) => ((await ready()).introspect as Validator)(token) } : {}),
  };
}

/**
 * Validates bearer tokens from one or more trusted authorization servers.
 * A JWT is routed by its (as yet unverified) `iss` claim to that issuer's
 * validator, which re-checks `iss` on the verified claims; an issuer not in
 * the list is refused without any network call. A token that is not a JWT
 * is opaque and carries no issuer, so it goes to the one issuer configured
 * for introspection. Only one issuer may be: introspection needs this
 * server's own client credentials, which fits the authorization server the
 * operator runs, and with two a token would have to be shown to both.
 * Tokens from other organisations' tenants are verified as JWTs.
 *
 * An entry may leave its URLs out: `{ issuer, audience }` verifies JWTs with
 * the `jwks_uri` from the issuer's metadata, and `introspection` without an
 * `endpoint` uses the metadata's `introspection_endpoint`.
 */
export function createOAuthValidator(options: OAuthOptions): (token: string) => Promise<AuthResult> {
  const issuers = Array.isArray(options) ? options : [options];
  if (issuers.length === 0) throw new Error('oauth: at least one issuer is required');

  const byIssuer = new Map<string, { jwt?: Validator; introspect?: Validator }>();
  for (const entry of issuers) {
    if (byIssuer.has(entry.issuer)) throw new Error(`oauth: issuer ${entry.issuer} is listed twice`);
    byIssuer.set(entry.issuer, issuerValidators(entry));
  }
  const introspecting = issuers.filter((entry) => entry.introspection);
  if (introspecting.length > 1) {
    throw new Error(
      `oauth: only one issuer may use introspection (found ${introspecting.map((e) => e.issuer).join(', ')}); ` +
        'an opaque token names no issuer, so it would have to be sent to each of them',
    );
  }
  const introspectOpaque = introspecting[0] ? byIssuer.get(introspecting[0].issuer)?.introspect : undefined;

  return async (token: string): Promise<AuthResult> => {
    const jwt = peekJwt(token);
    if (jwt) {
      const iss = jwt.payload['iss'];
      if (typeof iss !== 'string') throw invalid('Token has no issuer');
      const validators = byIssuer.get(iss);
      if (!validators) throw invalid('Unknown token issuer');
      if (validators.jwt) return validators.jwt(token);
      return (validators.introspect as Validator)(token);
    }

    if (!introspectOpaque) throw invalid('Not a JWT');
    return introspectOpaque(token);
  };
}
