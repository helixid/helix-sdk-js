// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import {
  constants,
  createPublicKey,
  verify as cryptoVerify,
  type JsonWebKey as NodeJwk,
  type KeyObject,
} from 'node:crypto';
import { MCPAuthError } from './errors.js';

/** The outcome of validating an OAuth access token. */
export interface AuthResult {
  /** The token's subject (`sub`). Logged as the caller identity in audit events. */
  sub: string;
  /** Granted scopes, compared against per-tool scopes. */
  scopes?: string[];
  clientId?: string;
  claims?: Record<string, unknown>;
}

export interface OAuthJwtOptions {
  /** Expected `iss`. */
  issuer: string;
  /** Expected `aud`: this MCP server's resource identifier (RFC 8707 / RFC 9728). */
  audience: string | string[];
  /** The authorization server's `jwks_uri`. https only (http allowed for loopback). */
  jwksUri: string;
  /** Allowed JWS algorithms. Default: RS/PS/ES 256-512 and EdDSA. `none` and HS* are never accepted. */
  algorithms?: string[];
  /** Allowed clock skew for exp/nbf. Default 30. */
  clockToleranceSeconds?: number;
  /** How long fetched keys are trusted. Default 10 minutes. */
  jwksCacheTtlMs?: number;
  /** Minimum gap between refetches triggered by an unknown `kid`. Default 30 seconds. */
  jwksRefetchCooldownMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

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

function assertJwksUri(uri: string): void {
  const url = new URL(uri);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('jwksUri must use https (http is allowed only for localhost)');
  }
}

/**
 * Default OAuth 2.1 access-token validator for JWT access tokens: verifies the
 * signature against the authorization server's JWKS (cached, refetched on key
 * rotation) and checks issuer, audience, expiry and not-before. For opaque
 * tokens or introspection, pass `validateOAuthToken` instead.
 */
export function createJwtValidator(options: OAuthJwtOptions): (token: string) => Promise<AuthResult> {
  assertJwksUri(options.jwksUri);
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
      throw invalid('Signing keys could not be retrieved');
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
    const now = Math.floor(Date.now() / 1000);
    const exp = claims['exp'];
    if (typeof exp !== 'number' || exp + tolerance < now) throw invalid('Token expired');
    const nbf = claims['nbf'];
    if (nbf !== undefined && (typeof nbf !== 'number' || nbf - tolerance > now)) {
      throw invalid('Token not yet valid');
    }
    if (claims['iss'] !== options.issuer) throw invalid('Unexpected token issuer');
    const aud = claims['aud'];
    const tokenAud = Array.isArray(aud) ? aud : [aud];
    if (!tokenAud.some((a) => typeof a === 'string' && audiences.includes(a))) {
      throw invalid('Token audience does not match this server');
    }
    const sub = claims['sub'];
    if (typeof sub !== 'string' || sub.length === 0) throw invalid('Token has no subject');

    const scope = claims['scope'] ?? claims['scp'];
    const scopes =
      typeof scope === 'string'
        ? scope.split(' ').filter(Boolean)
        : Array.isArray(scope)
          ? scope.filter((x): x is string => typeof x === 'string')
          : [];
    const clientId = claims['client_id'] ?? claims['azp'];
    return {
      sub,
      scopes,
      ...(typeof clientId === 'string' ? { clientId } : {}),
      claims,
    };
  };
}
