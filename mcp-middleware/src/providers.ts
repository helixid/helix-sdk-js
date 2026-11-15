// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { OAuthIntrospectionOptions, OAuthIssuerOptions } from './oauth.js';

/**
 * Presets for common identity providers: each turns the one or two values an
 * operator knows (a tenant ID, a domain) into an `oauth` issuer entry with the
 * provider's exact issuer string and endpoints. They add no trust of their
 * own: the tenant named is still the operator's, because a provider-wide
 * default would accept tokens minted in anyone's tenant.
 *
 * Any other OpenID Connect / OAuth 2.0 server needs no preset:
 * `{ issuer, audience }` is enough, the rest is read from its metadata.
 */

/** Introspection credentials; the preset supplies the endpoint. */
export type ProviderIntrospection = Omit<OAuthIntrospectionOptions, 'endpoint'>;

const hostOf = (value: string): string =>
  value
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/, '');

function required(value: string | undefined, what: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) throw new Error(`${what} is required`);
  return value.trim();
}

/**
 * Microsoft Entra ID (v2.0 access tokens). `audience` is the API's
 * application (client) ID, which is what Entra puts in `aud` for v2.0 tokens;
 * set `requestedAccessTokenVersion: 2` in the API's app manifest. Delegated
 * scopes arrive in `scp`, app permissions in `roles`; both are read. Entra
 * issues JWTs only, so there is no introspection.
 */
export function entra(options: { tenantId: string; audience: string | string[] }): OAuthIssuerOptions {
  const tenantId = required(options.tenantId, 'entra: tenantId');
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(tenantId)) {
    // "common" / "organizations" would mean every tenant; trust must name one.
    throw new Error('entra: tenantId must be the directory (tenant) ID, a GUID');
  }
  const base = `https://login.microsoftonline.com/${tenantId.toLowerCase()}`;
  return {
    issuer: `${base}/v2.0`,
    audience: options.audience,
    jwksUri: `${base}/discovery/v2.0/keys`,
    scopeClaims: ['scp', 'roles'],
  };
}

/**
 * Auth0. `domain` is the tenant domain (`tenant.us.auth0.com`, or a custom
 * domain). `audience` is the API identifier registered in Auth0; clients must
 * request it, otherwise Auth0 issues an opaque token meant only for its own
 * /userinfo. Auth0 documents no introspection endpoint, so JWTs only.
 */
export function auth0(options: { domain: string; audience: string | string[] }): OAuthIssuerOptions {
  const host = hostOf(required(options.domain, 'auth0: domain'));
  return {
    issuer: `https://${host}/`, // Auth0 issuers end with a slash
    audience: options.audience,
    jwksUri: `https://${host}/.well-known/jwks.json`,
  };
}

/**
 * Okta, custom authorization server (`default` unless named). The org
 * authorization server is not supported: Okta says its tokens are not meant
 * to be validated by your own resource servers. Pass `introspection`
 * credentials (a confidential client in the same org) to also accept tokens
 * by introspection, which is how revocation is seen before expiry.
 */
export function okta(options: {
  domain: string;
  authorizationServerId?: string;
  audience: string | string[];
  introspection?: ProviderIntrospection;
  /** Also introspect JWTs, to see revocation before expiry. Needs `introspection`. */
  introspectJwts?: boolean;
}): OAuthIssuerOptions {
  const host = hostOf(required(options.domain, 'okta: domain'));
  const serverId = encodeURIComponent(options.authorizationServerId?.trim() || 'default');
  const issuer = `https://${host}/oauth2/${serverId}`;
  return {
    issuer,
    audience: options.audience,
    jwksUri: `${issuer}/v1/keys`,
    ...(options.introspection ? { introspection: { ...options.introspection, endpoint: `${issuer}/v1/introspect` } } : {}),    ...(options.introspectJwts ? { introspectJwts: true } : {}),
  };
}

/**
 * Keycloak. `baseUrl` is the server root (`https://id.example.com`, plus
 * `/auth` on legacy installs). The realm's client needs an audience mapper so
 * access tokens name this server in `aud`. `introspection` credentials are a
 * confidential client in the realm.
 */
export function keycloak(options: {
  baseUrl: string;
  realm: string;
  audience: string | string[];
  introspection?: ProviderIntrospection;
  /** Also introspect JWTs, to see revocation before expiry. Needs `introspection`. */
  introspectJwts?: boolean;
}): OAuthIssuerOptions {
  const base = required(options.baseUrl, 'keycloak: baseUrl').replace(/\/+$/, '');
  const issuer = `${base}/realms/${encodeURIComponent(required(options.realm, 'keycloak: realm'))}`;
  return {
    issuer,
    audience: options.audience,
    jwksUri: `${issuer}/protocol/openid-connect/certs`,
    ...(options.introspection
      ? { introspection: { ...options.introspection, endpoint: `${issuer}/protocol/openid-connect/token/introspect` } }
      : {}),    ...(options.introspectJwts ? { introspectJwts: true } : {}),
  };
}
