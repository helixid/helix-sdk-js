import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  AuthorizationServerUnavailableError,
  createIntrospectionValidator,
  createJwtValidator,
  createOAuthValidator,
  helixidMCPMiddleware,
  toHttpErrorResponse,
  auth0,
  entra,
  keycloak,
  okta,
} from '../src/index.js';

const ISS_A = 'https://a.example.com';
const ISS_B = 'https://b.example.com/oauth2/default';
const AUD = 'https://mcp.example.com/mcp';
const INTROSPECT_B = `${ISS_B}/v1/introspect`;
const now = () => Math.floor(Date.now() / 1000);
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

function makeKey(kid: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' } };
}
function token(key: { kid: string; privateKey: KeyObject }, claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const head = b64({ alg: 'ES256', kid: key.kid, typ: 'at+jwt', ...header });
  const body = b64(claims);
  const sig = cryptoSign('sha256', Buffer.from(`${head}.${body}`), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${head}.${body}.${sig.toString('base64url')}`;
}
const claims = (extra: Record<string, unknown> = {}) => ({
  iss: ISS_A, aud: AUD, sub: 'user-1', exp: now() + 300, scope: 'read write', client_id: 'c1', ...extra,
});
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const jwksFetch = (keys: unknown[]) => vi.fn(async () => json({ keys })) as unknown as typeof fetch;
/** An introspection endpoint that knows a few opaque tokens. */
const introspectionFetch = (known: Record<string, Record<string, unknown>>) =>
  vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    const t = new URLSearchParams(String(init?.body)).get('token') ?? '';
    const found = known[t];
    return json(found ? { active: true, ...found } : { active: false });
  }) as unknown as typeof fetch;
const active = (extra: Record<string, unknown> = {}) => ({
  sub: 'opaque-user', scope: 'read', aud: AUD, iss: ISS_B, exp: now() + 300, client_id: 'c2', ...extra,
});

describe('introspection validator (RFC 7662)', () => {
  const base = {
    issuer: ISS_B,
    audience: AUD,
    introspection: { endpoint: INTROSPECT_B, clientId: 'rs', clientSecret: 's3cret' },
  };

  it('posts the token form-encoded with HTTP Basic client auth and reads sub, scopes and client_id', async () => {
    const f = introspectionFetch({ 'opaque-1': active() });
    const v = createIntrospectionValidator({ ...base, fetch: f });
    await expect(v('opaque-1')).resolves.toMatchObject({ sub: 'opaque-user', scopes: ['read'], clientId: 'c2' });
    const [url, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(INTROSPECT_B);
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['authorization']).toBe(`Basic ${Buffer.from('rs:s3cret').toString('base64')}`);
    expect(headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(String(init.body)).toBe('token=opaque-1&token_type_hint=access_token');
  });

  it('rejects inactive, wrong audience, wrong issuer, expired and subject-less answers as invalid tokens', async () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ['inactive', { active: false }],
      ['wrong audience', { active: true, ...active({ aud: 'https://other.example.com' }) }],
      ['wrong issuer', { active: true, ...active({ iss: 'https://evil.example.com' }) }],
      ['expired', { active: true, ...active({ exp: now() - 3600 }) }],
      ['not yet valid', { active: true, ...active({ nbf: now() + 3600 }) }],
      ['no subject and no client_id', { active: true, ...active({ sub: undefined, client_id: undefined }) }],
    ];
    for (const [label, body] of cases) {
      const v = createIntrospectionValidator({ ...base, fetch: vi.fn(async () => json(body)) as unknown as typeof fetch });
      await expect(v('t'), label).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    }
  });

  it('refuses an active token with no audience unless allowMissingAudience is set', async () => {
    const body = { active: true, ...active({ aud: undefined }) };
    const strict = createIntrospectionValidator({ ...base, fetch: vi.fn(async () => json(body)) as unknown as typeof fetch });
    await expect(strict('t')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Token has no audience' });
    const lenient = createIntrospectionValidator({
      ...base,
      introspection: { ...base.introspection, allowMissingAudience: true },
      fetch: vi.fn(async () => json(body)) as unknown as typeof fetch,
    });
    await expect(lenient('t')).resolves.toMatchObject({ sub: 'opaque-user' });
  });

  it('caches a positive answer, never a negative one, and not at all with cacheTtlMs 0', async () => {
    const f = introspectionFetch({ ok: active() });
    const v = createIntrospectionValidator({ ...base, fetch: f });
    await v('ok');
    await v('ok');
    expect(f).toHaveBeenCalledTimes(1);
    await expect(v('nope')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    await expect(v('nope')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    expect(f).toHaveBeenCalledTimes(3);

    const f0 = introspectionFetch({ ok: active() });
    const v0 = createIntrospectionValidator({ ...base, introspection: { ...base.introspection, cacheTtlMs: 0 }, fetch: f0 });
    await v0('ok');
    await v0('ok');
    expect(f0).toHaveBeenCalledTimes(2);
  });

  it('caches no longer than the token lives', async () => {
    const f = introspectionFetch({ short: active({ exp: now() + 1 }) });
    const v = createIntrospectionValidator({ ...base, clockToleranceSeconds: 0, introspection: { ...base.introspection, cacheTtlMs: 60_000 }, fetch: f });
    await v('short');
    vi.useFakeTimers({ now: Date.now() + 2_500, toFake: ['Date'] });
    try {
      // Past exp: the cached answer is dropped and the issuer asked again (which now says expired).
      await expect(v('short')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Token expired' });
    } finally {
      vi.useRealTimers();
    }
    expect(f).toHaveBeenCalledTimes(2);
  });

  it('reports an unreachable or broken authorization server as unavailable, which maps to no HTTP auth error', async () => {
    const broken: Array<[string, typeof fetch]> = [
      ['network error', vi.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch],
      ['HTTP 500', vi.fn(async () => json({ error: 'server_error' }, 500)) as unknown as typeof fetch],
      ['not JSON', vi.fn(async () => new Response('<html>', { status: 200 })) as unknown as typeof fetch],
      ['no active flag', vi.fn(async () => json({ sub: 'x' })) as unknown as typeof fetch],
    ];
    for (const [label, f] of broken) {
      const v = createIntrospectionValidator({ ...base, fetch: f });
      const err = await v('t').catch((e: unknown) => e);
      expect(err, label).toBeInstanceOf(AuthorizationServerUnavailableError);
      expect(toHttpErrorResponse(err, { resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp' }), label).toBeUndefined();
    }
  });

  it('a client-credentials token with client_id but no sub is identified by its client_id', async () => {
    const v = createIntrospectionValidator({ ...base, fetch: vi.fn(async () => json({ active: true, ...active({ sub: undefined, client_id: 'svc-7' }) })) as unknown as typeof fetch });
    await expect(v('t')).resolves.toMatchObject({ sub: 'svc-7', clientId: 'svc-7' });
  });

  it('refuses an active token the issuer labels as something other than an access token', async () => {
    const v = createIntrospectionValidator({ ...base, fetch: vi.fn(async () => json({ active: true, ...active(), token_type: 'Refresh' })) as unknown as typeof fetch });
    await expect(v('t')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Not an access token (token_type)' });
    const ok = createIntrospectionValidator({ ...base, fetch: vi.fn(async () => json({ active: true, ...active(), token_type: 'Bearer' })) as unknown as typeof fetch });
    await expect(ok('t')).resolves.toMatchObject({ sub: 'opaque-user' });
  });

  it('form-encodes client credentials before Basic-encoding them (RFC 6749 §2.3.1)', async () => {
    const f = introspectionFetch({ t: active() });
    const v = createIntrospectionValidator({ ...base, introspection: { ...base.introspection, clientId: 'my client', clientSecret: 'p@ss+w!rd' }, fetch: f });
    await v('t');
    const [, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['authorization']).toBe(`Basic ${Buffer.from('my+client:p%40ss%2Bw%21rd').toString('base64')}`);
  });

  it('sweeps expired cache entries once the cache is large', async () => {
    const shortLived = Object.fromEntries(Array.from({ length: 1_000 }, (_, i) => [`t${i}`, active({ exp: now() + 1 })]));
    const f = introspectionFetch({ ...shortLived, fresh: active({ exp: now() + 300 }) });
    const v = createIntrospectionValidator({ ...base, clockToleranceSeconds: 0, introspection: { ...base.introspection, cacheTtlMs: 60_000 }, fetch: f });
    for (let i = 0; i < 1_000; i += 1) await v(`t${i}`);
    vi.useFakeTimers({ now: Date.now() + 2_500, toFake: ['Date'] });
    try {
      // The 1001st insert finds the cache at the sweep size and drops the 1000 expired entries before storing.
      await expect(v('fresh')).resolves.toMatchObject({ sub: 'opaque-user' });
      // An old token is asked about again (its entry is gone) and is now expired.
      await expect(v('t0')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Token expired' });
      // The fresh one is served from cache.
      await v('fresh');
    } finally {
      vi.useRealTimers();
    }
    expect(f).toHaveBeenCalledTimes(1_002);
  });

  it('requires https for the introspection endpoint except on loopback', () => {
    expect(() => createIntrospectionValidator({ ...base, introspection: { ...base.introspection, endpoint: 'http://b.example.com/introspect' } })).toThrow();
    expect(() => createIntrospectionValidator({ ...base, introspection: { ...base.introspection, endpoint: 'http://localhost:9000/introspect' } })).not.toThrow();
  });
});

describe('multi-issuer validator', () => {
  const kA = makeKey('a1');
  const twoIssuers = () => {
    const fA = jwksFetch([kA.jwk]);
    const fB = introspectionFetch({ 'opaque-ok': active() });
    const v = createOAuthValidator([
      { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: fA },
      { issuer: ISS_B, audience: AUD, introspection: { endpoint: INTROSPECT_B, clientId: 'rs', clientSecret: 's' }, fetch: fB },
    ]);
    return { v, fA, fB };
  };

  it('routes a JWT to its issuer by iss and verifies it there; the other issuer is never contacted', async () => {
    const { v, fA, fB } = twoIssuers();
    await expect(v(token(kA, claims()))).resolves.toMatchObject({ sub: 'user-1', scopes: ['read', 'write'] });
    expect(fA).toHaveBeenCalledTimes(1);
    expect(fB).not.toHaveBeenCalled();
  });

  it('refuses a JWT from an issuer not in the list before any network call', async () => {
    const { v, fA, fB } = twoIssuers();
    await expect(v(token(kA, claims({ iss: 'https://evil.example.com' })))).rejects.toMatchObject({
      code: 'OAUTH_TOKEN_INVALID',
      message: 'Unknown token issuer',
    });
    await expect(v(token(kA, claims({ iss: undefined })))).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    expect(fA).not.toHaveBeenCalled();
    expect(fB).not.toHaveBeenCalled();
  });

  it('a JWT that names a trusted issuer but was signed by someone else is refused by that issuer', async () => {
    const { v } = twoIssuers();
    const forged = makeKey('a1');
    await expect(v(token(forged, claims()))).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
  });

  it('introspects a token that is not a JWT at the introspection issuer; the JWKS issuer is never contacted', async () => {
    const { v, fA, fB } = twoIssuers();
    await expect(v('opaque-ok')).resolves.toMatchObject({ sub: 'opaque-user', scopes: ['read'] });
    await expect(v('opaque-unknown')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Token is not active' });
    expect(fA).not.toHaveBeenCalled();
    expect(fB).toHaveBeenCalledTimes(2);
  });

  it('with no introspection issuer an opaque token is simply not a JWT', async () => {
    const v = createOAuthValidator({ issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: jwksFetch([kA.jwk]) });
    await expect(v('opaque')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Not a JWT' });
  });

  it('a JWT whose issuer is configured for introspection only is introspected, not key-checked', async () => {
    const kB = makeKey('b1');
    const jwt = token(kB, claims({ iss: ISS_B }));
    const fB = introspectionFetch({ [jwt]: active() });
    const v = createOAuthValidator([{ issuer: ISS_B, audience: AUD, introspection: { endpoint: INTROSPECT_B, clientId: 'rs', clientSecret: 's' }, fetch: fB }]);
    await expect(v(jwt)).resolves.toMatchObject({ sub: 'opaque-user' });
    expect(fB).toHaveBeenCalledTimes(1);
  });

  it('allows only one introspection issuer: an opaque token names no issuer and would have to be shown to each', () => {
    const one = { issuer: 'https://one.example.com', audience: AUD, introspection: { endpoint: 'https://one.example.com/i', clientId: 'a', clientSecret: 'b' } };
    const two = { issuer: 'https://two.example.com', audience: AUD, introspection: { endpoint: 'https://two.example.com/i', clientId: 'a', clientSecret: 'b' } };
    expect(() => createOAuthValidator([one, two])).toThrow(/only one issuer may use introspection/);
    // Any number of JWKS issuers beside it is fine.
    expect(() => createOAuthValidator([one, { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks` }, { issuer: 'https://c.example.com', audience: AUD, jwksUri: 'https://c.example.com/jwks' }])).not.toThrow();
  });

  it('introspectJwts: a JWT that passes its keys is also asked about, so revocation is seen before expiry', async () => {
    const jwt = token(kA, claims());
    const knownAtIssuer: Record<string, Record<string, unknown>> = { [jwt]: active({ iss: ISS_A, sub: 'user-1' }) };
    const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/jwks')) return json({ keys: [kA.jwk] });
      const found = knownAtIssuer[new URLSearchParams(String(init?.body)).get('token') ?? ''];
      return json(found ? { active: true, ...found } : { active: false });
    }) as unknown as typeof fetch;
    const entry = { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, introspection: { endpoint: `${ISS_A}/introspect`, clientId: 'rs', clientSecret: 's', cacheTtlMs: 0 }, fetch: f };

    const checked = createOAuthValidator({ ...entry, introspectJwts: true });
    await expect(checked(jwt)).resolves.toMatchObject({ sub: 'user-1', scopes: ['read', 'write'] });
    delete knownAtIssuer[jwt]; // revoked at the issuer; the signature is still good
    await expect(checked(jwt)).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Token is not active' });
    // A forged JWT never reaches the issuer.
    const calls = (f as unknown as ReturnType<typeof vi.fn>).mock.calls.length;
    await expect(checked(token(makeKey('a1'), claims()))).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    expect((f as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(calls);

    // Without the flag the same revoked JWT is still accepted until it expires.
    await expect(createOAuthValidator(entry)(jwt)).resolves.toMatchObject({ sub: 'user-1' });
    // The flag needs both modes.
    expect(() => createOAuthValidator({ issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, introspectJwts: true })).toThrow(/needs both/);
  });

  it('refuses a duplicate issuer, an issuer with no way to validate, and an empty list at construction', () => {
    const a = { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks` };
    expect(() => createOAuthValidator([a, a])).toThrow(/listed twice/);
    expect(() => createOAuthValidator([])).toThrow(/at least one issuer/);
  });

  it('the original single-issuer shape still works through the middleware', async () => {
    const mw = helixidMCPMiddleware({
      oauth: { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: jwksFetch([kA.jwk]) },
      toolScopes: { t: ['read'] },
    });
    await expect(mw({ name: 't', headers: { authorization: `Bearer ${token(kA, claims())}` } })).resolves.toMatchObject({ name: 't' });
  });
});

describe('access-token type and authorization-server outages', () => {
  const k = makeKey('k1');

  it('requireAccessTokenType refuses a JWT whose typ is not at+jwt (an ID token with the right audience)', async () => {
    const v = createJwtValidator({ issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: jwksFetch([k.jwk]), requireAccessTokenType: true });
    await expect(v(token(k, claims(), { typ: 'JWT' }))).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID', message: 'Not an access token (typ)' });
    await expect(v(token(k, claims(), { typ: 'at+jwt' }))).resolves.toMatchObject({ sub: 'user-1' });
    await expect(v(token(k, claims(), { typ: 'application/at+jwt' }))).resolves.toMatchObject({ sub: 'user-1' });
    // Default: typ is not checked, as before.
    const lax = createJwtValidator({ issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: jwksFetch([k.jwk]) });
    await expect(lax(token(k, claims(), { typ: 'JWT' }))).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('a JWKS that cannot be fetched is an unavailable authorization server, passed through the middleware as a server fault', async () => {
    const mw = helixidMCPMiddleware({
      oauth: [{ issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks`, fetch: vi.fn(async () => json({}, 503)) as unknown as typeof fetch }],
      toolScopes: { t: [] },
    });
    const err = await mw({ name: 't', headers: { authorization: `Bearer ${token(k, claims())}` } }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthorizationServerUnavailableError);
    expect(toHttpErrorResponse(err, { resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp' })).toBeUndefined();
  });

  it('a custom validateOAuthToken that throws anything else still means "token rejected" (401)', async () => {
    const mw = helixidMCPMiddleware({ validateOAuthToken: async () => { throw new Error('nope'); }, toolScopes: { t: [] } });
    await expect(mw({ name: 't', headers: { authorization: 'Bearer x' } })).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
  });
});

describe('issuer metadata discovery', () => {
  const k = makeKey('d1');
  /** Serves OIDC discovery, JWKS and introspection for one issuer; counts requests per URL. */
  const server = (issuer: string, metadata: Record<string, unknown> | null, opaque: Record<string, Record<string, unknown>> = {}) => {
    const hits: string[] = [];
    const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      hits.push(u);
      if (u === `${issuer}/.well-known/openid-configuration`) return metadata ? json(metadata) : json({}, 404);
      if (u.includes('/.well-known/')) return json({}, 404);
      if (u === `${issuer}/keys`) return json({ keys: [k.jwk] });
      if (u === `${issuer}/introspect`) {
        const found = opaque[new URLSearchParams(String(init?.body)).get('token') ?? ''];
        return json(found ? { active: true, ...found } : { active: false });
      }
      return json({}, 404);
    }) as unknown as typeof fetch;
    return { f, hits };
  };
  const meta = (issuer: string) => ({ issuer, jwks_uri: `${issuer}/keys`, introspection_endpoint: `${issuer}/introspect` });

  it('an entry with only issuer and audience verifies JWTs with the jwks_uri from its metadata, fetched once', async () => {
    const { f, hits } = server(ISS_B, meta(ISS_B));
    const v = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: f });
    expect(hits).toEqual([]); // nothing until a token arrives
    await expect(v(token(k, claims({ iss: ISS_B })))).resolves.toMatchObject({ sub: 'user-1' });
    await expect(v(token(k, claims({ iss: ISS_B })))).resolves.toMatchObject({ sub: 'user-1' });
    expect(hits).toEqual([`${ISS_B}/.well-known/openid-configuration`, `${ISS_B}/keys`]);
  });

  it('introspection without an endpoint uses the metadata introspection_endpoint', async () => {
    const { f, hits } = server(ISS_B, meta(ISS_B), { opq: active() });
    const v = createOAuthValidator({ issuer: ISS_B, audience: AUD, introspection: { clientId: 'rs', clientSecret: 's' }, fetch: f });
    await expect(v('opq')).resolves.toMatchObject({ sub: 'opaque-user' });
    expect(hits).toEqual([`${ISS_B}/.well-known/openid-configuration`, `${ISS_B}/introspect`]);
  });

  it('falls back to the RFC 8414 location when there is no OpenID configuration', async () => {
    const hits: string[] = [];
    const f = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      hits.push(u);
      if (u === 'https://b.example.com/.well-known/oauth-authorization-server/oauth2/default') return json(meta(ISS_B));
      if (u === `${ISS_B}/keys`) return json({ keys: [k.jwk] });
      return json({}, 404);
    }) as unknown as typeof fetch;
    const v = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: f });
    await expect(v(token(k, claims({ iss: ISS_B })))).resolves.toMatchObject({ sub: 'user-1' });
    expect(hits[0]).toBe(`${ISS_B}/.well-known/openid-configuration`);
  });

  it('refuses metadata that names another issuer, and metadata without the URL it needs', async () => {
    const wrong = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: server(ISS_B, meta('https://evil.example.com')).f });
    await expect(wrong(token(k, claims({ iss: ISS_B })))).rejects.toBeInstanceOf(AuthorizationServerUnavailableError);
    const noKeys = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: server(ISS_B, { issuer: ISS_B }).f });
    await expect(noKeys(token(k, claims({ iss: ISS_B })))).rejects.toThrow(/no jwks_uri/);
    const plainHttp = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: server(ISS_B, { issuer: ISS_B, jwks_uri: 'http://b.example.com/keys' }).f });
    await expect(plainHttp(token(k, claims({ iss: ISS_B })))).rejects.toBeInstanceOf(AuthorizationServerUnavailableError);
  });

  it('an unreachable metadata document is an outage, retried on the next token', async () => {
    let up = false;
    const good = server(ISS_B, meta(ISS_B));
    const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (!up) throw new Error('ECONNREFUSED');
      return good.f(url, init);
    }) as unknown as typeof fetch;
    const v = createOAuthValidator({ issuer: ISS_B, audience: AUD, fetch: f });
    await expect(v(token(k, claims({ iss: ISS_B })))).rejects.toBeInstanceOf(AuthorizationServerUnavailableError);
    up = true;
    await expect(v(token(k, claims({ iss: ISS_B })))).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('discovery needs an https issuer (loopback excepted), checked at construction', () => {
    expect(() => createOAuthValidator({ issuer: 'http://as.example.com', audience: AUD })).toThrow(/https/);
    expect(() => createOAuthValidator({ issuer: 'http://127.0.0.1:9000', audience: AUD })).not.toThrow();
  });
});

describe('provider presets', () => {
  const TENANT = '11111111-2222-3333-4444-555555555555';

  it('entra: v2.0 issuer and keys for one tenant, scopes from scp and roles, never a multi-tenant alias', async () => {
    const e = entra({ tenantId: TENANT.toUpperCase(), audience: 'api-client-id' });
    expect(e).toEqual({
      issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
      audience: 'api-client-id',
      jwksUri: `https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`,
      scopeClaims: ['scp', 'roles'],
    });
    for (const alias of ['common', 'organizations', 'consumers', '']) {
      expect(() => entra({ tenantId: alias, audience: 'x' }), alias).toThrow();
    }
    const k = makeKey('e1');
    const v = createOAuthValidator({ ...e, fetch: jwksFetch([k.jwk]) });
    const user = token(k, claims({ iss: e.issuer, aud: 'api-client-id', scope: undefined, scp: 'orders:read' }));
    await expect(v(user)).resolves.toMatchObject({ scopes: ['orders:read'] });
    const app = token(k, claims({ iss: e.issuer, aud: 'api-client-id', scope: undefined, roles: ['orders:admin'] }));
    await expect(v(app)).resolves.toMatchObject({ scopes: ['orders:admin'] });
  });

  it('auth0: issuer with the trailing slash, whatever form the domain is given in', () => {
    const want = { issuer: 'https://acme.us.auth0.com/', audience: AUD, jwksUri: 'https://acme.us.auth0.com/.well-known/jwks.json' };
    expect(auth0({ domain: 'acme.us.auth0.com', audience: AUD })).toEqual(want);
    expect(auth0({ domain: 'https://acme.us.auth0.com/', audience: AUD })).toEqual(want);
    expect(() => auth0({ domain: ' ', audience: AUD })).toThrow();
  });

  it('okta: the custom authorization server (default unless named), introspection endpoint derived', () => {
    expect(okta({ domain: 'dev-1.okta.com', audience: AUD })).toEqual({
      issuer: 'https://dev-1.okta.com/oauth2/default',
      audience: AUD,
      jwksUri: 'https://dev-1.okta.com/oauth2/default/v1/keys',
    });
    expect(okta({ domain: 'dev-1.okta.com', authorizationServerId: 'aus123', audience: AUD, introspection: { clientId: 'c', clientSecret: 's' } })).toEqual({
      issuer: 'https://dev-1.okta.com/oauth2/aus123',
      audience: AUD,
      jwksUri: 'https://dev-1.okta.com/oauth2/aus123/v1/keys',
      introspection: { clientId: 'c', clientSecret: 's', endpoint: 'https://dev-1.okta.com/oauth2/aus123/v1/introspect' },
    });
  });

  it('keycloak: realm issuer, certs and introspection', () => {
    expect(keycloak({ baseUrl: 'https://id.example.com/', realm: 'shop', audience: AUD, introspection: { clientId: 'c', clientSecret: 's' } })).toEqual({
      issuer: 'https://id.example.com/realms/shop',
      audience: AUD,
      jwksUri: 'https://id.example.com/realms/shop/protocol/openid-connect/certs',
      introspection: { clientId: 'c', clientSecret: 's', endpoint: 'https://id.example.com/realms/shop/protocol/openid-connect/token/introspect' },
    });
  });

  it('presets from different providers share one validator', async () => {
    const k = makeKey('p1');
    const a = auth0({ domain: 'acme.us.auth0.com', audience: AUD });
    const o = okta({ domain: 'dev-1.okta.com', audience: AUD });
    const v = createOAuthValidator([{ ...a, fetch: jwksFetch([k.jwk]) }, { ...o, fetch: jwksFetch([k.jwk]) }]);
    await expect(v(token(k, claims({ iss: a.issuer })))).resolves.toMatchObject({ sub: 'user-1' });
    await expect(v(token(k, claims({ iss: o.issuer })))).resolves.toMatchObject({ sub: 'user-1' });
    await expect(v(token(k, claims({ iss: 'https://acme.us.auth0.com' })))).rejects.toMatchObject({ message: 'Unknown token issuer' });
  });
});
