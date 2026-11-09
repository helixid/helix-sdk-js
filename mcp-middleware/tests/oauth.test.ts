import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  AuthorizationServerUnavailableError,
  createIntrospectionValidator,
  createJwtValidator,
  createOAuthValidator,
  helixidMCPMiddleware,
  toHttpErrorResponse,
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

  it('tries each introspection issuer in order for an opaque token and reports an outage over a refusal', async () => {
    const down = vi.fn(async () => { throw new Error('down'); }) as unknown as typeof fetch;
    const says = (body: unknown) => vi.fn(async () => json(body)) as unknown as typeof fetch;
    const mk = (f1: typeof fetch, f2: typeof fetch) =>
      createOAuthValidator([
        { issuer: 'https://one.example.com', audience: AUD, introspection: { endpoint: 'https://one.example.com/i', clientId: 'a', clientSecret: 'b' }, fetch: f1 },
        { issuer: 'https://two.example.com', audience: AUD, introspection: { endpoint: 'https://two.example.com/i', clientId: 'a', clientSecret: 'b' }, fetch: f2 },
      ]);
    // First says no, second vouches: accepted.
    await expect(mk(says({ active: false }), says({ active: true, ...active({ iss: 'https://two.example.com' }) }))('t')).resolves.toMatchObject({ sub: 'opaque-user' });
    // Both say no: the caller's token is bad.
    await expect(mk(says({ active: false }), says({ active: false }))('t')).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    // The first recognises the token as its own but for another audience: refused there, never shown to the second.
    const second = says({ active: true, ...active({ iss: 'https://two.example.com' }) });
    await expect(mk(says({ active: true, ...active({ iss: 'https://one.example.com', aud: 'https://elsewhere' }) }), second)('t')).rejects.toMatchObject({
      code: 'OAUTH_TOKEN_INVALID',
      message: 'Token audience does not match this server',
    });
    expect(second).not.toHaveBeenCalled();
    // One is down and the other says no: the token might still be good at the one that is down.
    await expect(mk(down, says({ active: false }))('t')).rejects.toBeInstanceOf(AuthorizationServerUnavailableError);
  });

  it('refuses a duplicate issuer, an issuer with no way to validate, and an empty list at construction', () => {
    const a = { issuer: ISS_A, audience: AUD, jwksUri: `${ISS_A}/jwks` };
    expect(() => createOAuthValidator([a, a])).toThrow(/listed twice/);
    expect(() => createOAuthValidator([{ issuer: ISS_A, audience: AUD }])).toThrow(/jwksUri, introspection, or both/);
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
