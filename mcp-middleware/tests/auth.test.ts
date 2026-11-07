import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeHelixVP, verifyVP as verifyVPExport, type HelixClient, type SignedVP } from '@helixid/sdk-js';
import {
  buildProtectedResourceMetadata,
  createHelixAuditSink,
  createJwtValidator,
  helixidMCPMiddleware,
  protectedResourceMetadataUrl,
  toHttpErrorResponse,
  type ToolAuditEvent,
} from '../src/index.js';

vi.mock('@helixid/sdk-js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@helixid/sdk-js')>();
  return { ...actual, verifyVP: vi.fn(actual.verifyVP) };
});

const verifyVP = vi.mocked(verifyVPExport);
beforeEach(() => {
  verifyVP.mockReset();
});
const client = {} as unknown as HelixClient;
const vpA = encodeHelixVP({ id: 'vp:a' } as unknown as SignedVP);
const vpB = encodeHelixVP({ id: 'vp:b' } as unknown as SignedVP);

const validResult = (scopes: string[]) => ({
  valid: true as const,
  agentDid: 'did:agent',
  privilegeScopes: scopes,
  effectiveScopes: scopes,
  vpId: 'vp:a',
  delegationChain: [],
});

describe('credential extraction', () => {
  it('accepts Authorization: HelixVP (any scheme case)', async () => {
    verifyVP.mockResolvedValueOnce(validResult([]));
    const mw = helixidMCPMiddleware({ client });
    const call = { name: 't', headers: { authorization: `helixvp ${vpA}` } };
    await expect(mw(call)).resolves.toBe(call);
    expect(verifyVP).toHaveBeenLastCalledWith({ id: 'vp:a' }, client, expect.anything());
  });

  it('accepts a Headers instance', async () => {
    verifyVP.mockResolvedValueOnce(validResult([]));
    const mw = helixidMCPMiddleware({ client });
    await expect(mw({ name: 't', headers: new Headers({ Authorization: `HelixVP ${vpA}` }) })).resolves.toBeDefined();
  });

  it('accepts the same VP in several places', async () => {
    verifyVP.mockResolvedValueOnce(validResult([]));
    const mw = helixidMCPMiddleware({ client });
    await expect(
      mw({
        name: 't',
        headers: { authorization: `HelixVP ${vpA}`, 'X-Helix-VP': vpA },
        _meta: { 'x-helix-vp': vpA },
      }),
    ).resolves.toBeDefined();
  });

  it('rejects different VPs across locations', async () => {
    const mw = helixidMCPMiddleware({ client });
    await expect(
      mw({ name: 't', headers: { authorization: `HelixVP ${vpA}`, 'x-helix-vp': vpB } }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_CONFLICT' });
    await expect(
      mw({ name: 't', headers: { 'x-helix-vp': vpA }, _meta: { 'x-helix-vp': vpB } }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_CONFLICT' });
  });

  it('rejects a VP together with a bearer token, and duplicate Authorization headers', async () => {
    const mw = helixidMCPMiddleware({ client, validateOAuthToken: async () => ({ sub: 'u' }) });
    await expect(
      mw({ name: 't', headers: { authorization: 'Bearer tok', 'x-helix-vp': vpA } }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_CONFLICT' });
    await expect(
      mw({ name: 't', headers: { authorization: [`HelixVP ${vpA}`, 'Bearer tok'] } }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_CONFLICT' });
  });

  it('rejects a bearer token when OAuth is not configured', async () => {
    const mw = helixidMCPMiddleware({ client });
    await expect(mw({ name: 't', headers: { authorization: 'Bearer tok' } })).rejects.toMatchObject({
      code: 'OAUTH_TOKEN_INVALID',
    });
  });
});

describe('per-tool scopes', () => {
  const toolScopes = { execute_query: ['read'], update_record: ['write'] };

  it('allows a listed tool with its scope', async () => {
    verifyVP.mockResolvedValueOnce(validResult(['read']));
    const mw = helixidMCPMiddleware({ client, toolScopes });
    await expect(mw({ name: 'execute_query', _meta: { 'x-helix-vp': vpA } })).resolves.toBeDefined();
  });

  it('denies an unlisted tool, including Object.prototype names and a missing name', async () => {
    const mw = helixidMCPMiddleware({ client, toolScopes });
    for (const name of ['delete_record', 'constructor', 'toString', undefined]) {
      verifyVP.mockResolvedValueOnce(validResult(['read', 'write', 'admin']));
      await expect(mw({ ...(name ? { name } : {}), _meta: { 'x-helix-vp': vpA } })).rejects.toMatchObject({
        code: 'TOOL_NOT_PERMITTED',
      });
    }
  });

  it('denies a listed tool when the scope is missing', async () => {
    verifyVP.mockResolvedValueOnce(validResult(['read']));
    const mw = helixidMCPMiddleware({ client, toolScopes });
    await expect(mw({ name: 'update_record', _meta: { 'x-helix-vp': vpA } })).rejects.toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('toolScopes takes precedence over the global requiredScopes', async () => {
    verifyVP.mockResolvedValueOnce(validResult(['read']));
    const mw = helixidMCPMiddleware({ client, toolScopes, requiredScopes: ['admin'] });
    await expect(mw({ name: 'execute_query', _meta: { 'x-helix-vp': vpA } })).resolves.toBeDefined();
  });
});

describe('OAuth callback validator', () => {
  it('uses scopes and subject from the callback result', async () => {
    const mw = helixidMCPMiddleware({
      toolScopes: { t: ['read'] },
      validateOAuthToken: async (token) => {
        if (token !== 'good') throw new Error('nope');
        return { sub: 'user-1', scopes: ['read'] };
      },
    });
    await expect(mw({ name: 't', headers: { authorization: 'Bearer good' } })).resolves.toBeDefined();
    await expect(mw({ name: 't', headers: { authorization: 'Bearer bad' } })).rejects.toMatchObject({
      code: 'OAUTH_TOKEN_INVALID',
    });
    expect(verifyVP).not.toHaveBeenCalled();
  });

  it('refuses both oauth and validateOAuthToken', () => {
    expect(() =>
      helixidMCPMiddleware({
        validateOAuthToken: async () => ({ sub: 'u' }),
        oauth: { issuer: 'i', audience: 'a', jwksUri: 'https://as.example.com/jwks' },
      }),
    ).toThrow();
  });
});

describe('JWT validator', () => {
  const ISS = 'https://as.example.com';
  const AUD = 'https://mcp.example.com/mcp';
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

  function makeKey(kid: string) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' } };
  }
  function token(key: { kid: string; privateKey: KeyObject }, claims: Record<string, unknown>, alg = 'ES256') {
    const head = b64({ alg, kid: key.kid, typ: 'at+jwt' });
    const body = b64(claims);
    const sig = cryptoSign('sha256', Buffer.from(`${head}.${body}`), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
    return `${head}.${body}.${sig.toString('base64url')}`;
  }
  const now = () => Math.floor(Date.now() / 1000);
  const good = (extra: Record<string, unknown> = {}) => ({
    iss: ISS, aud: AUD, sub: 'user-1', exp: now() + 300, scope: 'read write', client_id: 'c1', ...extra,
  });
  const jwksFetch = (keys: () => unknown[]) =>
    vi.fn(async () => new Response(JSON.stringify({ keys: keys() }), { status: 200 })) as unknown as typeof fetch;

  it('accepts a valid token and extracts sub/scopes/client', async () => {
    const k = makeKey('k1');
    const v = createJwtValidator({ issuer: ISS, audience: AUD, jwksUri: `${ISS}/jwks`, fetch: jwksFetch(() => [k.jwk]) });
    await expect(v(token(k, good()))).resolves.toMatchObject({ sub: 'user-1', scopes: ['read', 'write'], clientId: 'c1' });
  });

  it('rejects bad issuer, audience, expiry, not-before and signature', async () => {
    const k = makeKey('k1');
    const other = makeKey('k1');
    const v = createJwtValidator({ issuer: ISS, audience: AUD, jwksUri: `${ISS}/jwks`, fetch: jwksFetch(() => [k.jwk]) });
    for (const t of [
      token(k, good({ iss: 'https://evil.example.com' })),
      token(k, good({ aud: 'https://other.example.com' })),
      token(k, good({ exp: now() - 3600 })),
      token(k, good({ nbf: now() + 3600 })),
      token(k, good({ sub: undefined })),
      token(other, good()),
    ]) {
      await expect(v(t)).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    }
  });

  it('rejects alg none and HS256', async () => {
    const k = makeKey('k1');
    const v = createJwtValidator({ issuer: ISS, audience: AUD, jwksUri: `${ISS}/jwks`, fetch: jwksFetch(() => [k.jwk]) });
    await expect(v(`${b64({ alg: 'none' })}.${b64(good())}.`)).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    await expect(v(`${b64({ alg: 'HS256', kid: 'k1' })}.${b64(good())}.c2ln`)).rejects.toMatchObject({
      code: 'OAUTH_TOKEN_INVALID',
    });
  });

  it('caches keys and refetches once on an unknown kid (rotation)', async () => {
    const k1 = makeKey('k1');
    const k2 = makeKey('k2');
    let published = [k1.jwk];
    const f = jwksFetch(() => published);
    const v = createJwtValidator({
      issuer: ISS, audience: AUD, jwksUri: `${ISS}/jwks`, fetch: f, jwksRefetchCooldownMs: 0,
    });
    await v(token(k1, good()));
    await v(token(k1, good()));
    expect(f).toHaveBeenCalledTimes(1);
    published = [k1.jwk, k2.jwk];
    await expect(v(token(k2, good()))).resolves.toMatchObject({ sub: 'user-1' });
    expect(f).toHaveBeenCalledTimes(2);
  });

  it('requires https for the JWKS URI except on loopback', () => {
    expect(() => createJwtValidator({ issuer: ISS, audience: AUD, jwksUri: 'http://as.example.com/jwks' })).toThrow();
    expect(() => createJwtValidator({ issuer: ISS, audience: AUD, jwksUri: 'http://localhost:9000/jwks' })).not.toThrow();
  });
});

describe('RFC 9728 metadata and HTTP errors', () => {
  it('computes the well-known URL with the resource path inserted', () => {
    expect(protectedResourceMetadataUrl('https://mcp.example.com')).toBe(
      'https://mcp.example.com/.well-known/oauth-protected-resource',
    );
    expect(protectedResourceMetadataUrl('https://mcp.example.com/mcp')).toBe(
      'https://mcp.example.com/.well-known/oauth-protected-resource/mcp',
    );
  });

  it('builds metadata', () => {
    expect(
      buildProtectedResourceMetadata({
        resource: 'https://mcp.example.com/mcp',
        authorizationServers: ['https://as.example.com'],
        scopesSupported: ['read'],
      }),
    ).toEqual({
      resource: 'https://mcp.example.com/mcp',
      authorization_servers: ['https://as.example.com'],
      scopes_supported: ['read'],
      bearer_methods_supported: ['header'],
    });
  });

  const opts = { resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp' };

  it('missing credentials: 401 with both challenges and no error attribute', async () => {
    const mw = helixidMCPMiddleware({ client });
    const err = await mw({ name: 't' }).catch((e: unknown) => e);
    const res = toHttpErrorResponse(err, opts);
    expect(res?.status).toBe(401);
    expect(res?.headers['WWW-Authenticate']).toBe(
      `Bearer resource_metadata="${opts.resourceMetadataUrl}", HelixVP resource_metadata="${opts.resourceMetadataUrl}"`,
    );
  });

  it('maps invalid token, conflict and scope failures', () => {
    expect(toHttpErrorResponse({ code: 'OAUTH_TOKEN_INVALID', message: 'x' }, opts)?.status).toBe(401);
    expect(toHttpErrorResponse({ code: 'CREDENTIAL_CONFLICT', message: 'x' }, opts)?.status).toBe(400);
    expect(toHttpErrorResponse({ code: 'INSUFFICIENT_SCOPE', message: 'x' }, opts)?.status).toBe(403);
    expect(toHttpErrorResponse({ code: 'TOOL_NOT_PERMITTED', message: 'x' }, opts)?.status).toBe(403);
    expect(toHttpErrorResponse({ code: 'VP_VERIFICATION_FAILED', message: 'x' }, opts)?.status).toBe(401);
  });

  it('does not turn server-side faults into caller auth errors', () => {
    expect(toHttpErrorResponse({ code: 'ADMIN_AUTH_REQUIRED', message: 'x' }, opts)).toBeUndefined();
    expect(toHttpErrorResponse(new Error('boom'), opts)).toBeUndefined();
    expect(toHttpErrorResponse(null, opts)).toBeUndefined();
  });
});

describe('audit', () => {
  it('emits allowed and denied events with agentDid for VP callers', async () => {
    const events: ToolAuditEvent[] = [];
    const mw = helixidMCPMiddleware({
      client,
      toolScopes: { ok: ['read'], needs_write: ['write'] },
      auditSink: (e) => void events.push(e),
      serviceDid: 'did:web:svc',
    });
    verifyVP.mockResolvedValue(validResult(['read']));
    await mw({ name: 'ok', _meta: { 'x-helix-vp': vpA } });
    await mw({ name: 'needs_write', _meta: { 'x-helix-vp': vpA } }).catch(() => undefined);
    await mw({ name: 'unlisted', _meta: { 'x-helix-vp': vpA } }).catch(() => undefined);


    expect(events.map((e) => [e.event, e.toolName, e.requiredScope])).toEqual([
      ['AUTHZ_GRANTED', 'ok', undefined],
      ['AUTHZ_DENIED', 'needs_write', 'write'],
      ['AUTHZ_DENIED', 'unlisted', undefined],
    ]);
    expect(events[0]).toMatchObject({ agentDid: 'did:agent', authMethod: 'helixvp', serviceDid: 'did:web:svc' });
  });

  it('logs the OAuth subject for OAuth callers', async () => {
    const events: ToolAuditEvent[] = [];
    const mw = helixidMCPMiddleware({
      validateOAuthToken: async () => ({ sub: 'user-9', scopes: [] }),
      requiredScopes: ['read'],
      auditSink: (e) => void events.push(e),
    });
    await mw({ name: 't', headers: { authorization: 'Bearer x' } }).catch(() => undefined);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ event: 'AUTHZ_DENIED', oauthSubject: 'user-9', authMethod: 'oauth', requiredScope: 'read' });
    expect(events[0]?.agentDid).toBeUndefined();
  });

  it('does not log unidentified callers, and survives a failing sink', async () => {
    const sink = vi.fn(async () => {
      throw new Error('audit down');
    });
    const onAuditError = vi.fn();
    const mw = helixidMCPMiddleware({
      validateOAuthToken: async () => ({ sub: 'u', scopes: [] }),
      auditSink: sink,
      onAuditError,
    });
    await mw({ name: 't' }).catch(() => undefined);
    expect(sink).not.toHaveBeenCalled();
    const call = { name: 't', headers: { authorization: 'Bearer x' } };
    await expect(mw(call)).resolves.toBe(call);
    expect(onAuditError).toHaveBeenCalledTimes(1);
  });

  it('createHelixAuditSink posts to /v1/audit-log/events with the account key', async () => {
    const f = vi.fn(async () => new Response('{}', { status: 201 }));
    const sink = createHelixAuditSink({
      baseUrl: 'http://localhost:3680/',
      apiKey: 'hak_test',
      serviceDid: 'did:web:svc',
      fetch: f as unknown as typeof fetch,
    });
    await sink({
      event: 'AUTHZ_DENIED', result: 'denied', timestamp: '2026-01-01T00:00:00.000Z', authMethod: 'oauth',
      oauthSubject: 'user-9', toolName: 't', requiredScope: 'read', effectiveScopes: [],
    });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:3680/v1/audit-log/events');
    expect((init.headers as Record<string, string>)['authorization']).toBe('Bearer hak_test');
    expect(JSON.parse(init.body as string)).toMatchObject({
      event: 'AUTHZ_DENIED', serviceDid: 'did:web:svc', toolName: 't', requiredScope: 'read',
      result: 'denied', oauthSubject: 'user-9', source: 'mcp-middleware',
    });
    // The subject goes only in oauthSubject, never in a field every viewer sees.
    expect(JSON.parse(init.body as string)).not.toHaveProperty('resultSummary');
  });

  it('createHelixAuditSink refuses an event with no agentDid and no serviceDid', async () => {
    const sink = createHelixAuditSink({ baseUrl: 'http://localhost:1', apiKey: 'k', fetch: vi.fn() as unknown as typeof fetch });
    await expect(
      sink({ event: 'AUTHZ_GRANTED', result: 'allowed', timestamp: 't', authMethod: 'oauth', effectiveScopes: [] }),
    ).rejects.toThrow(/serviceDid/);
  });
});
