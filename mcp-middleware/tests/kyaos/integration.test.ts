// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the guard's authorize(), the denied proof in the HTTP refusal, and the index exports.
import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import * as middleware from '../../src/index.js';
import { helixidMCPMiddleware } from '../../src/middleware.js';
import { toHttpErrorResponse } from '../../src/metadata.js';
import { KyaOsError, createKyaOs, type KyaOsDenied } from '../../src/kyaos/index.js';
import { NOW, SERVER, signer } from './helpers.js';

describe('helixidMCPMiddleware().authorize', () => {
  it('resolves the identified caller, so the KYA-OS proof can name the client', async () => {
    const guard = helixidMCPMiddleware({
      validateOAuthToken: async (token) => (token === 'ok' ? { sub: 'agent-1', scopes: ['orders:read'] } : Promise.reject(new Error('no'))),
      toolScopes: { lookup_order: ['orders:read'] },
    });
    const toolCall = { name: 'lookup_order', headers: { authorization: 'Bearer ok' } };
    expect(await guard.authorize(toolCall)).toEqual({ authMethod: 'oauth', scopes: ['orders:read'], oauthSubject: 'agent-1' });
    await expect(guard(toolCall)).resolves.toBe(toolCall);
    await expect(guard.authorize({ name: 'refund_order', headers: { authorization: 'Bearer ok' } })).rejects.toMatchObject({ code: 'TOOL_NOT_PERMITTED' });
    expect(middleware.helixidMCPMiddleware).toBe(helixidMCPMiddleware);
  });
});

describe('toHttpErrorResponse with a denied proof', () => {
  it('carries the proof in the body as _meta["org.kya-os/response-proof"], and maps a KYA-OS session refusal to 400', async () => {
    const kya = createKyaOs({ signer, now: () => NOW });
    const denied = (await kya.start({ name: 'lookup_order', arguments: { _kyaos_session: 'sess_x' } })) as KyaOsDenied;
    expect(denied.error).toBeInstanceOf(KyaOsError);
    const response = toHttpErrorResponse(denied.error, { resourceMetadataUrl: 'https://orders.example/.well-known/oauth-protected-resource/mcp', proof: denied.proof });
    expect(response).toMatchObject({ status: 400, body: { error: 'invalid_request', _meta: { 'org.kya-os/response-proof': denied.proof } } });
    expect(response!.body.error_description).toContain('kyaos_<uuid-v4>');
    const verified = await kyaos.verifyDetachedProof(response!.body._meta!['org.kya-os/response-proof'] as kyaos.DetachedProof, { resolveDid: async () => null }, { now: NOW, expectedDid: SERVER }).catch((e: unknown) => e);
    expect((verified as { reason: string }).reason).toBe('jws_did_unresolved');
    // Without a proof the body is as before.
    expect(toHttpErrorResponse(denied.error, { resourceMetadataUrl: 'x' })!.body).toEqual({ error: 'invalid_request', error_description: expect.any(String) });
    expect(toHttpErrorResponse(Object.assign(new Error('scope'), { code: 'INSUFFICIENT_SCOPE' }), { resourceMetadataUrl: 'x', proof: denied.proof })!.body._meta).toEqual({
      'org.kya-os/response-proof': denied.proof,
    });
  });
});

describe('package index', () => {
  it('exports the KYA-OS layer', () => {
    expect(middleware.createKyaOs).toBe(createKyaOs);
    expect(middleware.KyaOsError).toBe(KyaOsError);
    expect(typeof middleware.describeKyaOs).toBe('function');
    expect(typeof middleware.MemoryNonceStore).toBe('function');
    expect(typeof middleware.RedisNonceStore).toBe('function');
    expect(typeof middleware.DynamoNonceStore).toBe('function');
    expect(typeof middleware.MemorySessionStore).toBe('function');
    expect(typeof middleware.buildResponseProof).toBe('function');
    expect(typeof middleware.attachResponseProof).toBe('function');
    expect(middleware.NO_SESSION_ID).toBe('none');
    expect(middleware.RESPONSE_PROOF_META_KEY).toBe('org.kya-os/response-proof');
  });
});
