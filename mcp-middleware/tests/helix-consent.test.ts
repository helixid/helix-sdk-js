// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// KYA-OS story L3-H in the middleware: the challenge's authorizationUrl is a consent request at Helix,
// and a retry's credential is verified in full by the local verifier before it grants anything.
import { describe, expect, it, vi } from 'vitest';
import { kyaos, generateKeyPair } from '@helixid/sdk-js';
import { ConsentUserUnknownError, consentRetryAuthorizer, createHelixConsent } from '../src/helix-consent.js';
import { MemoryResumeTokenStore } from '../src/resume-token-store.js';
import { createNeedsAuthorization, type ChallengeInput } from '../src/needs-authorization.js';

const HELIX = 'https://helix.example';
const SERVICE = 'did:web:shop.example:services:aa';
const AGENT = 'did:web:helix.example:agents:bb';
const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'K', env: { K: generateKeyPair().privateKey } });

function fakeHelix(status = 201) {
  const requests: string[] = [];
  const fetch: kyaos.consent.ConsentFetch = vi.fn(async (url: string, init?: { body?: string }) => {
    const body = JSON.parse(init?.body ?? '{}') as { request?: string };
    requests.push(body.request ?? '');
    if (url.endsWith('/withdrawals')) return { ok: true, status: 200, json: async () => ({ consentId: 'c1', withdrawn: ['c1'], userDid: 'did:key:z', revoked: [] }) };
    return { ok: status < 300, status, json: async () => (status < 300 ? { id: 'abc', authorizationUrl: `${HELIX}/consent/abc`, resultUrl: '', expiresAt: 1, status: 'pending' } : { error: { code: 'X' } }) };
  });
  return { fetch, requests };
}

const claims = (jws: string): Record<string, unknown> => JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
const input = (extra: Partial<ChallengeInput> = {}): ChallengeInput => ({ agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'], ...extra });

describe('createHelixConsent', () => {
  it('creates one consent request per challenge, for the caller as this service knows them', async () => {
    const { fetch, requests } = fakeHelix();
    let now = Date.parse('2026-11-24T00:00:00Z');
    const consent = createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 3600, hopLifetimeSeconds: 300, display: { serviceName: 'Shop' }, returnUrl: 'https://shop.example/back', fetch, now: () => now });
    const url = await consent.authorizationUrl({ agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'] }, input({ oauthSubject: 'user-7' }));
    expect(url).toBe(`${HELIX}/consent/abc`);
    expect(claims(requests[0]!)).toMatchObject({
      iss: SERVICE,
      serviceUserId: 'user-7',
      hopLifetimeSeconds: 300,
      display: { serviceName: 'Shop' },
      returnUrl: 'https://shop.example/back',
      grant: { validUntil: '2026-11-24T01:00:00.000Z', credentialSubject: { invoker: AGENT, invocationTarget: SERVICE, parentCapability: SERVICE, allowedAction: ['orders:read'] } },
    });
    now += 1000;
    const plain = createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, serviceUserOf: async () => 'u-9', fetch });
    await plain.authorizationUrl({ agentDid: AGENT, tool: 't', scopes: ['a'] }, input());
    expect(claims(requests[1]!)).toMatchObject({ serviceUserId: 'u-9' });
    expect(claims(requests[1]!)).not.toHaveProperty('hopLifetimeSeconds');
    expect(await plain.withdraw('c1')).toMatchObject({ consentId: 'c1' });
    expect(claims(requests[2]!)).toMatchObject({ iss: SERVICE, consentId: 'c1' });
  });

  it('refuses to ask consent for nobody, a wrong signer or a bad window, and relays Helix refusals', async () => {
    const { fetch } = fakeHelix();
    const consent = createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, fetch });
    await expect(consent.authorizationUrl({ agentDid: AGENT, tool: 't', scopes: ['a'] }, input())).rejects.toBeInstanceOf(ConsentUserUnknownError);
    await expect(createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, fetch, serviceUserOf: () => '' }).authorizationUrl({ agentDid: AGENT, tool: 't', scopes: ['a'] }, input())).rejects.toBeInstanceOf(ConsentUserUnknownError);
    expect(() => createHelixConsent({ helixUrl: HELIX, serviceDid: 'did:web:other', signer, windowSeconds: 60 })).toThrow(/signer/);
    expect(() => createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 0 })).toThrow(RangeError);
    const refused = fakeHelix(403);
    await expect(createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, fetch: refused.fetch }).authorizationUrl({ agentDid: AGENT, tool: 't', scopes: ['a'] }, input({ oauthSubject: 'u' }))).rejects.toMatchObject({ reason: 'consent_request_refused' });
  });

  it('puts the consent page in the signed challenge (authorizationUrl may be asynchronous)', async () => {
    const { fetch } = fakeHelix();
    const consent = createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, fetch });
    const layer = createNeedsAuthorization({ authorizationUrl: consent.authorizationUrl, store: new MemoryResumeTokenStore() });
    const challenge = await layer.challenge(input({ oauthSubject: 'user-1' }));
    expect(challenge.challenge.authorizationUrl).toBe(`${HELIX}/consent/abc`);
    const sync = createNeedsAuthorization({ authorizationUrl: (context, challengeInput) => `${HELIX}/static?agent=${encodeURIComponent(context.agentDid)}&user=${challengeInput.oauthSubject ?? ''}`, store: new MemoryResumeTokenStore() });
    expect((await sync.challenge(input({ oauthSubject: 'u2' }))).challenge.authorizationUrl).toContain('user=u2');
  });
});

describe('consentRetryAuthorizer', () => {
  const token = { agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'], expiresAt: Date.now() + 1000 };
  const result = (overrides: Partial<kyaos.verifier.VerifierResult>): kyaos.verifier.VerifierResult => ({
    ok: true,
    level: 'L2',
    effectiveScopes: ['orders:read'],
    reasons: [],
    messages: [],
    chainSummary: {} as never,
    agentDid: AGENT,
    proofFloor: false,
    capabilities: {} as never,
    fresh: true,
    warnings: [],
    ...overrides,
  });

  it('verifies the hop as a chain without a proof, statuses live, and grants what the verifier derives', async () => {
    const verify = vi.fn(async () => result({}));
    const authorize = consentRetryAuthorizer({ verify });
    expect(await authorize({ credential: { id: 'hop' }, token, agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'] })).toEqual({ scopes: ['orders:read'] });
    expect(verify).toHaveBeenCalledWith({ proof: undefined, chain: [{ id: 'hop' }] }, { requireProof: false, liveStatus: true });
    await authorize({ credential: [{ id: 'root' }, { id: 'leaf' }], token, agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'] });
    expect(verify).toHaveBeenLastCalledWith({ proof: undefined, chain: [{ id: 'root' }, { id: 'leaf' }] }, { requireProof: false, liveStatus: true });
  });

  it('refuses a chain that does not verify or delegates to another agent', async () => {
    await expect(consentRetryAuthorizer({ verify: async () => result({ ok: false, reasons: ['status_revoked'] as never }) })({ credential: {}, token, agentDid: AGENT, tool: 't', scopes: [] })).rejects.toThrow(/status_revoked/);
    await expect(consentRetryAuthorizer({ verify: async () => result({ agentDid: 'did:web:other' }) })({ credential: {}, token, agentDid: AGENT, tool: 't', scopes: [] })).rejects.toThrow(/not did:web/);
  });
});
