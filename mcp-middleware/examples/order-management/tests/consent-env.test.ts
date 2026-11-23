// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// Story L3-H in the sample: the challenge's consent page is Helix's when KYAOS_HELIX_CONSENT_URL is set.
import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair, kyaos } from '@helixid/sdk-js';
import { consentFromSettings, describeConsent, readConsentSettings } from '../src/consent-env.js';

const SERVICE = 'did:web:shop.example:services:aa';
const AGENT = 'did:web:helix.example:agents:bb';

describe('readConsentSettings', () => {
  it('is off without the URL, and refuses its other variables alone', () => {
    expect(readConsentSettings({})).toBeUndefined();
    expect(() => readConsentSettings({ KYAOS_CONSENT_USER: 'u' })).toThrow('KYAOS_CONSENT_USER needs KYAOS_HELIX_CONSENT_URL');
  });

  it('reads the URL, the window, the hop lifetime, the demo user and the branding', () => {
    expect(readConsentSettings({ KYAOS_HELIX_CONSENT_URL: 'https://helix.example/' })).toEqual({ helixUrl: 'https://helix.example', windowSeconds: 86_400 });
    expect(
      readConsentSettings({
        KYAOS_HELIX_CONSENT_URL: 'http://127.0.0.1:3000',
        KYAOS_CONSENT_WINDOW_SECONDS: '600',
        KYAOS_CONSENT_HOP_LIFETIME_SECONDS: '60',
        KYAOS_CONSENT_USER: ' user-1 ',
        KYAOS_CONSENT_SERVICE_NAME: 'Orders',
      }),
    ).toEqual({ helixUrl: 'http://127.0.0.1:3000', windowSeconds: 600, hopLifetimeSeconds: 60, demoUser: 'user-1', serviceName: 'Orders' });
    for (const env of [
      { KYAOS_HELIX_CONSENT_URL: 'not a url' },
      { KYAOS_HELIX_CONSENT_URL: 'ftp://helix.example' },
      { KYAOS_HELIX_CONSENT_URL: 'https://helix.example', KYAOS_CONSENT_WINDOW_SECONDS: '0' },
      { KYAOS_HELIX_CONSENT_URL: 'https://helix.example', KYAOS_CONSENT_HOP_LIFETIME_SECONDS: '1.5' },
    ]) {
      expect(() => readConsentSettings(env)).toThrow();
    }
  });

  it('describes itself', () => {
    expect(describeConsent(undefined)).toMatch(/off/);
    expect(describeConsent({ helixUrl: 'https://h', windowSeconds: 60, hopLifetimeSeconds: 10, demoUser: 'u' })).toBe('Helix https://h, window 60 s, hops 10 s, demo user u');
    expect(describeConsent({ helixUrl: 'https://h', windowSeconds: 60 })).toBe('Helix https://h, window 60 s');
  });
});

describe('consentFromSettings', () => {
  const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'K', env: { K: generateKeyPair().privateKey } });

  it('asks Helix for the caller, falling back to the demo user, and verifies retries with the local verifier', async () => {
    const requests: string[] = [];
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      requests.push((JSON.parse(String((init as RequestInit).body)) as { request: string }).request);
      return new Response(JSON.stringify({ id: 'x', authorizationUrl: 'https://helix.example/consent/x', resultUrl: '', expiresAt: 1, status: 'pending' }), { status: 201 });
    });
    const verify = vi.fn(async () => ({ ok: true, agentDid: AGENT, effectiveScopes: ['orders:read'], reasons: [] }) as never);
    let verifier: { verify: typeof verify } | undefined;
    const consent = consentFromSettings({ helixUrl: 'https://helix.example', windowSeconds: 60, hopLifetimeSeconds: 10, demoUser: 'demo', serviceName: 'Orders' }, SERVICE, signer, () => verifier);
    const context = { agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'] };
    expect(await consent.authorizationUrl(context, { ...context })).toBe('https://helix.example/consent/x');
    await consent.authorizationUrl(context, { ...context, oauthSubject: 'alice' });
    const users = requests.map((jws) => (JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString()) as { serviceUserId: string; display: unknown }));
    expect(users.map((claims) => claims.serviceUserId)).toEqual(['demo', 'alice']);
    expect(users[0]!.display).toEqual({ serviceName: 'Orders' });
    const retry = { credential: { id: 'hop' }, token: { agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'], expiresAt: 0 }, agentDid: AGENT, tool: 'list_orders', scopes: ['orders:read'] };
    await expect(consent.authorizer(retry)).rejects.toThrow(/no local verifier/);
    verifier = { verify };
    expect(await consent.authorizer(retry)).toEqual({ scopes: ['orders:read'] });
    const bare = consentFromSettings({ helixUrl: 'https://helix.example', windowSeconds: 60 }, SERVICE, signer, () => verifier);
    await bare.authorizationUrl(context, { ...context, oauthSubject: 'bob' });
    fetchMock.mockRestore();
  });
});
