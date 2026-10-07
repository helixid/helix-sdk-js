// Copyright 2026 DgVerse LLP
//
// Enterprise mode (an account API key): every call carries the key, not only
// signVP()/delegateAuthority(). Without it the server cannot attribute a
// verification to the verifying account, and refuses the account-scoped reads.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HelixClient } from '../../../src/client/HelixClient.js';

const BASE_URL = 'http://helix.test';

function lastCall(): { url: string; headers: Record<string, string>; body?: unknown } {
  const [url, init] = vi.mocked(fetch).mock.calls.at(-1)!;
  return {
    url: String(url),
    headers: init?.headers as Record<string, string>,
    ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
  };
}

describe('HelixClient in enterprise mode', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, status: 200, json: async () => [] }) as never),
    );
  });

  it('authenticates verification and the audit log with the account key', async () => {
    const client = new HelixClient(BASE_URL, { apiKey: 'hak_test' });

    await client.verifyVP({ id: 'vp-1' } as never);
    expect(lastCall()).toMatchObject({
      url: `${BASE_URL}/v1/vp/verify`,
      headers: { authorization: 'Bearer hak_test' },
    });

    await client.getAuditLog({ eventType: 'VP_REJECTED', before: '2026-06-01T00:00:00.000Z', agentDid: 'did:key:a', limit: 10 });
    expect(lastCall()).toMatchObject({
      url: `${BASE_URL}/v1/audit-log?eventType=VP_REJECTED&before=2026-06-01T00%3A00%3A00.000Z&agentDid=did%3Akey%3Aa&limit=10`,
      headers: { authorization: 'Bearer hak_test' },
    });
  });

  it('posts the consent-grant audit entry, which used to need an admin key', async () => {
    const client = new HelixClient(BASE_URL, { apiKey: 'hak_test' });

    await client.recordConsentGrantedAudit({ vcId: 'vc-1', agentDid: 'did:key:a' } as never);

    expect(lastCall()).toMatchObject({
      url: `${BASE_URL}/v1/audit-log/consent-granted`,
      headers: { authorization: 'Bearer hak_test' },
      body: { vcId: 'vc-1', agentDid: 'did:key:a' },
    });
  });

  it('still posts no audit entry when there is no credential at all', async () => {
    await new HelixClient(BASE_URL).recordConsentGrantedAudit({ vcId: 'vc-1', agentDid: 'did:key:a' } as never);

    expect(fetch).not.toHaveBeenCalled();
  });
});
