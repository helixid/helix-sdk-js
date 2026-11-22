import { describe, expect, it } from 'vitest';
import { HelixClient } from '../../../src/client/HelixClient.js';

describe('HelixClient onboarding', () => {
  it('onboards an agent in a single call, with no local keygen and no wallet write', async () => {
    const client = new HelixClient('http://localhost:3000');
    let onboardPayload: Record<string, unknown> | undefined;
    client.__setTestHttpAdapter({
      post: async (path: string, payload: Record<string, unknown>) => {
        if (path === '/v1/onboard') {
          onboardPayload = payload;
          return { agentDid: 'did:hedera:testnet:agent1', vcId: 'vc-1' };
        }
        throw new Error('unknown path');
      },
    } as any);

    const result = await client.onboardAgent('enroll:test', ['https://myagent.example.com']);

    expect(onboardPayload).toEqual({
      enrollmentToken: 'enroll:test',
      domains: ['https://myagent.example.com'],
    });
    expect(result).toEqual({ agentDid: 'did:hedera:testnet:agent1', vcId: 'vc-1' });
  });

  it('defaults domains to an empty array', async () => {
    const client = new HelixClient('http://localhost:3000');
    let onboardPayload: Record<string, unknown> | undefined;
    client.__setTestHttpAdapter({
      post: async (path: string, payload: Record<string, unknown>) => {
        onboardPayload = payload;
        return { agentDid: 'did:key:zTest', vcId: 'vc-1' };
      },
    } as any);

    await client.onboardAgent('enroll:test');

    expect(onboardPayload).toEqual({ enrollmentToken: 'enroll:test', domains: [] });
  });
});

describe('HelixClient without the Helix VP (KYA-OS story C-C)', () => {
  it('has no signVP or verifyVP: an agent signs each request itself (kyaos.withRequestProof)', () => {
    const client = new HelixClient('http://localhost:3000');
    expect('signVP' in client).toBe(false);
    expect('verifyVP' in client).toBe(false);
  });
});
