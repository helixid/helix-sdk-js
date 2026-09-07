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

describe('HelixClient signVP', () => {
  it('signs a VP server-side and returns it', async () => {
    const client = new HelixClient('http://localhost:3000');
    let requestedPath: string | undefined;
    let signPayload: Record<string, unknown> | undefined;
    const fakeSignedVP = { id: 'vp:test:1', holder: 'did:key:zAgent', proof: {} };
    client.__setTestHttpAdapter({
      post: async (path: string, payload: Record<string, unknown>) => {
        requestedPath = path;
        signPayload = payload;
        return { signedVP: fakeSignedVP };
      },
    } as any);

    const result = await client.signVP('did:key:zAgent', 'https://svc.example.com', {
      userDid: 'did:key:zUser',
    });

    expect(requestedPath).toBe('/v1/agents/did%3Akey%3AzAgent/vp');
    expect(signPayload).toEqual({
      targetService: 'https://svc.example.com',
      userDid: 'did:key:zUser',
    });
    expect(result).toEqual(fakeSignedVP);
  });

  it('omits optional fields entirely when not provided', async () => {
    const client = new HelixClient('http://localhost:3000');
    let signPayload: Record<string, unknown> | undefined;
    client.__setTestHttpAdapter({
      post: async (_path: string, payload: Record<string, unknown>) => {
        signPayload = payload;
        return { signedVP: {} };
      },
    } as any);

    await client.signVP('did:key:zAgent', 'https://svc.example.com');

    expect(signPayload).toEqual({ targetService: 'https://svc.example.com' });
  });
});
