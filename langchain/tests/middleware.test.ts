import { describe, expect, it, vi } from 'vitest';
import type { HelixClient } from '@helixid/sdk-js';
import { HelixIDMiddleware, HelixIDToolWrapper, filterToolsByScope } from '../src/index.js';

describe('@helixid/langchain', () => {
  const agentDid = 'did:hedera:testnet:agent';

  const fakeSignedVP = {
    id: 'vp:helix:test-1',
    holder: agentDid,
    verifiableCredential: [],
    proof: { type: 'Ed25519Signature2020' },
  };

  function fakeClient(signVP = vi.fn().mockResolvedValue(fakeSignedVP)) {
    return { signVP } as unknown as HelixClient;
  }

  it('injects _helixVP from handleToolStart by calling client.signVP()', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const middleware = HelixIDMiddleware({
      client: fakeClient(signVP),
      agentDid,
      targetService: 'orders',
      userDid: 'did:hedera:testnet:user',
    });

    const input: Record<string, unknown> = { query: 'book order' };
    await middleware.callbacks[0]!.handleToolStart({ name: 'orders' }, input);

    expect(signVP).toHaveBeenCalledWith(agentDid, 'orders', { userDid: 'did:hedera:testnet:user' });
    expect(input._helixVP).toEqual(expect.any(String));
  });

  it('wraps a tool and passes the VP to the original _call input', async () => {
    const originalCall = vi.fn().mockResolvedValue('done');
    const wrapped = HelixIDToolWrapper(
      { name: 'orders', _call: originalCall },
      { client: fakeClient(), agentDid, targetService: 'orders', userDid: 'did:hedera:testnet:user' },
    );

    const input: Record<string, unknown> = { query: 'book order' };
    await expect(wrapped._call(input)).resolves.toBe('done');
    expect(originalCall).toHaveBeenCalledWith(expect.objectContaining({ _helixVP: expect.any(String) }));
  });

  it('calls client.signVP() once per invocation', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const middleware = HelixIDMiddleware({
      client: fakeClient(signVP),
      agentDid,
      targetService: 'orders',
      userDid: 'did:hedera:testnet:user',
    });

    const input1: Record<string, unknown> = { query: 'first call' };
    const input2: Record<string, unknown> = { query: 'second call' };

    await middleware.callbacks[0]!.handleToolStart({ name: 'orders' }, input1);
    await middleware.callbacks[0]!.handleToolStart({ name: 'orders' }, input2);

    expect(input1._helixVP).toEqual(expect.any(String));
    expect(input2._helixVP).toEqual(expect.any(String));
    expect(signVP).toHaveBeenCalledTimes(2);
  });

  it('propagates a signing failure from the server (e.g. no active credential)', async () => {
    const signVP = vi.fn().mockRejectedValue(
      Object.assign(new Error('No active credential for agent DID'), {
        code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND',
      }),
    );
    const middleware = HelixIDMiddleware({
      client: fakeClient(signVP),
      agentDid,
      targetService: 'orders',
      userDid: 'did:hedera:testnet:user',
    });

    const input: Record<string, unknown> = { query: 'test' };
    await expect(
      middleware.callbacks[0]!.handleToolStart({ name: 'orders' }, input),
    ).rejects.toMatchObject({ code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND' });
  });

  describe('filterToolsByScope', () => {
    function fakeClientWithScopes(scopes: string[] | null) {
      const listVCs = vi.fn().mockResolvedValue(
        scopes === null
          ? []
          : [
              {
                vcId: 'vc:selected',
                subjectDid: agentDid,
                scopes,
                status: 'active',
                issuedAt: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            ],
      );
      return { listVCs } as unknown as HelixClient;
    }

    it('includes tools without requiredScope by default', async () => {
      const client = fakeClientWithScopes(['read:orders', 'write:orders']);
      const tools = [
        { name: 'tool1' },
        { name: 'tool2', metadata: {} },
      ];

      const filtered = await filterToolsByScope(tools, client, agentDid);
      expect(filtered).toHaveLength(2);
    });

    it('excludes tools with requiredScope if scope not in the active VC', async () => {
      const client = fakeClientWithScopes(['read:orders', 'write:orders']);
      const tools = [
        { name: 'tool1', metadata: { requiredScope: 'admin:all' } },
      ];

      const filtered = await filterToolsByScope(tools, client, agentDid);
      expect(filtered).toHaveLength(0);
    });

    it('includes tools with matching scope in VC metadata or name', async () => {
      const client = fakeClientWithScopes(['read:orders', 'write:orders']);
      const tools = [
        { name: 'tool1', metadata: { requiredScope: 'read:orders' } },
        { name: 'write:orders' },
      ];

      const filtered = await filterToolsByScope(tools, client, agentDid);
      expect(filtered).toHaveLength(2);
    });

    it('throws when the agent has no active credential', async () => {
      const client = fakeClientWithScopes(null);
      await expect(filterToolsByScope([{ name: 'tool1' }], client, agentDid)).rejects.toThrow(
        'No active credential for this agent. Run onboarding first.',
      );
    });
  });
});
