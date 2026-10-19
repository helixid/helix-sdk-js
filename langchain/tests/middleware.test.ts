import { describe, expect, it, vi } from 'vitest';
import { encodeHelixVP, type HelixClient, type SignedVP } from '@helixid/sdk-js';
import { HelixIDToolWrapper, currentHelixVPHeaders, filterToolsByScope } from '../src/index.js';

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

  it('signs a VP per call and exposes it as the X-Helix-VP header, not in the input', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    let seenHeaders: Record<string, string> = {};
    const originalCall = vi.fn(async () => {
      seenHeaders = currentHelixVPHeaders();
      return 'done';
    });
    const wrapped = HelixIDToolWrapper(
      { name: 'orders', _call: originalCall },
      { client: fakeClient(signVP), agentDid, targetService: 'orders', userDid: 'did:hedera:testnet:user' },
    );

    const input: Record<string, unknown> = { query: 'book order' };
    await expect(wrapped._call(input)).resolves.toBe('done');

    expect(signVP).toHaveBeenCalledWith(agentDid, 'orders', { userDid: 'did:hedera:testnet:user' });
    expect(originalCall).toHaveBeenCalledWith({ query: 'book order' });
    expect(input).toEqual({ query: 'book order' });
    expect(seenHeaders).toEqual({ 'X-Helix-VP': encodeHelixVP(fakeSignedVP as unknown as SignedVP) });
  });

  it('calls client.signVP() once per invocation', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const wrapped = HelixIDToolWrapper(
      { name: 'orders', _call: vi.fn().mockResolvedValue('done') },
      { client: fakeClient(signVP), agentDid, targetService: 'orders' },
    );

    await wrapped._call({ query: 'first call' });
    await wrapped._call({ query: 'second call' });

    expect(signVP).toHaveBeenCalledTimes(2);
  });

  it('has no VP headers outside a wrapped call', () => {
    expect(currentHelixVPHeaders()).toEqual({});
  });

  it('propagates a signing failure from the server (e.g. no active credential)', async () => {
    const signVP = vi.fn().mockRejectedValue(
      Object.assign(new Error('No active credential for agent DID'), {
        code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND',
      }),
    );
    const originalCall = vi.fn();
    const wrapped = HelixIDToolWrapper(
      { name: 'orders', _call: originalCall },
      { client: fakeClient(signVP), agentDid, targetService: 'orders' },
    );

    await expect(wrapped._call({ query: 'test' })).rejects.toMatchObject({
      code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND',
    });
    expect(originalCall).not.toHaveBeenCalled();
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
