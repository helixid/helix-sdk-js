import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair, kyaos, type HelixClient } from '@helixid/sdk-js';
import { HelixIDToolWrapper, filterToolsByScope, signCurrentRequest } from '../src/index.js';

describe('@helixid/langchain', () => {
  const agentDid = 'did:hedera:testnet:agent';
  const keys = generateKeyPair();
  const signer = new kyaos.EnvSigner({ did: 'did:web:agent.helix.test', envVar: 'K', env: { K: keys.privateKey } });
  const audience = 'did:web:orders.helix.test';
  const call = { name: 'lookup_order', arguments: { orderId: 'ORD-1' } };

  it('signs each request inside a wrapped call with a request proof in _meta, never in the input', async () => {
    const seen: kyaos.verifier.ProofRequest[] = [];
    const originalCall = vi.fn(async () => {
      seen.push(await signCurrentRequest(call));
      seen.push(await signCurrentRequest(call));
      return 'done';
    });
    const wrapped = HelixIDToolWrapper({ name: 'orders', _call: originalCall }, { signer, audience });
    const input: Record<string, unknown> = { query: 'book order' };
    await expect(wrapped._call(input)).resolves.toBe('done');
    expect(originalCall).toHaveBeenCalledWith({ query: 'book order' });
    expect(input).toEqual({ query: 'book order' });

    const [first, second] = seen as [kyaos.verifier.ProofRequest, kyaos.verifier.ProofRequest];
    const meta = (first.params as { _meta: Record<string, unknown> })._meta;
    const proof = kyaos.verifier.parseRequestProof(meta['org.kya-os/request-proof'])!;
    expect(proof).toMatchObject({ prf: 'org.kya-os/proof.v1', did: signer.did, kid: `${signer.did}#key-1`, audience });
    expect(proof.requestHash).toBe(kyaos.requestHashContentDigest(call));
    expect(meta['org.kya-os/delegation-chain']).toBeUndefined();
    const again = kyaos.verifier.parseRequestProof((second.params as { _meta: Record<string, unknown> })._meta['org.kya-os/request-proof'])!;
    expect(again.nonce).not.toBe(proof.nonce);
    expect(JSON.stringify(seen)).not.toContain(keys.privateKey);
  });

  it('attaches the chain, read per call when it is a function, and the cnf thumbprint', async () => {
    const hop = { id: 'urn:uuid:hop', proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'assertionMethod' } };
    const chain = vi.fn(async () => [hop]);
    const cnfJkt = 'A'.repeat(43);
    let request: kyaos.verifier.ProofRequest | undefined;
    const wrapped = HelixIDToolWrapper(
      { name: 'orders', _call: async () => (request = await signCurrentRequest({ method: 'tools/call', params: { name: 'x' } })) },
      { signer, audience, chain, cnfJkt },
    );
    await wrapped._call({});
    await wrapped._call({});
    expect(chain).toHaveBeenCalledTimes(2);
    const meta = (request!.params as { _meta: Record<string, unknown> })._meta;
    expect(meta['org.kya-os/delegation-chain']).toEqual([hop]);
    expect((meta['org.kya-os/request-proof'] as { cnf: unknown }).cnf).toEqual({ jkt: cnfJkt });

    const fixed = HelixIDToolWrapper({ name: 'orders', _call: async () => (request = await signCurrentRequest(call)) }, { signer, audience, chain: [hop] });
    await fixed._call({});
    expect((request!.params as { _meta: Record<string, unknown> })._meta['org.kya-os/delegation-chain']).toEqual([hop]);
  });

  it('refuses to sign outside a wrapped call', async () => {
    await expect(signCurrentRequest(call)).rejects.toThrow('not inside a HelixIDToolWrapper call');
  });

  it('propagates a signing failure and still runs nothing it should not', async () => {
    const broken = new kyaos.EnvSigner({ did: 'did:web:agent.helix.test', envVar: 'MISSING', env: {} });
    const wrapped = HelixIDToolWrapper({ name: 'orders', _call: async () => signCurrentRequest(call) }, { signer: broken, audience });
    await expect(wrapped._call({})).rejects.toThrow('MISSING is not set');
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
