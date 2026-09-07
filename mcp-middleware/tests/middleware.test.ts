import { describe, expect, it, vi } from 'vitest';
import { verifyVP as verifyVPExport } from '@helixid/sdk-js';
import { attachHelixVP } from '../src/attach.js';
import { helixidMCPMiddleware } from '../src/middleware.js';

vi.mock('@helixid/sdk-js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@helixid/sdk-js')>();
  return {
    ...actual,
    verifyVP: vi.fn(actual.verifyVP),
  };
});

const verifyVP = vi.mocked(verifyVPExport);

describe('helixidMCPMiddleware', () => {
  it('throws VP_MISSING when no _helixVP in input', async () => {
    const middleware = helixidMCPMiddleware({});

    await expect(middleware({ name: 'orders.lookup', input: {} })).rejects.toMatchObject({
      code: 'VP_MISSING',
    });
  });

  it('passes through a valid VP', async () => {
    verifyVP.mockResolvedValueOnce({
      valid: true,
      agentDid: 'did:agent',
      privilegeScopes: ['read:orders'],
      effectiveScopes: ['read:orders'],
      vpId: 'vp:helix:test',
      delegationChain: [],
    });

    const middleware = helixidMCPMiddleware({ requiredScopes: ['read:orders'] });
    const toolCall = {
      name: 'orders.lookup',
      input: { orderId: 'ORD-1', _helixVP: { id: 'vp:helix:test' } },
    };

    await expect(middleware(toolCall)).resolves.toBe(toolCall);
    expect(verifyVP).toHaveBeenCalledWith(
      toolCall.input._helixVP,
      undefined,
      expect.objectContaining({ allowSelfSigned: false }),
    );
  });

  it('throws VP_VERIFICATION_FAILED on invalid VP', async () => {
    verifyVP.mockResolvedValueOnce({
      valid: false,
      agentDid: '',
      privilegeScopes: [],
      effectiveScopes: [],
      vpId: '',
      delegationChain: [],
      error: 'bad signature',
    });

    const middleware = helixidMCPMiddleware({});

    await expect(
      middleware({ input: { _helixVP: { id: 'vp:helix:bad' } } }),
    ).rejects.toMatchObject({
      code: 'VP_VERIFICATION_FAILED',
    });
  });

  it('throws INSUFFICIENT_SCOPE when scope is missing', async () => {
    verifyVP.mockResolvedValueOnce({
      valid: true,
      agentDid: 'did:agent',
      privilegeScopes: ['read:orders'],
      effectiveScopes: ['read:orders'],
      vpId: 'vp:helix:test',
      delegationChain: [],
    });

    const middleware = helixidMCPMiddleware({ requiredScopes: ['write:orders'] });

    await expect(
      middleware({ input: { _helixVP: { id: 'vp:helix:test' } } }),
    ).rejects.toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });
});

describe('attachHelixVP', () => {
  const agentDid = 'did:hedera:testnet:agent';

  const fakeSignedVP = {
    id: 'vp:helix:test-1',
    holder: agentDid,
    verifiableCredential: [],
    proof: { type: 'Ed25519Signature2020' },
  };

  it('injects _helixVP into tool call input by calling client.signVP()', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const client = { signVP } as unknown as Parameters<typeof attachHelixVP>[1]['client'];

    const result = await attachHelixVP(
      { name: 'orders.lookup', input: { orderId: 'ORD-1' } },
      { client, agentDid, targetService: 'orders', userDid: 'did:hedera:testnet:user' },
    );

    expect(signVP).toHaveBeenCalledWith(agentDid, 'orders', { userDid: 'did:hedera:testnet:user' });
    expect(result.input?._helixVP).toEqual(fakeSignedVP);
    expect(result.input?.orderId).toBe('ORD-1');
  });

  it('omits userDid entirely when not provided', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const client = { signVP } as unknown as Parameters<typeof attachHelixVP>[1]['client'];

    await attachHelixVP(
      { name: 'orders.lookup' },
      { client, agentDid, targetService: 'orders' },
    );

    expect(signVP).toHaveBeenCalledWith(agentDid, 'orders', {});
  });

  it('propagates a signing failure from the server (e.g. no active credential)', async () => {
    const signVP = vi.fn().mockRejectedValue(
      Object.assign(new Error('No active credential for agent DID'), {
        code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND',
      }),
    );
    const client = { signVP } as unknown as Parameters<typeof attachHelixVP>[1]['client'];

    await expect(
      attachHelixVP({ name: 'orders.lookup' }, { client, agentDid, targetService: 'orders' }),
    ).rejects.toMatchObject({ code: 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND' });
  });
});

describe('package constraints', () => {
  it('does not import HelixClient', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../src/middleware.ts', import.meta.url), 'utf8'),
    );
    const attachSource = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../src/attach.ts', import.meta.url), 'utf8'),
    );
    expect(source).not.toContain('HelixClient');
    expect(attachSource).not.toContain('HelixClient');
  });

  it('does not reference localhost API URLs', async () => {
    const files = ['../src/middleware.ts', '../src/attach.ts', '../src/types.ts', '../src/index.ts'];
    const contents = await Promise.all(
      files.map((file) =>
        import('node:fs/promises').then((fs) => fs.readFile(new URL(file, import.meta.url), 'utf8')),
      ),
    );
    for (const content of contents) {
      expect(content).not.toContain('localhost:3000');
    }
  });
});
