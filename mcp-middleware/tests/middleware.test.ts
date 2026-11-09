import { describe, expect, it, vi } from 'vitest';
import { encodeHelixVP, verifyVP as verifyVPExport, type HelixClient, type SignedVP } from '@helixid/sdk-js';
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
const client = {} as unknown as HelixClient;

const meta = (vp: object) => ({ 'x-helix-vp': encodeHelixVP(vp as SignedVP) });

describe('helixidMCPMiddleware', () => {
  it('throws VP_MISSING when there is no VP in _meta or headers', async () => {
    const middleware = helixidMCPMiddleware({ client });

    await expect(middleware({ name: 'orders.lookup', input: {} })).rejects.toMatchObject({
      code: 'VP_MISSING',
    });
  });

  it('ignores a VP placed in the tool arguments', async () => {
    const middleware = helixidMCPMiddleware({ client });

    await expect(
      middleware({ name: 'orders.lookup', input: { _helixVP: { id: 'vp:helix:test' } } }),
    ).rejects.toMatchObject({ code: 'VP_MISSING' });
    expect(verifyVP).not.toHaveBeenCalled();
  });

  it('rejects a _meta VP that is not base64url JSON', async () => {
    const middleware = helixidMCPMiddleware({ client });

    await expect(
      middleware({ name: 'orders.lookup', _meta: { 'x-helix-vp': 'not json' } }),
    ).rejects.toMatchObject({ code: 'VP_INVALID_STRUCTURE' });
  });

  it('reads the VP from the X-Helix-VP header (any case)', async () => {
    verifyVP.mockResolvedValueOnce({
      valid: true,
      agentDid: 'did:agent',
      privilegeScopes: ['read:orders'],
      effectiveScopes: ['read:orders'],
      vpId: 'vp:helix:test',
      delegationChain: [],
    });

    const middleware = helixidMCPMiddleware({ client, requiredScopes: ['read:orders'] });
    const toolCall = {
      name: 'orders.lookup',
      headers: { 'x-helix-vp': meta({ id: 'vp:helix:test' })['x-helix-vp'] },
    };

    await expect(middleware(toolCall)).resolves.toBe(toolCall);
    expect(verifyVP).toHaveBeenLastCalledWith({ id: 'vp:helix:test' }, client, expect.anything());
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

    const middleware = helixidMCPMiddleware({ client, requiredScopes: ['read:orders'] });
    const toolCall = {
      name: 'orders.lookup',
      input: { orderId: 'ORD-1' },
      _meta: meta({ id: 'vp:helix:test' }),
    };

    await expect(middleware(toolCall)).resolves.toBe(toolCall);
    expect(verifyVP).toHaveBeenCalledWith(
      { id: 'vp:helix:test' },
      client,
      expect.objectContaining({ allowSelfSigned: false }),
    );
  });

  it('passes expectedTargetService through to verifyVP', async () => {
    verifyVP.mockResolvedValueOnce({
      valid: true,
      agentDid: 'did:agent',
      privilegeScopes: [],
      effectiveScopes: [],
      vpId: 'vp:helix:test',
      delegationChain: [],
    });

    const middleware = helixidMCPMiddleware({ client, expectedTargetService: 'did:web:svc.example.invalid' });
    await middleware({ name: 'orders.lookup', _meta: meta({ id: 'vp:helix:test' }) });
    expect(verifyVP).toHaveBeenLastCalledWith(
      { id: 'vp:helix:test' },
      client,
      expect.objectContaining({ expectedTargetService: 'did:web:svc.example.invalid' }),
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

    const middleware = helixidMCPMiddleware({ client });

    await expect(
      middleware({ _meta: meta({ id: 'vp:helix:bad' }) }),
    ).rejects.toMatchObject({
      code: 'VP_VERIFICATION_FAILED',
    });
  });

  it('maps a credential error thrown by the API (revoked, expired, wrong target) to VP_VERIFICATION_FAILED', async () => {
    const middleware = helixidMCPMiddleware({ client });
    for (const code of ['VC_REVOKED', 'VP_EXPIRED', 'VP_SIGNATURE_INVALID', 'DELEGATION_CHAIN_INVALID', 'DID_NOT_FOUND']) {
      verifyVP.mockRejectedValueOnce(Object.assign(new Error(`api said ${code}`), { code, httpStatus: 400 }));
      await expect(middleware({ name: 't', _meta: meta({ id: 'vp:helix:x' }) }), code).rejects.toMatchObject({
        code: 'VP_VERIFICATION_FAILED',
        message: `api said ${code}`,
      });
    }
  });

  it('passes an API failure that is not about the credential (our key refused, API down) through unmapped', async () => {
    const middleware = helixidMCPMiddleware({ client });
    for (const code of ['ACCESS_TOKEN_INVALID', 'ADMIN_AUTH_REQUIRED', 'INTERNAL_ERROR']) {
      verifyVP.mockRejectedValueOnce(Object.assign(new Error(`api said ${code}`), { code, httpStatus: code === 'INTERNAL_ERROR' ? 500 : 401 }));
      await expect(middleware({ name: 't', _meta: meta({ id: 'vp:helix:x' }) }), code).rejects.toMatchObject({ code });
    }
    verifyVP.mockRejectedValueOnce(new TypeError('fetch failed'));
    await expect(middleware({ name: 't', _meta: meta({ id: 'vp:helix:x' }) })).rejects.toBeInstanceOf(TypeError);
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

    const middleware = helixidMCPMiddleware({ client, requiredScopes: ['write:orders'] });

    await expect(
      middleware({ _meta: meta({ id: 'vp:helix:test' }) }),
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

  it('attaches the VP as _meta["x-helix-vp"] by calling client.signVP()', async () => {
    const signVP = vi.fn().mockResolvedValue(fakeSignedVP);
    const client = { signVP } as unknown as Parameters<typeof attachHelixVP>[1]['client'];

    const result = await attachHelixVP(
      { name: 'orders.lookup', input: { orderId: 'ORD-1' } },
      { client, agentDid, targetService: 'orders', userDid: 'did:hedera:testnet:user' },
    );

    expect(signVP).toHaveBeenCalledWith(agentDid, 'orders', { userDid: 'did:hedera:testnet:user' });
    expect(result._meta?.['x-helix-vp']).toBe(encodeHelixVP(fakeSignedVP as unknown as SignedVP));
    expect(result.input).toEqual({ orderId: 'ORD-1' });
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
