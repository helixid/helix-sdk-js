// Copyright 2026 DgVerse LLP
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HelixClient } from '../../../src/client/HelixClient.js';
import { HttpAdapter } from '../../../src/http/HttpAdapter.js';

describe('HelixClient Branch Coverage', () => {
  let client: HelixClient;
  let mockHttp: any;

  beforeEach(() => {
    mockHttp = {
      post: vi.fn(),
      get: vi.fn(),
      delete: vi.fn(),
    };
    client = new HelixClient('http://localhost');
    client.__setTestHttpAdapter(mockHttp);
  });

  it('constructor handles string baseUrl', () => {
    const c2 = new HelixClient('http://localhost');
    expect((c2 as any).http).toBeInstanceOf(HttpAdapter);
  });

  describe('createDID branches', () => {
    it('uses empty domains if not provided', async () => {
      mockHttp.post.mockResolvedValue({ didDocument: { id: 'did:1' }, hederaTransactionId: 'tx1' });
      const res = await client.createDID({ subjectType: 'user' });
      expect(mockHttp.post).toHaveBeenCalledWith('/v1/dids', expect.objectContaining({ domains: [] }));
      expect(res.did).toBe('did:1');
    });

    it('prefers id then did from response', async () => {
        mockHttp.post.mockResolvedValue({ id: 'did:id', didDocument: { id: 'did:doc' }, hederaTransactionId: 'tx1' });
        const res = await client.createDID({ subjectType: 'user' });
        expect(res.did).toBe('did:id');

        mockHttp.post.mockResolvedValue({ did: 'did:did', didDocument: { id: 'did:doc' }, hederaTransactionId: 'tx1' });
        const res2 = await client.createDID({ subjectType: 'user' });
        expect(res2.did).toBe('did:did');
    });
  });

  describe('resolveDID branches', () => {
    it('handles live=true', async () => {
      mockHttp.get.mockResolvedValue({ id: 'did:1' });
      const res = await client.resolveDID('did:1', { live: true });
      expect(mockHttp.get).toHaveBeenCalledWith('/v1/dids/did%3A1?live=true');
      expect(res.source).toBe('hedera');
    });

    it('prefers document then response', async () => {
        mockHttp.get.mockResolvedValue({ document: { id: 'did:doc' } });
        const res = await client.resolveDID('did:1');
        expect(res.didDocument.id).toBe('did:doc');
    });
  });

  describe('adapter checks', () => {
    it('throws for removeServiceEndpoint if DELETE missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.removeServiceEndpoint('did:1', 's1')).rejects.toThrow('DELETE not implemented by adapter');
    });

    it('throws for getVC if GET missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.getVC('vc1')).rejects.toThrow('GET not implemented by adapter');
    });

    it('throws for listVCs if GET missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.listVCs()).rejects.toThrow('GET not implemented by adapter');
    });

    it('throws for getStatusList if GET missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.getStatusList('l1')).rejects.toThrow('GET not implemented by adapter');
    });

    it('throws for getAuditLog if GET missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.getAuditLog()).rejects.toThrow('GET not implemented by adapter');
    });

    it('throws for fetchSessionPublicKey if GET missing', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.fetchSessionPublicKey()).rejects.toThrow('GET not implemented by adapter');
    });
  });

  describe('checkVCStatus branches', () => {
    // Status is decided server-side (see the SDK-API-only design) — the
    // SDK's only job is the GET and passing the status straight through.
    it('returns whatever status the API reports', async () => {
        mockHttp.get.mockResolvedValue({ vcId: 'vc:1', status: 'expired' });
        const res = await client.checkVCStatus({ id: 'vc:1' } as any);
        expect(mockHttp.get).toHaveBeenCalledWith('/v1/vcs/vc%3A1/status');
        expect(res).toBe('expired');
    });

    it('returns revoked when the API reports revoked', async () => {
        mockHttp.get.mockResolvedValue({ vcId: 'vc:2', status: 'revoked' });
        const res = await client.checkVCStatus({ id: 'vc:2' } as any);
        expect(res).toBe('revoked');
    });

    it('throws if the adapter has no GET support', async () => {
        const c2 = new HelixClient('http://localhost');
        c2.__setTestHttpAdapter({ post: vi.fn() });
        await expect(c2.checkVCStatus({ id: 'vc:1' } as any)).rejects.toThrow('GET not implemented by adapter');
    });
  });

  describe('onboarding branches', () => {
    it('onboards with default empty domains', async () => {
        mockHttp.post.mockResolvedValue({ agentDid: 'did:key:z1', vcId: 'vc-1' });
        await client.onboardAgent('token');
        expect(mockHttp.post).toHaveBeenCalledWith('/v1/onboard', { enrollmentToken: 'token', domains: [] });
    });
  });

  describe('VC lifecycle branches', () => {
    it('renewVC handles empty overrides', async () => {
        mockHttp.post.mockResolvedValue({ vcId: 'v2' });
        const res = await client.renewVC('v1');
        expect(mockHttp.post).toHaveBeenCalledWith('/v1/vcs/v1/renew', {});
        expect(res.vcId).toBe('v2');
    });
  });

  describe('enterprise (apiKey) mode', () => {
    const DID = 'did:web:helix.test:agents:a1';
    let enterprise: HelixClient;

    beforeEach(() => {
      enterprise = new HelixClient('http://localhost', { apiKey: 'hak_test' });
      enterprise.__setTestHttpAdapter(mockHttp);
    });

    it('builds its adapter with the api key so every call carries the bearer token', () => {
      const c2 = new HelixClient('http://localhost', { apiKey: 'hak_test' });
      expect(((c2 as any).http as HttpAdapter).hasApiKey()).toBe(true);
      expect(((c2 as any).http as HttpAdapter).hasAdminApiKey()).toBe(false);
    });

    it('signVP goes through the adapter to the custodial route', async () => {
      mockHttp.post.mockResolvedValue({ signedVP: { id: 'vp-1' } });
      const vp = await enterprise.signVP(DID, 'orders');
      expect(vp).toEqual({ id: 'vp-1' });
      expect(mockHttp.post).toHaveBeenCalledWith(
        `/v1/custodial-agents/${encodeURIComponent(DID)}/vp`,
        { targetService: 'orders' },
      );
    });

    it('delegateAuthority goes through the adapter to the custodial route', async () => {
      mockHttp.post.mockResolvedValue({ delegatedVC: { id: 'vc-child' } });
      const vc = await enterprise.delegateAuthority(DID, 'did:key:z6Mkchild', ['read:orders'], 3600);
      expect(vc).toEqual({ id: 'vc-child' });
      expect(mockHttp.post).toHaveBeenCalledWith(
        `/v1/custodial-agents/${encodeURIComponent(DID)}/delegate`,
        { to: 'did:key:z6Mkchild', scopes: ['read:orders'], expiresIn: 3600 },
      );
    });

    it('core mode keeps the admin-gated agent routes', async () => {
      mockHttp.post.mockResolvedValue({ signedVP: { id: 'vp-1' } });
      await client.signVP(DID, 'orders');
      expect(mockHttp.post).toHaveBeenCalledWith(`/v1/agents/${encodeURIComponent(DID)}/vp`, { targetService: 'orders' });
    });

    it('issueServiceDelegationGrant uses the same adapter (and so the same credential)', async () => {
      mockHttp.post.mockResolvedValue({ grantVC: { id: 'vc-grant' } });
      const vc = await enterprise.issueServiceDelegationGrant({
        serviceDid: 'did:web:sp', agentDid: DID, userDid: 'did:key:z6Mkuser', scopes: ['read:orders'],
      });
      expect(vc).toEqual({ id: 'vc-grant' });
      expect(mockHttp.post).toHaveBeenCalledWith('/v1/service-delegation-grants', expect.objectContaining({ serviceDid: 'did:web:sp' }));
    });

    it('issueServiceDelegationGrant passes allowDelegation through', async () => {
      mockHttp.post.mockResolvedValue({ grantVC: { id: 'vc-grant' } });
      await enterprise.issueServiceDelegationGrant({
        serviceDid: 'did:web:sp', agentDid: DID, userDid: 'did:key:z6Mkuser', scopes: ['read:orders'], allowDelegation: false,
      });
      expect(mockHttp.post).toHaveBeenCalledWith('/v1/service-delegation-grants', expect.objectContaining({ allowDelegation: false }));
    });

    it('getAgentScopes reads the agent scopes for a service through the adapter', async () => {
      mockHttp.get.mockResolvedValue({ agentDid: DID, scopes: ['read:orders'] });
      const result = await enterprise.getAgentScopes({ serviceDid: 'did:web:sp', agentDid: DID });
      expect(result).toEqual({ agentDid: DID, scopes: ['read:orders'] });
      expect(mockHttp.get).toHaveBeenCalledWith(
        `/v1/service-delegation-grants/agent-scopes?serviceDid=${encodeURIComponent('did:web:sp')}&agentDid=${encodeURIComponent(DID)}`,
      );
    });

    it('registerVC posts the signed credential', async () => {
      mockHttp.post.mockResolvedValue({ vcId: 'vc-grant', alreadyRegistered: false });
      const res = await enterprise.registerVC({ id: 'vc-grant' } as any);
      expect(res).toEqual({ vcId: 'vc-grant', alreadyRegistered: false });
      expect(mockHttp.post).toHaveBeenCalledWith('/v1/vcs/register', { vc: { id: 'vc-grant' } });
    });

    it('registerVC refuses in SDK-only mode', async () => {
      await expect(new HelixClient().registerVC({ id: 'vc-grant' } as any)).rejects.toThrow();
    });
  });
});
