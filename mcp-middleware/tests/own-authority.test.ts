// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// Own authority (four-clients) on the gated methods (MCP gate fixes): with `allowOwnAuthority`, an agent's
// attested capabilities count as far as the service offers them, across its tools, resources and prompts.
// `requireDelegation` keeps a tool out of own authority. The verifier is a stub that grants the agent's
// attested capabilities within the catalog the guard hands it.
import { describe, expect, it } from 'vitest';
import { helixidMCPMiddleware } from '../src/middleware.js';
import type { LocalVerifier, LocalVerifierCall } from '../src/verify-locally.js';

const SERVICE = 'did:web:orders.helix.test';
const AGENT = 'did:web:agents.helix.test:reader';
const META = { 'org.kya-os/request-proof': 'stub.proof.jws' };

function stubVerifier(attested: string[], allowOwnAuthority = true): LocalVerifier & { calls: LocalVerifierCall[] } {
  const calls: LocalVerifierCall[] = [];
  return {
    serviceDid: SERVICE,
    allowOwnAuthority,
    calls,
    seams: {} as LocalVerifier['seams'],
    nonceStore: {} as LocalVerifier['nonceStore'],
    statusCache: {} as LocalVerifier['statusCache'],
    verify: async () => {
      throw new Error('not used');
    },
    verifyCall: async (call) => {
      calls.push(call);
      const effectiveScopes = attested.filter((scope) => call.catalog?.includes(scope));
      return { ok: true, reasons: [], warnings: [], agentDid: AGENT, effectiveScopes, level: 'L3', fresh: true, proofFloor: false } as unknown as Awaited<
        ReturnType<LocalVerifier['verifyCall']>
      >;
    },
  };
}

describe('own authority across tools, resources and prompts', () => {
  it('hands the verifier every scope the service offers, once each', async () => {
    const verifier = stubVerifier(['orders:read']);
    const mw = helixidMCPMiddleware({
      verifier,
      serviceDid: SERVICE,
      inboundDelegation: false,
      toolScopes: { lookup_order: ['orders:read'] },
      resourceScopes: { 'orders://ledger': ['ledger:read'], 'orders://a': ['orders:read'] },
      promptScopes: { summarize: ['prompts:use'] },
    });
    await mw.authorize({ method: 'tools/call', name: 'lookup_order', _meta: META });
    expect(verifier.calls[0]?.catalog).toEqual(['orders:read', 'ledger:read', 'prompts:use']);
  });

  it('lets an agent read a resource and get a prompt on its attested capabilities alone', async () => {
    const verifier = stubVerifier(['ledger:read', 'prompts:use']);
    const mw = helixidMCPMiddleware({
      verifier,
      serviceDid: SERVICE,
      inboundDelegation: false,
      toolScopes: { lookup_order: ['orders:read'] },
      resourceScopes: { 'orders://ledger': ['ledger:read'] },
      promptScopes: { summarize: ['prompts:use'] },
    });
    const resource = await mw.authorize({ method: 'resources/read', name: 'orders://ledger', _meta: META });
    expect(resource.scopes).toEqual(['ledger:read', 'prompts:use']);
    const prompt = await mw.authorize({ method: 'prompts/get', name: 'summarize', _meta: META });
    expect(prompt.agentDid).toBe(AGENT);
    // A tool scope the agent is not attested for still refuses.
    await expect(mw.authorize({ method: 'tools/call', name: 'lookup_order', _meta: META })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
  });

  it('works with resources or prompts only, and passes no catalog without any scope map', async () => {
    const onlyResources = stubVerifier(['ledger:read']);
    await helixidMCPMiddleware({ verifier: onlyResources, serviceDid: SERVICE, inboundDelegation: false, resourceScopes: { 'orders://ledger': ['ledger:read'] } }).authorize({
      method: 'resources/read',
      name: 'orders://ledger',
      _meta: META,
    });
    expect(onlyResources.calls[0]?.catalog).toEqual(['ledger:read']);
    const none = stubVerifier([]);
    await helixidMCPMiddleware({ verifier: none, serviceDid: SERVICE, inboundDelegation: false }).authorize({ method: 'ping', _meta: META });
    expect(none.calls[0]?.catalog).toBeUndefined();
  });

  it('passes no catalog when the service did not opt in to own authority', async () => {
    const verifier = stubVerifier(['orders:read'], false);
    const mw = helixidMCPMiddleware({ verifier, serviceDid: SERVICE, inboundDelegation: false, toolScopes: { lookup_order: ['orders:read'] } });
    await expect(mw.authorize({ method: 'tools/call', name: 'lookup_order', _meta: META })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    expect(verifier.calls[0]?.catalog).toBeUndefined();
  });

  it('keeps a requireDelegation tool out of own authority', async () => {
    const verifier = stubVerifier(['orders:read', 'orders:admin']);
    const mw = helixidMCPMiddleware({
      verifier,
      serviceDid: SERVICE,
      inboundDelegation: false,
      toolScopes: { lookup_order: ['orders:read'], refund_order: ['orders:admin'] },
      tools: { refund_order: { requireDelegation: true } },
    });
    expect((await mw.authorize({ method: 'tools/call', name: 'lookup_order', _meta: META })).scopes).toContain('orders:read');
    await expect(mw.authorize({ method: 'tools/call', name: 'refund_order', _meta: META })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
  });
});
