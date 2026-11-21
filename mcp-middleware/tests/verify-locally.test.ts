// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story F-2: the local verifier's default seams (public resolution, decoded lists, cards) and its report hook.

import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';
import { buildDIDDocument, generateKeyPair, kyaos } from '@helixid/sdk-js';
import { MemoryNonceStore } from '../src/kyaos/nonce-store.js';
import { cardEndpointOf, createLocalVerifier, resolutionUrl, unrecordedReporter } from '../src/verify-locally.js';
import { NOW_MS, proofMeta } from './proof-helpers.js';

const SERVICE = 'did:web:orders.helix.test';
const AGENT = 'did:web:127.0.0.1%3A4000:agents:a1';
const keys = generateKeyPair();
const signer = new kyaos.EnvSigner({ did: AGENT, envVar: 'K', env: { K: keys.privateKey } });
const document = { ...buildDIDDocument(AGENT, keys.publicKey), service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://127.0.0.1:4000/agents/a1/card.json' }] };
const card = { id: AGENT, entityType: 'agent', name: 'a1', capabilities: ['read:orders'] };
const bits = gzipSync(new Uint8Array(32));
const statusList = { id: 'https://issuer.example/status/1', issuer: 'did:web:issuer.example', validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z', credentialSubject: { statusPurpose: 'revocation', encodedList: `u${bits.toString('base64url')}` } };

/** A fetch that serves the agent's document, card and a status list, remembering what was asked. */
function staticFetch(served: Record<string, unknown>, asked: string[] = []) {
  return async (url: string) => {
    asked.push(url);
    return { ok: url in served, status: url in served ? 200 : 404, json: async () => served[url] };
  };
}

describe('resolution URLs and card endpoints', () => {
  it('reads https only, and http on loopback only in development', () => {
    expect(resolutionUrl('https://example.com/did.json', false)).toBe('https://example.com/did.json');
    expect(resolutionUrl('http://example.com/did.json', false)).toBeUndefined();
    expect(resolutionUrl('http://example.com/did.json', true)).toBeUndefined();
    expect(resolutionUrl('https://127.0.0.1:4000/x', true)).toBe('http://127.0.0.1:4000/x');
    expect(resolutionUrl('http://localhost:4000/x', true)).toBe('http://localhost:4000/x');
    expect(resolutionUrl('https://127.0.0.1:4000/x', false)).toBe('https://127.0.0.1:4000/x');
    expect(resolutionUrl('not a url', true)).toBeUndefined();
    expect(resolutionUrl('ftp://127.0.0.1/x', true)).toBeUndefined();
  });

  it('finds the KyaOsEntityCard service', () => {
    expect(cardEndpointOf(document)).toBe('https://127.0.0.1:4000/agents/a1/card.json');
    expect(cardEndpointOf({ service: [{ type: ['Other', 'KyaOsEntityCard'], serviceEndpoint: 'https://x' }, 'junk'] })).toBe('https://x');
    expect(cardEndpointOf({ service: [{ type: 'KyaOsEntityCard', serviceEndpoint: { nested: true } }] })).toBeUndefined();
    expect(cardEndpointOf({})).toBeUndefined();
    expect(cardEndpointOf(null)).toBeUndefined();
  });
});

describe('createLocalVerifier defaults', () => {
  it('resolves did:web, the card and status lists over the injected fetch, and verifies a call', async () => {
    const asked: string[] = [];
    const served = {
      'http://127.0.0.1:4000/agents/a1/did.json': document,
      'http://127.0.0.1:4000/agents/a1/card.json': card,
      'https://issuer.example/status/1': statusList,
    };
    const verifier = createLocalVerifier({ serviceDid: SERVICE, fetch: staticFetch(served, asked), allowLoopbackHttp: true, clock: () => NOW_MS, reportVerification: () => undefined });
    const result = await verifier.verifyCall({ name: 't', _meta: await proofMeta(signer, SERVICE, { name: 't' }) });
    expect(result).toMatchObject({ ok: true, level: 'L1', proofDid: AGENT });
    // The document is read for the key, for the membership proof and for the card service (no cache yet).
    expect(asked).toEqual(['http://127.0.0.1:4000/agents/a1/did.json', 'http://127.0.0.1:4000/agents/a1/did.json', 'http://127.0.0.1:4000/agents/a1/did.json', 'http://127.0.0.1:4000/agents/a1/card.json']);
    expect(await verifier.seams.fetchStatusList!('https://issuer.example/status/1')).toMatchObject({ issuer: 'did:web:issuer.example', id: 'https://issuer.example/status/1', fresh: true });
    await expect(verifier.seams.fetchStatusList!('https://issuer.example/status/missing')).rejects.toThrow(/answered 404/);
    await expect(verifier.seams.fetchStatusList!('http://issuer.example/status/1')).rejects.toThrow(/only https/);
    expect(verifier.nonceStore).toBeInstanceOf(MemoryNonceStore);
    expect(await verifier.verifyCall({ name: 't', _meta: {} })).toBeUndefined();
    expect(await verifier.verifyCall({ name: 't' })).toBeUndefined();
  });

  it('refuses http resolution outside development and resolves did:key offline', async () => {
    const asked: string[] = [];
    const verifier = createLocalVerifier({ serviceDid: SERVICE, fetch: staticFetch({}, asked), clock: () => NOW_MS, reportVerification: () => undefined });
    const result = await verifier.verifyCall({ name: 't', _meta: await proofMeta(signer, SERVICE, { name: 't' }) });
    expect(result?.reasons).toEqual(['did_unresolved']);
    // Outside development the loopback did:web is read over https, where nothing answers.
    expect(asked).toEqual(['https://127.0.0.1:4000/agents/a1/did.json']);
    asked.length = 0;
    const didKey = generateKeyPair();
    const didKeyDid = `did:key:${kyaos.verifier.didKeyDocument(`did:key:z6Mk`) ? '' : ''}${(await import('@helixid/sdk-js')).publicKeyToMultibase(didKey.publicKey)}`;
    const keySigner = new kyaos.EnvSigner({ did: didKeyDid, kid: didKeyDid.slice('did:key:'.length), envVar: 'K', env: { K: didKey.privateKey } });
    const offline = await verifier.verifyCall({ name: 't', _meta: await proofMeta(keySigner, SERVICE, { name: 't' }) });
    expect(offline).toMatchObject({ ok: true, proofDid: didKeyDid });
    expect(asked).toEqual([]);
  });

  it('takes cards from local config before the resolver, and a resolveCard seam of the host', async () => {
    const configured = createLocalVerifier({ serviceDid: SERVICE, resolveDid: async () => document as never, cards: { [AGENT]: card }, clock: () => NOW_MS, reportVerification: () => undefined });
    expect(await configured.seams.resolveCard!(AGENT)).toBe(card);
    const hosted = createLocalVerifier({ serviceDid: SERVICE, resolveDid: async () => document as never, resolveCard: async () => ({ ...card, name: 'hosted' }), clock: () => NOW_MS, reportVerification: () => undefined });
    expect(await hosted.seams.resolveCard!(AGENT)).toMatchObject({ name: 'hosted' });
    const none = createLocalVerifier({ serviceDid: SERVICE, resolveDid: async () => ({ id: AGENT }) as never, clock: () => NOW_MS, reportVerification: () => undefined });
    expect(await none.seams.resolveCard!(AGENT)).toBeUndefined();
  });

  it('passes the service settings through to the verifier', async () => {
    const verifier = createLocalVerifier({
      serviceDid: SERVICE,
      resource: 'did:web:resource',
      resourceOwner: 'did:web:owner',
      trustedRootIssuers: ['did:web:owner'],
      trustedIssuers: ['did:web:helix'],
      maxChainLength: 3,
      skewSeconds: 10,
      maxClockSkewMs: 1000,
      catalog: ['read:orders'],
      resolveDid: async () => document as never,
      clock: () => NOW_MS,
      reportVerification: () => undefined,
    });
    expect(verifier.seams.trustedIssuers).toEqual(['did:web:helix']);
    const meta = await proofMeta(signer, SERVICE, { name: 't' }, [1, 2, 3, 4]);
    expect((await verifier.verifyCall({ name: 't', _meta: meta }))?.reasons).toEqual(['chain_too_long']);
    const direct = await verifier.verify({ proof: meta['org.kya-os/request-proof'], request: { method: 'tools/call', params: { name: 't' } } }, { expectedAudience: 'did:web:elsewhere' });
    expect(direct.reasons).toEqual(['audience_mismatch']);
    expect(() => createLocalVerifier({ serviceDid: 'nope' })).toThrow(/serviceDid must be a DID/);
  });

  it('says once that verifications are unrecorded without a report hook', async () => {
    const log = vi.fn();
    const verifier = createLocalVerifier({ serviceDid: SERVICE, resolveDid: async () => document as never, clock: () => NOW_MS, log });
    await verifier.verifyCall({ name: 't', _meta: await proofMeta(signer, SERVICE, { name: 't' }) });
    await verifier.verifyCall({ name: 't', _meta: await proofMeta(signer, SERVICE, { name: 't' }) });
    expect(log).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[0]?.[0]).toContain('unrecorded');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    unrecordedReporter()({ timestamp: '', serviceDid: SERVICE, ok: true, level: 'L1', effectiveScopes: [], reasons: [], fresh: true, chainDepth: 0 });
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('fetches through the global fetch when none is injected', async () => {
    const asked: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      asked.push(url);
      return new Response(JSON.stringify(document), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    try {
      const verifier = createLocalVerifier({ serviceDid: SERVICE, allowLoopbackHttp: true, clock: () => NOW_MS, reportVerification: () => undefined });
      const result = await verifier.verifyCall({ name: 't', _meta: await proofMeta(signer, SERVICE, { name: 't' }) });
      expect(result?.proofDid).toBe(AGENT);
      expect(asked[0]).toBe('http://127.0.0.1:4000/agents/a1/did.json');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
