// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story F-2: the guard verifies every request proof in-process; the Helix API is never asked.

import { describe, expect, it, vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import { helixidMCPMiddleware } from '../src/middleware.js';
import { ProofError } from '../src/errors.js';
import { fixtureSigner, fixtureVerifier, haveVerifierFixtures, loadCases, loadEnvironment, makeAgent, proofMeta, NOW_MS } from './proof-helpers.js';

const SERVICE = 'did:web:orders.helix.test';
const agent = makeAgent();

describe('helixidMCPMiddleware (proof path)', () => {
  it('throws PROOF_MISSING when there is no proof in _meta and no bearer token', async () => {
    const middleware = helixidMCPMiddleware({ verifier: fixtureVerifier(SERVICE) });
    await expect(middleware({ name: 'orders.lookup', input: {} })).rejects.toMatchObject({ code: 'PROOF_MISSING', httpStatus: 401 });
    // Arguments are never read as a credential.
    await expect(middleware({ name: 'orders.lookup', input: { 'org.kya-os/request-proof': { x: 1 } } })).rejects.toMatchObject({ code: 'PROOF_MISSING' });
  });

  it('requires a verifier to judge a proof', async () => {
    const middleware = helixidMCPMiddleware({});
    await expect(middleware({ name: 't', _meta: { 'org.kya-os/request-proof': {} } })).rejects.toThrow(/`verifier` is required/);
    expect(middleware.verifier).toBeUndefined();
  });

  it('accepts a valid proof from an agent whose document resolves, at L1 with no scopes when nothing is attested', async () => {
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [], minimumLevel: 'L1' });
    const call = { name: 'orders.lookup', input: { orderId: 'ORD-1' }, _meta: await proofMeta(agent.signer, SERVICE, { name: 'orders.lookup', input: { orderId: 'ORD-1' } }) };
    await expect(middleware(call)).resolves.toBe(call);
    expect(middleware.verifier).toBe(verifier);
    const caller = await middleware.authorize({ ...call, _meta: await proofMeta(agent.signer, SERVICE, { name: 'orders.lookup', input: { orderId: 'ORD-1' } }) });
    expect(caller).toEqual({ authMethod: 'kyaos', scopes: [], agentDid: agent.did, level: 'L1', proofAssurance: 'L3-minus', fresh: true, proofFloor: true });
    // Under the default minimum (L3, story C-C) the same unattested agent is refused, with the level it came to.
    const strict = helixidMCPMiddleware({ verifier, requiredScopes: [] });
    await expect(strict({ ...call, _meta: await proofMeta(agent.signer, SERVICE, { name: 'orders.lookup', input: { orderId: 'ORD-1' } }) })).rejects.toMatchObject({
      code: 'PROOF_LEVEL_INSUFFICIENT',
      derivedLevel: 'L1',
      requiredLevel: 'L3',
    });
  });

  it('refuses a replayed proof, a proof for another service and a tampered request, naming the reason', async () => {
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [], minimumLevel: 'L1' });
    const meta = await proofMeta(agent.signer, SERVICE, { name: 't', input: { a: 1 } });
    await expect(middleware({ name: 't', input: { a: 1 }, _meta: meta })).resolves.toBeDefined();
    const replay = await middleware({ name: 't', input: { a: 1 }, _meta: meta }).catch((e: unknown) => e);
    expect(replay).toBeInstanceOf(ProofError);
    expect(replay).toMatchObject({ code: 'PROOF_INVALID', httpStatus: 401, reasons: ['nonce_replayed'] });
    await expect(middleware({ name: 't', input: { a: 2 }, _meta: await proofMeta(agent.signer, SERVICE, { name: 't', input: { a: 1 } }) })).rejects.toMatchObject({ reasons: ['request_hash_mismatch'] });
    await expect(middleware({ name: 't', input: { a: 1 }, _meta: await proofMeta(agent.signer, 'did:web:other', { name: 't', input: { a: 1 } }) })).rejects.toMatchObject({ reasons: ['audience_mismatch'] });
  });

  it('hashes the JSON-RPC request the host hands over, as received', async () => {
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [], minimumLevel: 'L1' });
    const request = { method: 'tools/call', params: { name: 't', arguments: { a: 1 }, extra: 'member' } };
    const proof = await kyaos.verifier.signRequestProof(request, agent.signer, { audience: SERVICE, now: NOW_MS });
    const meta = { 'org.kya-os/request-proof': proof };
    // Rebuilt from name and input, the extra member is missing and the hash differs.
    await expect(middleware({ name: 't', input: { a: 1 }, _meta: meta })).rejects.toMatchObject({ reasons: ['request_hash_mismatch'] });
    await expect(middleware({ name: 't', input: { a: 1 }, _meta: meta, request: { ...request, params: { ...request.params, _meta: meta } } })).resolves.toBeDefined();
  });

  it('reads the proof under the legacy key for one major version', async () => {
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [], minimumLevel: 'L1' });
    const call = { name: 't', _meta: await proofMeta(agent.signer, SERVICE, { name: 't' }, undefined, { legacyKey: true }) };
    await expect(middleware(call)).resolves.toBe(call);
  });

  it('audits a refused call whose signer was identified, with the reasons; a replay names no principal', async () => {
    const events: unknown[] = [];
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const middleware = helixidMCPMiddleware({ verifier, auditSink: (e) => void events.push(e), serviceDid: SERVICE, minimumLevel: 'L1' });
    const meta = await proofMeta(agent.signer, SERVICE, { name: 't' });
    await middleware({ name: 't', _meta: meta });
    // §11.2 (story C-C): the nonce (step 8) is checked before the signature (step 9), so a replay proves nobody.
    await middleware({ name: 't', _meta: meta }).catch(() => undefined);
    // A malformed chain is refused after the proof held: that refusal names the agent.
    await middleware({ name: 't', _meta: await proofMeta(agent.signer, SERVICE, { name: 't' }, [{ id: 'x' }]) }).catch(() => undefined);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ event: 'AUTHZ_GRANTED', authMethod: 'kyaos', agentDid: agent.did, level: 'L1', fresh: true, serviceDid: SERVICE, proofAssurance: 'L3-minus', l3Minus: false });
    expect(events[1]).toMatchObject({ event: 'AUTHZ_DENIED', agentDid: agent.did });
  });

  it('takes verifier settings and builds the verifier with the service DID and the tool scopes as the catalog', async () => {
    const middleware = helixidMCPMiddleware({
      serviceDid: SERVICE,
      toolScopes: { t: ['read:orders'] },
      verifier: { clock: () => NOW_MS, resolveDid: async () => agent.document as never, reportVerification: () => undefined },
    });
    expect(middleware.verifier?.serviceDid).toBe(SERVICE);
    await expect(middleware({ name: 't', _meta: await proofMeta(agent.signer, SERVICE, { name: 't' }) })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    expect(() => helixidMCPMiddleware({ verifier: {} })).toThrow(/serviceDid must be a DID/);
  });
});

describe.skipIf(!haveVerifierFixtures)('helixidMCPMiddleware over the shared fixtures (a signed chain and an attested card)', () => {
  const env = loadEnvironment();
  const service = env.keys['service']!.did;
  const agentSigner = fixtureSigner(env, 'agent');
  const valid = loadCases('valid').find((c) => c.name === 'two_hop_chain')!;
  const chain = valid.input.chain;

  it('authorises a tool from the attestations ∩ the leaf allowedAction ∩ the tool scopes, at L3', async () => {
    const reports: unknown[] = [];
    const verifier = fixtureVerifier(service, { env, cards: { [env.keys['agent']!.did]: env.cards['attested'] }, reportVerification: (r) => void reports.push(r) });
    const middleware = helixidMCPMiddleware({ verifier, toolScopes: { lookup_order: ['read:orders'], refund_order: ['refund:orders'] } });
    const call = { name: 'lookup_order', input: { orderId: 'ORD-1001' }, _meta: await proofMeta(agentSigner, service, { name: 'lookup_order', input: { orderId: 'ORD-1001' } }, chain) };
    const caller = await middleware.authorize(call);
    expect(caller).toMatchObject({ authMethod: 'kyaos', agentDid: env.keys['agent']!.did, level: 'L3', fresh: true, scopes: ['read:orders', 'write:orders'] });
    expect(reports).toHaveLength(1);
    expect(reports[0]).toMatchObject({ ok: true, level: 'L3', toolName: 'lookup_order', chainDepth: 2, serviceDid: service, reasons: [] });
    await expect(middleware({ name: 'refund_order', input: {}, _meta: await proofMeta(agentSigner, service, { name: 'refund_order', input: {} }, chain) })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
  });

  it('refuses every chain and status fixture that is refused, with its reasons, and never falls back to a lookup', async () => {
    const lookups: string[] = [];
    const verifier = fixtureVerifier(service, { env, cards: { [env.keys['agent']!.did]: env.cards['attested'] }, resolveCard: async (did) => { lookups.push(did); return undefined; } });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [] });
    // Only the cases this guard's own settings reproduce: the service as audience and resource, nothing pinned,
    // and a refusal of the chain itself (the card cases need the fixture's card, which this guard does not hold).
    const plain = (c: { options: Record<string, unknown>; seams: Record<string, unknown>; name: string }) =>
      Object.keys(c.options).length === 2 &&
      c.options['resource'] === service &&
      c.seams['fetchStatusList'] === 'lists' &&
      !['root_not_responsible_party', 'card_malformed', 'card_subject_mismatch', 'card_unresolvable'].includes(c.name);
    const cases = [...loadCases('chain'), ...loadCases('status')].filter((c) => !c.expected.ok && c.input.proof !== undefined && plain(c));
    expect(cases.length).toBeGreaterThan(20);
    for (const fixture of cases) {
      const meta = await proofMeta(agentSigner, service, { name: 'lookup_order', input: { orderId: 'ORD-1001' } }, fixture.input.chain);
      const refused = await middleware({ name: 'lookup_order', input: { orderId: 'ORD-1001' }, _meta: meta }).catch((e: unknown) => e);
      expect(refused, fixture.name).toMatchObject({ code: 'PROOF_INVALID' });
      expect((refused as ProofError).reasons, fixture.name).toEqual(fixture.expected.reasons);
    }
    expect(lookups).toEqual([]);
  });

  it('reports verifications through the hook and survives a hook that throws', async () => {
    const onReportError = vi.fn();
    const verifier = fixtureVerifier(service, { env, reportVerification: async () => { throw new Error('trail down'); }, onReportError });
    const middleware = helixidMCPMiddleware({ verifier, requiredScopes: [], minimumLevel: 'L1' });
    await expect(middleware({ name: 'lookup_order', _meta: await proofMeta(agentSigner, service, { name: 'lookup_order' }, chain) })).resolves.toBeDefined();
    expect(onReportError).toHaveBeenCalledTimes(1);
  });
});

describe('package constraints', () => {
  it('does not import HelixClient or reference localhost API URLs', async () => {
    const fs = await import('node:fs/promises');
    for (const file of ['../src/middleware.ts', '../src/verify-locally.ts', '../src/credentials.ts', '../src/types.ts', '../src/index.ts']) {
      const content = await fs.readFile(new URL(file, import.meta.url), 'utf8');
      expect(content, file).not.toContain('HelixClient');
      expect(content, file).not.toContain('localhost:3000');
    }
  });
});
