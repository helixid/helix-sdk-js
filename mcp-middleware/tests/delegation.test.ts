// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story L3-D: forward delegation context on downstream calls.
 * Service A (the fixture world's `service`) is called by the agent with the
 * fixture's two-hop chain, owner → parent → agent, targeting A; A forwards
 * it to service B (a did:web of its own) through `withDelegation`; B
 * verifies the headers with its own local verifier. No secret is shared:
 * B reads only public DID documents, status lists and cards.
 */

import { describe, expect, it } from 'vitest';
import { kyaos, MemoryAuditSink } from '@helixid/sdk-js';
import { createMcpAuditTrail } from '../src/audit.js';
import {
  DELEGATION_HEADERS,
  DelegationContextMissingError,
  RedelegationError,
  VerificationCache,
  agentOfChain,
  buildChainString,
  buildOutboundDelegation,
  chainStringOf,
  currentDelegation,
  decodeDelegationCredential,
  delegationContextOf,
  delegationIdOf,
  encodeDelegationCredential,
  hasDelegationHeaders,
  hostOfDidWeb,
  mintDelegationProofJwt,
  revocationInvalidation,
  runWithDelegation,
  scopeList,
  verifyDelegationProofJwt,
  verifyInboundDelegationHeaders,
  withDelegation,
  type DelegationContext,
  type OutboundAttachment,
} from '../src/delegation/index.js';
import { helixidMCPMiddleware } from '../src/middleware.js';
import { cardFor, hop, serviceOn, withList } from './delegation-helpers.js';
import { NOW_MS, fixtureSigner, fixtureVerifier, haveVerifierFixtures, loadCases, loadEnvironment, proofMeta, type FixtureEnvironment } from './proof-helpers.js';

const env: FixtureEnvironment = haveVerifierFixtures ? withList(loadEnvironment(), 'service', 'https://service.example/status/1') : (undefined as never);
const chain: Array<Record<string, unknown>> = haveVerifierFixtures ? (loadCases('valid').find((entry) => entry.name === 'two_hop_chain')!.input.chain as never) : [];
const did = (label: string): string => env.keys[label]!.did;

describe.skipIf(!haveVerifierFixtures)('L3-D: service A forwards an agent\'s delegation to service B', () => {
  const B = serviceOn('b.helix.test');
  const A = (): kyaos.Signer => fixtureSigner(env, 'service');
  const context = (): DelegationContext => ({ agentDid: did('agent'), chain, scopes: ['read:orders', 'write:orders'], sessionId: 'sess-1' });
  const verifierB = (options: Parameters<typeof fixtureVerifier>[1] = {}): ReturnType<typeof fixtureVerifier> =>
    fixtureVerifier(B.did, { env, documents: { [B.did]: B.document }, cards: { [did('agent')]: env.cards['attested'] }, ...options });

  /** What A's `withDelegation` sends to `url`. */
  async function sent(url = 'https://b.helix.test/mcp', options: Partial<Parameters<typeof withDelegation>[1]> = {}): Promise<Headers> {
    let captured: Headers | undefined;
    const fetchImpl = (async (_input: unknown, init?: RequestInit) => {
      captured = new Headers(init?.headers);
      return new Response('{}');
    }) as typeof fetch;
    const forward = withDelegation(fetchImpl, { signer: A(), context: context(), clock: () => NOW_MS, ...options });
    await forward(url, { method: 'POST', headers: { 'content-type': 'application/json', [DELEGATION_HEADERS.agentDid]: 'did:key:spoofed' } });
    return captured!;
  }

  it('B accepts the forwarded chain with no shared secret, deriving the agent, the root and the scopes from the signed artifacts', async () => {
    const headers = await sent();
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get(DELEGATION_HEADERS.agentDid)).toBe(did('agent'));
    expect(headers.get(DELEGATION_HEADERS.sessionId)).toBe('sess-1');
    expect(headers.get(DELEGATION_HEADERS.chain)).toBeNull();
    const result = await verifyInboundDelegationHeaders(headers, { verifier: verifierB(), forwarders: [did('service')] });
    expect(result).toMatchObject({
      ok: true,
      agentDid: did('agent'),
      forwarder: did('service'),
      responsibleParty: did('owner'),
      invocationTarget: did('service'),
      sessionId: 'sess-1',
      level: 'L2',
      fresh: true,
      cached: false,
      advisory: { dropped: [] },
    });
    expect(result.effectiveScopes.sort()).toEqual(['read:orders', 'write:orders']);
    expect(result.claims).toMatchObject({ iss: did('service'), sub: did('owner'), aud: 'b.helix.test', scope: 'read:orders,write:orders' });
    expect(result.claims!.exp - result.claims!.iat).toBe(60);
    expect(result.delegationId).toBe(chain[1]!['id']);
  });

  it('without the helper B refuses: no headers is no credential, and a forward B does not accept is refused', async () => {
    const guard = helixidMCPMiddleware({ verifier: verifierB(), toolScopes: { lookup_order: ['read:orders'] }, tools: { lookup_order: { minimumLevel: 'L2' } } });
    await expect(guard({ name: 'lookup_order', headers: {} })).rejects.toMatchObject({ code: 'PROOF_MISSING' });
    const refused = await verifyInboundDelegationHeaders(await sent(), { verifier: verifierB() });
    expect(refused).toMatchObject({ ok: false, reasons: ['delegation_target_not_accepted'], effectiveScopes: [], level: 'L1' });
  });

  it('tampered advisory headers change nothing in B\'s decision; they are dropped where they disagree', async () => {
    const honest = await sent(undefined, { advisoryHeaders: true });
    const clean = await verifyInboundDelegationHeaders(honest, { verifier: verifierB(), forwarders: [did('service')] });
    expect(clean.advisory).toEqual({ chain: buildChainString(chain), grantedScopes: ['read:orders', 'write:orders'], dropped: [] });
    const tampered = await sent(undefined, { advisoryHeaders: true });
    tampered.set(DELEGATION_HEADERS.grantedScopes, 'read:orders,write:orders,admin:everything');
    tampered.set(DELEGATION_HEADERS.chain, 'urn:uuid:forged>del-001');
    const result = await verifyInboundDelegationHeaders(tampered, { verifier: verifierB(), forwarders: [did('service')] });
    expect(result.ok).toBe(true);
    expect(result.effectiveScopes.sort()).toEqual(clean.effectiveScopes.sort());
    expect(result.advisory).toEqual({ dropped: ['chain', 'grantedScopes'] });
  });

  describe('the proof JWT', () => {
    const forwarded = async (claims: Partial<Parameters<typeof mintDelegationProofJwt>[0]>, signer = A(), extra: Record<string, string> = {}): Promise<Headers> => {
      const headers = await sent();
      headers.set(
        DELEGATION_HEADERS.proof,
        await mintDelegationProofJwt(
          { sub: did('owner'), aud: 'b.helix.test', delegation_id: delegationIdOf(chain)!, delegation_chain: buildChainString(chain), scope: 'read:orders', now: NOW_MS, ...claims },
          signer,
        ),
      );
      for (const [name, value] of Object.entries(extra)) headers.set(name, value);
      return headers;
    };
    const verify = async (headers: Headers): Promise<string[]> => (await verifyInboundDelegationHeaders(headers, { verifier: verifierB(), forwarders: [did('service')] })).reasons;

    it('refuses a wrong aud, an expired proof, a proof from the future and a sub that is not the chain root', async () => {
      expect(await verify(await forwarded({ aud: 'c.helix.test' }))).toEqual(['delegation_proof_audience']);
      expect(await verify(await forwarded({ now: NOW_MS - 120_000 }))).toEqual(['delegation_proof_expired']);
      expect(await verify(await forwarded({ now: NOW_MS + 120_000 }))).toEqual(['delegation_proof_not_yet_valid']);
      expect(await verify(await forwarded({ sub: did('parent') }))).toEqual(['delegation_subject_mismatch']);
      expect(await verify(await forwarded({ sub: did('agent') }))).toEqual(['delegation_subject_mismatch']);
    });

    it('refuses a KYA-OS-Agent-DID that is not the DID the chain binds, a wrong delegation_id or chain, and a replayed jti', async () => {
      expect(await verify(await forwarded({}, A(), { [DELEGATION_HEADERS.agentDid]: did('stranger') }))).toEqual(['agent_did_mismatch']);
      expect(await verify(await forwarded({ delegation_id: 'urn:zcap:other' }))).toEqual(['delegation_id_mismatch']);
      expect(await verify(await forwarded({ delegation_chain: 'urn:uuid:a>b' }))).toEqual(['delegation_chain_mismatch']);
      const verifier = verifierB();
      const once = await forwarded({ jti: 'urn:uuid:once' });
      expect((await verifyInboundDelegationHeaders(once, { verifier, forwarders: [did('service')] })).ok).toBe(true);
      expect((await verifyInboundDelegationHeaders(once, { verifier, forwarders: [did('service')] })).reasons).toEqual(['delegation_proof_replayed']);
    });

    it('refuses a proof a stranger signed, or signed under the forwarder\'s name with another key, and a lifetime over 60 s', async () => {
      expect(await verify(await forwarded({}, fixtureSigner(env, 'stranger')))).toEqual(['delegation_target_not_accepted']);
      // B treating A's resource as its own (a shared resource): a stranger still cannot carry the chain.
      const stranger = await forwarded({}, fixtureSigner(env, 'stranger'));
      expect((await verifyInboundDelegationHeaders(stranger, { verifier: verifierB(), resource: did('service') })).reasons).toEqual(['delegation_forwarder_unbound']);
      const impostor = { did: did('service'), kid: 'key-1', sign: (data: Uint8Array) => fixtureSigner(env, 'stranger').sign(data) };
      expect(await verify(await forwarded({}, impostor))).toEqual(['delegation_proof_invalid']);
      const long = await sent();
      const claims = { iss: did('service'), sub: did('owner'), aud: 'b.helix.test', iat: NOW_MS / 1000, exp: NOW_MS / 1000 + 3600, jti: 'j', delegation_id: delegationIdOf(chain)!, delegation_chain: buildChainString(chain), scope: '' };
      long.set(DELEGATION_HEADERS.proof, await kyaos.signJws(claims, A()));
      expect(await verify(long)).toEqual(['delegation_proof_lifetime']);
      long.set(DELEGATION_HEADERS.proof, 'not.a.jwt');
      expect(await verify(long)).toEqual(['delegation_proof_malformed']);
      long.set(DELEGATION_HEADERS.proof, await kyaos.signJws({ ...claims, exp: 'later' }, A()));
      expect(await verify(long)).toEqual(['delegation_proof_malformed']);
      long.set(DELEGATION_HEADERS.proof, await kyaos.signJws({ ...claims, sub: '' }, A()));
      expect(await verify(long)).toEqual(['delegation_proof_malformed']);
      long.set(DELEGATION_HEADERS.proof, await kyaos.signJws(claims, A(), { header: { typ: 'secevent+jwt' } }));
      expect(await verify(long)).toEqual(['delegation_proof_malformed']);
    });

    it('the scope claim narrows what B grants and never widens it', async () => {
      const narrowed = await verifyInboundDelegationHeaders(await forwarded({ scope: 'read:orders' }), { verifier: verifierB(), forwarders: [did('service')] });
      expect(narrowed.effectiveScopes).toEqual(['read:orders']);
      const widened = await verifyInboundDelegationHeaders(await forwarded({ scope: 'read:orders,write:orders,read:catalog,admin' }), { verifier: verifierB(), forwarders: [did('service')] });
      expect(widened.effectiveScopes.sort()).toEqual(['read:orders', 'write:orders']);
    });
  });

  it('refuses missing, duplicated or malformed headers and an overlong chain before verifying anything', async () => {
    const verify = async (headers: Record<string, string | string[]>): Promise<string[]> => (await verifyInboundDelegationHeaders(headers, { verifier: verifierB(), forwarders: '*' })).reasons;
    const good = Object.fromEntries((await sent()).entries());
    expect(await verify({ ...good, [DELEGATION_HEADERS.agentDid.toLowerCase()]: [] as never })).toEqual(['delegation_headers_missing']);
    expect(await verify({ ...good, [DELEGATION_HEADERS.proof.toLowerCase()]: ['a', 'b'] })).toEqual(['delegation_header_duplicated']);
    expect(await verify({ ...good, [DELEGATION_HEADERS.credential.toLowerCase()]: 'not base64url!' })).toEqual(['delegation_credential_malformed']);
    expect(await verify({ ...good, [DELEGATION_HEADERS.credential.toLowerCase()]: encodeDelegationCredential(Array(11).fill(chain[0])) })).toEqual(['chain_too_long']);
    expect((await verifyInboundDelegationHeaders(good, { verifier: fixtureVerifier('did:key:z6Mk-not-web', { env }), forwarders: '*' })).reasons).toEqual(['configuration_error']);
  });

  it('a chain the verifier refuses is refused with the verifier\'s reasons (a hop with a broken signature)', async () => {
    const tamperedChain = [chain[0], { ...chain[1]!, validUntil: '2026-11-30T00:00:00Z' }];
    const headers = await sent(undefined, { context: { ...context(), chain: tamperedChain } });
    const result = await verifyInboundDelegationHeaders(headers, { verifier: verifierB(), forwarders: [did('service')] });
    expect(result).toMatchObject({ ok: false, reasons: ['hop_proof_invalid'], agentDid: did('agent') });
  });

  describe('re-delegation: A appends a hop of its own', () => {
    // The agent's parent delegated to A (parent → A), so A holds the leaf and may issue its own hop under it.
    const toA = (): Record<string, unknown> =>
      hop(env, 'parent', {
        id: 'urn:zcap:00000000-0000-4000-8000-0000000d3d01',
        issuer: did('parent'),
        invoker: did('service'),
        parentCapability: chain[0]!['id'] as string,
        invocationTarget: did('service'),
        allowedAction: ['read:orders', 'write:orders'],
        caveats: [{ type: 'MaxAmount', limit: '500.00', currency: 'USD' }, { type: 'ValidUntil', date: '2026-11-01T00:00:00Z' }],
        status: { url: 'https://parent.example/status/1', index: '3' },
      });
    const own = (allowedAction: string[], validUntil = '2026-10-01T00:00:00Z'): Record<string, unknown> =>
      hop(env, 'service', {
        id: 'urn:zcap:00000000-0000-4000-8000-0000000d3d02',
        issuer: did('service'),
        invoker: did('service'),
        parentCapability: 'urn:zcap:00000000-0000-4000-8000-0000000d3d01',
        invocationTarget: did('service'),
        allowedAction,
        validUntil,
        caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }, { type: 'ValidUntil', date: '2026-10-01T00:00:00Z' }],
        status: { url: 'https://service.example/status/1', index: '1' },
      });
    const delegated = (): DelegationContext => ({ agentDid: did('parent'), chain: [chain[0]!, toA()], scopes: ['read:orders', 'write:orders'] });
    const cards = { [did('service')]: cardFor(env, did('service'), ['read:orders', 'write:orders'], did('owner')) };

    it('an attenuating hop holds: B verifies the three hops and grants no more than A\'s own hop allows', async () => {
      const headers = await sent(undefined, { context: delegated(), redelegate: () => own(['read:orders']) });
      const result = await verifyInboundDelegationHeaders(headers, { verifier: verifierB({ cards }), forwarders: [did('service')] });
      expect(result).toMatchObject({ ok: true, agentDid: did('parent'), forwarder: did('service'), effectiveScopes: ['read:orders'] });
      expect(result.chain).toHaveLength(3);
    });

    it('a broadening hop is refused by A before anything is sent, and by B when sent anyway', async () => {
      await expect(sent(undefined, { context: delegated(), redelegate: () => own(['read:orders', 'admin:all']) })).rejects.toBeInstanceOf(RedelegationError);
      await expect(sent(undefined, { context: delegated(), redelegate: () => own(['read:orders'], '2027-06-01T00:00:00Z') })).rejects.toThrow(/validUntil broadened/);
      await expect(sent(undefined, { context: delegated(), redelegate: () => ({ ...own(['read:orders']), issuer: did('stranger') }) })).rejects.toThrow();
      const broad = [chain[0]!, toA(), own(['read:orders', 'admin:all'])];
      const target = new URL('https://b.helix.test/mcp');
      const { headers } = await buildOutboundDelegation(target, { agentDid: did('parent'), chain: broad, scopes: ['read:orders'] }, { signer: A(), clock: () => NOW_MS });
      const result = await verifyInboundDelegationHeaders(headers, { verifier: verifierB({ cards }), forwarders: [did('service')] });
      expect(result).toMatchObject({ ok: false, reasons: ['attenuation_violation'] });
    });

    it('A cannot re-delegate a chain it does not hold: continuity breaks', async () => {
      await expect(sent(undefined, { redelegate: () => own(['read:orders']) })).rejects.toThrow(/broken continuity/);
    });
  });

  describe('the verification cache', () => {
    it('serves the second call from the cache (not fresh), keyed by credential id, and drops it at once on a revocation signal for any hop', async () => {
      const verifier = verifierB();
      const cache = VerificationCache.forStatusCache(verifier.statusCache, { clock: () => NOW_MS });
      const options = { verifier, forwarders: [did('service')], cache };
      expect(await verifyInboundDelegationHeaders(await sent(), options)).toMatchObject({ ok: true, cached: false, fresh: true });
      expect(await verifyInboundDelegationHeaders(await sent(), options)).toMatchObject({ ok: true, cached: true, fresh: false });
      // Helix revokes the root hop; its signal names the root credential only, and the leaf's verdict falls with it.
      // The default the signal client uses: the status cache plus every verification cache linked to it.
      const signals = revocationInvalidation(verifier.statusCache);
      await signals.invalidate(chain[0]!['id'] as string);
      expect(cache.size).toBe(0);
      expect(await verifyInboundDelegationHeaders(await sent(), options)).toMatchObject({ ok: true, cached: false });
    });

    it('is bypassed for a tool whose minimum level is L3 (status read live), and never holds a refusal', async () => {
      const verifier = verifierB();
      const cache = new VerificationCache({ clock: () => NOW_MS });
      await verifyInboundDelegationHeaders(await sent(), { verifier, forwarders: [did('service')], cache });
      expect(await verifyInboundDelegationHeaders(await sent(), { verifier, forwarders: [did('service')], cache, liveStatus: true })).toMatchObject({ cached: false, fresh: true });
      const refused = await verifyInboundDelegationHeaders(await sent(undefined, { context: { ...context(), chain: [chain[0], { ...chain[1]!, validUntil: 'x' }] } }), { verifier, forwarders: [did('service')], cache: new VerificationCache() });
      expect(refused.ok).toBe(false);
    });

    it('keeps an entry no longer than its TTL, 60 s at most for a high-privilege scope, and only for the very chain', async () => {
      let now = NOW_MS;
      const cache = new VerificationCache({ ttlSeconds: 300, highPrivilegeScopes: ['write:orders'], clock: () => now });
      expect(cache.ttlFor(['read:orders'])).toBe(300);
      expect(cache.ttlFor(['write:orders'])).toBe(60);
      const result = { ok: true, chainSummary: { allowedAction: ['read:orders', 'write:orders'] }, effectiveScopes: [] } as unknown as kyaos.verifier.VerifierResult;
      cache.set(chain, result);
      expect(cache.get(chain)).toBe(result);
      expect(cache.get([chain[0]!, { ...chain[1]!, validUntil: '2026-11-30T00:00:00Z' }])).toBeUndefined();
      now += 61_000;
      expect(cache.get(chain)).toBeUndefined();
      expect(cache.get([])).toBeUndefined();
      cache.set([{ no: 'id' }], result);
      cache.set(chain, { ...result, ok: false });
      expect(cache.size).toBe(0);
      expect(await revocationInvalidation({ invalidate: async () => 'credential' as const }, cache).invalidate(chain[1]!['id'] as string)).toBe('credential');
      expect(cache.size).toBe(0);
      expect(() => new VerificationCache({ highPrivilegeTtl: 61 })).toThrow(RangeError);
      expect(() => new VerificationCache({ ttlSeconds: 0 })).toThrow(RangeError);
      cache.set(chain, result);
      cache.clear();
      expect(cache.size).toBe(0);
      // A chain whose hop id is already in the graph under another parent is not cached.
      cache.set([chain[1]!], result);
      expect(cache.size).toBe(0);
    });
  });

  describe('auditing every outbound attachment', () => {
    it('records delegation.outbound_attached with the chain string and the target audience', async () => {
      const sink = new MemoryAuditSink();
      const trail = createMcpAuditTrail({ reporter: sink, serviceDid: did('service'), clock: () => NOW_MS });
      const attachments: OutboundAttachment[] = [];
      await sent(undefined, {
        audit: async (attachment) => {
          attachments.push(attachment);
          await trail.outboundAudit()(attachment);
        },
      });
      expect(attachments[0]).toMatchObject({ audience: 'b.helix.test', chainString: buildChainString(chain), agentDid: did('agent'), forwarder: did('service'), redelegated: false });
      const event = sink.events[0]!;
      expect(event).toMatchObject({
        eventType: 'delegation.outbound_attached',
        action: { category: 'delegation.outbound', name: buildChainString(chain) },
        outcome: 'succeeded',
        resource: { kind: 'public_did', did: 'did:web:b.helix.test' },
        actor: { kind: 'pairwise_did', did: did('agent') },
        responsibleParty: { kind: 'pairwise_did', did: did('owner') },
        causationId: attachments[0]!.jti,
        details: { family: 'delegation', phase: 'outbound_attached' },
        authorization: { source: 'delegation', decision: 'allowed' },
      });
      // Helix hops sign with a base58btc proofValue, which has no §7.8 signed form: the reference is the hop id.
      expect(event.authorization?.delegationRef).toBe(chain[1]!['id']);
      expect(event.details).toMatchObject({ delegationRef: chain[1]!['id'], parentRef: chain[0]!['id'] });
      await trail.outboundAttached(attachments[0]!, { targetDid: 'did:web:b.helix.test:services:0b' });
      expect(sink.events[1]!.resource).toEqual({ kind: 'public_did', did: 'did:web:b.helix.test:services:0b' });
      await trail.outboundAttached({ ...attachments[0]!, audience: 'not a host', chain: [chain[1]!] });
      expect(sink.events[2]!.resource).toBeUndefined();
      await trail.outboundAudit({ targetDid: () => 'did:web:c.helix.test' })(attachments[0]!);
      expect(sink.events[3]!.resource).toEqual({ kind: 'public_did', did: 'did:web:c.helix.test' });
    });

    it('an audit failure never blocks the call', async () => {
      const errors: unknown[] = [];
      const headers = await sent(undefined, { audit: () => { throw new Error('down'); }, onAuditError: (error) => errors.push(error) });
      expect(headers.get(DELEGATION_HEADERS.proof)).not.toBeNull();
      expect(errors).toHaveLength(1);
    });
  });

  describe('the guard (helixidMCPMiddleware) on B', () => {
    const guard = (options: Partial<Parameters<typeof helixidMCPMiddleware>[0]> = {}): ReturnType<typeof helixidMCPMiddleware> =>
      helixidMCPMiddleware({
        verifier: verifierB(),
        toolScopes: { lookup_order: ['read:orders'], refund: ['admin:refund'] },
        tools: { lookup_order: { minimumLevel: 'L2' }, refund: { minimumLevel: 'L2' } },
        inboundDelegation: { forwarders: [did('service')] },
        ...options,
      });

    it('authorizes a forwarded call as the agent, at L2, with the forwarder named', async () => {
      const caller = await guard().authorize({ name: 'lookup_order', headers: await sent() });
      expect(caller).toMatchObject({ authMethod: 'kyaos', agentDid: did('agent'), level: 'L2', proofFloor: false, forwardedBy: did('service') });
      expect(caller.chain).toHaveLength(2);
      expect(delegationContextOf(caller, { sessionId: 's' })).toMatchObject({ agentDid: did('agent'), sessionId: 's' });
    });

    it('refuses a scope the chain does not grant, a tool that demands L3 (no agent proof downstream), and a refused proof', async () => {
      const events: unknown[] = [];
      const g = guard({ auditSink: (event) => void events.push(event) });
      await expect(g({ name: 'refund', headers: await sent() })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
      await expect(guard({ tools: {} })({ name: 'lookup_order', headers: await sent() })).rejects.toMatchObject({ code: 'PROOF_LEVEL_INSUFFICIENT' });
      const stranger = await sent();
      stranger.set(DELEGATION_HEADERS.agentDid, did('stranger'));
      await expect(g({ name: 'lookup_order', headers: stranger })).rejects.toMatchObject({ code: 'PROOF_INVALID' });
      const replayed = await sent();
      await g({ name: 'lookup_order', headers: replayed });
      await expect(g({ name: 'lookup_order', headers: replayed })).rejects.toMatchObject({ code: 'PROOF_INVALID', reasons: ['delegation_proof_replayed'] });
      expect(events.some((event) => (event as { reason?: string }).reason === 'delegation_proof_replayed')).toBe(true);
    });

    it('refuses headers next to a request proof, ignores them when inbound delegation is off, and needs a verifier', async () => {
      const headers = await sent();
      const meta = await proofMeta(fixtureSigner(env, 'agent'), B.did, { name: 'lookup_order' }, chain);
      await expect(guard()({ name: 'lookup_order', headers, _meta: meta })).rejects.toMatchObject({ code: 'CREDENTIAL_CONFLICT' });
      await expect(guard({ inboundDelegation: false })({ name: 'lookup_order', headers })).rejects.toMatchObject({ code: 'PROOF_MISSING' });
      await expect(helixidMCPMiddleware({ toolScopes: { lookup_order: [] } })({ name: 'lookup_order', headers })).rejects.toThrow(/verifier/);
      const own = new VerificationCache();
      await guard({ inboundDelegation: { forwarders: [did('service')], cache: own, audience: 'b.helix.test' } })({ name: 'lookup_order', headers: await sent() });
      expect(own.size).toBe(1);
      await guard({ inboundDelegation: { forwarders: [did('service')], cache: false } })({ name: 'lookup_order', headers: await sent() });
    });

    it('an agent\'s own call carries its chain on the caller, for the handler to forward', async () => {
      const verifierA = fixtureVerifier(did('service'), { env, cards: { [did('agent')]: env.cards['attested'] } });
      const guardA = helixidMCPMiddleware({ verifier: verifierA, toolScopes: { lookup_order: ['read:orders'] }, tools: { lookup_order: { minimumLevel: 'L2' } } });
      const meta = await proofMeta(fixtureSigner(env, 'agent'), did('service'), { name: 'lookup_order' }, chain);
      const caller = await guardA.authorize({ name: 'lookup_order', _meta: meta });
      const forwarded = delegationContextOf(caller)!;
      expect(forwarded.chain).toEqual(chain);
      let seen: Headers | undefined;
      const forward = withDelegation((async (_url: unknown, init?: RequestInit) => {
        seen = new Headers(init?.headers);
        return new Response('{}');
      }) as typeof fetch, { signer: A(), clock: () => NOW_MS });
      await runWithDelegation(forwarded, async () => {
        expect(currentDelegation()).toBe(forwarded);
        await forward(new Request('https://b.helix.test/mcp', { method: 'POST' }));
      });
      expect((await verifyInboundDelegationHeaders(seen!, { verifier: verifierB(), forwarders: [did('service')] })).ok).toBe(true);
      await expect(forward(new URL('https://b.helix.test/mcp'))).rejects.toBeInstanceOf(DelegationContextMissingError);
      await expect(withDelegation(fetch, { signer: A(), context: () => undefined })('https://b.helix.test')).rejects.toBeInstanceOf(DelegationContextMissingError);
      await expect(withDelegation(fetch, { signer: A(), context: { agentDid: 'x', chain: [{}], scopes: [] } })('https://b.helix.test')).rejects.toBeInstanceOf(DelegationContextMissingError);
      expect(delegationContextOf({ authMethod: 'oauth', scopes: [] })).toBeUndefined();
    });
  });

  it('the scopes option narrows what is forwarded', async () => {
    const headers = await sent(undefined, { scopes: (ctx) => ctx.scopes.filter((scope) => scope === 'write:orders') });
    const result = await verifyInboundDelegationHeaders(headers, { verifier: verifierB(), forwarders: '*' });
    expect(result.effectiveScopes).toEqual(['write:orders']);
    const fixed = await sent(undefined, { scopes: ['read:orders'] });
    expect((await verifyInboundDelegationHeaders(fixed, { verifier: verifierB(), forwarders: '*' })).effectiveScopes).toEqual(['read:orders']);
  });

  it('agentOfChain names the leaf delegate, or who delegated to the forwarder', () => {
    expect(agentOfChain(chain, did('service'))).toBe(did('agent'));
    const toService = [{ ...chain[0]!, credentialSubject: { ...(chain[0]!['credentialSubject'] as object), invoker: did('service') } }];
    expect(agentOfChain(toService, did('service'))).toBe(did('service'));
    expect(agentOfChain([chain[0]!, { issuer: 7, credentialSubject: { invoker: did('service') } }], did('service'))).toBeUndefined();
  });
});

describe('L3.23 / L3.24: the delegation proof JWT and the chain string', () => {
  const signer = (): kyaos.Signer => {
    const keys = { private: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' };
    return new kyaos.EnvSigner({ did: 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw', envVar: 'K', env: { K: keys.private } });
  };
  const base = { sub: 'did:key:root', aud: 'downstream.example', delegation_id: 'del-123', delegation_chain: 'vc-abc>del-123', scope: ['read', 'write'] };

  it('produces a compact EdDSA JWT with every §8.2 claim, exp 60 s after iat and a unique jti', async () => {
    const jwt = await mintDelegationProofJwt(base, signer());
    expect(jwt.split('.')).toHaveLength(3);
    const header = kyaos.readJwsHeader(jwt);
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'JWT', kid: `${signer().did}#${signer().kid}` });
    const result = await verifyDelegationProofJwt(jwt, { resolveDid: async (d) => kyaos.verifier.didKeyDocument(d) ?? null, audience: ['other', 'downstream.example'], now: Date.now() });
    expect(result.ok).toBe(true);
    const claims = (result as { claims: Record<string, unknown> }).claims;
    expect(claims).toMatchObject({ iss: signer().did, sub: 'did:key:root', aud: 'downstream.example', delegation_id: 'del-123', delegation_chain: 'vc-abc>del-123', scope: 'read,write' });
    expect((claims['exp'] as number) - (claims['iat'] as number)).toBe(60);
    const other = await mintDelegationProofJwt({ ...base, scope: 'read' }, signer());
    expect(JSON.parse(Buffer.from(other.split('.')[1]!, 'base64url').toString()).jti).not.toBe(claims['jti']);
  });

  it('throws for a signer that is not the iss, a missing claim, or a key that cannot sign', async () => {
    await expect(mintDelegationProofJwt({ ...base, iss: 'did:key:other' }, signer())).rejects.toThrow(/iss/);
    await expect(mintDelegationProofJwt({ ...base, aud: '' }, signer())).rejects.toThrow(/aud/);
    await expect(mintDelegationProofJwt(base, { did: 'did:key:x', kid: 'k', sign: async () => new Uint8Array(3) })).rejects.toThrow();
  });

  it('buildChainString: one hop, three hops concatenated, a hop with one id, and an empty chain', () => {
    expect(chainStringOf({ vcId: 'vc-abc', id: 'del-123' })).toBe('vc-abc>del-123');
    expect(chainStringOf({ id: 'del-123' })).toBe('del-123');
    expect(chainStringOf({ vcId: 'vc-abc' })).toBe('vc-abc');
    expect(chainStringOf({})).toBe('');
    const hopOf = (vc: string, del: string): Record<string, unknown> => ({ id: vc, credentialSubject: { id: del } });
    expect(buildChainString([hopOf('vc-1', 'del-1'), hopOf('vc-2', 'del-2'), hopOf('vc-3', 'del-3')])).toBe('vc-1>del-1>vc-2>del-2>vc-3>del-3');
    expect(buildChainString([])).toBe('');
    expect(buildChainString([7, { credentialSubject: 'x' }])).toBe('');
    expect(delegationIdOf([hopOf('vc-1', 'del-1')])).toBe('del-1');
    expect(delegationIdOf([{ id: 'vc' }])).toBeUndefined();
    expect(scopeList(' a, b,,a ')).toEqual(['a', 'b']);
  });

  it('header codec and helpers', () => {
    expect(decodeDelegationCredential(encodeDelegationCredential([{ a: 1 }]))).toEqual([{ a: 1 }]);
    expect(decodeDelegationCredential(Buffer.from('{"a":1}').toString('base64url'))).toEqual([{ a: 1 }]);
    expect(decodeDelegationCredential(Buffer.from('[]').toString('base64url'))).toBeUndefined();
    expect(decodeDelegationCredential(Buffer.from('7').toString('base64url'))).toBeUndefined();
    expect(decodeDelegationCredential(Buffer.from('{').toString('base64url'))).toBeUndefined();
    expect(decodeDelegationCredential('')).toBeUndefined();
    expect(hasDelegationHeaders(undefined)).toBe(false);
    expect(hasDelegationHeaders(new Headers({ [DELEGATION_HEADERS.proof]: 'x' }))).toBe(true);
    expect(hasDelegationHeaders({ 'kya-os-delegation-credential': ['x'] })).toBe(true);
    expect(hostOfDidWeb('did:web:127.0.0.1%3A3000:services:ab')).toBe('127.0.0.1:3000');
    expect(hostOfDidWeb('did:key:z6Mk')).toBeUndefined();
    expect(hostOfDidWeb('did:web:')).toBeUndefined();
    expect(hostOfDidWeb('did:web:%E0%A4%A')).toBeUndefined();
  });
});
