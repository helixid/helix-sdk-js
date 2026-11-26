// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story C-C: the per-request holder-of-key proof, the cnf fusion, chains without a proof and the minimum Card level.

import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import {
  DEFAULT_MINIMUM_LEVEL,
  LevelError,
  assertLevelPolicy,
  deriveConformanceLevel,
  derivedLevelOf,
  helixidMCPMiddleware,
  meetsMinimumLevel,
  minimumLevelFor,
  toHttpErrorResponse,
  verifyRequestProof,
  type ToolAuditEvent,
} from '../src/index.js';
import { fixtureSigner, fixtureVerifier, haveVerifierFixtures, loadCases, loadEnvironment, makeAgent, proofMeta, thumbprintOfHex, NOW_MS } from './proof-helpers.js';

const SERVICE = 'did:web:orders.helix.test';

describe('level policy helpers', () => {
  it('orders the levels, with L3-minus meeting L3 only when the policy says so', () => {
    expect(DEFAULT_MINIMUM_LEVEL).toBe('L3');
    expect(meetsMinimumLevel('L3', 'L3')).toBe(true);
    expect(meetsMinimumLevel('L2', 'L3')).toBe(false);
    expect(meetsMinimumLevel('L2', 'L2')).toBe(true);
    expect(meetsMinimumLevel('L1', 'L2')).toBe(false);
    expect(meetsMinimumLevel('L1', 'L1')).toBe(true);
    expect(meetsMinimumLevel('L3-minus', 'L3')).toBe(true);
    expect(meetsMinimumLevel('L3-minus', 'L3', false)).toBe(false);
    expect(meetsMinimumLevel('L3-minus', 'L2', false)).toBe(true);
    expect(derivedLevelOf('L3', 'L3-minus')).toBe('L3-minus');
    expect(derivedLevelOf('L3', 'L3')).toBe('L3');
    expect(derivedLevelOf('L2', 'L3-minus')).toBe('L2');
    expect(derivedLevelOf('L2', undefined)).toBe('L2');
  });

  it('takes a tool override, else the policy minimum, else L3', () => {
    const policy = { minimumLevel: 'L2' as const, tools: { lookup: { minimumLevel: 'L1' as const }, other: {} } };
    expect(minimumLevelFor(policy, 'lookup')).toBe('L1');
    expect(minimumLevelFor(policy, 'other')).toBe('L2');
    expect(minimumLevelFor(policy, 'unlisted')).toBe('L2');
    expect(minimumLevelFor({}, undefined)).toBe('L3');
    expect(minimumLevelFor({ tools: { toString: { minimumLevel: 'L1' } } }, 'hasOwnProperty')).toBe('L3');
  });

  it('refuses a policy naming a level that does not exist', () => {
    expect(() => assertLevelPolicy({ minimumLevel: 'L4' as never })).toThrow(/minimumLevel must be one of L1, L2, L3/);
    expect(() => assertLevelPolicy({ tools: { t: { minimumLevel: 'l2' as never } } })).toThrow(/tools\.t\.minimumLevel/);
    expect(() => helixidMCPMiddleware({ minimumLevel: 'L3-minus' as never })).toThrow(/minimumLevel/);
    expect(() => assertLevelPolicy({ minimumLevel: 'L2', tools: { t: { minimumLevel: 'L1' }, u: {} } })).not.toThrow();
  });

  it('derives the level per §9.4 from attestations, the proof floor and freshness', () => {
    const all = { verified: ['a'], unverified: [] };
    expect(deriveConformanceLevel(all, true, true)).toBe('L3');
    expect(deriveConformanceLevel(all, { ok: true })).toBe('L3');
    expect(deriveConformanceLevel(all, { ok: false })).toBe('L2');
    expect(deriveConformanceLevel(all, true, false)).toBe('L2');
    expect(deriveConformanceLevel(all)).toBe('L2');
    expect(deriveConformanceLevel({ verified: ['a'], unverified: ['b'] }, true, true)).toBe('L1');
    expect(deriveConformanceLevel({ verified: [], unverified: [] }, true, true)).toBe('L1');
  });

  it('answers a level refusal with 401 insufficient_user_authentication carrying both levels', () => {
    const response = toHttpErrorResponse(new LevelError('L2', 'L3'), { resourceMetadataUrl: 'https://svc/.well-known/oauth-protected-resource' });
    expect(response).toMatchObject({ status: 401, body: { error: 'insufficient_user_authentication', derivedLevel: 'L2', requiredLevel: 'L3' } });
    expect(response!.headers['WWW-Authenticate']).toContain('error="insufficient_user_authentication"');
    expect(new LevelError('L3-minus', 'L3')).toMatchObject({ code: 'PROOF_LEVEL_INSUFFICIENT', httpStatus: 401, reasons: ['proof_level_insufficient'], derivedLevel: 'L3-minus' });
  });
});

describe('verifyRequestProof (§11.2 order, through the local verifier)', () => {
  const agent = makeAgent();
  const verifierOf = () => fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
  const call = { name: 't', input: { a: 1 } };

  it('verifies and spends a proof; the same proof again is a replay', async () => {
    const verifier = verifierOf();
    const _meta = await proofMeta(agent.signer, SERVICE, call);
    expect(await verifyRequestProof(verifier, { ...call, _meta })).toMatchObject({ ok: true, did: agent.did, assurance: 'L3-minus', reasons: [] });
    expect((await verifyRequestProof(verifier, { ...call, _meta })).reasons).toEqual(['nonce_replayed']);
  });

  it('stops at the first broken binding in the spec order', async () => {
    const verifier = verifierOf();
    const tamper = (meta: Record<string, unknown>): Record<string, unknown> => {
      const proof = meta['org.kya-os/request-proof'] as { jws: string };
      return { 'org.kya-os/request-proof': { ...proof, jws: `${proof.jws.slice(0, -2)}AA` } };
    };
    // Audience (step 5) before the signature (step 9).
    expect((await verifyRequestProof(verifier, { ...call, _meta: tamper(await proofMeta(agent.signer, 'did:web:other', call)) })).reasons).toEqual(['audience_mismatch']);
    // The window (step 7) before the nonce and the signature.
    expect((await verifyRequestProof(verifier, { ...call, _meta: tamper(await proofMeta(agent.signer, SERVICE, call, undefined, { now: NOW_MS - 600_000 })) })).reasons).toEqual(['expired']);
    // The nonce (step 8) before the signature (step 9): a spent nonce under a bad signature is a replay.
    const good = await proofMeta(agent.signer, SERVICE, call);
    expect((await verifyRequestProof(verifier, { ...call, _meta: good })).ok).toBe(true);
    expect((await verifyRequestProof(verifier, { ...call, _meta: tamper(good) })).reasons).toEqual(['nonce_replayed']);
    expect((await verifyRequestProof(verifier, { ...call, _meta: tamper(await proofMeta(agent.signer, SERVICE, call)) })).reasons).toEqual(['invalid_signature']);
  });

  it('fuses the token cnf and passes the skew window through', async () => {
    const jkt = thumbprintOfHex(agent.publicKeyHex);
    const verifier = verifierOf();
    const _meta = await proofMeta(agent.signer, SERVICE, call, undefined, { cnfJkt: jkt, now: NOW_MS + 64_000 });
    // 64 s ahead of the clock: outside ±5 s, inside ±10 s.
    expect((await verifyRequestProof(verifier, { ...call, _meta }, { tokenCnfJkt: jkt })).reasons).toEqual(['created_in_future']);
    expect(await verifyRequestProof(verifier, { ...call, _meta }, { tokenCnfJkt: jkt, skewSeconds: 70 })).toMatchObject({ ok: true, assurance: 'L3' });
  });

  it('refuses a call with no proof as proof_missing', async () => {
    expect((await verifyRequestProof(verifierOf(), { ...call })).reasons).toEqual(['proof_missing']);
  });
});

describe('the guard: proofs, tokens and legacy carriers', () => {
  const agent = makeAgent();
  const jkt = thumbprintOfHex(agent.publicKeyHex);
  const guard = (options: Omit<Parameters<typeof helixidMCPMiddleware>[0], 'verifier'> = {}) =>
    helixidMCPMiddleware({ verifier: fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } }), requiredScopes: [], minimumLevel: 'L1', ...options });
  const call = { name: 't', input: { a: 1 } };

  it('fuses a sender-constrained token with the proof for L3, from AuthResult.cnfJkt or the token claims', async () => {
    const byField = guard({ validateOAuthToken: async () => ({ sub: 'u', cnfJkt: jkt }) });
    const headers = { authorization: 'Bearer tok' };
    const fused = await byField.authorize({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { cnfJkt: jkt }) });
    expect(fused).toMatchObject({ authMethod: 'kyaos', agentDid: agent.did, proofAssurance: 'L3', proofFloor: true });
    expect(fused.oauthSubject).toBeUndefined();
    const byClaims = guard({ validateOAuthToken: async () => ({ sub: 'u', claims: { cnf: { jkt } } }) });
    expect((await byClaims.authorize({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { cnfJkt: jkt }) })).proofAssurance).toBe('L3');
    // A token with no cnf leaves the proof at L3-minus.
    const plain = guard({ validateOAuthToken: async () => ({ sub: 'u' }) });
    expect((await plain.authorize({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call) })).proofAssurance).toBe('L3-minus');
  });

  it('refuses a downgrade (token cnf, proof without), a cnf that is not the token\'s, and a token nobody can check', async () => {
    const mw = guard({ validateOAuthToken: async () => ({ sub: 'u', cnfJkt: jkt }) });
    const headers = { authorization: 'Bearer tok' };
    await expect(mw({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call) })).rejects.toMatchObject({ code: 'PROOF_INVALID', reasons: ['cnf_required_by_token'] });
    const other = makeAgent('did:web:other.helix.test');
    const mismatched = guard({ validateOAuthToken: async () => ({ sub: 'u', cnfJkt: thumbprintOfHex(other.publicKeyHex) }) });
    await expect(mismatched({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { cnfJkt: jkt }) })).rejects.toMatchObject({ reasons: ['cnf_token_mismatch'] });
    await expect(guard()({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call) })).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
    const failing = guard({ validateOAuthToken: async () => { throw new Error('no'); } });
    await expect(failing({ ...call, headers, _meta: await proofMeta(agent.signer, SERVICE, call) })).rejects.toMatchObject({ code: 'OAUTH_TOKEN_INVALID' });
  });

  it('records the cnf diagnostic when a proof carries cnf and no token was given to fuse it', async () => {
    const events: ToolAuditEvent[] = [];
    const mw = guard({ auditSink: (e) => void events.push(e), serviceDid: SERVICE });
    const caller = await mw.authorize({ ...call, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { cnfJkt: jkt }) });
    expect(caller.cnfDiagnostics).toEqual(['cnf_present_but_token_unfused']);
    expect(events[0]).toMatchObject({ cnfDiagnostics: ['cnf_present_but_token_unfused'], proofAssurance: 'L3-minus' });
  });

  it('reads the canonical key when both keys are present, whatever the legacy one holds', async () => {
    const mw = guard();
    const canonical = (await proofMeta(agent.signer, SERVICE, call))['org.kya-os/request-proof'];
    const legacy = (await proofMeta(agent.signer, SERVICE, call, undefined, { legacyKey: true }))['org.kya-os/proof@1'];
    await expect(mw({ ...call, _meta: { 'org.kya-os/request-proof': canonical, 'org.kya-os/proof@1': { junk: true } } })).resolves.toBeDefined();
    await expect(mw({ ...call, _meta: { 'org.kya-os/request-proof': { junk: true }, 'org.kya-os/proof@1': legacy } })).rejects.toMatchObject({ reasons: ['malformed_proof'] });
    await expect(mw({ ...call, _meta: { 'org.kya-os/proof@1': legacy } })).resolves.toBeDefined();
  });

  it('accepts the legacy prf, and never covers _meta in requestHash: tampering _meta changes nothing, tampering arguments fails', async () => {
    const mw = guard();
    const request: kyaos.verifier.ProofRequest = { method: 'tools/call', params: { name: 't', arguments: { a: 1 } } };
    const legacyPrf = await kyaos.verifier.signRequestProof(request, agent.signer, { audience: SERVICE, now: NOW_MS, profile: 'org.kya-os/proof@1' });
    await expect(mw({ ...call, _meta: { 'org.kya-os/request-proof': legacyPrf } })).resolves.toBeDefined();
    const meta = await proofMeta(agent.signer, SERVICE, call);
    await expect(mw({ ...call, _meta: { ...meta, progressToken: 'p-1', 'vendor/extra': { anything: true } } })).resolves.toBeDefined();
    await expect(mw({ name: 't', input: { a: 2 }, _meta: await proofMeta(agent.signer, SERVICE, call) })).rejects.toMatchObject({ reasons: ['request_hash_mismatch'] });
  });

  it('refuses a proof whose kid names another DID, a key the DID does not publish, and an expired or future proof', async () => {
    const mw = guard();
    const proof = (await proofMeta(agent.signer, SERVICE, call))['org.kya-os/request-proof'] as Record<string, unknown>;
    await expect(mw({ ...call, _meta: { 'org.kya-os/request-proof': { ...proof, kid: 'did:web:other.helix.test#key-1' } } })).rejects.toMatchObject({ reasons: ['kid_did_mismatch'] });
    const noKeys = helixidMCPMiddleware({
      verifier: fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document }, resolveDidKeys: async () => [] }),
      requiredScopes: [],
      minimumLevel: 'L1',
    });
    await expect(noKeys({ ...call, _meta: await proofMeta(agent.signer, SERVICE, call) })).rejects.toMatchObject({ reasons: ['kid_not_in_did_document'] });
    await expect(mw({ ...call, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { now: NOW_MS - 120_000 }) })).rejects.toMatchObject({ reasons: ['expired'] });
    await expect(mw({ ...call, _meta: await proofMeta(agent.signer, SERVICE, call, undefined, { now: NOW_MS + 120_000 }) })).rejects.toMatchObject({ reasons: ['created_in_future'] });
  });
});

describe.skipIf(!haveVerifierFixtures)('the guard: levels over the shared fixtures (signed chains, attested cards)', () => {
  const env = loadEnvironment();
  const service = env.keys['service']!.did;
  const agentDid = env.keys['agent']!.did;
  const agentSigner = fixtureSigner(env, 'agent');
  const valid = loadCases('valid');
  const chainOf = (name: string): unknown => valid.find((c) => c.name === name)!.input.chain;
  const fresh = chainOf('two_hop_chain');
  const cached = chainOf('cached_status_demotes_to_l2');
  const lookup = { name: 'lookup_order', input: { orderId: 'ORD-1001' } };
  const toolScopes = { lookup_order: ['read:orders'] };
  const guard = (card: string, options: Omit<Parameters<typeof helixidMCPMiddleware>[0], 'verifier'> = {}) =>
    helixidMCPMiddleware({ verifier: fixtureVerifier(service, { env, cards: { [agentDid]: env.cards[card] } }), toolScopes, ...options });

  it('valid proof + attested card + live status → L3, allowed under the default minimum', async () => {
    const caller = await guard('attested').authorize({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh) });
    expect(caller).toMatchObject({ level: 'L3', fresh: true, proofFloor: true, proofAssurance: 'L3-minus' });
  });

  it('the same with a cached status read → L2: refused for an L3 tool with the derived level, allowed for an L2 tool', async () => {
    const events: ToolAuditEvent[] = [];
    const strict = guard('attested', { auditSink: (e) => void events.push(e) });
    const refused = await strict({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, cached) }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(LevelError);
    expect(refused).toMatchObject({ derivedLevel: 'L2', requiredLevel: 'L3' });
    expect(events[0]).toMatchObject({ event: 'AUTHZ_DENIED', level: 'L2', fresh: false, requiredLevel: 'L3', reason: 'level_insufficient: L2 < L3', agentDid });
    const relaxed = guard('attested', { tools: { lookup_order: { minimumLevel: 'L2' } } });
    expect(await relaxed.authorize({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, cached) })).toMatchObject({ level: 'L2', fresh: false });
  });

  it('L3-minus is refused for an L3 tool only when l3MinusSatisfiesL3 is false; the token cnf fusion lifts it to L3', async () => {
    const events: ToolAuditEvent[] = [];
    const strict = guard('attested', { l3MinusSatisfiesL3: false, auditSink: (e) => void events.push(e) });
    await expect(strict({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh) })).rejects.toMatchObject({ derivedLevel: 'L3-minus', requiredLevel: 'L3' });
    expect(events[0]).toMatchObject({ event: 'AUTHZ_DENIED', level: 'L3', proofAssurance: 'L3-minus', l3Minus: true });
    const jkt = kyaos.verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(env.keys['agent']!.public_key_hex, 'hex').toString('base64url') });
    const fused = guard('attested', { l3MinusSatisfiesL3: false, validateOAuthToken: async () => ({ sub: 'agent', cnfJkt: jkt }) });
    const caller = await fused.authorize({ ...lookup, headers: { authorization: 'Bearer t' }, _meta: await proofMeta(agentSigner, service, lookup, fresh, { cnfJkt: jkt }) });
    expect(caller).toMatchObject({ level: 'L3', proofAssurance: 'L3' });
    // Default policy: L3-minus satisfies L3.
    expect((await guard('attested').authorize({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh) })).proofAssurance).toBe('L3-minus');
  });

  it('an unattested capability → L1, refused even for an L2 tool', async () => {
    const mw = guard('one_bare', { minimumLevel: 'L2' });
    await expect(mw({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh) })).rejects.toMatchObject({ derivedLevel: 'L1', requiredLevel: 'L2' });
  });

  it('a chain without a proof: refused for an L3 tool, accepted for a tool set to L2, the leaf delegate as the unproven agent', async () => {
    const events: ToolAuditEvent[] = [];
    const chainOnly = { 'org.kya-os/delegation-chain': fresh };
    await expect(guard('attested')({ ...lookup, _meta: chainOnly })).rejects.toMatchObject({ code: 'PROOF_LEVEL_INSUFFICIENT', derivedLevel: 'L2', requiredLevel: 'L3' });
    const l2 = guard('attested', { tools: { lookup_order: { minimumLevel: 'L2' } }, auditSink: (e) => void events.push(e) });
    const caller = await l2.authorize({ ...lookup, _meta: chainOnly });
    expect(caller).toMatchObject({ authMethod: 'kyaos', agentDid, level: 'L2', proofFloor: false, scopes: ['read:orders', 'write:orders'] });
    expect(caller.proofAssurance).toBeUndefined();
    expect(events[0]).toMatchObject({ event: 'AUTHZ_GRANTED', level: 'L2', l3Minus: false, fresh: true });
    expect(events[0]!.proofAssurance).toBeUndefined();
    // The chain is verified in full all the same: a broken one is refused whatever the tool's level.
    const broken = [...(fresh as unknown[])].reverse();
    await expect(l2({ ...lookup, _meta: { 'org.kya-os/delegation-chain': broken } })).rejects.toMatchObject({ code: 'PROOF_INVALID' });
  });

  it('refuses leafInvoker !== proof.did and responsibleParty !== issuer(root)', async () => {
    const stranger = fixtureSigner(env, 'stranger');
    const mw = helixidMCPMiddleware({ verifier: fixtureVerifier(service, { env }), toolScopes, minimumLevel: 'L1' });
    await expect(mw({ ...lookup, _meta: await proofMeta(stranger, service, lookup, fresh) })).rejects.toMatchObject({ reasons: ['leaf_invoker_mismatch'] });
    const wrongParty = guard('stranger_responsible', { minimumLevel: 'L1' });
    await expect(wrongParty({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh) })).rejects.toMatchObject({ reasons: ['root_not_responsible_party'] });
  });

  it('reports the level, the proof floor, L3-minus and the cnf diagnostics to the verification hook', async () => {
    const reports: unknown[] = [];
    const verifier = fixtureVerifier(service, { env, cards: { [agentDid]: env.cards['attested'] }, reportVerification: (r) => void reports.push(r) });
    const mw = helixidMCPMiddleware({ verifier, toolScopes });
    const jkt = kyaos.verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(env.keys['agent']!.public_key_hex, 'hex').toString('base64url') });
    await mw({ ...lookup, _meta: await proofMeta(agentSigner, service, lookup, fresh, { cnfJkt: jkt }) });
    await mw({ ...lookup, _meta: { 'org.kya-os/delegation-chain': fresh } }).catch(() => undefined);
    expect(reports[0]).toMatchObject({ ok: true, level: 'L3', proofFloor: true, l3Minus: true, cnfDiagnostics: ['cnf_present_but_token_unfused'], agentDid });
    expect(reports[1]).toMatchObject({ ok: true, level: 'L2', proofFloor: false, l3Minus: false, cnfDiagnostics: [], agentDid });
  });
});
