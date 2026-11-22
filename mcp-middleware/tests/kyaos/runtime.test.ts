// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the handshake tool, sessions and the proof around every tool call (L2.1 to L2.15, L2.17).
import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import {
  HANDSHAKE_INPUT_SCHEMA,
  KyaOsError,
  MemoryNonceStore,
  MemorySessionStore,
  NO_SESSION_ID,
  createKyaOs,
  type KyaOsAllowed,
  type KyaOsDenied,
  type KyaOsOptions,
  type NonceStore,
} from '../../src/kyaos/index.js';
import { AGENT, NOW, ORIGIN, SERVER, clock, handshakeArgs, resolveDid, signer } from './helpers.js';

const SECOND = 1000;
const SESSION_ID = /^kyaos_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function runtime(overrides: Partial<KyaOsOptions> = {}) {
  const time = clock();
  const kya = createKyaOs({ signer, publicOrigin: ORIGIN, now: time.now, ...overrides });
  return { kya, time };
}

async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof KyaOsError) return error.reason;
    throw error;
  }
  throw new Error('expected a refusal');
}

const call = (args: Record<string, unknown> = { orderId: 'ORD-1001' }, meta?: Record<string, unknown>) => ({
  name: 'lookup_order',
  arguments: args,
  ...(meta ? { _meta: meta } : {}),
});
const body = { content: [{ type: 'text', text: '{"id":"ORD-1001"}' }], structuredContent: { id: 'ORD-1001' } };

describe('createKyaOs', () => {
  it('derives the server DID from the signer and validates the config', () => {
    const { kya } = runtime();
    expect(kya.serverDid).toBe(SERVER);
    expect(kya.clockSkewSeconds).toBe(120);
    expect(kya.sessionsEnabled).toBe(true);
    expect(kya.handshakeToolName).toBe('_kyaos_handshake');
    expect(kya.isHandshake('_kyaos_handshake')).toBe(true);
    expect(kya.isHandshake('lookup_order')).toBe(false);
    expect(kya.isHandshake(undefined)).toBe(false);
    expect(kya.nonceStore).toBeInstanceOf(MemoryNonceStore);
    expect(kya.sessionStore).toBeInstanceOf(MemorySessionStore);
    expect(kya.describe()).toEqual({ endpoints: { handshake: '/mcp#_kyaos_handshake' }, clockSkewSeconds: 120, capabilities: { proofs: true }, handshakeTool: '_kyaos_handshake' });
    expect(createKyaOs({ signer, serverDid: SERVER }).serverDid).toBe(SERVER);
    expect(() => createKyaOs({ signer, serverDid: 'did:web:other.example' })).toThrow("is not the signer's DID");
    expect(() => createKyaOs({ signer: { did: 'orders', kid: 'key-1', sign: signer.sign.bind(signer) } })).toThrow('must be a DID');
    expect(() => createKyaOs({ signer, clockSkewSeconds: 29 })).toThrow(RangeError);
    expect(createKyaOs({ signer, clockSkewSeconds: 600, session: { enabled: false, ttlMinutes: 5 }, toolsEndpoint: '/api/mcp' }).describe()).toEqual({
      endpoints: {},
      clockSkewSeconds: 600,
      capabilities: { proofs: true },
      handshakeTool: '_kyaos_handshake',
    });
    expect(createKyaOs({ signer, session: { ttlMinutes: 5 } }).sessionStore.ttlMinutes).toBe(5);
    expect(createKyaOs({ signer }).sessionStore.ttlMinutes).toBe(30);
    expect(HANDSHAKE_INPUT_SCHEMA.required).toEqual(['nonce', 'audience', 'timestamp']);
    expect(HANDSHAKE_INPUT_SCHEMA.properties.nonce.minLength).toBe(22);
  });
});

describe('handshake (L2.1 to L2.7, L2.9, L2.14)', () => {
  it('creates a session on a correct handshake, answering with kyaos_<uuid-v4>, the server DID, capabilities and TTL', async () => {
    const { kya } = runtime();
    const args = handshakeArgs({ agentDid: AGENT, clientInfo: { name: 'e2e' }, clientProtocolVersion: '1.0' });
    const response = await kya.handshake(args);
    expect(response).toEqual({
      sessionId: response.sessionId,
      serverDid: SERVER,
      protocolVersion: '1.0',
      serverCapabilities: { proofs: true, delegation: false, statusList: false },
      sessionTtl: 1800,
      nonce: args['nonce'],
    });
    expect(response.sessionId).toMatch(SESSION_ID);
    const session = (await kya.sessionStore.get(response.sessionId, NOW))!;
    expect(session).toMatchObject({ agentDid: AGENT, identityState: 'anonymous', audience: SERVER, nonce: args['nonce'], createdAt: NOW, lastActivity: NOW, expiresAt: NOW + 30 * 60_000 });
    // A handshake without an agent opens an anonymous session; a verified agent an authenticated one.
    const anonymous = await kya.handshake(handshakeArgs());
    expect((await kya.sessionStore.get(anonymous.sessionId, NOW))!).toMatchObject({ identityState: 'anonymous' });
    expect((await kya.sessionStore.get(anonymous.sessionId, NOW))!).not.toHaveProperty('agentDid');
    const authenticated = await kya.handshake(handshakeArgs({ agentDid: AGENT }), { authenticatedAgentDid: AGENT });
    expect((await kya.sessionStore.get(authenticated.sessionId, NOW))!).toMatchObject({ agentDid: AGENT, identityState: 'authenticated' });
    const verifiedOnly = await kya.handshake(handshakeArgs(), { authenticatedAgentDid: AGENT });
    expect((await kya.sessionStore.get(verifiedOnly.sessionId, NOW))!).toMatchObject({ agentDid: AGENT, identityState: 'authenticated' });
    expect(await refusal(() => kya.handshake(handshakeArgs({ agentDid: 'did:key:z6Mkother' }), { authenticatedAgentDid: AGENT }))).toBe('agent_did_mismatch');
  });

  it('accepts the public origin as audience and refuses any other (L2.1)', async () => {
    const { kya } = runtime();
    expect((await kya.handshake(handshakeArgs({ audience: ORIGIN }))).serverDid).toBe(SERVER);
    expect(await refusal(() => kya.handshake(handshakeArgs({ audience: 'did:web:other.example' })))).toBe('audience_mismatch');
    expect(await refusal(() => kya.handshake(handshakeArgs({ audience: 'https://other.example' })))).toBe('audience_mismatch');
    const noOrigin = createKyaOs({ signer, now: () => NOW });
    expect(await refusal(() => noOrigin.handshake(handshakeArgs({ audience: ORIGIN })))).toBe('audience_mismatch');
  });

  it('refuses a stale or future timestamp outside the skew and accepts one within it, inclusive (L2.3, L2.4, L2.9)', async () => {
    const { kya } = runtime();
    const ts = Math.floor(NOW / 1000);
    expect((await kya.handshake(handshakeArgs({ timestamp: ts - 120 }))).sessionId).toMatch(SESSION_ID);
    expect((await kya.handshake(handshakeArgs({ timestamp: ts + 120 }))).sessionId).toMatch(SESSION_ID);
    expect(await refusal(() => kya.handshake(handshakeArgs({ timestamp: ts - 121 })))).toBe('timestamp_skew');
    expect(await refusal(() => kya.handshake(handshakeArgs({ timestamp: ts + 121 })))).toBe('timestamp_skew');
    expect(await refusal(() => kya.handshake(handshakeArgs({ timestamp: ts - 10_000 })))).toBe('timestamp_skew');
    const tight = createKyaOs({ signer, clockSkewSeconds: 30, now: () => NOW });
    expect((await tight.handshake(handshakeArgs({ timestamp: ts - 30 }))).sessionId).toMatch(SESSION_ID);
    expect(await refusal(() => tight.handshake(handshakeArgs({ timestamp: ts - 31 })))).toBe('timestamp_skew');
    expect(tight.clockSkewSeconds).toBe(30);
  });

  it('refuses a malformed request before anything else (L2.2, L2.14)', async () => {
    const { kya } = runtime();
    expect(await refusal(() => kya.handshake(handshakeArgs({ nonce: 'k7Hy9mNpQrStUvWxYz01A' })))).toBe('nonce_invalid');
    expect(await refusal(() => kya.handshake(handshakeArgs({ nonce: 'k7Hy9mNpQrStUvWxYz01Aa==' })))).toBe('nonce_invalid');
    expect(await refusal(() => kya.handshake(handshakeArgs({ timestamp: 'now' })))).toBe('timestamp_invalid');
    expect(await refusal(() => kya.handshake(handshakeArgs({ audience: '' })))).toBe('audience_invalid');
    expect(await refusal(() => kya.handshake(handshakeArgs({ agentDid: 'agent' })))).toBe('agent_did_invalid');
    expect(await refusal(() => kya.handshake(handshakeArgs({ extra: 1 })))).toBe('unknown_member');
    expect(await refusal(() => kya.handshake('nope'))).toBe('request_not_object');
    expect(kya.sessionStore).toHaveProperty('size', 0);
  });

  it('refuses a replayed nonce from the same agent, retaining it until ts + skew + 1 s and no shorter (L2.5)', async () => {
    const { kya, time } = runtime();
    const args = handshakeArgs({ agentDid: AGENT });
    await kya.handshake(args);
    expect(await refusal(() => kya.handshake(args))).toBe('nonce_replayed');
    // Same nonce, another agent or anonymous: another tuple.
    expect((await kya.handshake({ ...args, agentDid: 'did:key:z6Mkother' })).sessionId).toMatch(SESSION_ID);
    expect((await kya.handshake(handshakeArgs({ nonce: args['nonce'] as string }))).sessionId).toMatch(SESSION_ID);
    // Still refused at the end of the acceptance window (ts + skew), and one more second.
    time.set(NOW + 120 * SECOND);
    expect(await refusal(() => kya.handshake(args))).toBe('nonce_replayed');
    time.set(NOW + 121 * SECOND - 1);
    expect(await refusal(() => kya.handshake(args))).toBe('nonce_replayed');
    expect((kya.nonceStore as MemoryNonceStore).has(args['nonce'] as string, AGENT)).toBe(true);
    // After retention the entry is gone, but the timestamp is now outside the window anyway.
    time.set(NOW + 121 * SECOND);
    expect((kya.nonceStore as MemoryNonceStore).has(args['nonce'] as string, AGENT)).toBe(false);
    expect(await refusal(() => kya.handshake(args))).toBe('timestamp_skew');
  });

  it('refuses the handshake while sessions are disabled', async () => {
    const kya = createKyaOs({ signer, session: { enabled: false }, now: () => NOW });
    expect(await refusal(() => kya.handshake(handshakeArgs()))).toBe('sessions_disabled');
  });

  it('handshakeToolResult answers as a tool result: the response, or an isError result naming the reason', async () => {
    const { kya } = runtime();
    const ok = await kya.handshakeToolResult(handshakeArgs());
    expect(ok['structuredContent']).toMatchObject({ serverDid: SERVER, protocolVersion: '1.0' });
    expect(JSON.parse((ok['content'] as { text: string }[])[0]!.text)).toEqual(ok['structuredContent']);
    expect(ok).not.toHaveProperty('isError');
    const bad = await kya.handshakeToolResult(handshakeArgs({ audience: 'did:web:other.example' }));
    expect(bad).toEqual({
      isError: true,
      content: [{ type: 'text', text: expect.stringMatching(/^audience_mismatch: /) }],
      structuredContent: { error: 'audience_mismatch', message: expect.stringContaining('other.example') },
    });
    const broken = createKyaOs({ signer, now: () => NOW, nonceStore: { insert: async () => Promise.reject(new Error('store down')) } });
    await expect(broken.handshakeToolResult(handshakeArgs())).rejects.toThrow('store down');
  });
});

describe('start / finish / call: the proof around a tool call (L2.11, L2.12, L2.17)', () => {
  it('allows a call, strips _kyaos* before the handler, and signs a proof the SDK verifies by recomputing both hashes', async () => {
    const { kya } = runtime();
    const handshake = await kya.handshake(handshakeArgs({ agentDid: AGENT }));
    const args = { orderId: 'ORD-1001', _kyaos_session: handshake.sessionId, _kyaos_proof: { jws: 'x' } };
    const meta = { traceparent: '00-1-2-01', 'io.modelcontextprotocol/trace': 'x', 'x-helix-vp': 'ignored', 'org.kya-os/request-proof': { jws: 'y', meta: {} } };
    const seen: unknown[] = [];
    const outcome = await kya.call(call(args, meta), async (handlerArgs, context) => {
      seen.push(handlerArgs, context);
      return body;
    });
    expect(outcome.outcome).toBe('allowed');
    const allowed = outcome as KyaOsAllowed & { result: typeof body & { _meta: Record<string, unknown> } };
    expect(seen[0]).toEqual({ orderId: 'ORD-1001' });
    expect(seen[1]).toEqual({ session: expect.objectContaining({ id: handshake.sessionId, agentDid: AGENT }), clientDid: AGENT });
    expect(allowed.arguments).toEqual({ orderId: 'ORD-1001' });
    expect(Object.keys(allowed.result._meta)).toEqual(['org.kya-os/response-proof']);
    const proof = allowed.result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta).toEqual({
      did: SERVER,
      kid: `${SERVER}#key-1`,
      ts: Math.floor(NOW / 1000),
      nonce: proof.meta.nonce,
      audience: SERVER,
      sessionId: handshake.sessionId,
      requestHash: kyaos.hashRequest({ method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } }),
      responseHash: kyaos.hashResponse(body, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE),
      outcome: 'allowed',
      clientDid: AGENT,
      prf: kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE,
    });
    expect(kyaos.isValidNonce(proof.meta.nonce)).toBe(true);
    // The SDK, given the request as sent (control arguments and all) and the result as received.
    const verified = await kyaos.verifyResponseProof(allowed.result, SERVER, resolveDid as never, {
      request: { method: 'tools/call', params: { name: 'lookup_order', arguments: args, _meta: meta } },
      now: NOW,
    });
    expect(verified.outcome).toBe('allowed');
    expect(verified.responseHash).toBe(proof.meta.responseHash);
    // A swapped body fails.
    await expect(
      kyaos.verifyResponseProof({ ...allowed.result, structuredContent: { id: 'ORD-9999' } }, SERVER, resolveDid as never, {
        request: { method: 'tools/call', params: { name: 'lookup_order', arguments: args } },
        now: NOW,
      }),
    ).rejects.toMatchObject({ reason: 'response_hash_mismatch' });
  });

  it('authorises a call without a session from its credentials alone; the proof says sessionId none and the server DID as audience', async () => {
    const { kya } = runtime();
    const started = await kya.start(call(), { authorize: () => ({ agentDid: AGENT }) });
    expect(started.outcome).toBe('allowed');
    const allowed = started as KyaOsAllowed;
    expect(allowed.session).toBeUndefined();
    expect(allowed.clientDid).toBe(AGENT);
    const result = await allowed.finish(body);
    const proof = result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta.sessionId).toBe(NO_SESSION_ID);
    expect(proof.meta.audience).toBe(SERVER);
    expect(proof.meta.clientDid).toBe(AGENT);
    expect((await kyaos.verifyResponseProof(result, SERVER, resolveDid as never, { request: { method: 'tools/call', params: call() }, now: NOW })).outcome).toBe('allowed');
    // No authorize, no session, no client: an anonymous proof; a sync authorize that returns nothing is fine too.
    const anonymous = (await kya.start(call())) as KyaOsAllowed;
    expect((await anonymous.finish(body))._meta['org.kya-os/response-proof']).toMatchObject({ meta: expect.not.objectContaining({ clientDid: expect.anything() }) });
    const voided = (await kya.start(call(), { authorize: () => undefined })) as KyaOsAllowed;
    expect(voided.clientDid).toBeUndefined();
    const explicit = (await kya.start(call(), { clientDid: 'did:key:z6Mkexplicit', authorize: () => ({ agentDid: AGENT }) })) as KyaOsAllowed;
    expect(explicit.clientDid).toBe('did:key:z6Mkexplicit');
    const noArgs = (await kya.start({ name: 'lookup_order' })) as KyaOsAllowed;
    expect(noArgs.arguments).toEqual({});
    expect(noArgs.requestHash).toBe(kyaos.hashRequest({ method: 'tools/call', params: { name: 'lookup_order', arguments: {} } }));
    const badArgs = (await kya.start({ name: 'lookup_order', arguments: 'x' as never })) as KyaOsAllowed;
    expect(badArgs.arguments).toEqual({});
  });

  it('uses the session audience (the public origin) in the proof and advances lastActivity on every valid call (L2.10)', async () => {
    const { kya, time } = runtime();
    const handshake = await kya.handshake(handshakeArgs({ audience: ORIGIN }));
    time.advance(10 * SECOND);
    const first = (await kya.start(call({ _kyaos_session: handshake.sessionId }))) as KyaOsAllowed;
    expect(first.session!.lastActivity).toBe(NOW + 10 * SECOND);
    expect(first.session!.expiresAt).toBe(NOW + 10 * SECOND + 30 * 60_000);
    const proof = (await first.finish(body))._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta.audience).toBe(ORIGIN);
    expect(proof.meta.sessionId).toBe(handshake.sessionId);
    time.advance(20 * SECOND);
    const second = (await kya.start(call({ _kyaos_session: handshake.sessionId }))) as KyaOsAllowed;
    expect(second.session!.lastActivity).toBe(NOW + 30 * SECOND);
    // A denied call does not count as activity.
    time.advance(5 * SECOND);
    await kya.start(call({ _kyaos_session: handshake.sessionId }), { authorize: () => Promise.reject(new Error('no')) });
    expect((await kya.sessionStore.get(handshake.sessionId, time.now()))!.lastActivity).toBe(NOW + 30 * SECOND);
  });

  it('expires an idle session after the TTL and then refuses the session id (L2.8)', async () => {
    const { kya, time } = runtime({ session: { ttlMinutes: 1 } });
    const handshake = await kya.handshake(handshakeArgs());
    expect(handshake.sessionTtl).toBe(60);
    time.advance(59 * SECOND);
    expect((await kya.start(call({ _kyaos_session: handshake.sessionId }))).outcome).toBe('allowed');
    // The valid call moved the expiry out by the TTL, so another 59 s is still inside it.
    time.advance(59 * SECOND);
    expect((await kya.start(call({ _kyaos_session: handshake.sessionId }))).outcome).toBe('allowed');
    time.advance(60 * SECOND);
    const denied = (await kya.start(call({ _kyaos_session: handshake.sessionId }))) as KyaOsDenied;
    expect(denied.outcome).toBe('denied');
    expect(denied.reason).toBe('session_unknown');
    expect(denied.error).toBeInstanceOf(KyaOsError);
  });

  it('denies with a signed proof, without responseHash, when authorization throws or the session is not usable', async () => {
    const { kya } = runtime();
    const scopeError = Object.assign(new Error('Required scope: orders:admin'), { code: 'INSUFFICIENT_SCOPE' });
    const denied = (await kya.start(call(), { authorize: () => Promise.reject(scopeError), clientDid: AGENT })) as KyaOsDenied;
    expect(denied).toMatchObject({ outcome: 'denied', reason: 'INSUFFICIENT_SCOPE', error: scopeError, requestHash: kyaos.hashRequest({ method: 'tools/call', params: call() }) });
    expect(denied.proof.meta).toEqual({
      did: SERVER,
      kid: `${SERVER}#key-1`,
      ts: Math.floor(NOW / 1000),
      nonce: denied.proof.meta.nonce,
      audience: SERVER,
      sessionId: NO_SESSION_ID,
      requestHash: denied.requestHash,
      outcome: 'denied',
      reason: 'INSUFFICIENT_SCOPE',
      clientDid: AGENT,
    });
    const verified = await kyaos.verifyResponseProof({ error: 'insufficient_scope' }, SERVER, resolveDid as never, { request: { method: 'tools/call', params: call() }, proof: denied.proof, now: NOW });
    expect(verified.outcome).toBe('denied');
    expect(verified.responseHash).toBeUndefined();
    // Reasons: a code, else the message, else "denied"; a KyaOsError's reason.
    expect(((await kya.start(call(), { authorize: () => Promise.reject(new Error('token expired')) })) as KyaOsDenied).reason).toBe('token expired');
    expect(((await kya.start(call(), { authorize: () => Promise.reject(new Error('')) })) as KyaOsDenied).reason).toBe('denied');
    expect(((await kya.start(call(), { authorize: () => Promise.reject('nope') })) as KyaOsDenied).reason).toBe('denied');
    expect(((await kya.start(call(), { authorize: () => Promise.reject({ code: '' }) })) as KyaOsDenied).reason).toBe('denied');
    expect(((await kya.start(call(), { authorize: () => Promise.reject(new KyaOsError('audience_mismatch', 'x')) })) as KyaOsDenied).reason).toBe('audience_mismatch');
    // Session problems.
    expect(((await kya.start(call({ _kyaos_session: 'sess_abc' }))) as KyaOsDenied).reason).toBe('session_id_malformed');
    expect(((await kya.start(call({ _kyaos_session: 'kyaos_11111111-2222-4333-8444-555555555555' }))) as KyaOsDenied).reason).toBe('session_unknown');
    const noSessions = createKyaOs({ signer, session: { enabled: false }, now: () => NOW });
    expect(((await noSessions.start(call({ _kyaos_session: 'kyaos_11111111-2222-4333-8444-555555555555' }))) as KyaOsDenied).reason).toBe('sessions_disabled');
    expect((await noSessions.start(call())).outcome).toBe('allowed');
  });

  it('refuses a call on another agent\'s session, and names the session in a denied proof', async () => {
    const { kya } = runtime();
    const handshake = await kya.handshake(handshakeArgs({ agentDid: AGENT, audience: ORIGIN }));
    const denied = (await kya.start(call({ _kyaos_session: handshake.sessionId }), { authorize: () => ({ agentDid: 'did:key:z6Mkother' }) })) as KyaOsDenied;
    expect(denied.reason).toBe('session_agent_mismatch');
    expect(denied.session?.id).toBe(handshake.sessionId);
    expect(denied.proof.meta.sessionId).toBe(handshake.sessionId);
    expect(denied.proof.meta.audience).toBe(ORIGIN);
    expect(denied.proof.meta.clientDid).toBe('did:key:z6Mkother');
    // The session's own agent, or an anonymous caller, is fine; the session's agent becomes the clientDid.
    const own = (await kya.start(call({ _kyaos_session: handshake.sessionId }), { authorize: () => ({ agentDid: AGENT }) })) as KyaOsAllowed;
    expect(own.clientDid).toBe(AGENT);
    const anonymous = (await kya.start(call({ _kyaos_session: handshake.sessionId }))) as KyaOsAllowed;
    expect(anonymous.clientDid).toBe(AGENT);
    // An anonymous session takes any caller.
    const open = await kya.handshake(handshakeArgs());
    expect((await kya.start(call({ _kyaos_session: open.sessionId }), { authorize: () => ({ agentDid: AGENT }) })).outcome).toBe('allowed');
  });

  it('call() returns the denial instead of running the handler', async () => {
    const { kya } = runtime();
    let ran = false;
    const outcome = await kya.call(call(), async () => {
      ran = true;
      return body;
    }, { authorize: () => Promise.reject(new Error('no')) });
    expect(outcome.outcome).toBe('denied');
    expect(ran).toBe(false);
  });

  it('records every proof nonce in the replay store and retries a collision', async () => {
    const inserted: [string, string | undefined, number][] = [];
    let refuse = 2;
    const store: NonceStore = {
      insert: async (nonce, agentDid, expiresAt) => {
        inserted.push([nonce, agentDid, expiresAt]);
        if (refuse > 0) {
          refuse -= 1;
          return false;
        }
        return true;
      },
    };
    const kya = createKyaOs({ signer, nonceStore: store, now: () => NOW });
    const started = (await kya.start(call())) as KyaOsAllowed;
    const result = await started.finish(body);
    const proof = result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(inserted).toHaveLength(3);
    expect(inserted.map(([, did]) => did)).toEqual([SERVER, SERVER, SERVER]);
    expect(inserted[2]![0]).toBe(proof.meta.nonce);
    expect(inserted[2]![2]).toBe((proof.meta.ts + 120 + 1) * 1000);
    expect(new Set(inserted.map(([nonce]) => nonce)).size).toBe(3);
    // Three refusals in a row: no proof, the call fails rather than reusing a nonce.
    refuse = 3;
    await expect(((await kya.start(call())) as KyaOsAllowed).finish(body)).rejects.toThrow('fresh proof nonce');
  });

  it('cross-border rule: the nonce store and the session store are the only state the layer touches', async () => {
    const stores: string[] = [];
    const nonceStore: NonceStore = {
      insert: async (nonce, agentDid, expiresAt) => {
        stores.push(`nonce:${agentDid}:${expiresAt - NOW}`);
        return true;
      },
    };
    const kya = createKyaOs({ signer, nonceStore, now: () => NOW });
    const handshake = await kya.handshake(handshakeArgs({ agentDid: AGENT }));
    await kya.call(call({ _kyaos_session: handshake.sessionId }), async () => body);
    expect(stores).toEqual([`nonce:${AGENT}:121000`, `nonce:${SERVER}:121000`]);
    expect(await kya.sessionStore.get(handshake.sessionId, NOW)).toBeDefined();
  });
});
