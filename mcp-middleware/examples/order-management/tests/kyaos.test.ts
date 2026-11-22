// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story L2-A: the sample with the handshake tool, sessions and a proof on every call outcome.

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildDIDDocument, generateKeyPair, kyaos, publicKeyToMultibase } from '@helixid/sdk-js';
import { MemoryNonceStore, createKyaOs, type KyaOsRuntime } from '@helixid/mcp-middleware';
import { createOrderServer } from '../src/app.js';
import { createOrderStore } from '../src/orders.js';

const SERVICE = 'did:web:orders.example';
const agentKeys = generateKeyPair();
const AGENT = `did:key:${publicKeyToMultibase(agentKeys.publicKey)}`;
const agentSigner = new kyaos.EnvSigner({ did: AGENT, kid: AGENT.slice('did:key:'.length), envVar: 'AGENT_KEY', env: { AGENT_KEY: agentKeys.privateKey } });
const keys = generateKeyPair();
const document = buildDIDDocument(SERVICE, keys.publicKey);
const resolveDid = async (did: string) => (did === SERVICE ? document : null);
const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'SAMPLE_SERVICE_KEY', env: { SAMPLE_SERVICE_KEY: keys.privateKey } });

const TOKENS: Record<string, { sub: string; scopes: string[] }> = {
  reader: { sub: 'user-reader', scopes: ['orders:read'] },
};
/** A request proof the agent mints now; with no chain and no card it identifies the agent and delegates nothing (story F-2). */
const proofMeta = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> => ({
  'org.kya-os/request-proof': await kyaos.verifier.signRequestProof({ method: 'tools/call', params: { name, arguments: args } }, agentSigner, { audience: SERVICE, now: time }),
});

let server: Server;
let base: string;
let runtime: KyaOsRuntime;
let time: number;

beforeEach(async () => {
  time = Date.now();
  runtime = createKyaOs({ signer, publicOrigin: 'http://localhost', nonceStore: new MemoryNonceStore(), session: { ttlMinutes: 1 }, now: () => time });
  server = createOrderServer({
    resource: 'http://localhost/mcp',
    store: createOrderStore(),
    auth: {
      serviceDid: SERVICE,
      verifier: { clock: () => time, reportVerification: () => undefined },
      validateOAuthToken: async (token) => {
        const found = TOKENS[token];
        if (!found) throw new Error('unknown token');
        return found;
      },
    },
    kyaos: runtime,
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let nextId = 1;
async function rpc(method: string, params: Record<string, unknown>, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}
const callTool = (name: string, args: Record<string, unknown>, headers?: Record<string, string>, _meta?: Record<string, unknown>) =>
  rpc('tools/call', { name, arguments: args, ...(_meta ? { _meta } : {}) }, headers);
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const handshakeArgs = (extra: Record<string, unknown> = {}) => ({ nonce: kyaos.generateNonce(), audience: SERVICE, timestamp: Math.floor(time / 1000), ...extra });
const proofOf = (body: { result: { _meta: Record<string, unknown> } }) => body.result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;

describe('order-management sample with KYA-OS', () => {
  it('lists the handshake tool and opens a session with it, without credentials', async () => {
    const list = await rpc('tools/list', {});
    expect(list.body.result.tools.map((t: { name: string }) => t.name).sort()).toEqual(['_kyaos_handshake', 'lookup_order', 'refund_order']);
    const args = handshakeArgs({ agentDid: AGENT, clientInfo: { name: 'test' } });
    const res = await callTool('_kyaos_handshake', args);
    expect(res.status).toBe(200);
    expect(res.body.result.structuredContent).toEqual({
      sessionId: expect.stringMatching(/^kyaos_/),
      serverDid: SERVICE,
      protocolVersion: '1.0',
      serverCapabilities: { proofs: true, delegation: false, statusList: false },
      sessionTtl: 60,
      nonce: args.nonce,
    });
    const session = await runtime.sessionStore.get(res.body.result.structuredContent.sessionId, time);
    expect(session).toMatchObject({ agentDid: AGENT, identityState: 'anonymous', audience: SERVICE });
  });

  it('refuses a handshake with a short nonce, a stale timestamp, the wrong audience, or a replayed nonce, as a tool error', async () => {
    // A short nonce is refused by the tool's input schema before the runtime sees it (the runtime's own check is unit-tested).
    const short = await callTool('_kyaos_handshake', handshakeArgs({ nonce: 'short' }));
    expect(short.status).toBe(200);
    expect(short.body.result.isError).toBe(true);
    expect(short.body.result.content[0].text).toContain('nonce');
    // A 22-char nonce that is not base64url reaches the runtime.
    const cases: [Record<string, unknown>, string][] = [
      [handshakeArgs({ nonce: 'k7Hy9mNpQrStUvWxYz01A=' }), 'nonce_invalid'],
      [handshakeArgs({ timestamp: Math.floor(time / 1000) - 121 }), 'timestamp_skew'],
      [handshakeArgs({ audience: 'did:web:other.example' }), 'audience_mismatch'],
    ];
    for (const [args, reason] of cases) {
      const res = await callTool('_kyaos_handshake', args);
      expect(res.status, reason).toBe(200);
      expect(res.body.result.isError, reason).toBe(true);
      expect(res.body.result.structuredContent.error, reason).toBe(reason);
    }
    const args = handshakeArgs();
    expect((await callTool('_kyaos_handshake', args)).body.result.isError).toBeUndefined();
    const replay = await callTool('_kyaos_handshake', args);
    expect(replay.body.result.structuredContent).toEqual({ error: 'nonce_replayed', message: 'nonce was already used' });
    expect((await callTool('_kyaos_handshake', handshakeArgs({ audience: 'http://localhost' }))).body.result.isError).toBeUndefined();
  });

  it('makes the session authenticated when the handshake carries a good request proof, and refuses a bad one', async () => {
    const first = handshakeArgs();
    const res = await callTool('_kyaos_handshake', first, {}, await proofMeta('_kyaos_handshake', first));
    expect(res.status).toBe(200);
    const session = await runtime.sessionStore.get(res.body.result.structuredContent.sessionId, time);
    expect(session).toMatchObject({ agentDid: AGENT, identityState: 'authenticated' });
    // The same proof again is a replayed nonce: refused before the handshake runs.
    const second = handshakeArgs();
    const stale = await proofMeta('_kyaos_handshake', second);
    expect((await callTool('_kyaos_handshake', second, {}, stale)).status).toBe(200);
    const bad = await callTool('_kyaos_handshake', second, {}, stale);
    expect(bad.status).toBe(401);
    const third = handshakeArgs({ agentDid: 'did:key:z6Mkother' });
    const other = await callTool('_kyaos_handshake', third, {}, await proofMeta('_kyaos_handshake', third));
    expect(other.body.result.structuredContent.error).toBe('agent_did_mismatch');
  });

  it('signs a proof over every allowed call that the SDK verifies against the server DID by recomputing both hashes', async () => {
    const handshake = await callTool('_kyaos_handshake', handshakeArgs({ agentDid: AGENT }));
    const sessionId = handshake.body.result.structuredContent.sessionId as string;
    const args = { orderId: 'ORD-1001', _kyaos_session: sessionId };
    // Unknown _meta keys are ignored; the retired x-helix-vp is one of them now.
    const meta = { traceparent: '00-1-2-01', 'io.modelcontextprotocol/trace': 'x', 'org.example/other': { deep: true }, 'x-helix-vp': 'ignored' };
    const res = await callTool('lookup_order', args, bearer('reader'), meta);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.result.content[0].text)).toMatchObject({ id: 'ORD-1001' });
    const proof = proofOf(res.body);
    expect(proof.meta).toMatchObject({ did: SERVICE, sessionId, outcome: 'allowed', clientDid: AGENT, prf: 'org.kya-os/response-proof.envelope' });
    expect(proof.meta.clientDid).toBe(AGENT);
    const verified = await kyaos.verifyResponseProof(res.body.result, SERVICE, resolveDid as never, {
      request: { method: 'tools/call', params: { name: 'lookup_order', arguments: args, _meta: meta } },
      now: time,
    });
    expect(verified.outcome).toBe('allowed');
    expect(verified.responseHash).toBe(proof.meta.responseHash);
    // A swapped body fails.
    await expect(
      kyaos.verifyResponseProof({ ...res.body.result, content: [{ type: 'text', text: 'swapped' }] }, SERVICE, resolveDid as never, {
        request: { method: 'tools/call', params: { name: 'lookup_order', arguments: args } },
        now: time,
      }),
    ).rejects.toMatchObject({ reason: 'response_hash_mismatch' });
    // lastActivity moved with the valid call.
    time += 30_000;
    await callTool('lookup_order', args, bearer('reader'));
    expect((await runtime.sessionStore.get(sessionId, time))!.lastActivity).toBe(time);
    // A call without a session is still authorised, with sessionId none.
    const bare = await callTool('lookup_order', { orderId: 'ORD-1002' }, bearer('reader'));
    expect(proofOf(bare.body).meta).toMatchObject({ sessionId: 'none', outcome: 'allowed' });
    expect(proofOf(bare.body).meta).not.toHaveProperty('clientDid');
  });

  it('never lets _kyaos* arguments reach the tool, and ignores unknown _meta keys', async () => {
    // refund_order's schema is strict about reason; a control argument that reached zod unstripped would still be dropped,
    // so prove it another way: the covered request hash excludes it and the tool answers as if it were never there.
    const res = await callTool('lookup_order', { orderId: 'ORD-9999', _kyaos_proof: { jws: 'x' }, _kyaos_other: 1 }, bearer('reader'), { 'org.example/unknown': { deep: true } });
    expect(res.status).toBe(200);
    expect(res.body.result.isError).toBe(true);
    expect(res.body.result.content[0].text).toBe('Order ORD-9999 not found');
    expect(proofOf(res.body).meta.requestHash).toBe(kyaos.hashRequest({ method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-9999' } } }));
  });

  it('answers a denied call with the usual 401/403 and a denied proof without responseHash in the body', async () => {
    const refused = await callTool('refund_order', { orderId: 'ORD-1001', reason: 'x' }, bearer('reader'));
    expect(refused.status).toBe(403);
    const proof = refused.body._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta).toMatchObject({ outcome: 'denied', reason: 'INSUFFICIENT_SCOPE', sessionId: 'none' });
    expect(proof.meta).not.toHaveProperty('responseHash');
    const verified = await kyaos.verifyResponseProof(refused.body, SERVICE, resolveDid as never, {
      request: { method: 'tools/call', params: { name: 'refund_order', arguments: { orderId: 'ORD-1001', reason: 'x' } } },
      proof,
      now: time,
    });
    expect(verified.outcome).toBe('denied');
    const anonymous = await callTool('lookup_order', { orderId: 'ORD-1001' });
    expect(anonymous.status).toBe(401);
    expect((anonymous.body._meta['org.kya-os/response-proof'] as kyaos.DetachedProof).meta.reason).toBe('PROOF_MISSING');
  });

  it('refuses an unknown, expired or malformed session id with 400 and a denied proof', async () => {
    const malformed = await callTool('lookup_order', { orderId: 'ORD-1001', _kyaos_session: 'sess_x' }, bearer('reader'));
    expect(malformed.status).toBe(400);
    expect(malformed.body._meta['org.kya-os/response-proof'].meta.reason).toBe('session_id_malformed');
    const handshake = await callTool('_kyaos_handshake', handshakeArgs());
    const sessionId = handshake.body.result.structuredContent.sessionId as string;
    expect((await callTool('lookup_order', { orderId: 'ORD-1001', _kyaos_session: sessionId }, bearer('reader'))).status).toBe(200);
    time += 61_000;
    const expired = await callTool('lookup_order', { orderId: 'ORD-1001', _kyaos_session: sessionId }, bearer('reader'));
    expect(expired.status).toBe(400);
    expect(expired.body._meta['org.kya-os/response-proof'].meta).toMatchObject({ reason: 'session_unknown', sessionId: 'none' });
  });

  it('signs each call of a batch with its own proof', async () => {
    const res = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...bearer('reader') },
      body: JSON.stringify([
        { jsonrpc: '2.0', id: 'a', method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } },
        { jsonrpc: '2.0', id: 'b', method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1002' } } },
      ]),
    });
    expect(res.status).toBe(200);
    const bodies = (await res.json()) as { id: string; result: { _meta: Record<string, unknown> } }[];
    expect(bodies).toHaveLength(2);
    const hashes = bodies.map((b) => (b.result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof).meta.responseHash);
    expect(new Set(hashes).size).toBe(2);
  });
});
