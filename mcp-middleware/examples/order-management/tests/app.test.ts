// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MemoryAuditSink, generateKeyPair, kyaos, parseAuditEvent, publicKeyToMultibase } from '@helixid/sdk-js';
import { createMcpAuditTrail, type McpAuditTrail } from '@helixid/mcp-middleware';
import { createOrderServer, type OrderServerOptions } from '../src/app.js';
import { createOrderStore } from '../src/orders.js';

const TOKENS: Record<string, { sub: string; scopes: string[] }> = {
  reader: { sub: 'user-reader', scopes: ['orders:read'] },
  admin: { sub: 'user-admin', scopes: ['orders:read', 'orders:admin'] },
};
const SERVICE_DID = 'did:web:orders.example';

/** A KYA-OS agent (did:key, resolved offline) that mints a request proof per call; nothing asks the Helix API (story F-2). */
const agentKeys = generateKeyPair();
const AGENT = `did:key:${publicKeyToMultibase(agentKeys.publicKey)}`;
const agentSigner = new kyaos.EnvSigner({ did: AGENT, kid: AGENT.slice('did:key:'.length), envVar: 'AGENT_KEY', env: { AGENT_KEY: agentKeys.privateKey } });
const SERVICE = 'did:web:orders.example';
const proofMeta = async (name: string, args: Record<string, unknown>, audience = SERVICE): Promise<Record<string, unknown>> => ({
  'org.kya-os/request-proof': await kyaos.verifier.signRequestProof({ method: 'tools/call', params: { name, arguments: args } }, agentSigner, { audience }),
});

let server: Server;
let base: string;
let sink: MemoryAuditSink;
let audit: McpAuditTrail;

async function listen(options: Partial<OrderServerOptions> = {}): Promise<{ server: Server; base: string }> {
  const created = createOrderServer({
    resource: 'http://localhost/mcp',
    authorizationServers: ['https://as.example.com'],
    store: createOrderStore(),
    auth: {
      serviceDid: SERVICE_DID,
      verifier: { reportVerification: () => undefined },
      validateOAuthToken: async (token) => {
        const found = TOKENS[token];
        if (!found) throw new Error('unknown token');
        return found;
      },
      auditSink: audit.toolAuditSink(),
    },
    identity: { publicOrigin: 'http://localhost', path: '/mcp', did: 'did:web:orders.example', card: { name: 'Orders (test)', capabilities: ['tools/list', 'tools/call'] } },
    audit,
    ...options,
  });
  await new Promise<void>((resolve) => created.listen(0, '127.0.0.1', resolve));
  return { server: created, base: `http://127.0.0.1:${(created.address() as AddressInfo).port}` };
}

beforeEach(async () => {
  sink = new MemoryAuditSink();
  audit = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE_DID });
  ({ server, base } = await listen());
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let nextId = 1;
async function rpc(method: string, params: Record<string, unknown>, headers: Record<string, string> = {}, at: string = base) {
  const res = await fetch(`${at}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}

const callTool = (name: string, args: Record<string, unknown>, headers?: Record<string, string>, _meta?: Record<string, unknown>, at?: string) =>
  rpc('tools/call', { name, arguments: args, ...(_meta ? { _meta } : {}) }, headers, at);
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const resultText = (body: { result: { content: Array<{ text: string }> } }) => body.result.content[0]!.text;

/** The events recorded since `from`, oldest first. */
const eventsFrom = (from: number) => sink.events.slice(from);
const typesFrom = (from: number) => sink.eventTypes.slice(from);

/** No event may carry what the call carried: arguments, the answer, the bearer token, the VP. */
function expectNothingLeaked(secrets: string[]): void {
  for (const entry of sink.entries) {
    for (const secret of secrets) expect(entry.canonical, secret).not.toContain(secret);
    expect(parseAuditEvent(JSON.parse(entry.canonical))).toEqual(entry.event);
  }
}

describe('order-management sample server', () => {
  it('serves its own did.json and card.json (KYA-OS story C-A) and the card projection names the canonical card', async () => {
    const did = await fetch(`${base}/.well-known/did.json`);
    expect(did.status).toBe(200);
    const document = (await did.json()) as { id: string; service: { type: string; serviceEndpoint: string }[] };
    expect(document.id).toBe('did:web:orders.example');
    expect(document.service).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'http://localhost/.well-known/kya-os-card.json' }]);
    const card = await fetch(`${base}/.well-known/kya-os-card.json`);
    expect(card.status).toBe(200);
    expect(await card.json()).toEqual({ id: 'did:web:orders.example', entityType: 'mcp', name: 'Orders (test)', capabilities: ['tools/list', 'tools/call'], didDocument: 'http://localhost/.well-known/did.json', proofProfile: 'org.kya-os/proof.v1' });
    expect((await fetch(`${base}/.well-known/did.json`, { method: 'POST' })).status).toBe(404);
  });

  it('serves RFC 9728 metadata at the well-known path for /mcp', async () => {
    const res = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      resource: 'http://localhost/mcp',
      authorization_servers: ['https://as.example.com'],
      scopes_supported: ['orders:read', 'orders:admin'],
      bearer_methods_supported: ['header'],
      resource_name: 'Order Management (HelixID sample)',
    });
  });

  it('lets anyone initialize and list tools, without an audit event', async () => {
    const init = await rpc('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'test', version: '0' },
    });
    expect(init.status).toBe(200);
    expect(init.body.result.serverInfo.name).toBe('order-management');

    const list = await rpc('tools/list', {});
    expect(list.body.result.tools.map((t: { name: string }) => t.name).sort()).toEqual(['lookup_order', 'refund_order']);
    expect(sink.eventTypes).toEqual([]);
  });

  it('answers a tool call with no credentials with 401 and both challenges, audited as a denied call', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-1001' });
    expect(res.status).toBe(401);
    const challenge = res.headers.get('www-authenticate') ?? '';
    expect(challenge).toContain('Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"');
    expect(challenge).toContain('KyaOS resource_metadata=');
    expect(sink.eventTypes).toEqual(['session.established', 'tool.call.denied']);
    expect(sink.events[1]).toMatchObject({ outcome: 'denied', reason: { code: 'proof_missing' }, details: { family: 'tool', phase: 'denied', attempt: '1' } });
    expect(sink.events[1]!.actor).toBeUndefined();
  });

  it('answers an unknown bearer token with 401 invalid_token, audited by code, never by message', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('nope'));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('error="invalid_token"');
    expect(sink.eventTypes).toEqual(['session.established', 'tool.call.denied']);
    expect(sink.events[1]!.reason).toEqual({ code: 'oauth_token_invalid' });
    expectNothingLeaked(['nope', 'unknown token', 'rejected']);
  });

  it('records exactly the typed lifecycle of a lookup through the OAuth door', async () => {
    const lookup = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'));
    expect(lookup.status).toBe(200);
    expect(JSON.parse(resultText(lookup.body))).toMatchObject({ id: 'ORD-1001', status: 'shipped' });

    expect(sink.eventTypes).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
    const [session, approved, started, completed] = sink.events;
    const correlationId = session!.correlationId;
    expect(correlationId).toMatch(/^audit_/);
    for (const event of sink.events) {
      expect(event.correlationId).toBe(correlationId);
      expect(event.resource).toEqual({ kind: 'public_did', did: SERVICE_DID });
      expect(event.source.producer).toEqual({ kind: 'pairwise_did', did: SERVICE_DID });
      expect(event.binding).toBe('urn:kya-os:audit-binding:mcp:2025-11-25');
    }
    // The OAuth subject enters only as a keyed commitment, learned at the decision and carried by the tool events.
    expect(session!.actor).toBeUndefined();
    expect(approved!.actor).toEqual({ kind: 'keyed_commitment', value: expect.stringMatching(/^sha256:[0-9a-f]{64}$/), keyId: 'oauth-subject-v1' });
    expect(started!.actor).toEqual(approved!.actor);
    expect(completed!.actor).toEqual(approved!.actor);
    // The guard reports the required scope only when it was missing, so an approval names no scope.
    expect(approved).toMatchObject({ outcome: 'succeeded', authorization: { source: 'policy', decision: 'allowed' } });
    expect(approved!.authorization!.scopeId).toBeUndefined();
    expect(started).toMatchObject({ outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(completed).toMatchObject({ outcome: 'succeeded', details: { family: 'tool', phase: 'completed', attempt: '1' } });
    expect(sink.events.map((event) => event.source.sourceSequence)).toEqual(['1', '2', '3', '4']);
    expectNothingLeaked(['ORD-1001', 'shipped', 'Asha', 'reader', 'user-reader', 'lookup_order']);
  });

  it('audits a reader refused a refund as authorization.denied then tool.call.denied, with the missing scope', async () => {
    const refund = await callTool('refund_order', { orderId: 'ORD-1001', reason: 'damaged' }, bearer('reader'));
    expect(refund.status).toBe(403);
    expect(refund.headers.get('www-authenticate')).toContain('error="insufficient_scope"');
    expect(refund.headers.get('www-authenticate')).toContain('scope="orders:admin"');

    expect(sink.eventTypes).toEqual(['session.established', 'authorization.denied', 'tool.call.denied']);
    expect(sink.events[1]).toMatchObject({
      outcome: 'denied',
      reason: { code: 'insufficient_scope' },
      authorization: { source: 'policy', decision: 'denied', scopeId: 'orders:admin' },
    });
    expect(sink.events[2]).toMatchObject({ outcome: 'denied', reason: { code: 'insufficient_scope' } });
    expect(sink.events[2]!.actor).toEqual(sink.events[1]!.actor);
    expect(new Set(sink.events.map((event) => event.correlationId)).size).toBe(1);
    expectNothingLeaked(['damaged', 'ORD-1001', 'reader', 'refund_order']);
  });

  it('gives each call its own correlation id', async () => {
    await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'));
    await callTool('lookup_order', { orderId: 'ORD-1002' }, bearer('admin'));
    expect(sink.eventTypes).toHaveLength(8);
    const ids = new Set(sink.events.map((event) => event.correlationId));
    expect(ids.size).toBe(2);
    expect(sink.events[1]!.actor).not.toEqual(sink.events[5]!.actor);
  });

  it('lets an admin refund once', async () => {
    const first = await callTool('refund_order', { orderId: 'ORD-1002', reason: 'customer request' }, bearer('admin'));
    expect(first.status).toBe(200);
    expect(JSON.parse(resultText(first.body))).toMatchObject({ id: 'ORD-1002', status: 'refunded', refundReason: 'customer request' });

    const again = await callTool('refund_order', { orderId: 'ORD-1002', reason: 'again' }, bearer('admin'));
    expect(again.body.result.isError).toBe(true);
    expect(resultText(again.body)).toContain('already refunded');
    // A tool error is the tool's answer: the call completed.
    expect(typesFrom(4)).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
    expectNothingLeaked(['customer request', 'already refunded', 'again']);
  });

  it('reports a missing order as a tool error, not an auth error', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-9999' }, bearer('reader'));
    expect(res.status).toBe(200);
    expect(res.body.result.isError).toBe(true);
    expect(sink.eventTypes).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
  });

  it('denies a tool that is not in the scope map', async () => {
    const res = await callTool('delete_order', { orderId: 'ORD-1001' }, bearer('admin'));
    expect(res.status).toBe(403);
    expect(sink.eventTypes).toEqual(['session.established', 'authorization.denied', 'tool.call.denied']);
    expect(sink.events[1]).toMatchObject({ reason: { code: 'tool_not_permitted' }, authorization: { source: 'policy', decision: 'denied' } });
    expect(sink.events[2]).toMatchObject({ reason: { code: 'tool_not_permitted' } });
    expectNothingLeaked(['delete_order', 'toolScopes']);
  });

  it('records a KYA-OS request proof verified in-process by its level, attributed to the agent, and a refused one as proof.rejected (story F-2)', async () => {
    const meta = await proofMeta('lookup_order', { orderId: 'ORD-1001' });
    const first = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, meta);
    // The agent presented no chain and no attested card: a valid proof with no delegated scope is refused by scope, never by the API.
    expect(first.status).toBe(403);
    expect(first.headers.get('www-authenticate')).toContain('scope="orders:read"');
    expect(sink.eventTypes).toEqual(['session.established', 'proof.verified', 'authorization.denied', 'tool.call.denied']);
    for (const event of sink.events.slice(1)) expect(event.actor).toEqual({ kind: 'pairwise_did', did: AGENT });
    expect(sink.events[1]).toMatchObject({ outcome: 'succeeded', details: { family: 'proof', phase: 'verified', verificationCode: 'KYAOS_PROOF_L1' } });
    expect(sink.events[2]).toMatchObject({ reason: { code: 'insufficient_scope' }, authorization: { source: 'delegation', decision: 'denied', scopeId: 'orders:read' } });

    const replay = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, meta);
    expect(replay.status).toBe(401);
    expect(replay.body.error_description).toContain('nonce_replayed');
    expect(typesFrom(4)).toEqual(['session.established', 'proof.rejected', 'tool.call.denied']);
    expect(eventsFrom(4)[1]).toMatchObject({ outcome: 'denied', reason: { code: 'nonce_replayed' }, actor: { kind: 'pairwise_did', did: AGENT } });
    expect(eventsFrom(4)[2]!.reason).toEqual({ code: 'proof_invalid' });

    const tampered = await callTool('lookup_order', { orderId: 'ORD-1002' }, {}, await proofMeta('lookup_order', { orderId: 'ORD-1001' }));
    expect(tampered.status).toBe(401);
    expect(tampered.body.error_description).toContain('request_hash_mismatch');
    // A proof that names no verified DID is never attributed: only the call is recorded, denied by its code.
    expect(typesFrom(7)).toEqual(['session.established', 'tool.call.denied']);
    expect(eventsFrom(7)[1]).toMatchObject({ reason: { code: 'proof_invalid' } });
    expect(eventsFrom(7)[1]!.actor).toBeUndefined();
    const elsewhere = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, await proofMeta('lookup_order', { orderId: 'ORD-1001' }, 'did:web:other.example'));
    expect(elsewhere.status).toBe(401);
    expect(elsewhere.body.error_description).toContain('audience_mismatch');
    expectNothingLeaked(['ORD-1001', 'ORD-1002', 'lookup_order', JSON.stringify(meta)]);
  });

  it('rejects a proof and a bearer token together with 400, audited as credential_conflict', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'), await proofMeta('lookup_order', { orderId: 'ORD-1001' }));
    expect(res.status).toBe(400);
    expect(sink.eventTypes).toEqual(['session.established', 'tool.call.denied']);
    expect(sink.events[1]!.reason).toEqual({ code: 'credential_conflict' });
  });

  it('records tool names only when the trail is told to', async () => {
    const named = new MemoryAuditSink();
    const namedTrail = createMcpAuditTrail({ reporter: named, serviceDid: SERVICE_DID, includeToolNames: true });
    const other = await listen({ audit: namedTrail, auth: { verifier: { reportVerification: () => undefined }, serviceDid: SERVICE_DID, validateOAuthToken: async () => TOKENS['reader']!, auditSink: namedTrail.toolAuditSink() } });
    try {
      await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'), undefined, other.base);
    } finally {
      await new Promise<void>((resolve) => other.server.close(() => resolve()));
    }
    expect(named.eventTypes).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
    expect(named.events.map((event) => event.action.name)).toEqual([undefined, 'lookup_order', 'lookup_order', 'lookup_order']);
    for (const entry of named.entries) expect(entry.canonical).not.toContain('ORD-1001');
  });

  it('serves without an audit trail', async () => {
    const quiet = createOrderServer({
      resource: 'http://localhost/mcp',
      store: createOrderStore(),
      auth: { verifier: { reportVerification: () => undefined }, serviceDid: SERVICE_DID, validateOAuthToken: async () => TOKENS['reader']! },
    });
    await new Promise<void>((resolve) => quiet.listen(0, '127.0.0.1', resolve));
    try {
      const res = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'), undefined, `http://127.0.0.1:${(quiet.address() as AddressInfo).port}`);
      expect(res.status).toBe(200);
    } finally {
      await new Promise<void>((resolve) => quiet.close(() => resolve()));
    }
    expect(sink.eventTypes).toEqual([]);
  });

  it('answers 503 with Retry-After, not 401, when the authorization server cannot be reached, audited as a failed call', async () => {
    const down = createOrderServer({
      resource: 'http://localhost/mcp',
      store: createOrderStore(),
      auth: {
        oauth: { issuer: 'http://127.0.0.1:9', audience: 'http://localhost/mcp', jwksUri: 'http://127.0.0.1:9/jwks', fetch: async () => { throw new Error('ECONNREFUSED'); } },
        onAuditError: () => {},
      },
      audit,
      onServerError: () => {},
    });
    await new Promise<void>((resolve) => down.listen(0, '127.0.0.1', resolve));
    try {
      const port = (down.address() as AddressInfo).port;
      const jwt = `${Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'k' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'http://127.0.0.1:9', aud: 'http://localhost/mcp', sub: 'u', exp: 9999999999 })).toString('base64url')}.c2ln`;
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${jwt}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } }),
      });
      expect(res.status).toBe(503);
      expect(res.headers.get('retry-after')).toBe('5');
      expect(await res.json()).toMatchObject({ error: 'temporarily_unavailable' });
    } finally {
      await new Promise<void>((resolve) => down.close(() => resolve()));
    }
    expect(sink.eventTypes).toEqual(['session.established', 'tool.call.failed']);
    expect(sink.events[1]!.reason).toEqual({ code: 'server_error' });
  });

  it('rejects a malformed body, wrong methods and unknown paths', async () => {
    const bad = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
    expect(bad.status).toBe(400);
    expect((await fetch(`${base}/mcp`)).status).toBe(405);
    expect((await fetch(`${base}/elsewhere`)).status).toBe(404);
    expect(sink.eventTypes).toEqual([]);
  });
});
