// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateKeyPair, kyaos, publicKeyToMultibase } from '@helixid/sdk-js';
import type { ToolAuditEvent } from '@helixid/mcp-middleware';
import { createOrderServer } from '../src/app.js';
import { createOrderStore } from '../src/orders.js';

const TOKENS: Record<string, { sub: string; scopes: string[] }> = {
  reader: { sub: 'user-reader', scopes: ['orders:read'] },
  admin: { sub: 'user-admin', scopes: ['orders:read', 'orders:admin'] },
};

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
let audit: ToolAuditEvent[];

beforeEach(async () => {
  audit = [];
  server = createOrderServer({
    resource: 'http://localhost/mcp',
    authorizationServers: ['https://as.example.com'],
    store: createOrderStore(),
    auth: {
      serviceDid: SERVICE,
      verifier: { reportVerification: () => undefined },
      validateOAuthToken: async (token) => {
        const found = TOKENS[token];
        if (!found) throw new Error('unknown token');
        return found;
      },
      auditSink: (event) => void audit.push(event),
    },
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
const resultText = (body: { result: { content: Array<{ text: string }> } }) => body.result.content[0]!.text;

describe('order-management sample server', () => {
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

  it('lets anyone initialize and list tools', async () => {
    const init = await rpc('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'test', version: '0' },
    });
    expect(init.status).toBe(200);
    expect(init.body.result.serverInfo.name).toBe('order-management');

    const list = await rpc('tools/list', {});
    expect(list.body.result.tools.map((t: { name: string }) => t.name).sort()).toEqual(['lookup_order', 'refund_order']);
  });

  it('answers a tool call with no credentials with 401 and both challenges', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-1001' });
    expect(res.status).toBe(401);
    const challenge = res.headers.get('www-authenticate') ?? '';
    expect(challenge).toContain('Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"');
    expect(challenge).toContain('KyaOS resource_metadata=');
    expect(audit).toEqual([]);
  });

  it('answers an unknown bearer token with 401 invalid_token', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('nope'));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('error="invalid_token"');
  });

  it('lets a reader look up an order but not refund it, and audits both', async () => {
    const lookup = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'));
    expect(lookup.status).toBe(200);
    expect(JSON.parse(resultText(lookup.body))).toMatchObject({ id: 'ORD-1001', status: 'shipped' });

    const refund = await callTool('refund_order', { orderId: 'ORD-1001', reason: 'damaged' }, bearer('reader'));
    expect(refund.status).toBe(403);
    expect(refund.headers.get('www-authenticate')).toContain('error="insufficient_scope"');
    expect(refund.headers.get('www-authenticate')).toContain('scope="orders:admin"');

    expect(audit.map((e) => [e.event, e.toolName, e.oauthSubject, e.requiredScope])).toEqual([
      ['AUTHZ_GRANTED', 'lookup_order', 'user-reader', undefined],
      ['AUTHZ_DENIED', 'refund_order', 'user-reader', 'orders:admin'],
    ]);
    expect(audit[0]).toMatchObject({ serviceDid: 'did:web:orders.example', authMethod: 'oauth' });
  });

  it('lets an admin refund once', async () => {
    const first = await callTool('refund_order', { orderId: 'ORD-1002', reason: 'customer request' }, bearer('admin'));
    expect(first.status).toBe(200);
    expect(JSON.parse(resultText(first.body))).toMatchObject({ id: 'ORD-1002', status: 'refunded', refundReason: 'customer request' });

    const again = await callTool('refund_order', { orderId: 'ORD-1002', reason: 'again' }, bearer('admin'));
    expect(again.body.result.isError).toBe(true);
    expect(resultText(again.body)).toContain('already refunded');
  });

  it('reports a missing order as a tool error, not an auth error', async () => {
    const res = await callTool('lookup_order', { orderId: 'ORD-9999' }, bearer('reader'));
    expect(res.status).toBe(200);
    expect(res.body.result.isError).toBe(true);
  });

  it('denies a tool that is not in the scope map', async () => {
    const res = await callTool('delete_order', { orderId: 'ORD-1001' }, bearer('admin'));
    expect(res.status).toBe(403);
    expect(audit.at(-1)).toMatchObject({ event: 'AUTHZ_DENIED', toolName: 'delete_order' });
  });

  it('verifies a KYA-OS request proof in _meta in-process, attributed to the agent, and refuses a replay or a tampered body', async () => {
    const meta = await proofMeta('lookup_order', { orderId: 'ORD-1001' });
    const first = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, meta);
    // The agent presented no chain and no attested card: a valid proof with no delegated scope is refused by scope, never by the API.
    expect(first.status).toBe(403);
    expect(first.headers.get('www-authenticate')).toContain('scope="orders:read"');
    expect(audit.at(-1)).toMatchObject({ event: 'AUTHZ_DENIED', agentDid: AGENT, authMethod: 'kyaos', level: 'L1', requiredScope: 'orders:read' });
    const replay = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, meta);
    expect(replay.status).toBe(401);
    expect(replay.body.error_description).toContain('nonce_replayed');
    const tampered = await callTool('lookup_order', { orderId: 'ORD-1002' }, {}, await proofMeta('lookup_order', { orderId: 'ORD-1001' }));
    expect(tampered.status).toBe(401);
    expect(tampered.body.error_description).toContain('request_hash_mismatch');
    const elsewhere = await callTool('lookup_order', { orderId: 'ORD-1001' }, {}, await proofMeta('lookup_order', { orderId: 'ORD-1001' }, 'did:web:other.example'));
    expect(elsewhere.status).toBe(401);
    expect(elsewhere.body.error_description).toContain('audience_mismatch');
  });

  it('takes a bearer token next to a proof as its sender constraint, not as a second caller (story C-C)', async () => {
    // The proof decides who called: the token's scopes are not the agent's, so the unattested agent is still refused by scope.
    const fused = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'), await proofMeta('lookup_order', { orderId: 'ORD-1001' }));
    expect(fused.status).toBe(403);
    expect(audit.at(-1)).toMatchObject({ event: 'AUTHZ_DENIED', agentDid: AGENT, authMethod: 'kyaos', proofAssurance: 'L3-minus' });
    // A chain without a proof and a bearer token are two callers: refused with 400.
    const both = await callTool('lookup_order', { orderId: 'ORD-1001' }, bearer('reader'), { 'org.kya-os/delegation-chain': [{}] });
    expect(both.status).toBe(400);
  });

  it('answers 503 with Retry-After, not 401, when the authorization server cannot be reached', async () => {
    const down = createOrderServer({
      resource: 'http://localhost/mcp',
      store: createOrderStore(),
      auth: {
        oauth: { issuer: 'http://127.0.0.1:9', audience: 'http://localhost/mcp', jwksUri: 'http://127.0.0.1:9/jwks', fetch: async () => { throw new Error('ECONNREFUSED'); } },
        onAuditError: () => {},
      },
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
  });

  it('rejects a malformed body, wrong methods and unknown paths', async () => {
    const bad = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
    expect(bad.status).toBe(400);
    expect((await fetch(`${base}/mcp`)).status).toBe(405);
    expect((await fetch(`${base}/elsewhere`)).status).toBe(404);
  });
});
