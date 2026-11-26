// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// The one-line HTTP gate: metadata, method policy, refusals mapped to HTTP, the audited call, the KYA-OS
// session layer, and what it hands the handler behind it (req.helixMcp).
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryAuditSink } from '@helixid/sdk-js';
import { helixMcpGate, type GatedRequest, type HelixMcpGate, type HelixMcpGateOptions } from '../src/http-gate.js';
import { createMcpAuditTrail, type ToolAuditEvent } from '../src/audit.js';
import { AuthorizationServerUnavailableError } from '../src/errors.js';
import { MemoryNonceStore } from '../src/kyaos/nonce-store.js';
import type { KyaOsRuntime } from '../src/kyaos/runtime.js';
import { fixtureVerifier } from './proof-helpers.js';

const SERVICE = 'did:web:orders.helix.test';
const READER = { authorization: 'Bearer reader' };

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

/** The gate in front of a handler that echoes what the gate handed it, as JSON. */
async function serve(options: Partial<HelixMcpGateOptions>, behind?: (req: GatedRequest, res: ServerResponse) => Promise<void> | void, before?: (req: GatedRequest) => void) {
  const holder: { gate?: HelixMcpGate } = {};
  const server = createServer((req: GatedRequest, res) => {
    before?.(req);
    holder.gate!(req, res, () => {
      if (behind) {
        void behind(req, res);
        return;
      }
      res.writeHead(req.helixMcp ? 200 : 404, { 'content-type': 'application/json' }).end(JSON.stringify(req.helixMcp ? { body: req.helixMcp.body, callers: [...req.helixMcp.callers.keys()] } : { next: req.url }));
    });
  });
  const gate = helixMcpGate({
    resource: 'http://127.0.0.1/mcp',
    validateOAuthToken: async (token) => {
      if (token === 'reader') return { sub: 'user-1', scopes: ['orders:read'] };
      throw new Error('unknown token');
    },
    toolScopes: { lookup_order: ['orders:read'], refund_order: ['orders:admin'] },
    ...options,
  });
  holder.gate = gate;
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = async (body: unknown, headers: Record<string, string> = {}, raw?: string) => {
    const res = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: raw ?? JSON.stringify(body) });
    const text = await res.text();
    return { status: res.status, headers: res.headers, body: text ? (JSON.parse(text) as Record<string, any>) : undefined };
  };
  const rpc = (method: string, params: Record<string, unknown> = {}, headers: Record<string, string> = {}) => post({ jsonrpc: '2.0', id: 1, method, params }, headers);
  return { gate, base, post, rpc };
}

describe('helixMcpGate', () => {
  it('serves the RFC 9728 metadata, passes other paths on, and answers 405 to anything but POST on the MCP path', async () => {
    const { gate, base } = await serve({ resourceName: 'Orders', authorizationServers: ['https://login.example'], resourceScopes: { 'file:///a': ['docs:read'] } });
    expect(gate.mcpPath).toBe('/mcp');
    expect(gate.metadataUrl).toBe('http://127.0.0.1/.well-known/oauth-protected-resource/mcp');
    const metadata = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(metadata).toEqual({
      resource: 'http://127.0.0.1/mcp',
      authorization_servers: ['https://login.example'],
      scopes_supported: ['orders:read', 'orders:admin', 'docs:read'],
      bearer_methods_supported: ['header'],
      resource_name: 'Orders',
    });
    expect(await (await fetch(`${base}/elsewhere`)).json()).toEqual({ next: '/elsewhere' });
    const get = await fetch(`${base}/mcp`);
    expect([get.status, get.headers.get('allow')]).toEqual([405, 'POST']);
  });

  it('lets the open methods through and hands the body on; refuses the rest without a credential, with the challenge', async () => {
    const { rpc } = await serve({ scopesSupported: ['custom'] });
    const init = await rpc('initialize', { protocolVersion: '2025-06-18' });
    expect(init).toMatchObject({ status: 200, body: { body: { method: 'initialize' } } });
    const list = await rpc('resources/list');
    expect(list.status).toBe(401);
    expect(list.headers.get('www-authenticate')).toContain('resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp"');
    const call = await rpc('tools/call', { name: 'lookup_order', arguments: { orderId: 'ORD-1' } });
    expect(call.status).toBe(401);
    const scoped = await rpc('tools/call', { name: 'refund_order', arguments: {} }, READER);
    expect([scoped.status, scoped.body?.['error']]).toEqual([403, 'insufficient_scope']);
    const ok = await rpc('tools/call', { name: 'lookup_order', arguments: { orderId: 'ORD-1' } }, READER);
    expect(ok).toMatchObject({ status: 200, body: { callers: ['lookup_order'] } });
  });

  it('reads a body a framework already parsed (object or text), and refuses bad JSON and an oversized body', async () => {
    const parsed = await serve({}, undefined, (req) => {
      req.body = { jsonrpc: '2.0', id: 1, method: 'initialize' };
    });
    expect((await parsed.post(undefined, {}, '')).body).toEqual({ body: { jsonrpc: '2.0', id: 1, method: 'initialize' }, callers: [] });
    const text = await serve({}, undefined, (req) => {
      req.body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}';
    });
    expect((await text.post(undefined, {}, '')).body).toMatchObject({ body: { method: 'tools/list' } });
    const { post } = await serve({ maxBodyBytes: 10 });
    expect((await post(undefined, {}, 'not json')).status).toBe(400);
    const big = await post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { pad: 'x'.repeat(100) } });
    expect([big.status, big.body?.['error']?.['message']]).toEqual([413, 'Request body too large']);
  });

  it('answers a down authorization server with 503 and Retry-After, any other fault with 500, and reports both', async () => {
    const faults: unknown[] = [];
    const down = await serve({
      validateOAuthToken: async () => {
        throw new AuthorizationServerUnavailableError('down');
      },
      onServerError: (error) => void faults.push(error),
    });
    const res = await down.rpc('tools/call', { name: 'lookup_order' }, READER);
    expect([res.status, res.headers.get('retry-after'), res.body?.['error']]).toEqual([503, '5', 'temporarily_unavailable']);
    // A verifier that throws is a fault of this server (no verifier for a proof): 500.
    const broken = await serve({ onServerError: (error) => void faults.push(error) });
    const meta = { 'org.kya-os/request-proof': { prf: 'org.kya-os/proof.v1' } };
    expect((await broken.rpc('tools/call', { name: 'lookup_order', _meta: meta })).status).toBe(500);
    expect((await broken.rpc('resources/list', { _meta: meta })).status).toBe(500);
    expect(faults).toHaveLength(3);
  });

  it('records the call and its caller: the audit trail joins the guard, and wrapTool runs the tool audited, in its delegation', async () => {
    const sink = new MemoryAuditSink();
    const audit = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE, includeToolNames: true });
    const events: ToolAuditEvent[] = [];
    const ran: unknown[] = [];
    const { rpc } = await serve(
      { audit, serviceDid: SERVICE, trustProxy: true },
      async (req, res) => {
        const tool = req.helixMcp!.wrapTool('lookup_order', async (args: unknown) => {
          ran.push(args);
          return { content: [{ type: 'text', text: 'ok' }] };
        });
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await tool({ orderId: 'ORD-1' })));
      },
    );
    const ok = await rpc('tools/call', { name: 'lookup_order', arguments: { orderId: 'ORD-1' } }, { ...READER, 'x-forwarded-for': '203.0.113.9, 10.0.0.1' });
    expect(ok.body).toEqual({ content: [{ type: 'text', text: 'ok' }] });
    expect(ran).toEqual([{ orderId: 'ORD-1' }]);
    expect(sink.eventTypes).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
    const refused = await rpc('tools/call', { name: 'lookup_order', arguments: {} });
    expect(refused.status).toBe(401);
    expect(sink.eventTypes.slice(4)).toEqual(['session.established', 'authorization.denied', 'tool.call.denied']);
    // The guard's own sink, when given, is used as is; the caller's forwarded address reaches it only with trustProxy.
    const own = await serve({ audit, auditSink: (event) => void events.push(event) });
    await own.rpc('tools/call', { name: 'lookup_order' }, { 'x-forwarded-for': '203.0.113.9' });
    expect(events[0]).toMatchObject({ clientIp: '127.0.0.1', reasonCode: 'proof_missing' });
    const trusted = await serve({ auditSink: (event) => void events.push(event), trustProxy: true });
    await trusted.rpc('ping', {}, { 'x-forwarded-for': '203.0.113.9' });
    await trusted.rpc('ping');
    expect(events.slice(1).map((event) => event.clientIp)).toEqual(['203.0.113.9', '127.0.0.1']);
  });

  it('takes a batch, requests with no params or id, a nameless tool call, and audits a fault by its code', async () => {
    const sink = new MemoryAuditSink();
    const audit = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE });
    const { post } = await serve({ audit, serviceDid: SERVICE });
    const batch = await post([{ jsonrpc: '2.0', id: 1, method: 'ping' }, 'garbage', { jsonrpc: '2.0', id: 2, method: 'tools/call' }], READER);
    expect([batch.status, batch.body?.['error']]).toEqual([403, 'insufficient_scope']);
    expect(sink.eventTypes).toEqual(['session.established', 'authorization.approved', 'authorization.denied', 'tool.call.denied']);
    // A proof with no verifier configured is this server's fault: 500, the call recorded as failed.
    const fault = await post({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'lookup_order', _meta: { 'org.kya-os/request-proof': { prf: 'x' } } } });
    expect(fault.status).toBe(500);
    expect(sink.events.at(-1)).toMatchObject({ eventType: 'tool.call.failed', reason: { code: 'server_error' } });
  });

  it('builds the verifier with the replay store the environment names, the runtime’s, or the one given', () => {
    const base = { resource: 'http://127.0.0.1/mcp', serviceDid: SERVICE };
    const fromEnv = helixMcpGate({ ...base, verifier: { resolveDid: async () => ({}) as never }, env: {} });
    expect(fromEnv.guard.verifier?.nonceStore).toBeDefined();
    const store = new MemoryNonceStore();
    expect(helixMcpGate({ ...base, verifier: { nonceStore: store } }).guard.verifier?.nonceStore).toBe(store);
    const runtime = fakeKyaOs({});
    expect(helixMcpGate({ ...base, verifier: {}, kyaos: runtime }).guard.verifier?.nonceStore).toBe(runtime.nonceStore);
    const built = fixtureVerifier(SERVICE);
    expect(helixMcpGate({ ...base, verifier: built }).guard.verifier).toBe(built);
    expect(helixMcpGate({ resource: 'http://127.0.0.1/mcp', validateOAuthToken: async () => ({ sub: 'u' }) }).guard.verifier).toBeUndefined();
  });
});

/** A KYA-OS runtime stand-in: the handshake tool, and `start` answering as told. */
function fakeKyaOs(answers: { start?: (authorize: () => Promise<unknown>) => Promise<Record<string, unknown>> }): KyaOsRuntime {
  return {
    handshakeToolName: '_kyaos_handshake',
    nonceStore: new MemoryNonceStore(),
    isHandshake: (name: string | undefined) => name === '_kyaos_handshake',
    handshakeToolResult: async (_args: unknown, options?: { authenticatedAgentDid?: string }) => ({ structuredContent: { agent: options?.authenticatedAgentDid ?? null } }),
    start: async (_call: unknown, options?: { authorize?: () => Promise<unknown> }) => answers.start!(options!.authorize!),
  } as unknown as KyaOsRuntime;
}

describe('helixMcpGate with the KYA-OS layer', () => {
  it('opens the handshake to anonymous agents, refuses a bad credential on it, and answers it through req.helixMcp', async () => {
    const kyaos = fakeKyaOs({});
    const { rpc } = await serve({ kyaos }, async (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await req.helixMcp!.handshake({})));
    });
    expect((await rpc('tools/call', { name: '_kyaos_handshake', arguments: {} })).body).toEqual({ structuredContent: { agent: null } });
    expect((await rpc('tools/call', { name: '_kyaos_handshake', arguments: {} }, { authorization: 'Bearer nope' })).status).toBe(401);
    expect((await rpc('tools/call', { name: '_kyaos_handshake', arguments: {} }, READER)).body).toEqual({ structuredContent: { agent: null } });
    // Under an audit trail the handshake is no audited call.
    const sink = new MemoryAuditSink();
    const audited = await serve({ kyaos, audit: createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE }) }, async (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await req.helixMcp!.handshake({})));
    });
    await audited.rpc('tools/call', { name: '_kyaos_handshake', arguments: {} });
    expect(sink.eventTypes).toEqual([]);
    // Without the layer there is no handshake to answer.
    const plain = await serve({}, async (req, res) => {
      await req.helixMcp!.handshake({}).catch((error: Error) => res.writeHead(500, { 'content-type': 'application/json' }).end(JSON.stringify(error.message)));
    });
    expect(await plain.rpc('initialize')).toMatchObject({ status: 500, body: 'helixMcpGate: the handshake needs the `kyaos` option' });
  });

  it('answers a denied start with its proof, a needs_authorization with the signed result, and finishes an allowed call', async () => {
    const outcomes: Array<(authorize: () => Promise<unknown>) => Promise<Record<string, unknown>>> = [
      async (authorize) => {
        const error = await authorize().catch((e: unknown) => e);
        return { outcome: 'denied', error, proof: { jws: 'j', meta: { outcome: 'denied' } } };
      },
      async () => ({ outcome: 'needs_authorization', error: { code: 'NEEDS_AUTHORIZATION' }, result: { isError: true, _meta: { p: 1 } } }),
      async (authorize) => {
        await authorize();
        return { outcome: 'allowed', arguments: { orderId: 'ORD-1' }, session: { id: 's1' }, finish: async (result: Record<string, unknown>) => ({ ...result, _meta: { signed: true } }) };
      },
    ];
    const kyaos = fakeKyaOs({ start: (authorize) => outcomes.shift()!(authorize) });
    const { rpc, post } = await serve({ kyaos }, async (req, res) => {
      const body = req.helixMcp!.body as { params: { arguments: unknown } };
      const tool = req.helixMcp!.wrapTool('lookup_order', async () => ({ content: [], args: body.params.arguments }));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await tool()));
    });
    const denied = await rpc('tools/call', { name: 'lookup_order', arguments: {} });
    expect([denied.status, denied.body?.['_meta']?.['org.kya-os/response-proof']]).toEqual([401, { jws: 'j', meta: { outcome: 'denied' } }]);
    const challenged = await post({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'lookup_order', arguments: {} } }, READER);
    expect(challenged.body).toEqual({ jsonrpc: '2.0', id: null, result: { isError: true, _meta: { p: 1 } } });
    const allowed = await rpc('tools/call', { name: 'lookup_order', arguments: { orderId: 'ORD-1', _kyaos_session: 's1' } }, READER);
    expect(allowed.body).toEqual({ content: [], args: { orderId: 'ORD-1' }, _meta: { signed: true } });
  });

  it('runs a tool with no finisher or delegation as it is (a tool the gate did not see)', async () => {
    const audit = vi.fn();
    const { rpc } = await serve({}, async (req, res) => {
      audit(req.helixMcp!.call);
      const tool = req.helixMcp!.wrapTool('other', () => 'plain');
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(await tool()));
    });
    expect((await rpc('initialize')).body).toBe('plain');
    expect(audit).toHaveBeenCalledWith(undefined);
  });
});
