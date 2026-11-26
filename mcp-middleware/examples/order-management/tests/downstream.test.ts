// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story L3-D in the sample: the agent calls service A's
 * forward_lookup_order with its request proof and chain; A's handler calls
 * service B's lookup_order through withDelegation; B verifies the forwarded
 * chain and A's delegation proof with its own verifier. Two real servers
 * over HTTP, the helix-core verifier fixture world, no secret shared.
 */

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { MemoryAuditSink } from '@helixid/sdk-js';
import { createKyaOs, createMcpAuditTrail } from '@helixid/mcp-middleware';
import { createServer } from 'node:http';
import { vi } from 'vitest';
import { createOrderServer, type OrderServerOptions } from '../src/app.js';
import { createOrderStore } from '../src/orders.js';
import { cardFor, hop, serviceOn } from '../../../tests/delegation-helpers.js';
import { NOW_MS, fixtureSigner, fixtureVerifier, haveVerifierFixtures, loadEnvironment, proofMeta } from '../../../tests/proof-helpers.js';

const env = haveVerifierFixtures ? loadEnvironment() : (undefined as never);
// The account (the fixture's owner) roots one hop to the agent at service A, in the sample's scope names.
const chain = haveVerifierFixtures
  ? [
      hop(env, 'owner', {
        id: 'urn:zcap:00000000-0000-4000-8000-0000000d3e01',
        issuer: env.keys['owner']!.did,
        invoker: env.keys['agent']!.did,
        parentCapability: env.keys['service']!.did,
        invocationTarget: env.keys['service']!.did,
        allowedAction: ['orders:read'],
        status: { url: 'https://owner.example/status/1', index: '3' },
      }),
    ]
  : [];
const servers: Server[] = [];

async function listen(options: OrderServerOptions): Promise<string> {
  const server = createOrderServer(options);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe.skipIf(!haveVerifierFixtures)('forward_lookup_order: service A calls service B on the agent\'s behalf (story L3-D)', () => {
  const A = (): string => env.keys['service']!.did;
  const agent = (): string => env.keys['agent']!.did;
  const B = serviceOn('b.helix.test');

  async function freePort(): Promise<number> {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = (probe.address() as AddressInfo).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    return port;
  }

  async function world(forwarders?: readonly string[]): Promise<{ a: string; sink: MemoryAuditSink }> {
    const cards = { [agent()]: cardFor(env, agent(), ['orders:read'], env.keys['owner']!.did) };
    const b = await listen({
      resource: 'http://b.helix.test/mcp',
      store: createOrderStore(),
      auth: {
        serviceDid: B.did,
        verifier: fixtureVerifier(B.did, { env, documents: { [B.did]: B.document }, cards }),
        tools: { lookup_order: { minimumLevel: 'L2' } },
        inboundDelegation: forwarders === undefined ? {} : { forwarders },
      },
    });
    const sink = new MemoryAuditSink();
    const trail = createMcpAuditTrail({ reporter: sink, serviceDid: A() });
    const a = await listen({
      resource: 'http://a.helix.test/mcp',
      store: createOrderStore(),
      auth: { serviceDid: A(), verifier: fixtureVerifier(A(), { env, cards }), tools: { forward_lookup_order: { minimumLevel: 'L2' } } },
      downstream: {
        url: 'http://b.helix.test/mcp',
        signer: fixtureSigner(env, 'service'),
        advisoryHeaders: true,
        audit: trail.outboundAudit(),
        clock: () => NOW_MS,
        // b.helix.test is the test server B listens on.
        fetch: (input, init) => fetch(String(input).replace('http://b.helix.test', b), init),
      },
    });
    return { a, sink };
  }

  async function forward(a: string): Promise<{ status: number; body: { result: { content: Array<{ text: string }>; isError?: boolean } } }> {
    const _meta = await proofMeta(fixtureSigner(env, 'agent'), A(), { name: 'forward_lookup_order', input: { orderId: 'ORD-1001' } }, chain, { now: NOW_MS });
    const res = await fetch(`${a}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'forward_lookup_order', arguments: { orderId: 'ORD-1001' }, _meta } }),
    });
    return { status: res.status, body: (await res.json()) as never };
  }

  it('B answers the agent\'s lookup, and A audits the attachment with the chain string and B\'s host', async () => {
    const { a, sink } = await world([A()]);
    const { status, body } = await forward(a);
    expect({ status, body }).toMatchObject({ status: 200 });
    expect(body.result.isError).toBeUndefined();
    const answer = JSON.parse(body.result.content[0]!.text) as { downstreamStatus: number; downstream: { result: { content: Array<{ text: string }> } } };
    expect(answer.downstreamStatus).toBe(200);
    expect(JSON.parse(answer.downstream.result.content[0]!.text)).toMatchObject({ id: 'ORD-1001', customer: 'Asha Rao' });
    const attached = sink.events.find((event) => event.eventType === 'delegation.outbound_attached')!;
    expect(attached).toMatchObject({ resource: { kind: 'public_did', did: 'did:web:b.helix.test' }, actor: { kind: 'pairwise_did', did: agent() } });
    expect(attached.action.name).toContain(String(chain[0]!['id']));
  });

  it('with the KYA-OS layer and the call audit on A, over the default fetch to B\'s real host: the forward carries the call\'s correlation id', async () => {
    const cards = { [agent()]: cardFor(env, agent(), ['orders:read'], env.keys['owner']!.did) };
    const port = await freePort();
    // B listens on the port its audience names (listen() would pick its own).
    const b = createOrderServer({
      resource: `http://127.0.0.1:${port}/mcp`,
      store: createOrderStore(),
      auth: {
        serviceDid: B.did,
        verifier: fixtureVerifier(B.did, { env, documents: { [B.did]: B.document }, cards }),
        tools: { lookup_order: { minimumLevel: 'L2' } },
        inboundDelegation: { forwarders: [A()], audience: `127.0.0.1:${port}` },
      },
    });
    servers.push(b);
    await new Promise<void>((resolve) => b.listen(port, '127.0.0.1', resolve));
    const sink = new MemoryAuditSink();
    const trail = createMcpAuditTrail({ reporter: sink, serviceDid: A() });
    const signer = fixtureSigner(env, 'service');
    const a = await listen({
      resource: 'http://a.helix.test/mcp',
      store: createOrderStore(),
      audit: trail,
      kyaos: createKyaOs({ signer, publicOrigin: 'http://a.helix.test', toolsEndpoint: 'http://a.helix.test/mcp' }),
      auth: { serviceDid: A(), verifier: fixtureVerifier(A(), { env, cards }), tools: { forward_lookup_order: { minimumLevel: 'L2' } }, auditSink: trail.toolAuditSink() },
      downstream: { url: `http://127.0.0.1:${port}/mcp`, signer, audit: trail.outboundAudit(), clock: () => NOW_MS },
    });
    const { status, body } = await forward(a);
    expect({ status, isError: body.result.isError }).toEqual({ status: 200, isError: undefined });
    const attached = sink.events.find((event) => event.eventType === 'delegation.outbound_attached')!;
    const started = sink.events.find((event) => event.eventType === 'session.established')!;
    expect(attached.correlationId).toBe(started.correlationId);
  });

  it('a downstream answer that is not JSON is the tool\'s error; a failed audit write is logged and never blocks', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const cards = { [agent()]: cardFor(env, agent(), ['orders:read'], env.keys['owner']!.did) };
    const a = await listen({
      resource: 'http://a.helix.test/mcp',
      store: createOrderStore(),
      auth: { serviceDid: A(), verifier: fixtureVerifier(A(), { env, cards }), tools: { forward_lookup_order: { minimumLevel: 'L2' } } },
      downstream: {
        url: 'http://b.helix.test/mcp',
        signer: fixtureSigner(env, 'service'),
        audit: () => {
          throw new Error('trail down');
        },
        fetch: async () => new Response('bad gateway', { status: 502 }),
      },
    });
    const { body } = await forward(a);
    expect(body.result.isError).toBe(true);
    expect(JSON.parse(body.result.content[0]!.text)).toEqual({ downstreamStatus: 502, downstream: null });
    expect(errors).toHaveBeenCalledWith('outbound delegation audit failed:', 'trail down');
    errors.mockRestore();
  });

  it('by default B accepts the forward of any service for the authority granted at that service', async () => {
    const { a } = await world();
    const { body } = await forward(a);
    expect(body.result.isError).toBeUndefined();
    expect(JSON.parse(body.result.content[0]!.text)).toMatchObject({ downstreamStatus: 200 });
  });

  it('B refuses when it does not accept A\'s forwards; A reports the refusal as the tool\'s error', async () => {
    const { a } = await world([]);
    const { body } = await forward(a);
    expect(body.result.isError).toBe(true);
    expect(JSON.parse(body.result.content[0]!.text)).toMatchObject({ downstreamStatus: 401 });
  });
});
