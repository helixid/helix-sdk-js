// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * Story A-2 through the sample server, over HTTP: with required delivery a
 * refund does not happen when its intent cannot be receipted, and a refund
 * whose terminal append fails comes back with the degraded audit marker.
 */

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuditDeliveryError,
  auditEventDigest,
  createAuditDelivery,
  type AuditRecorderClient,
  type AuditRecorderSubmission,
  type SignedAuditEntry,
} from '@helixid/sdk-js';
import { AUDIT_META_KEY, createMcpAuditTrail } from '@helixid/mcp-middleware';
import { createOrderServer } from '../src/app.js';
import { createOrderStore, type OrderStore } from '../src/orders.js';

class FakeRecorder implements AuditRecorderClient {
  readonly recorded: string[] = [];
  failOn = new Set<string>();

  async submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry> {
    const { eventType } = submission.producerEvent;
    if (this.failOn.has(eventType)) throw new AuditDeliveryError(`refused ${eventType}`, 503, 'AUDIT_JOURNAL_FAILURE');
    this.recorded.push(eventType);
    const eventDigest = auditEventDigest(submission.producerEvent);
    return { core: { ledgerId: 'l', ledgerEpochId: 'e', sequence: String(this.recorded.length), eventDigest, event: submission.producerEvent }, eventDigest } as unknown as SignedAuditEntry;
  }
}

let server: Server | undefined;
afterEach(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

async function start(recorder: FakeRecorder): Promise<{ base: string; store: OrderStore }> {
  const audit = createMcpAuditTrail({ reporter: createAuditDelivery({ recorder }), serviceDid: 'did:web:orders.example' });
  const store = createOrderStore();
  server = createOrderServer({
    resource: 'http://localhost/mcp',
    store,
    audit,
    auth: {
      serviceDid: 'did:web:orders.example',
      validateOAuthToken: async () => ({ sub: 'admin', scopes: ['orders:read', 'orders:admin'] }),
      auditSink: audit.toolAuditSink(),
    },
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${(server!.address() as AddressInfo).port}`, store };
}

async function refund(base: string, orderId: string): Promise<{ status: number; body: { result?: { isError?: boolean; content: Array<{ text: string }>; _meta?: Record<string, unknown> } } }> {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer admin' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund_order', arguments: { orderId, reason: 'test' } } }),
  });
  return { status: res.status, body: (await res.json()) as never };
}

describe('order-management sample with required audit delivery', () => {
  it('records the whole call when the recorder answers', async () => {
    const recorder = new FakeRecorder();
    const { base, store } = await start(recorder);
    const answer = await refund(base, 'ORD-1001');
    expect(answer.status).toBe(200);
    expect(answer.body.result?.isError).toBeFalsy();
    expect(store.get('ORD-1001')?.status).toBe('refunded');
    expect(recorder.recorded).toEqual(['session.established', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
  });

  it('does not run the refund when its intent cannot be receipted', async () => {
    const recorder = new FakeRecorder();
    recorder.failOn.add('tool.call.started');
    const { base, store } = await start(recorder);
    const answer = await refund(base, 'ORD-1001');
    expect(answer.body.result?.isError).toBe(true);
    expect(JSON.parse(answer.body.result!.content[0]!.text)).toMatchObject({ success: false, error: { code: 'audit_delivery_failed' } });
    expect(answer.body.result?._meta?.[AUDIT_META_KEY]).toMatchObject({ status: 'degraded' });
    expect(store.get('ORD-1001')?.status).not.toBe('refunded');
  });

  it('refuses the call before the guard when even the session cannot be recorded', async () => {
    const recorder = new FakeRecorder();
    recorder.failOn.add('session.established');
    const { base, store } = await start(recorder);
    expect((await refund(base, 'ORD-1001')).status).toBe(500);
    expect(store.get('ORD-1001')?.status).not.toBe('refunded');
  });

  it('returns the degraded audit marker when the completion cannot be recorded after the refund ran', async () => {
    const recorder = new FakeRecorder();
    recorder.failOn.add('tool.call.completed');
    const { base, store } = await start(recorder);
    const answer = await refund(base, 'ORD-1001');
    expect(store.get('ORD-1001')?.status).toBe('refunded');
    expect(answer.body.result?.isError).toBe(true);
    expect(answer.body.result?._meta?.[AUDIT_META_KEY]).toEqual({ status: 'degraded', reason: 'Required terminal audit delivery failed after the tool ran' });
  });
});
