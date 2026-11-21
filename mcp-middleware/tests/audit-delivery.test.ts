// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Story A-2 point 3 in the middleware: required mode gets the intent receipt
 * before the handler runs (and does not run it otherwise), a failed terminal
 * append returns the degraded audit marker, buffered refuses an ephemeral
 * outbox at startup, best-effort needs AAP-1 accepted.
 */

import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  AuditDeliveryError,
  MemoryAuditOutbox,
  auditEventDigest,
  createAuditDelivery,
  type AuditRecorderClient,
  type AuditRecorderSubmission,
  type SignedAuditEntry,
} from '@helixid/sdk-js';
import {
  AUDIT_META_KEY,
  auditToolHandlers,
  auditUnavailableResponse,
  createHelixAuditDelivery,
  createMcpAuditTrail,
  markAuditDegraded,
  runAuditedTool,
} from '../src/index.js';

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const SERVICE_DID = 'did:web:orders.example';

/** Answers like the recorder; `failOn` names the event types it refuses. */
class FakeRecorder implements AuditRecorderClient {
  readonly recorded: string[] = [];
  failOn = new Set<string>();

  async submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry> {
    const { eventType } = submission.producerEvent;
    if (this.failOn.has(eventType) || this.failOn.has('*')) throw new AuditDeliveryError(`recorder refused ${eventType}`, 503, 'AUDIT_JOURNAL_FAILURE');
    this.recorded.push(eventType);
    const eventDigest = auditEventDigest(submission.producerEvent);
    const sequence = String(this.recorded.length);
    return {
      core: { ledgerId: 'ledger_x', ledgerEpochId: 'epoch-1', sequence, eventDigest, event: submission.producerEvent },
      eventDigest,
      entryDigest: `sha256:${sequence.padStart(64, '0')}`,
      recorderReceipt: { core: { sequence }, jws: `receipt-${sequence}` },
    } as unknown as SignedAuditEntry;
  }
}

function setup() {
  const recorder = new FakeRecorder();
  const audit = createMcpAuditTrail({ reporter: createAuditDelivery({ recorder }), serviceDid: SERVICE_DID });
  return { recorder, audit, call: audit.beginToolCall({ toolName: 'get_order' }) };
}

const ok = { content: [{ type: 'text', text: '{"orderId":"ORD-1"}' }], _meta: { other: 1 } };

describe('runAuditedTool (required delivery)', () => {
  it('records the intent before the handler and the completion after, and returns the result untouched', async () => {
    const { recorder, call } = setup();
    const handler = vi.fn(async () => {
      expect(recorder.recorded).toEqual(['tool.call.started']);
      return ok;
    });
    expect(await runAuditedTool(call, handler)).toBe(ok);
    expect(recorder.recorded).toEqual(['tool.call.started', 'tool.call.completed']);
  });

  it('does not run the handler when the intent cannot be receipted', async () => {
    const { recorder, call } = setup();
    recorder.failOn.add('tool.call.started');
    const handler = vi.fn(async () => ok);
    const errors = vi.fn();
    const result = await runAuditedTool(call, handler, { onAuditError: errors });
    expect(handler).not.toHaveBeenCalled();
    expect(result).toEqual(auditUnavailableResponse('Required intent audit delivery failed; the tool did not run'));
    expect(result.isError).toBe(true);
    expect(JSON.parse((result.content![0] as { text: string }).text)).toMatchObject({ success: false, error: { code: 'audit_delivery_failed' } });
    expect(errors).toHaveBeenCalledWith(expect.any(AuditDeliveryError), 'intent');
  });

  it('returns the degraded audit marker when the terminal append fails after the handler ran', async () => {
    const { recorder, call } = setup();
    recorder.failOn.add('tool.call.completed');
    const handler = vi.fn(async () => ({ ...ok, _meta: { other: 1, [AUDIT_META_KEY]: { proofs: true } } }));
    const result = await runAuditedTool(call, handler);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({
      content: ok.content,
      isError: true,
      _meta: { other: 1, [AUDIT_META_KEY]: { proofs: true, status: 'degraded', reason: 'Required terminal audit delivery failed after the tool ran' } },
    });
  });

  it('records a throwing handler as failed (code only) and rethrows, even if that append fails', async () => {
    const { recorder, call, audit } = setup();
    await expect(runAuditedTool(call, async () => { throw new Error('secret detail'); })).rejects.toThrow('secret detail');
    expect(recorder.recorded).toEqual(['tool.call.started', 'tool.call.failed']);
    const errors = vi.fn();
    recorder.failOn.add('tool.call.failed');
    await expect(runAuditedTool(audit.beginToolCall(), () => { throw new Error('again'); }, { onAuditError: errors })).rejects.toThrow('again');
    expect(errors).toHaveBeenCalledWith(expect.any(AuditDeliveryError), 'terminal');
  });

  it('marks a result degraded without losing what it carried', () => {
    expect(markAuditDegraded({ content: [] }, 'r')).toEqual({ content: [], isError: true, _meta: { [AUDIT_META_KEY]: { status: 'degraded', reason: 'r' } } });
    expect(markAuditDegraded({ _meta: { [AUDIT_META_KEY]: 'not an object' } }, 'r')._meta).toEqual({ [AUDIT_META_KEY]: { status: 'degraded', reason: 'r' } });
  });
});

describe('auditToolHandlers', () => {
  it('wraps every tool callback a server registers, and leaves other registrations alone', async () => {
    const { recorder, call } = setup();
    const registered = new Map<string, unknown>();
    const server = {
      registerTool(name: string, _config: unknown, callback?: unknown) {
        registered.set(name, callback ?? _config);
        return name;
      },
    };
    expect(auditToolHandlers(server, call)).toBe(server);
    expect(server.registerTool('get_order', { description: 'x' }, async (args: { orderId: string }) => ({ content: [{ type: 'text', text: args.orderId }] }))).toBe('get_order');
    server.registerTool('metadata_only', 'not-a-callback');
    expect(registered.get('metadata_only')).toBe('not-a-callback');
    const wrapped = registered.get('get_order') as (args: { orderId: string }) => Promise<unknown>;
    expect(await wrapped({ orderId: 'ORD-7' })).toEqual({ content: [{ type: 'text', text: 'ORD-7' }] });
    expect(recorder.recorded).toEqual(['tool.call.started', 'tool.call.completed']);
  });
});

describe('createHelixAuditDelivery', () => {
  const fetchFor = (recorder: FakeRecorder): typeof fetch => async (_url, init) => {
    const wire = JSON.parse(String(init!.body)) as { producerEvent: AuditRecorderSubmission['producerEvent'] };
    try {
      return new Response(JSON.stringify({ entry: await recorder.submit({ producerEvent: wire.producerEvent, encryptedEvidence: [] }) }), { status: 201 });
    } catch {
      return new Response(JSON.stringify({ error: { code: 'AUDIT_JOURNAL_FAILURE' } }), { status: 503 });
    }
  };

  it('submits to the HelixID recorder in required mode by default', async () => {
    const recorder = new FakeRecorder();
    const sink = createHelixAuditDelivery({ baseUrl: 'https://api.example.com', apiKey: 'k', fetch: fetchFor(recorder), timeoutMs: 1_000, ledgerId: 'ledger_x' });
    expect(sink.delivery).toBe('required');
    const audit = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE_DID });
    const recorded = await audit.tool('started', { outcome: 'unknown' });
    expect(recorded.receipt?.recorderReceipt.jws).toBe('receipt-1');
    recorder.failOn.add('*');
    await expect(audit.tool('completed', { outcome: 'succeeded' })).rejects.toThrow(/AUDIT_JOURNAL_FAILURE/);
  });

  it('refuses at startup: buffered with no outbox or an ephemeral one, best-effort without AAP-1', () => {
    const base = { baseUrl: 'https://api.example.com', apiKey: 'k' };
    expect(() => createHelixAuditDelivery({ ...base, delivery: 'buffered' })).toThrow(/durable outbox/);
    expect(() => createHelixAuditDelivery({ ...base, delivery: 'buffered', outbox: 'memory' })).toThrow(/ephemeral outbox is refused/);
    expect(() => createHelixAuditDelivery({ ...base, delivery: 'buffered', outbox: new MemoryAuditOutbox() })).toThrow(/ephemeral outbox is refused/);
    expect(() => createHelixAuditDelivery({ ...base, delivery: 'best-effort' })).toThrow(/AAP-1 only/);
    const accepted = createHelixAuditDelivery({ ...base, delivery: 'best-effort', acceptAap1: true });
    expect(accepted.profile).toBe('AAP-1');
  });

  it('buffers to a durable outbox directory and delivers on its interval', async () => {
    const recorder = new FakeRecorder();
    recorder.failOn.add('*');
    const directory = mkdtempSync(join(tmpdir(), 'helix-mw-outbox-'));
    dirs.push(directory);
    const failures = vi.fn();
    const sink = createHelixAuditDelivery({
      baseUrl: 'https://api.example.com',
      apiKey: 'k',
      delivery: 'buffered',
      outboxDir: directory,
      fetch: fetchFor(recorder),
      flushIntervalMs: 20,
      onDeliveryFailure: failures,
    });
    try {
      const audit = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE_DID });
      const call = audit.beginToolCall();
      // Buffered: the intent is durably queued, so the handler runs although the recorder is down.
      const result = await runAuditedTool(call, async () => ok);
      expect(result).toBe(ok);
      expect(readdirSync(join(directory, 'pending'))).toHaveLength(2);
      await vi.waitFor(() => expect(failures).toHaveBeenCalled(), { timeout: 2_000 });
      recorder.failOn.clear();
      await vi.waitFor(() => expect(readdirSync(join(directory, 'pending'))).toHaveLength(0), { timeout: 2_000 });
      expect(recorder.recorded).toEqual(['tool.call.started', 'tool.call.completed']);
    } finally {
      sink.stop();
    }
  });
});
