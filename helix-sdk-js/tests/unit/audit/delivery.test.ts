// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Story A-2 on the producer side: the recorder client, the outboxes (the
 * reference outbox contract, restart durability, dead letters) and the three
 * delivery modes (required by default, buffered refusing an ephemeral outbox,
 * best-effort only with AAP-1 accepted).
 */

import { mkdtempSync, readdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  AuditDeliveryConfigError,
  AuditDeliveryError,
  AuditDeliverySink,
  AuditOutboxConflictError,
  AuditTrail,
  DurableOutbox,
  HttpAuditRecorderClient,
  MemoryAuditOutbox,
  MemoryAuditSink,
  TeeAuditSink,
  assertAuditOutboxContract,
  assertEntryBindsSubmission,
  auditEventDigest,
  auditSubmissionWire,
  createAuditDelivery,
  evaluateAuditOutboxProviderContract,
  sameAuditSubmission,
  type AuditOutboxItem,
  type AuditProducerEvent,
  type AuditRecorderClient,
  type AuditRecorderSubmission,
  type EvidenceRef,
  type SignedAuditEntry,
} from '../../../src/index.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'helix-outbox-'));
  dirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const producer = { kind: 'pairwise_did' as const, did: 'did:web:orders.example.com' };

function trailOver(sink: ConstructorParameters<typeof AuditTrail>[0]['sink'], sourceId = 'mcp-middleware:orders'): AuditTrail {
  return new AuditTrail({ sink, sourceId, producer, tenantRef: producer, clock: () => 1_780_000_000_000 });
}

function eventOf(eventId: string, sourceId = 'mcp-middleware:orders'): AuditProducerEvent {
  return trailOver(new MemoryAuditSink(), sourceId).build({
    eventId,
    eventType: 'tool.call.completed',
    action: { category: 'tool.call' },
    outcome: 'succeeded',
    details: { family: 'tool', phase: 'completed', attempt: '1' },
  });
}

/** A recorder stand-in that answers like the real one: sequence, receipt, the same entry on redelivery. */
class FakeRecorder implements AuditRecorderClient {
  readonly submissions: AuditRecorderSubmission[] = [];
  readonly entries = new Map<string, SignedAuditEntry>();
  down = false;

  async submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry> {
    this.submissions.push(submission);
    if (this.down) throw new AuditDeliveryError('recorder unreachable');
    const key = `${submission.producerEvent.source.sourceId}\0${submission.producerEvent.eventId}`;
    const existing = this.entries.get(key);
    if (existing !== undefined) return existing;
    const sequence = String(this.entries.size + 1);
    const eventDigest = auditEventDigest(submission.producerEvent);
    const entry = {
      core: { ledgerId: submission.ledgerId ?? 'ledger_x', ledgerEpochId: 'epoch-1', sequence, eventDigest, event: submission.producerEvent },
      eventDigest,
      entryDigest: `sha256:${sequence.padStart(64, '0')}`,
      recorderReceipt: { core: { sequence }, jws: `receipt-${sequence}` },
    } as unknown as SignedAuditEntry;
    this.entries.set(key, entry);
    return entry;
  }
}

const evidenceRef: EvidenceRef = {
  objectId: 'evi_1',
  ciphertextDigest: `sha256:${'1'.repeat(64)}`,
  mediaType: 'text/plain',
  size: '3',
  encryption: { suite: 'A256GCM', keyId: 'k', nonce: 'n', aadDigest: `sha256:${'2'.repeat(64)}` },
};

describe('HttpAuditRecorderClient', () => {
  it('posts the submission wire with the bearer key and returns the entry that binds it', async () => {
    const recorder = new FakeRecorder();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchStub: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init! });
      const wire = JSON.parse(String(init!.body)) as { producerEvent: AuditProducerEvent; ledgerId?: string };
      const entry = await recorder.submit({ producerEvent: wire.producerEvent, encryptedEvidence: [], ...(wire.ledgerId !== undefined ? { ledgerId: wire.ledgerId } : {}) });
      return new Response(JSON.stringify({ entry }), { status: 201 });
    };
    const client = new HttpAuditRecorderClient({ baseUrl: 'https://api.example.com//', apiKey: 'k1', fetch: fetchStub });
    const event = eventOf('http-1');
    const entry = await client.submit({ ledgerId: 'ledger_x', expectedLedgerEpochId: 'epoch-1', producerEvent: event, encryptedEvidence: [{ ref: evidenceRef, ciphertext: new Uint8Array([1, 2, 3]) }] });
    expect(entry.core.event).toEqual(event);
    expect(calls[0]!.url).toBe('https://api.example.com/v1/audit/submissions');
    expect((calls[0]!.init.headers as Record<string, string>)['authorization']).toBe('Bearer k1');
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({
      ledgerId: 'ledger_x',
      expectedLedgerEpochId: 'epoch-1',
      producerEvent: event,
      encryptedEvidence: [{ ref: evidenceRef, ciphertextBase64url: 'AQID' }],
    });
    expect(auditSubmissionWire({ producerEvent: event, encryptedEvidence: [] })).toEqual({ producerEvent: event });
  });

  it('turns refusals, unreachable recorders and answers that do not bind the event into AuditDeliveryError', async () => {
    const event = eventOf('http-2');
    const answer = (status: number, body: string): typeof fetch => async () => new Response(body, { status });
    const cases: Array<[typeof fetch, RegExp, number | undefined, string | undefined]> = [
      [answer(503, JSON.stringify({ error: { code: 'AUDIT_JOURNAL_FAILURE' } })), /refused the submission \(503 AUDIT_JOURNAL_FAILURE\)/, 503, 'AUDIT_JOURNAL_FAILURE'],
      [answer(500, 'not json'), /refused the submission \(500\)/, 500, undefined],
      [answer(201, '{}'), /refused the submission \(201\)/, 201, undefined],
      [async () => { throw new TypeError('fetch failed'); }, /could not be reached/, undefined, undefined],
    ];
    for (const [fetchStub, message, status, code] of cases) {
      const error = await new HttpAuditRecorderClient({ baseUrl: 'https://api.example.com', apiKey: 'k', fetch: fetchStub }).submit({ producerEvent: event, encryptedEvidence: [] }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(AuditDeliveryError);
      expect((error as AuditDeliveryError).message).toMatch(message);
      expect((error as AuditDeliveryError).status).toBe(status);
      expect((error as AuditDeliveryError).code).toBe(code);
    }
    const otherEntry = await new FakeRecorder().submit({ producerEvent: eventOf('someone-else'), encryptedEvidence: [] });
    const lying = new HttpAuditRecorderClient({ baseUrl: 'https://api.example.com', apiKey: 'k', fetch: answer(201, JSON.stringify({ entry: otherEntry })) });
    await expect(lying.submit({ producerEvent: event, encryptedEvidence: [] })).rejects.toThrow(/does not bind/);
    const entry = await new FakeRecorder().submit({ producerEvent: event, encryptedEvidence: [] });
    expect(() => assertEntryBindsSubmission(entry, { ledgerId: 'ledger_other', producerEvent: event, encryptedEvidence: [] })).toThrow(/does not bind/);
    expect(() => assertEntryBindsSubmission(entry, { producerEvent: event, encryptedEvidence: [] })).not.toThrow();
  });
});

describe('outboxes', () => {
  it('pass the reference outbox contract, memory and durable', async () => {
    assertAuditOutboxContract(await evaluateAuditOutboxProviderContract(() => new MemoryAuditOutbox()));
    const report = await evaluateAuditOutboxProviderContract(() => new DurableOutbox({ directory: tempDir() }));
    for (const item of report.checks) if (!item.passed) console.error(item.name, item.error);
    expect(report.checks.map((item) => item.passed)).toEqual([true, true, true, true]);
    assertAuditOutboxContract(report);
  });

  it('fails the contract, and says so, for an outbox that loses order', async () => {
    const lossy = new MemoryAuditOutbox();
    const reversed = Object.assign(Object.create(lossy) as MemoryAuditOutbox, {
      async *pending() {
        const items: AuditOutboxItem[] = [];
        for await (const item of lossy.pending()) items.push(item);
        yield* items.reverse();
      },
    });
    const report = await evaluateAuditOutboxProviderContract(() => reversed);
    expect(report.passed).toBe(false);
    expect(() => assertAuditOutboxContract(report)).toThrow(/declares and preserves FIFO order per source/);
  });

  it('keeps durable items, their evidence bytes and failure counts across a restart, in order', async () => {
    const directory = tempDir();
    const first = new DurableOutbox({ directory });
    const withEvidence: AuditOutboxItem = {
      eventId: 'e1',
      submission: { producerEvent: { ...eventOf('e1'), evidence: [evidenceRef] }, encryptedEvidence: [{ ref: evidenceRef, ciphertext: new Uint8Array([7, 8, 9]) }] },
      enqueuedAt: 1,
      attempts: 0,
    };
    await first.enqueue(withEvidence);
    await first.enqueue({ eventId: 'e2', submission: { ledgerId: 'ledger_x', expectedLedgerEpochId: 'epoch-9', producerEvent: eventOf('e2'), encryptedEvidence: [] }, enqueuedAt: 2, attempts: 0 });
    await first.markFailed('e1', new Error('offline'));

    const restarted = new DurableOutbox({ directory });
    const items: AuditOutboxItem[] = [];
    for await (const item of restarted.pending()) items.push(item);
    expect(items.map((item) => [item.eventId, item.attempts])).toEqual([
      ['e1', 1],
      ['e2', 0],
    ]);
    expect(Buffer.from(items[0]!.submission.encryptedEvidence[0]!.ciphertext)).toEqual(Buffer.from([7, 8, 9]));
    expect(items[1]!.submission).toMatchObject({ ledgerId: 'ledger_x', expectedLedgerEpochId: 'epoch-9' });
    expect(sameAuditSubmission(items[0]!.submission, withEvidence.submission)).toBe(true);
    await expect(restarted.enqueue({ ...withEvidence, submission: { ...withEvidence.submission, encryptedEvidence: [{ ref: evidenceRef, ciphertext: new Uint8Array([0]) }] } })).rejects.toThrow(
      AuditOutboxConflictError,
    );
    await restarted.enqueue({ eventId: 'e3', submission: { producerEvent: eventOf('e3'), encryptedEvidence: [] }, enqueuedAt: 3, attempts: 0 });
    const order: string[] = [];
    for await (const item of new DurableOutbox({ directory }).pending(2)) order.push(item.eventId);
    expect(order).toEqual(['e1', 'e2']);
    await restarted.markDelivered('missing');
    await restarted.markFailed('missing', new Error('x'));
  });

  it('moves an item to dead letters after its attempts, leaves out files that vanished, and refuses foreign files', async () => {
    const directory = tempDir();
    const outbox = new DurableOutbox({ directory, maxAttempts: 2 });
    await outbox.enqueue({ eventId: 'd1', submission: { producerEvent: eventOf('d1'), encryptedEvidence: [] }, enqueuedAt: 1, attempts: 0 });
    await outbox.enqueue({ eventId: 'd2', submission: { producerEvent: eventOf('d2'), encryptedEvidence: [] }, enqueuedAt: 2, attempts: 0 });
    await outbox.markFailed({ sourceId: 'mcp-middleware:orders', eventId: 'd1' }, new Error('x'));
    await outbox.markFailed({ sourceId: 'mcp-middleware:orders', eventId: 'd1' }, new Error('x'));
    expect((await outbox.deadLetters()).map((item) => [item.eventId, item.attempts])).toEqual([['d1', 2]]);
    // A fresh instance numbers after the dead letters too.
    const reopened = new DurableOutbox({ directory, maxAttempts: 2 });
    await reopened.enqueue({ eventId: 'd3', submission: { producerEvent: eventOf('d3'), encryptedEvidence: [] }, enqueuedAt: 3, attempts: 0 });
    const files = readdirSync(join(directory, 'pending')).sort();
    expect(files).toHaveLength(2);
    // A file delivered by another path between listing and reading is skipped.
    const iterator = reopened.pending()[Symbol.asyncIterator]();
    const firstItem = await iterator.next();
    expect(firstItem.value?.eventId).toBe('d2');
    unlinkSync(join(directory, 'pending', files[1]!));
    expect((await iterator.next()).done).toBe(true);
    expect(await new DurableOutbox({ directory: tempDir() }).deadLetters()).toEqual([]);

    const foreign = tempDir();
    const bad = new DurableOutbox({ directory: foreign });
    await bad.enqueue({ eventId: 'f1', submission: { producerEvent: eventOf('f1'), encryptedEvidence: [] }, enqueuedAt: 1, attempts: 0 });
    const [file] = readdirSync(join(foreign, 'pending'));
    writeFileSync(join(foreign, 'pending', file!), JSON.stringify({ format: 'other' }));
    await expect(new DurableOutbox({ directory: foreign }).enqueue({ eventId: 'f2', submission: { producerEvent: eventOf('f2'), encryptedEvidence: [] }, enqueuedAt: 1, attempts: 0 })).rejects.toThrow(
      /Not a helix audit outbox item/,
    );
  });

  it('refuses a bare event id that several sources have pending', async () => {
    for (const outbox of [new MemoryAuditOutbox(), new DurableOutbox({ directory: tempDir() })]) {
      await outbox.enqueue({ eventId: 'same', submission: { producerEvent: eventOf('same', 'source-a'), encryptedEvidence: [] }, enqueuedAt: 1, attempts: 0 });
      await outbox.enqueue({ eventId: 'same', submission: { producerEvent: eventOf('same', 'source-b'), encryptedEvidence: [] }, enqueuedAt: 2, attempts: 0 });
      await expect(outbox.markDelivered('same')).rejects.toThrow(/several sources/);
      await outbox.markDelivered({ sourceId: 'source-a', eventId: 'same' });
      await outbox.markDelivered('same');
      const left: AuditOutboxItem[] = [];
      for await (const item of outbox.pending()) left.push(item);
      expect(left).toEqual([]);
    }
  });
});

describe('AuditDeliverySink', () => {
  it('refuses misconfiguration at startup: an unknown mode, buffered without a durable outbox, best-effort without accepting AAP-1', () => {
    const recorder = new FakeRecorder();
    expect(() => createAuditDelivery({ recorder, delivery: 'sometimes' as never })).toThrow(AuditDeliveryConfigError);
    expect(() => createAuditDelivery({ recorder, delivery: 'buffered' })).toThrow(/durable outbox/);
    expect(() => createAuditDelivery({ recorder, delivery: 'buffered', outbox: new MemoryAuditOutbox() })).toThrow(/ephemeral outbox is refused/);
    expect(() => createAuditDelivery({ recorder, delivery: 'best-effort' })).toThrow(/AAP-1 only/);
    expect(createAuditDelivery({ recorder }).delivery).toBe('required');
    expect(createAuditDelivery({ recorder }).profile).toBe('AAP-2');
    expect(createAuditDelivery({ recorder, delivery: 'best-effort', acceptAap1: true }).profile).toBe('AAP-1');
  });

  it('required (default): the record carries the signed receipt, and fails when it cannot be obtained', async () => {
    const recorder = new FakeRecorder();
    const failures = vi.fn();
    const sink = createAuditDelivery({ recorder, ledgerId: 'ledger_x', expectedLedgerEpochId: 'epoch-1', onDeliveryFailure: failures });
    const trail = trailOver(sink);
    const recorded = await trail.record({ eventType: 'tool.call.started', action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(recorded.receipt?.recorderReceipt.jws).toBe('receipt-1');
    expect(recorder.submissions[0]).toMatchObject({ ledgerId: 'ledger_x', expectedLedgerEpochId: 'epoch-1' });
    recorder.down = true;
    await expect(trail.record({ eventType: 'tool.call.completed', action: { category: 'tool.call' }, outcome: 'succeeded', details: { family: 'tool', phase: 'completed', attempt: '1' } })).rejects.toThrow(
      /unreachable/,
    );
    expect(failures).toHaveBeenCalledTimes(1);
    await trail.settled();
    // The recorder's answer must bind the event, or the record fails.
    const lying: AuditRecorderClient = { submit: async (s) => ({ ...(await new FakeRecorder().submit(s)), eventDigest: `sha256:${'0'.repeat(64)}` }) };
    await expect(trailOver(createAuditDelivery({ recorder: lying })).record({ eventType: 'tool.call.started', action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } })).rejects.toThrow(
      /does not bind/,
    );
  });

  it('best-effort: a failed delivery is reported and the record goes on, with no receipt', async () => {
    const recorder = new FakeRecorder();
    recorder.down = true;
    const failures = vi.fn();
    const trail = trailOver(createAuditDelivery({ recorder, delivery: 'best-effort', acceptAap1: true, onDeliveryFailure: failures }));
    const recorded = await trail.record({ eventType: 'tool.call.started', action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(recorded.receipt).toBeUndefined();
    expect(failures).toHaveBeenCalledTimes(1);
    recorder.down = false;
    expect((await trail.record({ eventType: 'tool.call.started', action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } })).receipt).toBeDefined();
  });

  it('buffered: items wait in the durable outbox, survive a restart, and are delivered in order once the recorder is back', async () => {
    const directory = tempDir();
    const recorder = new FakeRecorder();
    recorder.down = true;
    const before = createAuditDelivery({ recorder, delivery: 'buffered', outbox: new DurableOutbox({ directory }), ledgerId: 'ledger_x', expectedLedgerEpochId: 'never-pinned' });
    const trail = trailOver(before);
    const events: string[] = [];
    for (const phase of ['started', 'completed'] as const) {
      const recorded = await trail.record({ eventType: `tool.call.${phase}`, action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase, attempt: '1' } });
      expect(recorded.receipt).toBeUndefined();
      events.push(recorded.event.eventId);
    }
    expect(await before.flush()).toEqual({ delivered: 0, failed: 1 });

    // The process restarts: a new outbox over the same directory, the recorder is reachable again.
    recorder.down = false;
    const after = createAuditDelivery({ recorder, delivery: 'buffered', outbox: new DurableOutbox({ directory }) });
    expect(await after.flush()).toEqual({ delivered: 2, failed: 0 });
    expect([...recorder.entries.values()].map((entry) => entry.core.event.eventId)).toEqual(events);
    expect(recorder.submissions.every((submission) => submission.expectedLedgerEpochId === undefined)).toBe(true);
    expect(recorder.submissions.at(-1)?.ledgerId).toBe('ledger_x');
    expect(await after.flush()).toEqual({ delivered: 0, failed: 0 });
    expect(readdirSync(join(directory, 'pending'))).toEqual([]);
  });

  it('buffered: a failure blocks the rest of its source only, acknowledgement failures are reported, flushes coalesce, and the timer flushes', async () => {
    const recorder = new FakeRecorder();
    const outbox = new DurableOutbox({ directory: tempDir() });
    const acks = vi.fn();
    const failures = vi.fn();
    const sink = new AuditDeliverySink({ recorder, delivery: 'buffered', outbox, onAcknowledgementFailure: acks, onDeliveryFailure: failures });
    const a = trailOver(sink, 'source-a');
    const b = trailOver(sink, 'source-b');
    const started = { eventType: 'tool.call.started' as const, action: { category: 'tool.call' }, outcome: 'unknown' as const, details: { family: 'tool' as const, phase: 'started' as const, attempt: '1' } };
    await a.record({ ...started, eventId: 'a1' });
    await a.record({ ...started, eventId: 'a2' });
    await b.record({ ...started, eventId: 'b1' });
    const original = recorder.submit.bind(recorder);
    recorder.submit = async (submission) => {
      if (submission.producerEvent.eventId === 'a1') throw new AuditDeliveryError('refused');
      return original(submission);
    };
    const [first, second] = await Promise.all([sink.flush(), sink.flush()]);
    expect(first).toEqual({ delivered: 1, failed: 1 });
    expect(second).toBe(first);
    expect(failures).toHaveBeenCalledTimes(1);
    const pending: string[] = [];
    for await (const item of outbox.pending()) pending.push(`${item.eventId}:${item.attempts}`);
    expect(pending).toEqual(['a1:1', 'a2:0']);

    recorder.submit = original;
    const markDelivered = outbox.markDelivered.bind(outbox);
    outbox.markDelivered = async () => {
      throw new Error('disk');
    };
    expect(await sink.flush()).toEqual({ delivered: 2, failed: 0 });
    expect(acks).toHaveBeenCalledTimes(2);
    outbox.markDelivered = markDelivered;
    // Redelivery after a failed acknowledgement resolves to the same receipts.
    vi.useFakeTimers();
    try {
      sink.start(50);
      sink.start(50);
      await vi.advanceTimersByTimeAsync(60);
      sink.stop();
      sink.stop();
    } finally {
      vi.useRealTimers();
    }
    await sink.flush();
    const left: string[] = [];
    for await (const item of outbox.pending()) left.push(item.eventId);
    expect(left).toEqual([]);
    expect(recorder.entries.size).toBe(3);
  });

  it('is a no-op flush outside buffered mode, and a tee returns the first receipt', async () => {
    const recorder = new FakeRecorder();
    const sink = createAuditDelivery({ recorder });
    expect(await sink.flush()).toEqual({ delivered: 0, failed: 0 });
    sink.start();
    sink.stop();
    const echo = new MemoryAuditSink();
    const recorded = await trailOver(new TeeAuditSink([echo, sink])).record({
      eventType: 'tool.call.started',
      action: { category: 'tool.call' },
      outcome: 'unknown',
      details: { family: 'tool', phase: 'started', attempt: '1' },
    });
    expect(recorded.receipt?.recorderReceipt.jws).toBe('receipt-1');
    expect(echo.entries).toHaveLength(1);
  });
});
