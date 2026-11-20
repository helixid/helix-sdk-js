// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../../../src/audit/canonical.js';
import { auditEventDigest, digestText } from '../../../src/audit/digest.js';
import { EvidenceEncryptor, MemoryEvidenceStore, AuditEvidenceError, evidenceAad } from '../../../src/audit/evidence.js';
import { AuditEventInvalidError, parseAuditEvent, validateAuditEvent } from '../../../src/audit/schema.js';
import { MemoryAuditSink } from '../../../src/audit/sink.js';
import { AuditTrail, DEFAULT_AUDIT_PRIVACY, keyedCommitment, pairwiseDid, publicDid } from '../../../src/audit/trail.js';
import {
  AUDIT_BINDING_HELIX,
  AUDIT_BINDING_MCP,
  type AuditEventInput,
  type AuditProducerEvent,
  type AuditTrailOptions,
  type PartyRef,
  type ProtocolBindingId,
} from '../../../src/audit/types.js';
import { auditEventsFixture, auditIntegrityVectors, describeFixture, type AuditEventsFixture } from './fixtures.js';

const PRODUCER: PartyRef = { kind: 'pairwise_did', did: 'did:key:zProducer' };
const TENANT: PartyRef = { kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-v1' };

function makeTrail(sink: MemoryAuditSink, options: Partial<AuditTrailOptions> = {}): AuditTrail {
  return new AuditTrail({ sink, sourceId: 'test-source', producer: PRODUCER, tenantRef: TENANT, ...options });
}

const sessionInput = (): AuditEventInput => ({
  eventType: 'session.established',
  action: { category: 'session' },
  outcome: 'succeeded',
  details: { family: 'session', phase: 'established' },
});

/** A fixture trail: the fixture's envelope, with a clock and id generator that replay one recorded event. */
function fixtureTrail(fixture: AuditEventsFixture, sink: MemoryAuditSink, event: { eventId: string; occurredAt: number }, extra: Partial<AuditTrailOptions> = {}): AuditTrail {
  return new AuditTrail({
    sink,
    sourceId: fixture.trail.sourceId,
    producer: fixture.trail.producer as PartyRef,
    tenantRef: fixture.trail.tenantRef as PartyRef,
    binding: fixture.trail.binding as ProtocolBindingId,
    privacy: fixture.trail.privacy as AuditTrailOptions['privacy'],
    clock: () => event.occurredAt,
    newEventId: () => event.eventId,
    ...extra,
  });
}

/** What a producer handed `record()` for a recorded event: the event minus the envelope the trail fills. */
function inputOf(event: Record<string, unknown>): AuditEventInput {
  const { schema: _s, eventVersion: _v, binding: _b, tenantRef: _t, source: _src, privacy: _p, eventId: _id, occurredAt: _at, evidence: _e, ...rest } = event;
  return rest as unknown as AuditEventInput;
}

describeFixture('fixtures/kya-os-helix/audit-events.json', () => {
  const fixture = auditEventsFixture();

  it('replays every sample event to the identical event, canonical text and digest', async () => {
    expect(fixture.events.length).toBeGreaterThanOrEqual(13);
    for (const sample of fixture.events) {
      const sink = new MemoryAuditSink();
      const trail = fixtureTrail(fixture, sink, sample.event as { eventId: string; occurredAt: number });
      const entry = await trail.record(sample.input as unknown as AuditEventInput);
      expect(entry.event, sample.name).toEqual(sample.event);
      expect(entry.canonical, sample.name).toBe(sample.canonical);
      expect(entry.eventDigest, sample.name).toBe(sample.digest);
      expect(sink.entries).toEqual([entry]);
      // The recorded event is a producer event under the strict schema, and digests the same when re-read.
      expect(parseAuditEvent(JSON.parse(entry.canonical))).toEqual(sample.event);
      expect(auditEventDigest(sample.event as unknown as AuditProducerEvent)).toBe(sample.digest);
    }
  });

  it('withholds the tool name of tool_call_completed_name_withheld', () => {
    const sample = fixture.events.find((candidate) => candidate.name === 'tool_call_completed_name_withheld')!;
    expect((sample.input['action'] as { name?: string }).name).toBe('lookup_order');
    expect((sample.event['action'] as { name?: string }).name).toBeUndefined();
  });

  it('chains three events of one source by sequence and previous digest', async () => {
    const { entries } = fixture.chain;
    expect(entries).toHaveLength(3);
    const sink = new MemoryAuditSink();
    let index = 0;
    const trail = fixtureTrail(fixture, sink, { eventId: '', occurredAt: 0 }, {
      sourceId: fixture.chain.sourceId,
      clock: () => entries[index]!.event['occurredAt'] as number,
      newEventId: () => entries[index]!.event['eventId'] as string,
    });
    for (index = 0; index < entries.length; index += 1) {
      const expected = entries[index]!;
      const entry = await trail.record(inputOf(expected.event));
      expect(entry.event).toEqual(expected.event);
      expect(entry.canonical).toBe(expected.canonical);
      expect(entry.eventDigest).toBe(expected.digest);
      expect(entry.event.source.sourceSequence).toBe(String(index + 1));
      expect(entry.event.source.previousSourceEventDigest).toBe(index === 0 ? undefined : entries[index - 1]!.digest);
    }
    expect(trail.sequence).toBe(4);
    expect(trail.previousSourceEventDigest).toBe(entries[2]!.digest);
  });

  it('records the tool name only when includeToolNames is set', async () => {
    const { input, included, withheld } = fixture.tool_names;
    const at = included as { eventId: string; occurredAt: number };
    const withNames = new MemoryAuditSink();
    const withoutNames = new MemoryAuditSink();
    await fixtureTrail(fixture, withNames, at, { includeToolNames: true }).record(input as unknown as AuditEventInput);
    await fixtureTrail(fixture, withoutNames, at, { includeToolNames: false }).record(input as unknown as AuditEventInput);
    expect(withNames.events[0]).toEqual(included);
    expect(withoutNames.events[0]).toEqual(withheld);
    expect(withoutNames.events[0]!.action.name).toBeUndefined();
  });

  it('refuses every rejection at the fixture path', () => {
    expect(fixture.rejections.length).toBeGreaterThanOrEqual(12);
    for (const rejection of fixture.rejections) {
      const result = validateAuditEvent(rejection.event);
      expect(result.ok, rejection.name).toBe(false);
      if (!result.ok) expect(result.issues[0]!.path, rejection.name).toBe(rejection.path);
      let thrown: unknown;
      try {
        parseAuditEvent(rejection.event);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, rejection.name).toBeInstanceOf(AuditEventInvalidError);
      expect((thrown as AuditEventInvalidError).code).toBe('AUDIT_EVENT_INVALID');
      expect((thrown as AuditEventInvalidError).message).toContain(`Audit event is invalid at ${rejection.path || '$'}:`);
    }
  });

  it('re-derives evidence_event through a trail with an evidence vault', async () => {
    const { evidence, evidence_event } = fixture;
    const ref = evidence.ref as { encryption: { nonce: string }; objectId: string };
    const stream = [Buffer.from(ref.encryption.nonce, 'base64url'), Buffer.from(ref.objectId.slice('evi_'.length), 'base64url')];
    const encryptor = new EvidenceEncryptor({ key: evidence.key_hex, keyId: evidence.key_id, randomBytes: () => Uint8Array.from(stream.shift()!) });
    const sink = new MemoryAuditSink();
    const trail = fixtureTrail(fixture, sink, evidence_event.event as { eventId: string; occurredAt: number }, {
      tenantRef: evidence.tenant as PartyRef,
      evidence: { encryptor, store: new MemoryEvidenceStore() },
    });
    const detailRef = await trail.evidence(evidence.plaintext_utf8, evidence.media_type, evidence.purpose, { commitPlaintext: true });
    expect(detailRef).toEqual(evidence.ref);
    expect([...trail.evidenceAad(evidence.purpose)]).toEqual([...Buffer.from(evidence.aad_utf8, 'utf8')]);
    const entry = await trail.record({
      eventType: 'tool.call.started',
      actor: { kind: 'pairwise_did', did: 'did:key:zFixtureAgent' },
      action: { category: 'tool.call', detailRef },
      outcome: 'unknown',
      evidence: [detailRef],
      details: { family: 'tool', phase: 'started', attempt: '1' },
    });
    expect(entry.event).toEqual(evidence_event.event);
    expect(entry.canonical).toBe(evidence_event.canonical);
    expect(entry.eventDigest).toBe(evidence_event.digest);
  });

  it('validates, canonicalizes and digests every audit-integrity vector event', () => {
    const vectors = auditIntegrityVectors().filter((vector) => vector.input.event !== undefined);
    expect(vectors).toHaveLength(3);
    for (const vector of vectors) {
      const result = validateAuditEvent(vector.input.event);
      expect(result.ok, vector.id).toBe(true);
      expect(canonicalize(vector.input.event), vector.id).toBe(vector.input.eventCanonical);
      expect(auditEventDigest(vector.input.event as AuditProducerEvent), vector.id).toBe(vector.input.eventDigest);
    }
  });
});

describe('AuditTrail', () => {
  it('refuses an empty or overlong sourceId', () => {
    expect(() => makeTrail(new MemoryAuditSink(), { sourceId: '' })).toThrow(TypeError);
    expect(() => makeTrail(new MemoryAuditSink(), { sourceId: 'x'.repeat(257) })).toThrow('sourceId must be 1 to 256 characters');
  });

  it('fills the envelope with its defaults: Helix binding, internal privacy, Date.now, audit_<uuid>', async () => {
    const sink = new MemoryAuditSink();
    const trail = makeTrail(sink);
    const before = Date.now();
    const entry = await trail.record(sessionInput());
    expect(entry.event.binding).toBe(AUDIT_BINDING_HELIX);
    expect(entry.event.privacy).toEqual(DEFAULT_AUDIT_PRIVACY);
    expect(entry.event.eventId).toMatch(/^audit_[0-9a-f-]{36}$/);
    expect(entry.event.occurredAt).toBeGreaterThanOrEqual(before);
    expect(entry.event.occurredAt).toBeLessThanOrEqual(Date.now());
    expect(entry.event.source).toEqual({ producer: PRODUCER, sourceId: 'test-source', sourceSequence: '1' });
    expect(entry.event.tenantRef).toEqual(TENANT);
    expect(entry.event.evidence).toEqual([]);
    expect(trail.sourceId).toBe('test-source');
    expect(trail.includeToolNames).toBe(false);
  });

  it('takes a binding, privacy override and caller-chosen id and time', async () => {
    const trail = makeTrail(new MemoryAuditSink(), { binding: AUDIT_BINDING_MCP, privacy: { classification: 'confidential', retentionClass: 'audit-30d' } });
    const entry = await trail.record({ ...sessionInput(), eventId: 'my-id', occurredAt: 1234, privacy: { legalHold: 'case-7' } });
    expect(entry.event.binding).toBe(AUDIT_BINDING_MCP);
    expect(entry.event.eventId).toBe('my-id');
    expect(entry.event.occurredAt).toBe(1234);
    expect(entry.event.privacy).toEqual({ classification: 'confidential', retentionClass: 'audit-30d', legalHold: 'case-7' });
  });

  it('bounds every caller-presented reference', () => {
    const trail = makeTrail(new MemoryAuditSink(), { includeToolNames: true });
    const long = 'x'.repeat(257);
    const long129 = 'y'.repeat(129);
    const event = trail.build({
      eventType: 'delegation.verified',
      correlationId: long,
      causationId: 'line\nbreak',
      action: { category: 'delegation', name: long },
      outcome: 'succeeded',
      reason: { code: long129 },
      authorization: {
        source: 'delegation',
        decision: 'allowed',
        scopeId: long,
        delegationRef: long,
        grantRef: long,
        policyId: long,
        policyVersion: long,
        verificationCode: long129,
      },
      details: { family: 'delegation', phase: 'verified', delegationRef: long, parentRef: long },
    });
    expect(event.correlationId).toBe(digestText(long));
    expect(event.causationId).toBe(digestText('line\nbreak'));
    expect(event.action.name).toBe(digestText(long));
    expect(event.reason).toEqual({ code: digestText(long129) });
    expect(event.authorization).toEqual({
      source: 'delegation',
      decision: 'allowed',
      scopeId: digestText(long),
      delegationRef: digestText(long),
      grantRef: digestText(long),
      policyId: digestText(long),
      policyVersion: digestText(long),
      verificationCode: digestText(long129),
    });
    expect(event.details).toEqual({ family: 'delegation', phase: 'verified', delegationRef: digestText(long), parentRef: digestText(long) });
  });

  it('keeps a reference that fits, and the authorization and reason members as given', () => {
    const trail = makeTrail(new MemoryAuditSink());
    const event = trail.build({
      eventType: 'authorization.denied',
      correlationId: 'call-1',
      action: { category: 'authorization', name: 'lookup_order' },
      outcome: 'denied',
      reason: { code: 'insufficient_scope' },
      authorization: { source: 'policy', decision: 'denied', scopeId: 'orders:admin' },
      details: { family: 'authorization', phase: 'denied' },
    });
    // A non-tool event keeps its action name whatever the tool-name policy says.
    expect(event.action).toEqual({ category: 'authorization', name: 'lookup_order' });
    expect(event.authorization).toEqual({ source: 'policy', decision: 'denied', scopeId: 'orders:admin' });
    expect(event.reason).toEqual({ code: 'insufficient_scope' });
  });

  it('bounds the detail references of every family that has them, and leaves the others alone', () => {
    const trail = makeTrail(new MemoryAuditSink());
    const long = 'z'.repeat(300);
    const build = (eventType: AuditEventInput['eventType'], category: string, details: AuditEventInput['details']) =>
      trail.build({ eventType, action: { category }, outcome: 'succeeded', details }).details;
    expect(build('delegation.issued', 'delegation', { family: 'delegation', phase: 'issued', delegationRef: long })).toEqual({
      family: 'delegation',
      phase: 'issued',
      delegationRef: digestText(long),
    });
    expect(build('grant.used', 'authorization', { family: 'authorization', phase: 'grant_used', grantRef: long })).toEqual({
      family: 'authorization',
      phase: 'grant_used',
      grantRef: digestText(long),
    });
    expect(build('grant.used', 'authorization', { family: 'authorization', phase: 'grant_used' })).toEqual({ family: 'authorization', phase: 'grant_used' });
    expect(build('consent.approved', 'consent', { family: 'consent', phase: 'approved', consentRef: long })).toEqual({
      family: 'consent',
      phase: 'approved',
      consentRef: digestText(long),
    });
    expect(build('consent.approved', 'consent', { family: 'consent', phase: 'approved' })).toEqual({ family: 'consent', phase: 'approved' });
    expect(build('tool.call.started', 'tool.call', { family: 'tool', phase: 'started', attempt: '1', idempotencyRef: long })).toEqual({
      family: 'tool',
      phase: 'started',
      attempt: '1',
      idempotencyRef: digestText(long),
    });
    expect(build('tool.call.started', 'tool.call', { family: 'tool', phase: 'started', attempt: '1' })).toEqual({ family: 'tool', phase: 'started', attempt: '1' });
    expect(build('session.rejected', 'session', { family: 'session', phase: 'rejected', reasonCode: long })).toEqual({
      family: 'session',
      phase: 'rejected',
      reasonCode: digestText(long),
    });
    expect(build('session.rejected', 'session', { family: 'session', phase: 'rejected' })).toEqual({ family: 'session', phase: 'rejected' });
    expect(build('proof.verified', 'proof', { family: 'proof', phase: 'verified', verificationCode: long })).toEqual({
      family: 'proof',
      phase: 'verified',
      verificationCode: digestText(long),
    });
    expect(build('proof.verified', 'proof', { family: 'proof', phase: 'verified' })).toEqual({ family: 'proof', phase: 'verified' });
    expect(build('key.rotated', 'configuration', { family: 'key', phase: 'rotated' })).toEqual({ family: 'key', phase: 'rotated' });
    expect(build('audit.accessed', 'audit', { family: 'administration', phase: 'accessed', purpose: 'review' })).toEqual({
      family: 'administration',
      phase: 'accessed',
      purpose: 'review',
    });
  });

  it('drops a tool name on tool events unless includeToolNames, and bounds it when kept', () => {
    const withheld = makeTrail(new MemoryAuditSink()).build({
      eventType: 'tool.call.completed',
      action: { category: 'tool.call', name: 'lookup_order' },
      outcome: 'succeeded',
      details: { family: 'tool', phase: 'completed', attempt: '1' },
    });
    expect(withheld.action).toEqual({ category: 'tool.call' });
    const kept = makeTrail(new MemoryAuditSink(), { includeToolNames: true }).build({
      eventType: 'tool.call.completed',
      action: { category: 'tool.call', name: 'x'.repeat(300) },
      outcome: 'succeeded',
      details: { family: 'tool', phase: 'completed', attempt: '1' },
    });
    expect(kept.action).toEqual({ category: 'tool.call', name: digestText('x'.repeat(300)) });
  });

  it('refuses an invalid input without consuming a sequence', async () => {
    const sink = new MemoryAuditSink();
    const trail = makeTrail(sink);
    // Validation runs before any sequence is claimed.
    await expect(
      trail.record({ ...sessionInput(), details: { family: 'tool', phase: 'started', attempt: '1' } } as unknown as AuditEventInput),
    ).rejects.toThrow(AuditEventInvalidError);
    expect(() => trail.build({ ...sessionInput(), unknownMember: 1 } as unknown as AuditEventInput)).toThrow('Audit event is invalid at $:');
    expect(trail.sequence).toBe(1);
    const entry = await trail.record(sessionInput());
    expect(entry.event.source.sourceSequence).toBe('1');
    expect(sink.entries).toHaveLength(1);
  });

  it('serializes concurrent records: sequences in call order, each linked to its predecessor', async () => {
    const sink = new MemoryAuditSink();
    const trail = makeTrail(sink);
    const [a, b, c] = await Promise.all([trail.record(sessionInput()), trail.record(sessionInput()), trail.record(sessionInput())]);
    expect([a.event.source.sourceSequence, b.event.source.sourceSequence, c.event.source.sourceSequence]).toEqual(['1', '2', '3']);
    expect(a.event.source.previousSourceEventDigest).toBeUndefined();
    expect(b.event.source.previousSourceEventDigest).toBe(a.eventDigest);
    expect(c.event.source.previousSourceEventDigest).toBe(b.eventDigest);
    expect(sink.entries).toEqual([a, b, c]);
    expect(trail.previousSourceEventDigest).toBe(c.eventDigest);
  });

  it('consumes a sequence on a sink failure and keeps the predecessor link on the last appended event', async () => {
    const sink = new MemoryAuditSink();
    let fail = false;
    const flaky = {
      append: async (entry: Parameters<MemoryAuditSink['append']>[0]) => {
        if (fail) throw new Error('sink down');
        await sink.append(entry);
      },
    };
    const trail = makeTrail(sink, { sink: flaky });
    const first = await trail.record(sessionInput());
    fail = true;
    await expect(trail.record(sessionInput())).rejects.toThrow('sink down');
    fail = false;
    const third = await trail.record(sessionInput());
    expect(third.event.source.sourceSequence).toBe('3');
    expect(third.event.source.previousSourceEventDigest).toBe(first.eventDigest);
    expect(sink.entries).toEqual([first, third]);
  });

  describe('evidence()', () => {
    const encryptor = new EvidenceEncryptor({ key: 'ab'.repeat(32), keyId: 'k1' });

    it('refuses without a vault', async () => {
      const trail = makeTrail(new MemoryAuditSink());
      await expect(trail.evidence('x', 'text/plain', 'tool.call.arguments')).rejects.toThrow(AuditEvidenceError);
      await expect(trail.evidence('x', 'text/plain', 'tool.call.arguments')).rejects.toThrow('no evidence vault');
    });

    it('encrypts under the tenant and purpose AAD, stores the object and returns its reference', async () => {
      const store = new MemoryEvidenceStore();
      const trail = makeTrail(new MemoryAuditSink(), { evidence: { encryptor, store } });
      const plain = await trail.evidence('{"a":1}', 'application/json', 'tool.call.arguments');
      expect(plain.plaintextCommitment).toBeUndefined();
      const committed = await trail.evidence(Buffer.from('{"a":1}'), 'application/json', 'tool.call.arguments', { commitPlaintext: true });
      expect(committed.plaintextCommitment).toMatch(/^sha256:/);
      const uncommitted = await trail.evidence('{"a":1}', 'application/json', 'tool.call.arguments', { commitPlaintext: false });
      expect(uncommitted.plaintextCommitment).toBeUndefined();
      const stored = await store.get(committed.objectId);
      expect(stored).not.toBeNull();
      const aad = evidenceAad(TENANT, 'tool.call.arguments');
      expect([...trail.evidenceAad('tool.call.arguments')]).toEqual([...aad]);
      expect(Buffer.from(encryptor.decrypt(stored!, aad)).toString('utf8')).toBe('{"a":1}');
      expect(() => encryptor.decrypt(stored!, evidenceAad(TENANT, 'tool.call.response'))).toThrow(AuditEvidenceError);
      // The reference is what an event carries.
      const entry = await trail.record({ ...sessionInput(), evidence: [committed] });
      expect(entry.event.evidence).toEqual([committed]);
    });
  });

  it('offers the PartyRef helpers', () => {
    expect(publicDid('did:web:a')).toEqual({ kind: 'public_did', did: 'did:web:a' });
    expect(pairwiseDid('did:key:z1')).toEqual({ kind: 'pairwise_did', did: 'did:key:z1' });
    expect(keyedCommitment(`sha256:${'0'.repeat(64)}`, 'k')).toEqual({ kind: 'keyed_commitment', value: `sha256:${'0'.repeat(64)}`, keyId: 'k' });
  });
});
