// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import {
  AUDIT_BINDING_HELIX,
  AUDIT_BINDING_MCP,
  AUDIT_EVENT_FAMILIES,
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  AUDIT_EVENT_VERSION,
  AUDIT_INTEGRITY_SUITE,
  auditEventFamily,
  type AuditEventDetails,
  type AuditEventFamily,
  type AuditEventType,
} from '../../../src/audit/types.js';
import { AuditEventInvalidError, parseAuditEvent, validateAuditEvent } from '../../../src/audit/schema.js';

/** The family of every event type, as AUDITABILITY.md lists them. */
const EXPECTED_FAMILY: Record<AuditEventType, AuditEventFamily> = {
  'session.established': 'session',
  'session.rejected': 'session',
  'session.expired': 'session',
  'session.replay_rejected': 'session',
  'tool.call.started': 'tool',
  'tool.call.completed': 'tool',
  'tool.call.failed': 'tool',
  'tool.call.denied': 'tool',
  'tool.call.challenged': 'tool',
  'proof.generated': 'proof',
  'proof.verified': 'proof',
  'proof.rejected': 'proof',
  'delegation.issued': 'delegation',
  'delegation.verified': 'delegation',
  'delegation.rejected': 'delegation',
  'delegation.revoked': 'delegation',
  'delegation.cascade_revoked': 'delegation',
  'delegation.outbound_attached': 'delegation',
  'authorization.evaluated': 'authorization',
  'authorization.approved': 'authorization',
  'authorization.denied': 'authorization',
  'authorization.step_up_required': 'authorization',
  'grant.used': 'authorization',
  'consent.requested': 'consent',
  'consent.approved': 'consent',
  'consent.denied': 'consent',
  'credential.required': 'consent',
  'credential.verified': 'consent',
  'credential.failed': 'consent',
  'key.rotated': 'key',
  'policy.changed': 'key',
  'configuration.changed': 'key',
  'integrity_suite.transitioned': 'key',
  'ledger.epoch.started': 'ledger',
  'ledger.epoch.transitioned': 'ledger',
  'checkpoint.created': 'ledger',
  'checkpoint.anchored': 'ledger',
  'checkpoint.anchor_failed': 'ledger',
  'evidence.disposed': 'ledger',
  'projection.reconciled': 'ledger',
  'audit.source_high_water': 'administration',
  'audit.accessed': 'administration',
  'audit.exported': 'administration',
  'legal_hold.applied': 'administration',
  'retention.executed': 'administration',
};

/** A minimal, valid details payload per family. */
const MINIMAL_DETAILS: Record<AuditEventFamily, AuditEventDetails> = {
  session: { family: 'session', phase: 'established' },
  tool: { family: 'tool', phase: 'started', attempt: '1' },
  proof: { family: 'proof', phase: 'verified' },
  delegation: { family: 'delegation', phase: 'verified', delegationRef: 'urn:uuid:1' },
  authorization: { family: 'authorization', phase: 'approved' },
  consent: { family: 'consent', phase: 'approved' },
  key: { family: 'key', phase: 'rotated' },
  ledger: { family: 'ledger', phase: 'checkpoint_created' },
  administration: { family: 'administration', phase: 'accessed' },
};

describe('audit event catalog', () => {
  it('holds the 45 event types and 9 families', () => {
    expect(AUDIT_EVENT_TYPES).toHaveLength(45);
    expect(new Set(AUDIT_EVENT_TYPES).size).toBe(45);
    expect(AUDIT_EVENT_FAMILIES).toHaveLength(9);
    expect(AUDIT_EVENT_SCHEMA).toBe('https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0');
    expect(AUDIT_EVENT_VERSION).toBe('1.0.0');
    expect(AUDIT_INTEGRITY_SUITE).toBe('KYA-AUDIT-JCS-SHA256-JWS-2026');
    expect(AUDIT_BINDING_MCP).toBe('urn:kya-os:audit-binding:mcp:2025-11-25');
    expect(AUDIT_BINDING_HELIX).toBe('urn:kya-os:audit-binding:helix:2026-11-20');
  });

  it.each(AUDIT_EVENT_TYPES)('%s belongs to its family and validates with that family', (eventType) => {
    const family = EXPECTED_FAMILY[eventType];
    expect(auditEventFamily(eventType)).toBe(family);
    const event = {
      schema: AUDIT_EVENT_SCHEMA,
      eventId: 'e1',
      eventType,
      eventVersion: AUDIT_EVENT_VERSION,
      binding: AUDIT_BINDING_MCP,
      occurredAt: 1,
      tenantRef: { kind: 'pairwise_did', did: 'did:key:z1' },
      source: { producer: { kind: 'pairwise_did', did: 'did:key:z1' }, sourceId: 's' },
      action: { category: family },
      outcome: 'succeeded',
      evidence: [],
      details: MINIMAL_DETAILS[family],
      privacy: { classification: 'internal', retentionClass: 'audit-indefinite' },
    };
    expect(parseAuditEvent(event)).toEqual(event);
    // Any other family is refused at details.family.
    const other = AUDIT_EVENT_FAMILIES.find((candidate) => candidate !== family)!;
    const wrong = validateAuditEvent({ ...event, details: MINIMAL_DETAILS[other] });
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) {
      expect(wrong.issues[0]).toEqual({ path: 'details.family', message: `must be "${family}" for ${eventType}` });
    }
  });
});

describe('AuditEventInvalidError', () => {
  it('names the first issue, or says only that the event is invalid', () => {
    const named = new AuditEventInvalidError([{ path: 'actor', message: 'bad' }, { path: 'x', message: 'y' }]);
    expect(named.code).toBe('AUDIT_EVENT_INVALID');
    expect(named.httpStatus).toBe(400);
    expect(named.name).toBe('AuditEventInvalidError');
    expect(named.message).toBe('Audit event is invalid at actor: bad');
    expect(named.issues).toHaveLength(2);
    expect(named.details).toEqual({ issues: [{ path: 'actor', message: 'bad' }, { path: 'x', message: 'y' }] });
    expect(new AuditEventInvalidError([{ path: '', message: 'unknown member' }]).message).toBe('Audit event is invalid at $: unknown member');
    expect(new AuditEventInvalidError([]).message).toBe('Audit event is invalid');
  });

  it('is what parseAuditEvent throws', () => {
    expect(() => parseAuditEvent(null)).toThrow(AuditEventInvalidError);
    expect(() => parseAuditEvent({})).toThrow(/Audit event is invalid at /);
  });
});
