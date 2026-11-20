// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import { MemoryAuditSink, TeeAuditSink } from '../../../src/audit/sink.js';
import type { AuditTrailEntry } from '../../../src/audit/types.js';

const entry = (eventType: string): AuditTrailEntry =>
  ({ event: { eventType }, canonical: `{"eventType":"${eventType}"}`, eventDigest: `sha256:${'0'.repeat(64)}` }) as unknown as AuditTrailEntry;

describe('MemoryAuditSink', () => {
  it('keeps entries in order and exposes events and event types', async () => {
    const sink = new MemoryAuditSink();
    await sink.append(entry('session.established'));
    await sink.append(entry('tool.call.started'));
    expect(sink.entries).toHaveLength(2);
    expect(sink.events.map((event) => event.eventType)).toEqual(['session.established', 'tool.call.started']);
    expect(sink.eventTypes).toEqual(['session.established', 'tool.call.started']);
  });
});

describe('TeeAuditSink', () => {
  it('delivers every entry to each sink in turn', async () => {
    const a = new MemoryAuditSink();
    const b = new MemoryAuditSink();
    const tee = new TeeAuditSink([a, b]);
    await tee.append(entry('proof.verified'));
    expect(a.eventTypes).toEqual(['proof.verified']);
    expect(b.eventTypes).toEqual(['proof.verified']);
  });

  it('fails the record when one sink fails, and stops there', async () => {
    const a = new MemoryAuditSink();
    const failing = {
      append: async () => {
        throw new Error('sink down');
      },
    };
    const b = new MemoryAuditSink();
    await expect(new TeeAuditSink([a, failing, b]).append(entry('proof.verified'))).rejects.toThrow('sink down');
    expect(a.eventTypes).toEqual(['proof.verified']);
    expect(b.eventTypes).toEqual([]);
  });
});
