// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MemoryAuditSink,
  keyedCommitmentValue,
  parseAuditEvent,
  type AuditProducerEvent,
  type AuditTrailEntry,
} from '@helixid/sdk-js';
import {
  McpAuditTrail,
  ToolCallAudit,
  createHelixAuditReporter,
  createHelixAuditSink,
  createMcpAuditTrail,
  createNeedsAuthorization,
  type ToolAuditEvent,
} from '../src/index.js';

const SERVICE = 'did:web:orders.example';
const AGENT = 'did:key:zAgent';

function trailWithSink(options: Partial<Parameters<typeof createMcpAuditTrail>[0]> = {}): { trail: McpAuditTrail; sink: MemoryAuditSink } {
  const sink = new MemoryAuditSink();
  const trail = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE, ...options });
  return { trail, sink };
}

const decision = (overrides: Partial<ToolAuditEvent> = {}): ToolAuditEvent => ({
  event: 'AUTHZ_GRANTED',
  result: 'allowed',
  timestamp: '2026-01-01T00:00:00.000Z',
  authMethod: 'kyaos',
  agentDid: AGENT,
  level: 'L2',
  fresh: true,
  toolName: 'lookup_order',
  effectiveScopes: ['orders:read'],
  serviceDid: SERVICE,
  ...overrides,
});

describe('createHelixAuditReporter', () => {
  afterEach(() => vi.unstubAllGlobals());

  const entry: AuditTrailEntry = {
    event: { eventType: 'session.established' } as unknown as AuditProducerEvent,
    canonical: '{"eventType":"session.established"}',
    eventDigest: `sha256:${'0'.repeat(64)}`,
  };

  it('posts the canonical event text with the bearer key, trailing slash trimmed', async () => {
    const f = vi.fn(async () => new Response('{"recorded":true}', { status: 201 }));
    const reporter = createHelixAuditReporter({ baseUrl: 'http://localhost:3680///', apiKey: 'hak', fetch: f as unknown as typeof fetch, timeoutMs: 50 });
    await reporter.append(entry);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://localhost:3680/v1/audit-log/events');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer hak' });
    expect(init.body).toBe(entry.canonical);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('throws on a non-2xx answer', async () => {
    const f = vi.fn(async () => new Response('nope', { status: 500 }));
    const reporter = createHelixAuditReporter({ baseUrl: 'http://localhost:1', apiKey: 'k', fetch: f as unknown as typeof fetch });
    await expect(reporter.append(entry)).rejects.toThrow('audit-log/events responded 500');
  });

  it('uses the global fetch and a 5 s timeout by default', async () => {
    const f = vi.fn(async () => new Response('{}', { status: 201 }));
    vi.stubGlobal('fetch', f);
    await createHelixAuditReporter({ baseUrl: 'http://localhost:1', apiKey: 'k' }).append(entry);
    expect(f).toHaveBeenCalledTimes(1);
  });
});

describe('createHelixAuditSink', () => {
  it('passes sourceId and includeToolNames through to the trail', async () => {
    const f = vi.fn(async () => new Response('{}', { status: 201 }));
    const sink = createHelixAuditSink({
      baseUrl: 'http://localhost:1',
      apiKey: 'k',
      serviceDid: SERVICE,
      sourceId: 'orders-eu-1',
      includeToolNames: true,
      fetch: f as unknown as typeof fetch,
    });
    await sink(decision({ authMethod: 'oauth', oauthSubject: 'user-9', agentDid: undefined }));
    const body = JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect(body.source.sourceId).toBe('orders-eu-1');
    expect(body.action).toEqual({ category: 'authorization', name: 'lookup_order' });
    expect(body.eventType).toBe('authorization.approved');
  });

  it('lets a failed POST propagate to the caller (the middleware reports it through onAuditError)', async () => {
    const f = vi.fn(async () => new Response('', { status: 401 }));
    const sink = createHelixAuditSink({ baseUrl: 'http://localhost:1', apiKey: 'k', serviceDid: SERVICE, fetch: f as unknown as typeof fetch });
    await expect(sink(decision())).rejects.toThrow('responded 401');
  });
});

describe('createMcpAuditTrail', () => {
  it('needs a server DID or a producer', () => {
    expect(() => createMcpAuditTrail({ reporter: new MemoryAuditSink() })).toThrow(TypeError);
    expect(() => createMcpAuditTrail({ reporter: new MemoryAuditSink() })).toThrow(/serviceDid/);
    expect(createMcpAuditTrail({ reporter: new MemoryAuditSink(), producer: { kind: 'public_did', did: 'did:web:p' } })).toBeInstanceOf(McpAuditTrail);
  });

  it('defaults: pairwise producer, tenant = producer, source mcp-middleware:<did>, MCP binding, resource = the server', async () => {
    const { trail, sink } = trailWithSink();
    const entry = await trail.session('established', { succeeded: true });
    expect(entry.event).toMatchObject({
      eventType: 'session.established',
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
      tenantRef: { kind: 'pairwise_did', did: SERVICE },
      source: { producer: { kind: 'pairwise_did', did: SERVICE }, sourceId: `mcp-middleware:${SERVICE}`, sourceSequence: '1' },
      resource: { kind: 'public_did', did: SERVICE },
      action: { category: 'session' },
      outcome: 'succeeded',
      details: { family: 'session', phase: 'established' },
    });
    expect(entry.event.actor).toBeUndefined();
    expect(entry.event.correlationId).toBeUndefined();
    expect(sink.entries).toEqual([entry]);
    expect(trail.serviceDid).toBe(SERVICE);
    expect(trail.includeToolNames).toBe(false);
    expect(trail.trail.sourceId).toBe(`mcp-middleware:${SERVICE}`);
  });

  it('takes an explicit producer, tenant, source, clock and id generator; no resource without a server DID', async () => {
    const sink = new MemoryAuditSink();
    const trail = createMcpAuditTrail({
      reporter: sink,
      producer: { kind: 'public_did', did: 'did:web:producer' },
      tenantRef: { kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-v1' },
      sourceId: 'src-1',
      clock: () => 1750000001123,
      newEventId: () => 'fixed-id',
    });
    const entry = await trail.session('rejected', { succeeded: false, reasonCode: 'vp_expired' });
    expect(entry.event).toMatchObject({
      eventId: 'fixed-id',
      occurredAt: 1750000001123,
      tenantRef: { kind: 'keyed_commitment', keyId: 'tenant-key-v1' },
      source: { producer: { kind: 'public_did', did: 'did:web:producer' }, sourceId: 'src-1' },
      outcome: 'denied',
      reason: { code: 'vp_expired' },
      details: { family: 'session', phase: 'rejected', reasonCode: 'vp_expired' },
    });
    expect(entry.event.resource).toBeUndefined();
    expect(trail.serviceDid).toBeUndefined();
    expect((await createMcpAuditTrail({ reporter: sink, producer: { kind: 'public_did', did: 'did:web:p' } }).session('established', { succeeded: true })).event.source.sourceId).toBe(
      'mcp-middleware:server',
    );
  });
});

describe('McpAuditTrail events', () => {
  it('session: an expired session failed, a rejected one was denied', async () => {
    const { trail } = trailWithSink();
    expect((await trail.session('expired', { succeeded: false })).event.outcome).toBe('failed');
    expect((await trail.session('replay_rejected', { succeeded: false, reasonCode: 'nonce_reused' })).event.outcome).toBe('denied');
  });

  it('proof: digest, verification code and reason', async () => {
    const { trail } = trailWithSink();
    const verified = await trail.proof('verified', { outcome: 'succeeded', proofDigest: `sha256:${'c'.repeat(64)}`, verificationCode: 'VP_VERIFIED' });
    expect(verified.event).toMatchObject({
      eventType: 'proof.verified',
      action: { category: 'proof' },
      details: { family: 'proof', phase: 'verified', proofDigest: `sha256:${'c'.repeat(64)}`, verificationCode: 'VP_VERIFIED' },
    });
    expect(verified.event.reason).toBeUndefined();
    const rejected = await trail.proof('rejected', { outcome: 'denied', reasonCode: 'VP_SIGNATURE_INVALID' });
    expect(rejected.event).toMatchObject({ eventType: 'proof.rejected', outcome: 'denied', reason: { code: 'VP_SIGNATURE_INVALID' }, details: { family: 'proof', phase: 'rejected' } });
  });

  it('delegation: reference, parent and reason', async () => {
    const { trail } = trailWithSink();
    const issued = await trail.delegation('issued', { delegationRef: 'urn:uuid:child', outcome: 'succeeded', parentRef: 'urn:uuid:root' });
    expect(issued.event).toMatchObject({
      eventType: 'delegation.issued',
      action: { category: 'delegation' },
      details: { family: 'delegation', phase: 'issued', delegationRef: 'urn:uuid:child', parentRef: 'urn:uuid:root' },
    });
    const rejected = await trail.delegation('rejected', { delegationRef: 'urn:uuid:child', outcome: 'denied', reasonCode: 'chain_broken' });
    expect(rejected.event).toMatchObject({ reason: { code: 'chain_broken' }, details: { family: 'delegation', phase: 'rejected', delegationRef: 'urn:uuid:child' } });
    expect((rejected.event.details as { parentRef?: string }).parentRef).toBeUndefined();
  });

  it('authorization: every phase, grant_used as grant.used, the grant reference, the tool-name policy', async () => {
    const { trail } = trailWithSink();
    const approved = await trail.authorization('approved', { outcome: 'succeeded', toolName: 'lookup_order' });
    expect(approved.event).toMatchObject({ eventType: 'authorization.approved', action: { category: 'authorization' }, details: { family: 'authorization', phase: 'approved' } });
    expect(approved.event.action.name).toBeUndefined();
    const denied = await trail.authorization('denied', { outcome: 'denied', reasonCode: 'insufficient_scope' });
    expect(denied.event).toMatchObject({ eventType: 'authorization.denied', reason: { code: 'insufficient_scope' } });
    const grant = await trail.authorization('grant_used', { outcome: 'succeeded', grantRef: 'vc:helix:grant-1' });
    expect(grant.event).toMatchObject({ eventType: 'grant.used', details: { family: 'authorization', phase: 'grant_used', grantRef: 'vc:helix:grant-1' } });
    for (const phase of ['evaluated', 'step_up_required'] as const) {
      expect((await trail.authorization(phase, { outcome: 'challenged' })).event.eventType).toBe(`authorization.${phase}`);
    }
    const named = trailWithSink({ includeToolNames: true }).trail;
    expect((await named.authorization('approved', { outcome: 'succeeded', toolName: 'lookup_order' })).event.action).toEqual({ category: 'authorization', name: 'lookup_order' });
  });

  it('tool: attempt defaults to 1, reason and the tool-name policy', async () => {
    const { trail } = trailWithSink();
    const started = await trail.tool('started', { outcome: 'unknown', toolName: 'lookup_order' });
    expect(started.event).toMatchObject({ eventType: 'tool.call.started', action: { category: 'tool.call' }, details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(started.event.action.name).toBeUndefined();
    const failed = await trail.tool('failed', { outcome: 'failed', attempt: '2', reasonCode: 'handler_error' });
    expect(failed.event).toMatchObject({ eventType: 'tool.call.failed', reason: { code: 'handler_error' }, details: { attempt: '2' } });
    const named = trailWithSink({ includeToolNames: true }).trail;
    expect((await named.tool('completed', { outcome: 'succeeded', toolName: 'lookup_order' })).event.action).toEqual({ category: 'tool.call', name: 'lookup_order' });
  });

  it('copies the context onto the event', async () => {
    const { trail } = trailWithSink();
    const entry = await trail.tool('completed', {
      outcome: 'succeeded',
      context: {
        actor: { kind: 'pairwise_did', did: AGENT },
        responsibleParty: { kind: 'public_did', did: 'did:key:zUser' },
        authorization: { source: 'delegation', decision: 'allowed', scopeId: 'orders:read' },
        correlationId: 'call-1',
        causationId: 'call-0',
      },
    });
    expect(entry.event).toMatchObject({
      actor: { kind: 'pairwise_did', did: AGENT },
      responsibleParty: { kind: 'public_did', did: 'did:key:zUser' },
      authorization: { source: 'delegation', decision: 'allowed', scopeId: 'orders:read' },
      correlationId: 'call-1',
      causationId: 'call-0',
    });
    expect(parseAuditEvent(JSON.parse(entry.canonical))).toEqual(entry.event);
  });

  it('commits an OAuth subject under the trail key', () => {
    const key = Buffer.from('k'.repeat(32));
    const { trail } = trailWithSink({ oauthSubjectKey: key });
    expect(trail.oauthActor('user-9')).toEqual({ kind: 'keyed_commitment', value: keyedCommitmentValue(key, 'user-9'), keyId: 'oauth-subject-v1' });
    // Without a key, each trail commits under its own random key.
    expect(trailWithSink().trail.oauthActor('user-9')).not.toEqual(trailWithSink().trail.oauthActor('user-9'));
  });
});

describe('McpAuditTrail.toolAuditSink', () => {
  it('a KYA-OS caller allowed: proof.verified at its level, then authorization.approved from delegation', async () => {
    const { trail, sink } = trailWithSink();
    await trail.toolAuditSink()(decision({ correlationId: 'call-7' }));
    expect(sink.eventTypes).toEqual(['proof.verified', 'authorization.approved']);
    const [proof, authorization] = sink.events;
    expect(proof).toMatchObject({
      actor: { kind: 'pairwise_did', did: AGENT },
      correlationId: 'call-7',
      resource: { kind: 'public_did', did: SERVICE },
      outcome: 'succeeded',
      details: { family: 'proof', phase: 'verified', verificationCode: 'KYAOS_PROOF_L2' },
    });
    expect(proof!.authorization).toBeUndefined();
    expect(authorization).toMatchObject({
      actor: { kind: 'pairwise_did', did: AGENT },
      correlationId: 'call-7',
      outcome: 'succeeded',
      authorization: { source: 'delegation', decision: 'allowed' },
      details: { family: 'authorization', phase: 'approved' },
    });
    expect(authorization!.authorization!.scopeId).toBeUndefined();
    expect(authorization!.action.name).toBeUndefined();
  });

  it('a request proof the local verifier refused: proof.rejected by its first reason, and no authorization event (story F-2)', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ event: 'AUTHZ_DENIED', result: 'denied', effectiveScopes: [], reason: 'proof_expired,status_unavailable' }));
    await sinkFn(decision({ event: 'AUTHZ_DENIED', result: 'denied', effectiveScopes: [], reason: ' ' }));
    expect(sink.eventTypes).toEqual(['proof.rejected', 'proof.rejected']);
    expect(sink.events[0]).toMatchObject({ outcome: 'denied', reason: { code: 'proof_expired' }, actor: { kind: 'pairwise_did', did: AGENT } });
    expect(sink.events[1]).toMatchObject({ reason: { code: 'proof_invalid' } });
  });

  it('names the level in the verification code, with _CACHED when a status was not read live, and none without a level', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ level: 'L3', fresh: false }));
    await sinkFn(decision({ level: undefined, fresh: undefined }));
    expect(sink.events[0]!.details).toMatchObject({ verificationCode: 'KYAOS_PROOF_L3_CACHED' });
    expect(sink.events[2]!.details).toMatchObject({ verificationCode: 'KYAOS_PROOF' });
  });

  it('a KYA-OS caller denied: insufficient_scope with the scope, else tool_not_permitted', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ event: 'AUTHZ_DENIED', result: 'denied', requiredScope: 'orders:admin', reason: 'insufficient scope' }));
    await sinkFn(decision({ event: 'AUTHZ_DENIED', result: 'denied', toolName: 'delete_order', reason: 'tool is not in toolScopes' }));
    expect(sink.eventTypes).toEqual(['proof.verified', 'authorization.denied', 'proof.verified', 'authorization.denied']);
    expect(sink.events[1]).toMatchObject({ outcome: 'denied', reason: { code: 'insufficient_scope' }, authorization: { source: 'delegation', decision: 'denied', scopeId: 'orders:admin' } });
    expect(sink.events[3]).toMatchObject({ outcome: 'denied', reason: { code: 'tool_not_permitted' }, authorization: { source: 'delegation', decision: 'denied' } });
    expect(sink.events[3]!.authorization!.scopeId).toBeUndefined();
    for (const event of sink.events) expect(JSON.stringify(event)).not.toContain('toolScopes');
  });

  it('an L3-E needs_authorization challenge: authorization.denied keeps the reason needs_authorization', async () => {
    const { trail, sink } = trailWithSink();
    const layer = createNeedsAuthorization({ authorizationUrl: 'https://consent.example/authorize', auditSink: trail.toolAuditSink(), serviceDid: SERVICE });
    await layer.challenge({ agentDid: AGENT, tool: 'delete_order', scopes: ['orders:admin'], effectiveScopes: ['orders:read'] });
    expect(sink.eventTypes).toEqual(['proof.verified', 'authorization.denied']);
    expect(sink.events[1]).toMatchObject({ outcome: 'denied', reason: { code: 'needs_authorization' }, authorization: { decision: 'denied', scopeId: 'orders:admin' } });
  });

  it('an OAuth caller: only the authorization event, from policy, the subject as a keyed commitment', async () => {
    const key = Buffer.from('k'.repeat(32));
    const { trail, sink } = trailWithSink({ oauthSubjectKey: key });
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ authMethod: 'oauth', agentDid: undefined, level: undefined, fresh: undefined, oauthSubject: 'user-9' }));
    await sinkFn(decision({ authMethod: 'oauth', agentDid: undefined, level: undefined, fresh: undefined, oauthSubject: 'user-9', event: 'AUTHZ_DENIED', result: 'denied', requiredScope: 'orders:admin' }));
    expect(sink.eventTypes).toEqual(['authorization.approved', 'authorization.denied']);
    expect(sink.events[0]).toMatchObject({
      actor: { kind: 'keyed_commitment', value: keyedCommitmentValue(key, 'user-9'), keyId: 'oauth-subject-v1' },
      authorization: { source: 'policy', decision: 'allowed' },
    });
    expect(sink.events[1]).toMatchObject({ authorization: { source: 'policy', decision: 'denied', scopeId: 'orders:admin' }, reason: { code: 'insufficient_scope' } });
    for (const entry of sink.entries) expect(entry.canonical).not.toContain('user-9');
  });

  it('handles a decision with no tool name', async () => {
    const { trail, sink } = trailWithSink({ includeToolNames: true });
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ toolName: undefined }));
    await sinkFn(decision({ toolName: undefined, event: 'AUTHZ_DENIED', result: 'denied' }));
    expect(sink.eventTypes).toEqual(['proof.verified', 'authorization.approved', 'proof.verified', 'authorization.denied']);
    expect(sink.events[1]!.authorization).toEqual({ source: 'delegation', decision: 'allowed' });
    expect(sink.events[1]!.action).toEqual({ category: 'authorization' });
    expect(sink.events[3]!.action).toEqual({ category: 'authorization' });
  });

  it('records no actor for a decision that names no caller', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision({ authMethod: 'oauth', agentDid: undefined }));
    await sinkFn(decision({ agentDid: undefined }));
    expect(sink.eventTypes).toEqual(['authorization.approved', 'proof.verified', 'authorization.approved']);
    for (const event of sink.events) expect(event.actor).toBeUndefined();
  });

  it('records the tool name on the authorization event only when includeToolNames', async () => {
    const { trail, sink } = trailWithSink({ includeToolNames: true });
    await trail.toolAuditSink()(decision());
    expect(sink.events[0]!.action).toEqual({ category: 'proof' });
    expect(sink.events[1]!.action).toEqual({ category: 'authorization', name: 'lookup_order' });
  });

  it('lets a reporter failure propagate', async () => {
    const trail = createMcpAuditTrail({
      reporter: {
        append: async () => {
          throw new Error('reporter down');
        },
      },
      serviceDid: SERVICE,
    });
    await expect(trail.toolAuditSink()(decision())).rejects.toThrow('reporter down');
    await expect(trail.beginToolCall().started()).rejects.toThrow('reporter down');
  });
});

describe('McpAuditTrail.beginToolCall', () => {
  it('gives the call an audit_<uuid> correlation id, or keeps the one given', () => {
    const { trail } = trailWithSink();
    const call = trail.beginToolCall();
    expect(call).toBeInstanceOf(ToolCallAudit);
    expect(call.correlationId).toMatch(/^audit_[0-9a-f-]{36}$/);
    expect(trail.beginToolCall({ correlationId: 'call-1' }).correlationId).toBe('call-1');
    expect(call.actor).toBeUndefined();
    expect(call.delegation).toBeUndefined();
  });

  it('records session.established, then the guard decision and the tool lifecycle under one correlation id and actor', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    const call = trail.beginToolCall({ toolName: 'lookup_order', correlationId: 'call-1' });
    const result = await call.run(async () => {
      expect(sink.eventTypes).toEqual(['session.established']);
      await sinkFn(decision());
      await call.started();
      await call.completed();
      return 'answer';
    });
    expect(result).toBe('answer');
    expect(sink.eventTypes).toEqual(['session.established', 'proof.verified', 'authorization.approved', 'tool.call.started', 'tool.call.completed']);
    for (const event of sink.events) expect(event.correlationId).toBe('call-1');
    // The caller was learned from the decision and attributed to the later tool events.
    expect(sink.events[0]!.actor).toBeUndefined();
    for (const event of sink.events.slice(1)) expect(event.actor).toEqual({ kind: 'pairwise_did', did: AGENT });
    expect(call.actor).toEqual({ kind: 'pairwise_did', did: AGENT });
    expect(sink.events[3]).toMatchObject({ outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(sink.events[4]).toMatchObject({ outcome: 'succeeded', details: { family: 'tool', phase: 'completed', attempt: '1' } });
    expect(sink.events.map((event) => event.source.sourceSequence)).toEqual(['1', '2', '3', '4', '5']);
    // No tool name anywhere by default.
    for (const entry of sink.entries) expect(entry.canonical).not.toContain('lookup_order');
  });

  it('keeps a given actor, and records failed and denied with their codes', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    const actor = { kind: 'public_did' as const, did: 'did:web:known' };
    const call = trail.beginToolCall({ toolName: 't', actor });
    await call.run(async () => {
      await sinkFn(decision());
      await call.failed('handler_error');
      await call.denied('insufficient_scope');
    });
    expect(sink.eventTypes).toEqual(['session.established', 'proof.verified', 'authorization.approved', 'tool.call.failed', 'tool.call.denied']);
    // The decision's own events name the verified agent; the call's events keep the actor given up front.
    expect(sink.events.map((event) => event.actor)).toEqual([actor, { kind: 'pairwise_did', did: AGENT }, { kind: 'pairwise_did', did: AGENT }, actor, actor]);
    expect(call.actor).toEqual(actor);
    expect(sink.events[3]).toMatchObject({ outcome: 'failed', reason: { code: 'handler_error' } });
    expect(sink.events[4]).toMatchObject({ outcome: 'denied', reason: { code: 'insufficient_scope' } });
  });

  it('scopes the context to run(): a decision outside it has no correlation id, and an explicit one wins inside', async () => {
    const { trail, sink } = trailWithSink();
    const sinkFn = trail.toolAuditSink();
    await sinkFn(decision());
    expect(sink.events[0]!.correlationId).toBeUndefined();
    const call = trail.beginToolCall({ correlationId: 'call-1' });
    await call.run(async () => sinkFn(decision({ correlationId: 'explicit' })));
    expect(sink.events.slice(-2).map((event) => event.correlationId)).toEqual(['explicit', 'explicit']);
    // Two concurrent calls keep their own ids.
    const a = trail.beginToolCall({ correlationId: 'a' });
    const b = trail.beginToolCall({ correlationId: 'b' });
    await Promise.all([a.run(() => sinkFn(decision())), b.run(() => sinkFn(decision()))]);
    const ids = sink.events.slice(-6).map((event) => event.correlationId);
    expect(ids.filter((id) => id === 'a')).toHaveLength(3);
    expect(ids.filter((id) => id === 'b')).toHaveLength(3);
  });

});
