// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// Gap 1: the guard decides which JSON-RPC methods need a caller (all but `openMethods`); resources and
// prompts have their own deny-by-default scope maps. Gap 2: every refusal is audited, including those of a
// caller the guard could not identify (anonymous, with what it claimed marked unverified).
import { describe, expect, it } from 'vitest';
import { MemoryAuditSink, kyaos } from '@helixid/sdk-js';
import { helixidMCPMiddleware } from '../src/middleware.js';
import { AuthorizationServerUnavailableError } from '../src/errors.js';
import { createMcpAuditTrail, type ToolAuditEvent } from '../src/audit.js';
import { DEFAULT_OPEN_METHODS, claimedIssuerOf, headerOf, methodOf, refusalCodeOf, targetOf } from '../src/gate.js';
import { toHttpErrorResponse } from '../src/metadata.js';
import { fixtureVerifier, makeAgent, NOW_MS } from './proof-helpers.js';

const SERVICE = 'did:web:orders.helix.test';
const READER = { authorization: 'Bearer reader' };

function gate(extra: Parameters<typeof helixidMCPMiddleware>[0] = {}) {
  const events: ToolAuditEvent[] = [];
  const mw = helixidMCPMiddleware({
    validateOAuthToken: async (token) => {
      if (token === 'reader') return { sub: 'user-1', scopes: ['docs:read'] };
      throw new Error('unknown token');
    },
    toolScopes: { lookup: [] },
    resourceScopes: { 'file:///docs/a.md': ['docs:read'], 'file:///docs/secret.md': ['docs:admin'] },
    promptScopes: { summarize: ['docs:read'] },
    auditSink: (event) => void events.push(event),
    serviceDid: SERVICE,
    ...extra,
  });
  return { mw, events };
}

const jwt = (claims: Record<string, unknown>): string => `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;

describe('which methods need a caller', () => {
  it('lets the default open methods through unchecked and unaudited', async () => {
    const { mw, events } = gate();
    expect(DEFAULT_OPEN_METHODS).toEqual(['initialize', 'notifications/initialized', 'tools/list']);
    for (const method of DEFAULT_OPEN_METHODS) expect(await mw.authorize({ method })).toEqual({ authMethod: 'none', scopes: [] });
    expect(await mw.authorize({ request: { method: 'tools/list', params: {} } })).toEqual({ authMethod: 'none', scopes: [] });
    expect(events).toEqual([]);
  });

  it('refuses every other method without a credential (401), and audits each refusal with its method', async () => {
    const { mw, events } = gate();
    for (const method of ['resources/list', 'resources/read', 'prompts/list', 'prompts/get', 'ping', 'tools/call']) {
      const error = await mw.authorize({ method, name: 'x' }).catch((e: unknown) => e);
      expect(toHttpErrorResponse(error, { resourceMetadataUrl: 'https://x' })?.status).toBe(401);
    }
    expect(events.map((e) => [e.method, e.authMethod, e.reasonCode])).toEqual([
      ['resources/list', 'none', 'proof_missing'],
      ['resources/read', 'none', 'proof_missing'],
      ['prompts/list', 'none', 'proof_missing'],
      ['prompts/get', 'none', 'proof_missing'],
      ['ping', 'none', 'proof_missing'],
      ['tools/call', 'none', 'proof_missing'],
    ]);
    expect(events[1]).toMatchObject({ resourceUri: 'x' });
    expect(events[3]).toMatchObject({ promptName: 'x' });
    expect(events[5]).toMatchObject({ toolName: 'x' });
  });

  it('the operator sets the open list: [] opens nothing, and any method can be opened', async () => {
    const closed = gate({ openMethods: [] });
    await expect(closed.mw.authorize({ method: 'initialize' })).rejects.toMatchObject({ code: 'PROOF_MISSING' });
    const open = gate({ openMethods: ['resources/list'] });
    expect(await open.mw.authorize({ method: 'resources/list' })).toEqual({ authMethod: 'none', scopes: [] });
    await expect(open.mw.authorize({ method: 'tools/list' })).rejects.toMatchObject({ code: 'PROOF_MISSING' });
  });

  it('a verified caller may list; resources and prompts need their scope and are deny by default', async () => {
    const { mw, events } = gate();
    expect(await mw.authorize({ method: 'resources/list', headers: READER })).toMatchObject({ authMethod: 'oauth', oauthSubject: 'user-1' });
    expect(await mw.authorize({ method: 'prompts/list', headers: READER })).toMatchObject({ authMethod: 'oauth' });
    // The target comes from the request's params when the host passes no name.
    await mw.authorize({ request: { method: 'resources/read', params: { uri: 'file:///docs/a.md' } }, headers: READER });
    await mw.authorize({ request: { method: 'prompts/get', params: { name: 'summarize' } }, headers: READER });
    await expect(mw.authorize({ method: 'resources/read', name: 'file:///docs/secret.md', headers: READER })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    const unlisted = await mw.authorize({ method: 'resources/read', name: 'file:///etc/passwd', headers: READER }).catch((e: unknown) => e);
    expect(unlisted).toMatchObject({ code: 'RESOURCE_NOT_PERMITTED', message: 'This resource is not permitted' });
    expect(toHttpErrorResponse(unlisted, { resourceMetadataUrl: 'https://x' })).toMatchObject({ status: 403, body: { error: 'insufficient_scope' } });
    await expect(mw.authorize({ method: 'prompts/get', name: 'other', headers: READER })).rejects.toMatchObject({ code: 'PROMPT_NOT_PERMITTED', httpStatus: 403 });
    await expect(mw.authorize({ method: 'resources/read', headers: READER })).rejects.toMatchObject({ code: 'RESOURCE_NOT_PERMITTED' });
    expect(events.map((e) => [e.method, e.result, e.resourceUri ?? e.promptName, e.reasonCode ?? e.reason])).toEqual([
      ['resources/list', 'allowed', undefined, undefined],
      ['prompts/list', 'allowed', undefined, undefined],
      ['resources/read', 'allowed', 'file:///docs/a.md', undefined],
      ['prompts/get', 'allowed', 'summarize', undefined],
      ['resources/read', 'denied', 'file:///docs/secret.md', 'insufficient scope'],
      ['resources/read', 'denied', 'file:///etc/passwd', 'resource_not_permitted'],
      ['prompts/get', 'denied', 'other', 'prompt_not_permitted'],
      ['resources/read', 'denied', undefined, 'resource_not_permitted'],
    ]);
    // No resourceScopes / promptScopes at all: nothing is permitted.
    const bare = helixidMCPMiddleware({ validateOAuthToken: async () => ({ sub: 'u', scopes: [] }) });
    await expect(bare.authorize({ method: 'resources/read', name: 'file:///a', headers: READER })).rejects.toMatchObject({ code: 'RESOURCE_NOT_PERMITTED' });
    await expect(bare.authorize({ method: 'prompts/get', name: 'p', headers: READER })).rejects.toMatchObject({ code: 'PROMPT_NOT_PERMITTED' });
  });

  it('a KYA-OS proof for another method binds that request; the received one, or rebuilt from input and _meta', async () => {
    const agent = makeAgent();
    const verifier = fixtureVerifier(SERVICE, { documents: { [agent.did]: agent.document } });
    const mw = helixidMCPMiddleware({ verifier, minimumLevel: 'L1', resourceScopes: { 'file:///a': [] } });
    const signed = await kyaos.withRequestProof({ method: 'resources/read', params: { uri: 'file:///a' } }, agent.signer, { audience: SERVICE, now: NOW_MS });
    const params = signed.params as { uri: string; _meta: Record<string, unknown> };
    expect(await mw.authorize({ method: 'resources/read', request: signed, _meta: params._meta })).toMatchObject({ authMethod: 'kyaos', agentDid: agent.did });
    const again = await kyaos.withRequestProof({ method: 'resources/read', params: { uri: 'file:///a' } }, agent.signer, { audience: SERVICE, now: NOW_MS });
    const meta = (again.params as { _meta: Record<string, unknown> })._meta;
    expect(await mw.authorize({ method: 'resources/read', name: 'file:///a', input: { uri: 'file:///a' }, _meta: meta })).toMatchObject({ agentDid: agent.did });
  });
});

describe('auditing a caller the guard could not identify', () => {
  it('records the method, target, address, user agent and the unverified issuer of a refused bearer', async () => {
    const { mw, events } = gate();
    const token = jwt({ iss: 'https://login.example', sub: 'x' });
    await mw.authorize({ method: 'tools/call', name: 'lookup', clientIp: '203.0.113.7', headers: { authorization: `Bearer ${token}`, 'user-agent': 'claude-code/2.0' } }).catch(() => undefined);
    expect(events).toEqual([
      expect.objectContaining({
        event: 'AUTHZ_DENIED', result: 'denied', authMethod: 'none', method: 'tools/call', toolName: 'lookup', reasonCode: 'oauth_token_invalid',
        clientIp: '203.0.113.7', userAgent: 'claude-code/2.0', oauthIssuer: 'https://login.example', claimedVerified: false, serviceDid: SERVICE, effectiveScopes: [],
      }),
    ]);
    expect(events[0]).not.toHaveProperty('oauthSubject');
  });

  it('records ambiguous credentials, a bearer with no validator, and nothing for a server fault', async () => {
    const { mw, events } = gate();
    await mw.authorize({ name: 'lookup', headers: { authorization: ['Bearer a', 'Bearer b'] } }).catch(() => undefined);
    const noOAuth = helixidMCPMiddleware({ auditSink: (event) => void events.push(event) });
    await noOAuth.authorize({ name: 'lookup', headers: { authorization: 'Bearer opaque' } }).catch(() => undefined);
    expect(events.map((e) => e.reasonCode)).toEqual(['credential_conflict', 'oauth_token_invalid']);
    expect(events[1]).not.toHaveProperty('oauthIssuer');
    const down = helixidMCPMiddleware({
      validateOAuthToken: async () => {
        throw new AuthorizationServerUnavailableError('down');
      },
      auditSink: (event) => void events.push(event),
    });
    await expect(down.authorize({ name: 'lookup', headers: READER })).rejects.toBeInstanceOf(AuthorizationServerUnavailableError);
    expect(events).toHaveLength(2);
  });

  it('reaches the Helix trail as authorization.denied with the reason code and no actor', async () => {
    const sink = new MemoryAuditSink();
    const trail = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE });
    const mw = helixidMCPMiddleware({ auditSink: trail.toolAuditSink(), serviceDid: SERVICE, resourceScopes: {} });
    await mw.authorize({ method: 'resources/list' }).catch(() => undefined);
    expect(sink.eventTypes).toEqual(['authorization.denied']);
    expect(sink.events[0]).toMatchObject({ outcome: 'denied', reason: { code: 'proof_missing' } });
    expect(sink.events[0]).not.toHaveProperty('actor');
    // An unidentified event with no reason code still records one.
    await trail.toolAuditSink()({ event: 'AUTHZ_DENIED', result: 'denied', timestamp: new Date().toISOString(), authMethod: 'none', effectiveScopes: [] });
    expect(sink.events[1]).toMatchObject({ reason: { code: 'unidentified' } });
    // A refused tools/call names its tool (when the trail records names); an identified caller's refusal keeps its reason code.
    const named = createMcpAuditTrail({ reporter: sink, serviceDid: SERVICE, includeToolNames: true });
    const oauth = helixidMCPMiddleware({ auditSink: named.toolAuditSink(), validateOAuthToken: async () => ({ sub: 'u', scopes: [] }), resourceScopes: {} });
    await oauth.authorize({ method: 'tools/call', name: 'lookup' }).catch(() => undefined);
    await oauth.authorize({ method: 'resources/read', name: 'file:///x', headers: READER }).catch(() => undefined);
    expect(sink.events.slice(2).map((event) => [event.eventType, event.reason?.code, event.action.name])).toEqual([
      ['authorization.denied', 'proof_missing', 'lookup'],
      ['authorization.denied', 'resource_not_permitted', undefined],
    ]);
  });
});

describe('gate helpers', () => {
  it('reads the method, target, headers, issuer and refusal code', () => {
    expect(methodOf({})).toBe('tools/call');
    expect(methodOf({ method: '' , request: { method: 'ping' } })).toBe('ping');
    expect(methodOf({ request: { method: '' } })).toBe('tools/call');
    expect(targetOf('resources/read', { request: { method: 'resources/read', params: { uri: 7 } } })).toBeUndefined();
    expect(targetOf('prompts/get', { request: { method: 'prompts/get' } })).toBeUndefined();
    expect(headerOf(undefined, 'user-agent')).toBeUndefined();
    expect(headerOf(new Headers({ 'User-Agent': 'h' }), 'user-agent')).toBe('h');
    expect(headerOf({ 'User-Agent': ['first', 'second'] }, 'user-agent')).toBe('first');
    expect(headerOf({ 'user-agent': '' }, 'user-agent')).toBeUndefined();
    expect(claimedIssuerOf({ authorization: `Bearer ${jwt({ sub: 'no-iss' })}` })).toBeUndefined();
    expect(claimedIssuerOf({ authorization: 'Bearer aaa.%%%.c' })).toBeUndefined();
    expect(claimedIssuerOf({ authorization: 'Bearer bm90IGpzb24.bm90IGpzb24.x' })).toBeUndefined();
    expect(refusalCodeOf({ code: 'PROOF_INVALID', reasons: ['status_revoked'] })).toBe('status_revoked');
    expect(refusalCodeOf({ code: 'PROOF_INVALID', reasons: [] })).toBe('proof_invalid');
    expect(refusalCodeOf({ code: 'TOOL_NOT_PERMITTED' })).toBeUndefined();
    expect(refusalCodeOf(null)).toBeUndefined();
    expect(refusalCodeOf('x')).toBeUndefined();
  });
});
