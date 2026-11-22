// Copyright 2026 DgVerse LLP
// KYA-OS story L3-E: the signed needs_authorization challenge, the resume token and the retry seam (L3.25, L3.26).
import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import * as middleware from '../../src/index.js';
import {
  DEFAULT_RESUME_TTL_SECONDS,
  NeedsAuthorizationError,
  ResumeRefusedError,
  challengeToolResult,
  createNeedsAuthorization,
  isNeedsAuthorizationError,
  readResumeRetry,
  type NeedsAuthorizationOptions,
  type RetryAuthorizer,
} from '../../src/needs-authorization.js';
import { MemoryResumeTokenStore } from '../../src/resume-token-store.js';
import { helixidMCPMiddleware } from '../../src/middleware.js';
import { toHttpErrorResponse } from '../../src/metadata.js';
import { createKyaOs, type KyaOsNeedsAuthorization } from '../../src/kyaos/index.js';
import type { ToolAuditEvent } from '../../src/audit.js';
import { AGENT, NOW, SERVER, clock, resolveDid, signer } from './helpers.js';

const CONSENT = 'https://consent.example/authorize';
const TOOL = 'refund_order';
const SCOPES = ['orders:admin'];
const context = { agentDid: AGENT, tool: TOOL, scopes: SCOPES };

/** A credential the test authorizer accepts: it grants whatever `allowedAction` says. */
const HOP = { type: ['VerifiableCredential', 'DelegationCredential'], credentialSubject: { invoker: AGENT, invocationTarget: SERVER, allowedAction: ['orders:admin'] } };
const testAuthorizer: RetryAuthorizer = ({ credential, agentDid }) => {
  const subject = (credential as { credentialSubject?: { invoker?: string; allowedAction?: string[] } }).credentialSubject;
  if (subject?.invoker !== agentDid) throw new Error('invoker is not the caller');
  return { scopes: subject.allowedAction ?? [] };
};

function layer(overrides: Partial<NeedsAuthorizationOptions> = {}) {
  const time = clock();
  const events: ToolAuditEvent[] = [];
  const na = createNeedsAuthorization({ authorizationUrl: CONSENT, auditSink: (e) => void events.push(e), now: time.now, serviceDid: SERVER, ...overrides });
  return { na, time, events };
}

async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof ResumeRefusedError) return error.reason;
    throw error;
  }
  throw new Error('expected a refusal');
}

describe('createNeedsAuthorization', () => {
  it('validates its options', () => {
    expect(() => createNeedsAuthorization({ authorizationUrl: CONSENT, ttlSeconds: 0 })).toThrow(RangeError);
    expect(() => createNeedsAuthorization({ authorizationUrl: CONSENT, ttlSeconds: Number.NaN })).toThrow(RangeError);
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT });
    expect(na.ttlSeconds).toBe(DEFAULT_RESUME_TTL_SECONDS);
    expect(na.store).toBeInstanceOf(MemoryResumeTokenStore);
    expect(na.readRetry).toBe(readResumeRetry);
  });

  it('builds the SPEC §9.2 challenge with a token bound to the agent, tool and scopes, and audits it (L3.26)', async () => {
    const { na, events } = layer({ ttlSeconds: 300, display: { title: 'Orders', hint: ['link'] } });
    const error = await na.challenge({ ...context, effectiveScopes: ['orders:read'], authMethod: 'oauth', oauthSubject: 'sub-1', level: 'L2', fresh: true });
    expect(error).toBeInstanceOf(NeedsAuthorizationError);
    expect(isNeedsAuthorizationError(error)).toBe(true);
    expect(isNeedsAuthorizationError({ code: 'NEEDS_AUTHORIZATION' })).toBe(true);
    expect(isNeedsAuthorizationError(new Error('x'))).toBe(false);
    expect(error.code).toBe('NEEDS_AUTHORIZATION');
    expect(error.httpStatus).toBe(403);
    expect(error.message).toBe('refund_order requires delegation with scope: orders:admin');
    expect(error.challenge).toEqual({
      error: 'needs_authorization',
      message: 'refund_order requires delegation with scope: orders:admin',
      authorizationUrl: CONSENT,
      resumeToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      expiresAt: Math.floor(NOW / 1000) + 300,
      scopes: ['orders:admin'],
      display: { title: 'Orders', hint: ['link'] },
    });
    expect((na.store as MemoryResumeTokenStore).has(error.challenge.resumeToken)).toBe(true);
    expect(await na.store.consume(error.challenge.resumeToken)).toEqual({ agentDid: AGENT, tool: TOOL, scopes: ['orders:admin'], expiresAt: NOW + 300_000 });
    expect(events).toEqual([
      {
        event: 'AUTHZ_DENIED',
        result: 'denied',
        timestamp: new Date(NOW).toISOString(),
        authMethod: 'oauth',
        agentDid: AGENT,
        oauthSubject: 'sub-1',
        level: 'L2',
        fresh: true,
        toolName: TOOL,
        requiredScope: 'orders:admin',
        effectiveScopes: ['orders:read'],
        reason: 'needs_authorization',
        serviceDid: SERVER,
      },
    ]);
    // The tool result the runtime signs: the challenge as text and as structured content, flagged as an error.
    expect(challengeToolResult(error.challenge)).toEqual({
      isError: true,
      content: [{ type: 'text', text: JSON.stringify(error.challenge) }],
      structuredContent: error.challenge,
    });
  });

  it('takes the URL, message and display from the context, and records the first missing scope', async () => {
    const { na, events } = layer({
      authorizationUrl: (c) => `${CONSENT}?agent=${encodeURIComponent(c.agentDid)}&tool=${c.tool}&scope=${c.scopes.join('+')}`,
      message: (c) => `grant ${c.scopes.join(', ')} to ${c.agentDid}`,
    });
    const error = await na.challenge({ ...context, scopes: ['orders:read', 'orders:admin'], missing: ['orders:admin'], display: { hint: ['qr'], qrUrl: 'https://consent.example/qr' } });
    expect(error.challenge.authorizationUrl).toBe('https://consent.example/authorize?agent=did%3Akey%3Az6Mkagent&tool=refund_order&scope=orders:read+orders:admin');
    expect(error.challenge.message).toBe('grant orders:read, orders:admin to did:key:z6Mkagent');
    expect(error.challenge.display).toEqual({ hint: ['qr'], qrUrl: 'https://consent.example/qr' });
    expect(error.challenge.scopes).toEqual(['orders:read', 'orders:admin']);
    expect(events[0]).toMatchObject({ requiredScope: 'orders:admin', effectiveScopes: [], authMethod: 'kyaos' });
    expect(events[0]).not.toHaveProperty('oauthSubject');
    const plain = await na.challenge({ ...context, message: 'please', missing: [] });
    expect(plain.challenge.message).toBe('please');
    expect(plain.challenge).not.toHaveProperty('display');
    await expect(na.challenge({ ...context, scopes: [] })).rejects.toThrow('at least one scope');
    const bad = createNeedsAuthorization({ authorizationUrl: 'ftp://consent.example' });
    await expect(bad.challenge(context)).rejects.toThrow('must be http(s)');
    const unparsable = createNeedsAuthorization({ authorizationUrl: () => 'not a url' });
    await expect(unparsable.challenge(context)).rejects.toThrow();
  });

  it('never lets an audit failure block the challenge, and audits nothing without a sink', async () => {
    const seen: unknown[] = [];
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, auditSink: () => Promise.reject(new Error('sink down')), onAuditError: (e) => void seen.push(e) });
    expect((await na.challenge(context)).challenge.error).toBe('needs_authorization');
    expect(seen).toHaveLength(1);
    const silent = createNeedsAuthorization({ authorizationUrl: CONSENT, auditSink: () => Promise.reject(new Error('sink down')) });
    expect((await silent.challenge(context)).challenge.error).toBe('needs_authorization');
    const none = createNeedsAuthorization({ authorizationUrl: CONSENT });
    expect((await none.challenge(context)).challenge.scopes).toEqual(SCOPES);
  });
});

describe('authorizeRetry (the seam F-2 and L3-H implement)', () => {
  it('refuses by default: without an authorizer no credential ever verifies, so consent alone never authorises the call', async () => {
    const { na } = layer();
    const { resumeToken } = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(resumeToken, HOP, context))).toBe('retry_authorizer_missing');
  });

  it('consumes the token first: a replayed, expired, malformed or unknown token is refused', async () => {
    const { na, time } = layer({ authorizer: testAuthorizer, ttlSeconds: 60 });
    const { resumeToken } = (await na.challenge(context)).challenge;
    expect(await na.authorizeRetry(resumeToken, HOP, context)).toEqual({ scopes: ['orders:admin'] });
    expect(await refusal(() => na.authorizeRetry(resumeToken, HOP, context))).toBe('resume_token_unknown');
    const expiring = (await na.challenge(context)).challenge;
    time.advance(60_000);
    expect(await refusal(() => na.authorizeRetry(expiring.resumeToken, HOP, context))).toBe('resume_token_unknown');
    expect(await refusal(() => na.authorizeRetry('nope', HOP, context))).toBe('resume_token_malformed');
    expect(await refusal(() => na.authorizeRetry(undefined, HOP, context))).toBe('resume_token_malformed');
    expect(await refusal(() => na.authorizeRetry('k7Hy9mNpQrStUvWxYz01AB', HOP, context))).toBe('resume_token_unknown');
    // A retry without the credential spends the token too.
    const spent = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(spent.resumeToken, undefined, context))).toBe('delegation_missing');
    expect(await refusal(() => na.authorizeRetry(spent.resumeToken, HOP, context))).toBe('resume_token_unknown');
    const nulled = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(nulled.resumeToken, null, context))).toBe('delegation_missing');
  });

  it('checks the binding: another agent, another tool or wider scopes are refused', async () => {
    const { na } = layer({ authorizer: testAuthorizer });
    const other = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(other.resumeToken, HOP, { ...context, agentDid: 'did:key:z6Mkother' }))).toBe('resume_token_agent_mismatch');
    const tool = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(tool.resumeToken, HOP, { ...context, tool: 'lookup_order' }))).toBe('resume_token_tool_mismatch');
    const wider = (await na.challenge(context)).challenge;
    expect(await refusal(() => na.authorizeRetry(wider.resumeToken, HOP, { ...context, scopes: ['orders:admin', 'orders:export'] }))).toBe('resume_token_scope_mismatch');
    // Fewer scopes than the challenge asked for are within the binding.
    const narrower = (await na.challenge({ ...context, scopes: ['orders:read', 'orders:admin'] })).challenge;
    expect(await na.authorizeRetry(narrower.resumeToken, HOP, context)).toEqual({ scopes: ['orders:admin'] });
  });

  it('hands the credential to the authorizer with the consumed binding, and maps its refusal', async () => {
    const seen: unknown[] = [];
    const { na } = layer({
      authorizer: (input) => {
        seen.push(input);
        return { scopes: ['orders:admin', 7 as unknown as string] };
      },
    });
    const { resumeToken } = (await na.challenge(context)).challenge;
    expect(await na.authorizeRetry(resumeToken, HOP, context)).toEqual({ scopes: ['orders:admin'] });
    expect(seen).toEqual([{ credential: HOP, token: { agentDid: AGENT, tool: TOOL, scopes: SCOPES, expiresAt: NOW + DEFAULT_RESUME_TTL_SECONDS * 1000 }, agentDid: AGENT, tool: TOOL, scopes: SCOPES }]);
    const refusing = layer({ authorizer: () => Promise.reject(new Error('chain does not verify')) }).na;
    const t1 = (await refusing.challenge(context)).challenge;
    await expect(refusing.authorizeRetry(t1.resumeToken, HOP, context)).rejects.toMatchObject({ reason: 'delegation_refused', message: 'the delegation credential was refused: chain does not verify' });
    const nonError = layer({ authorizer: () => Promise.reject('nope') }).na;
    const t2 = (await nonError.challenge(context)).challenge;
    await expect(nonError.authorizeRetry(t2.resumeToken, HOP, context)).rejects.toMatchObject({ reason: 'delegation_refused', message: 'the delegation credential was refused: nope' });
    const passThrough = layer({ authorizer: () => Promise.reject(new ResumeRefusedError('delegation_refused', 'own words')) }).na;
    const t3 = (await passThrough.challenge(context)).challenge;
    await expect(passThrough.authorizeRetry(t3.resumeToken, HOP, context)).rejects.toMatchObject({ reason: 'delegation_refused', message: 'own words' });
    const empty = layer({ authorizer: () => ({}) as never }).na;
    const t4 = (await empty.challenge(context)).challenge;
    expect(await empty.authorizeRetry(t4.resumeToken, HOP, context)).toEqual({ scopes: [] });
  });

  it('reads the retry from the control arguments of a call', () => {
    expect(readResumeRetry({})).toBeUndefined();
    expect(readResumeRetry({ input: { orderId: 'ORD-1' } })).toBeUndefined();
    expect(readResumeRetry({ input: { orderId: 'ORD-1', _kyaos_resume: 'tok' } })).toEqual({ resumeToken: 'tok', credential: undefined });
    expect(readResumeRetry({ input: { _kyaos_resume: 'tok', _kyaos_delegation: HOP } })).toEqual({ resumeToken: 'tok', credential: HOP });
  });
});

describe('the guard with needsAuthorization', () => {
  const TOKENS: Record<string, { sub: string; scopes: string[] }> = {
    agent: { sub: AGENT, scopes: ['orders:read'] },
    other: { sub: 'did:key:z6Mkother', scopes: ['orders:read'] },
  };
  function guard(na: middleware.NeedsAuthorization, events: ToolAuditEvent[]) {
    return helixidMCPMiddleware({
      validateOAuthToken: async (token) => TOKENS[token] ?? Promise.reject(new Error('unknown')),
      toolScopes: { lookup_order: ['orders:read'], refund_order: ['orders:admin'] },
      auditSink: (e) => void events.push(e),
      needsAuthorization: na,
      serviceDid: SERVER,
    });
  }
  const call = (name: string, token: string, input: Record<string, unknown> = {}) => ({ name, input, headers: { authorization: `Bearer ${token}` } });

  it('answers a missing scope with the challenge, then accepts the retry the authorizer verifies, and refuses one without the credential', async () => {
    const events: ToolAuditEvent[] = [];
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, authorizer: testAuthorizer, auditSink: (e) => void events.push(e), now: () => NOW });
    const g = guard(na, events);
    // An allowed call is untouched.
    expect(await g.authorize(call('lookup_order', 'agent'))).toMatchObject({ scopes: ['orders:read'], oauthSubject: AGENT });
    const error = await g.authorize(call('refund_order', 'agent')).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NeedsAuthorizationError);
    const { resumeToken } = (error as NeedsAuthorizationError).challenge;
    expect(events.map((e) => [e.event, e.reason])).toEqual([
      ['AUTHZ_GRANTED', undefined],
      ['AUTHZ_DENIED', 'needs_authorization'],
    ]);
    // Retry without the hop: refused, token spent.
    await expect(g.authorize(call('refund_order', 'agent', { _kyaos_resume: resumeToken }))).rejects.toMatchObject({ code: 'RESUME_REFUSED', reason: 'delegation_missing' });
    await expect(g.authorize(call('refund_order', 'agent', { _kyaos_resume: resumeToken, _kyaos_delegation: HOP }))).rejects.toMatchObject({ reason: 'resume_token_unknown' });
    // A fresh challenge, retried with the hop: the caller gains the granted scope and the call is allowed, audited as granted.
    const again = (await g.authorize(call('refund_order', 'agent')).catch((e: unknown) => e)) as NeedsAuthorizationError;
    const caller = await g.authorize(call('refund_order', 'agent', { orderId: 'ORD-1001', _kyaos_resume: again.challenge.resumeToken, _kyaos_delegation: HOP }));
    expect(caller).toEqual({ authMethod: 'oauth', scopes: ['orders:read', 'orders:admin'], oauthSubject: AGENT });
    expect(events.at(-1)).toMatchObject({ event: 'AUTHZ_GRANTED', toolName: 'refund_order', effectiveScopes: ['orders:read', 'orders:admin'] });
    // The token is bound to the agent: another caller cannot spend it.
    const third = (await g.authorize(call('refund_order', 'agent')).catch((e: unknown) => e)) as NeedsAuthorizationError;
    await expect(g.authorize(call('refund_order', 'other', { _kyaos_resume: third.challenge.resumeToken, _kyaos_delegation: HOP }))).rejects.toMatchObject({ reason: 'resume_token_agent_mismatch' });
    // A retry on another tool is refused even though that tool would have been allowed.
    const fourth = (await g.authorize(call('refund_order', 'agent')).catch((e: unknown) => e)) as NeedsAuthorizationError;
    await expect(g.authorize(call('lookup_order', 'agent', { _kyaos_resume: fourth.challenge.resumeToken, _kyaos_delegation: HOP }))).rejects.toMatchObject({ reason: 'resume_token_tool_mismatch' });
  });

  it('refuses a retry whose credential grants too little with the plain 403, never a second challenge', async () => {
    const events: ToolAuditEvent[] = [];
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, authorizer: () => ({ scopes: ['orders:export'] }), now: () => NOW });
    const g = guard(na, events);
    const error = (await g.authorize(call('refund_order', 'agent')).catch((e: unknown) => e)) as NeedsAuthorizationError;
    await expect(g.authorize(call('refund_order', 'agent', { _kyaos_resume: error.challenge.resumeToken, _kyaos_delegation: HOP }))).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    expect(events.at(-1)).toMatchObject({ event: 'AUTHZ_DENIED', reason: 'insufficient scope', requiredScope: 'orders:admin' });
  });

  it('keeps the plain 403 for a caller with no identity to bind to, and when the layer is off', async () => {
    // A verified proof whose principal the verifier did not name (a stub local verifier, story F-2): nothing to bind the token to.
    const verifier = {
      serviceDid: SERVER,
      verifyCall: async () => ({ ok: true, effectiveScopes: ['orders:read'], level: 'L1', fresh: true, reasons: [], chainSummary: { depth: 0 } }),
    } as never;
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, now: () => NOW });
    const anonymous = helixidMCPMiddleware({ verifier, toolScopes: { refund_order: ['orders:admin'] }, needsAuthorization: na });
    await expect(anonymous.authorize({ name: 'refund_order', _meta: { 'org.kya-os/request-proof': {} } })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    // requiredScopes without a tool name: nothing to bind the token to either.
    const unnamed = helixidMCPMiddleware({ validateOAuthToken: async () => TOKENS['agent']!, requiredScopes: ['orders:admin'], needsAuthorization: na });
    await expect(unnamed.authorize({ headers: { authorization: 'Bearer agent' } })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    const off = helixidMCPMiddleware({ validateOAuthToken: async () => TOKENS['agent']!, toolScopes: { refund_order: ['orders:admin'] } });
    await expect(off.authorize({ name: 'refund_order', input: { _kyaos_resume: 'x' }, headers: { authorization: 'Bearer agent' } })).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
  });
});

describe('the KYA-OS runtime signs the challenge', () => {
  it('with outcome needs_authorization and responseHash over the whole tool result, so a tampered authorizationUrl fails the SDK check', async () => {
    const time = clock();
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, now: time.now });
    const kya = createKyaOs({ signer, now: time.now });
    const request = { method: 'tools/call', params: { name: TOOL, arguments: { orderId: 'ORD-1001', _kyaos_other: 'never hashed' } } };
    const started = (await kya.start({ name: TOOL, arguments: request.params.arguments }, { authorize: async () => Promise.reject(await na.challenge(context)), clientDid: AGENT })) as KyaOsNeedsAuthorization;
    expect(started.outcome).toBe('needs_authorization');
    expect(started.error).toBeInstanceOf(NeedsAuthorizationError);
    expect(started.challenge.resumeToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(started.result).toEqual({
      isError: true,
      content: [{ type: 'text', text: JSON.stringify(started.challenge) }],
      structuredContent: started.challenge,
      _meta: { 'org.kya-os/response-proof': started.proof },
    });
    expect(started.proof.meta).toMatchObject({
      did: SERVER,
      outcome: 'needs_authorization',
      reason: 'requires delegation with scope: orders:admin',
      clientDid: AGENT,
      sessionId: 'none',
      prf: 'org.kya-os/response-proof.envelope',
      requestHash: kyaos.hashRequest(request),
      responseHash: kyaos.hashResponse(started.result, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE),
    });
    const verified = await kyaos.verifyResponseProof(started.result, SERVER, resolveDid as never, { request, now: NOW });
    expect(verified.outcome).toBe('needs_authorization');
    const tampered = { ...started.result, structuredContent: { ...started.challenge, authorizationUrl: 'https://evil.example/authorize' } };
    await expect(kyaos.verifyResponseProof(tampered, SERVER, resolveDid as never, { request, now: NOW })).rejects.toMatchObject({ reason: 'response_hash_mismatch' });
    // call() hands the outcome back instead of running the tool.
    let ran = false;
    const outcome = await kya.call({ name: TOOL, arguments: {} }, () => void (ran = true) ?? {}, { authorize: async () => Promise.reject(await na.challenge(context)) });
    expect(outcome.outcome).toBe('needs_authorization');
    expect(ran).toBe(false);
  });
});

describe('toHttpErrorResponse', () => {
  it('answers the challenge as a 403 whose body is the challenge, and a refused retry as insufficient_scope', async () => {
    const na = createNeedsAuthorization({ authorizationUrl: CONSENT, now: () => NOW });
    const error = await na.challenge(context);
    const response = toHttpErrorResponse(error, { resourceMetadataUrl: 'https://orders.example/.well-known/oauth-protected-resource/mcp' });
    expect(response).toMatchObject({ status: 403, body: { ...error.challenge, error_description: error.message } });
    expect(response!.headers['WWW-Authenticate']).toContain('error="needs_authorization"');
    const refused = toHttpErrorResponse(new ResumeRefusedError('resume_token_unknown', 'spent'), { resourceMetadataUrl: 'x' });
    expect(refused).toMatchObject({ status: 403, body: { error: 'insufficient_scope', error_description: 'spent' } });
  });
});

describe('package index', () => {
  it('exports the L3-E layer', () => {
    expect(middleware.createNeedsAuthorization).toBe(createNeedsAuthorization);
    expect(middleware.NeedsAuthorizationError).toBe(NeedsAuthorizationError);
    expect(middleware.ResumeRefusedError).toBe(ResumeRefusedError);
    expect(middleware.MemoryResumeTokenStore).toBe(MemoryResumeTokenStore);
    expect(typeof middleware.RedisResumeTokenStore).toBe('function');
    expect(middleware.RESUME_CONTROL_ARGUMENT).toBe('_kyaos_resume');
    expect(middleware.DELEGATION_CONTROL_ARGUMENT).toBe('_kyaos_delegation');
  });
});
