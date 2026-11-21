// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story L3-E: the sample answers a call without authority with the signed needs_authorization
// challenge, and the retry with the resume token and the delegation credential runs the tool.

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildDIDDocument, generateKeyPair, kyaos } from '@helixid/sdk-js';
import { createKyaOs, createNeedsAuthorization, type NeedsAuthorization, type ToolAuditEvent } from '@helixid/mcp-middleware';
import { createOrderServer } from '../src/app.js';
import { createOrderStore } from '../src/orders.js';
import { demoRetryAuthorizer } from '../src/demo-authorizer.js';

const SERVICE = 'did:web:orders.example';
const AGENT = 'did:key:z6MkdemoAgent';
const OTHER = 'did:key:z6MkotherAgent';
const CONSENT = 'https://consent.example/authorize';
const keys = generateKeyPair();
const document = buildDIDDocument(SERVICE, keys.publicKey);
const resolveDid = async (did: string) => (did === SERVICE ? document : null);
const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'SAMPLE_SERVICE_KEY', env: { SAMPLE_SERVICE_KEY: keys.privateKey } });
const TOKENS: Record<string, { sub: string; scopes: string[] }> = {
  agent: { sub: AGENT, scopes: ['orders:read'] },
  other: { sub: OTHER, scopes: ['orders:read'] },
};

/** A §6.10-shaped root hop the demo authorizer accepts (structurally; no signature is verified in DEMO_MODE). */
const hopFor = (invoker: string, allowedAction = ['orders:admin'], extra: Record<string, unknown> = {}) => ({
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/zcap/v1'],
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:key:z6MkuserConsentKey',
  validUntil: new Date(Date.now() + 3_600_000).toISOString(),
  credentialSubject: { invoker, invocationTarget: SERVICE, parentCapability: SERVICE, allowedAction },
  proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'assertionMethod', verificationMethod: 'did:key:z6MkuserConsentKey#z6MkuserConsentKey', proofValue: 'z-demo' },
  ...extra,
});

let server: Server;
let base: string;
let events: ToolAuditEvent[];
let layer: NeedsAuthorization;
let time: number;

async function start(withKyaOs: boolean): Promise<void> {
  time = Date.now();
  events = [];
  layer = createNeedsAuthorization({
    authorizationUrl: (c) => `${CONSENT}?tool=${c.tool}&scope=${c.scopes.join('+')}`,
    authorizer: demoRetryAuthorizer(SERVICE, () => time),
    auditSink: (e) => void events.push(e),
    ttlSeconds: 60,
    now: () => time,
    serviceDid: SERVICE,
  });
  server = createOrderServer({
    resource: 'http://localhost/mcp',
    store: createOrderStore(),
    auth: {
      serviceDid: SERVICE,
      validateOAuthToken: async (token) => TOKENS[token] ?? Promise.reject(new Error('unknown token')),
      auditSink: (e) => void events.push(e),
      needsAuthorization: layer,
    },
    ...(withKyaOs ? { kyaos: createKyaOs({ signer, publicOrigin: 'http://localhost', now: () => time }) } : {}),
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let nextId = 1;
async function callTool(name: string, args: Record<string, unknown>, token: string) {
  const id = nextId++;
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }),
  });
  const text = await res.text();
  return { id, status: res.status, body: text ? JSON.parse(text) : undefined };
}
const REFUND = { orderId: 'ORD-1001', reason: 'damaged' };
const request = (name: string, args: Record<string, unknown>) => ({ method: 'tools/call', params: { name, arguments: args } });

describe('order-management sample with needs_authorization (KYA-OS on)', () => {
  beforeEach(() => start(true));

  it('answers a call without the authority with the signed challenge as the tool result, audited', async () => {
    const res = await callTool('refund_order', REFUND, 'agent');
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(res.id);
    const result = res.body.result;
    expect(result.isError).toBe(true);
    const challenge = result.structuredContent;
    expect(challenge).toEqual({
      error: 'needs_authorization',
      message: 'refund_order requires delegation with scope: orders:admin',
      authorizationUrl: `${CONSENT}?tool=refund_order&scope=orders:admin`,
      resumeToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      expiresAt: Math.floor(time / 1000) + 60,
      scopes: ['orders:admin'],
    });
    expect(JSON.parse(result.content[0].text)).toEqual(challenge);
    const proof = result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta).toMatchObject({ outcome: 'needs_authorization', responseHash: kyaos.hashResponse(result, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE) });
    const verified = await kyaos.verifyResponseProof(result, SERVICE, resolveDid as never, { request: request('refund_order', REFUND), now: time });
    expect(verified.outcome).toBe('needs_authorization');
    await expect(
      kyaos.verifyResponseProof({ ...result, structuredContent: { ...challenge, authorizationUrl: 'https://evil.example/' } }, SERVICE, resolveDid as never, { request: request('refund_order', REFUND), now: time }),
    ).rejects.toMatchObject({ reason: 'response_hash_mismatch' });
    expect(events).toEqual([expect.objectContaining({ event: 'AUTHZ_DENIED', reason: 'needs_authorization', toolName: 'refund_order', agentDid: AGENT, requiredScope: 'orders:admin', effectiveScopes: ['orders:read'], serviceDid: SERVICE })]);
    // The order was not touched.
    expect(JSON.parse((await callTool('lookup_order', { orderId: 'ORD-1001' }, 'agent')).body.result.content[0].text).status).toBe('shipped');
  });

  it('runs the tool on the retry with the resume token and the root hop, once; a replayed token is refused', async () => {
    const challenge = (await callTool('refund_order', REFUND, 'agent')).body.result.structuredContent;
    const retry = { ...REFUND, _kyaos_resume: challenge.resumeToken, _kyaos_delegation: hopFor(AGENT) };
    const ok = await callTool('refund_order', retry, 'agent');
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.result.isError).toBeUndefined();
    expect(JSON.parse(ok.body.result.content[0].text)).toMatchObject({ id: 'ORD-1001', status: 'refunded', refundReason: 'damaged' });
    const proof = ok.body.result._meta['org.kya-os/response-proof'] as kyaos.DetachedProof;
    expect(proof.meta).toMatchObject({ outcome: 'allowed' });
    // The control arguments never reached the tool and are not in the covered request.
    expect(proof.meta.requestHash).toBe(kyaos.hashRequest(request('refund_order', REFUND)));
    expect(events.at(-1)).toMatchObject({ event: 'AUTHZ_GRANTED', effectiveScopes: ['orders:read', 'orders:admin'] });
    const replay = await callTool('refund_order', { ...retry, orderId: 'ORD-1002' }, 'agent');
    expect(replay.status).toBe(403);
    expect(replay.body).toMatchObject({ error: 'insufficient_scope' });
    expect(replay.body._meta['org.kya-os/response-proof'].meta).toMatchObject({ outcome: 'denied', reason: 'RESUME_REFUSED' });
    expect(replay.body.error_description).toContain('unknown, already used or expired');
  });

  it('refuses an expired token, another agent, another tool, a retry without the hop, and a hop the demo authorizer does not accept', async () => {
    const token = async () => (await callTool('refund_order', REFUND, 'agent')).body.result.structuredContent.resumeToken as string;
    const expired = await token();
    time += 61_000;
    const late = await callTool('refund_order', { ...REFUND, _kyaos_resume: expired, _kyaos_delegation: hopFor(AGENT) }, 'agent');
    expect(late.status).toBe(403);
    expect(late.body.error_description).toContain('unknown, already used or expired');
    const stolen = await callTool('refund_order', { ...REFUND, _kyaos_resume: await token(), _kyaos_delegation: hopFor(OTHER) }, 'other');
    expect(stolen.body.error_description).toContain('another agent');
    const wrongTool = await callTool('lookup_order', { orderId: 'ORD-1001', _kyaos_resume: await token(), _kyaos_delegation: hopFor(AGENT) }, 'agent');
    expect(wrongTool.status).toBe(403);
    expect(wrongTool.body.error_description).toContain('issued for refund_order, not lookup_order');
    const noHop = await callTool('refund_order', { ...REFUND, _kyaos_resume: await token() }, 'agent');
    expect(noHop.status).toBe(403);
    expect(noHop.body.error_description).toContain('consent alone does not authorise the call');
    const cases: [unknown, string][] = [
      ['not an object', 'must be an object'],
      [{ ...hopFor(AGENT), type: 'VerifiableCredential' }, 'not a DelegationCredential'],
      [{ ...hopFor(AGENT), credentialSubject: 'x' }, 'credentialSubject is missing'],
      [hopFor(OTHER), 'is not the caller'],
      [hopFor(AGENT, ['orders:admin'], { credentialSubject: { invoker: AGENT, invocationTarget: 'did:web:other.example', allowedAction: ['orders:admin'] } }), 'is not this service'],
      [hopFor(AGENT, ['orders:read']), 'allowedAction does not cover orders:admin'],
      [hopFor(AGENT, 'orders:admin' as unknown as string[]), 'allowedAction does not cover orders:admin'],
      [hopFor(AGENT, ['orders:admin'], { validUntil: new Date(time - 1).toISOString() }), 'has expired'],
      [{ ...hopFor(AGENT), proof: undefined }, 'carries no proof'],
    ];
    for (const [hop, reason] of cases) {
      const res = await callTool('refund_order', { ...REFUND, _kyaos_resume: await token(), _kyaos_delegation: hop }, 'agent');
      expect(res.status, reason).toBe(403);
      expect(res.body.error_description, reason).toContain(reason);
      expect(res.body.error_description, reason).toContain('the delegation credential was refused');
    }
    // A single-type credential is read too.
    const single = await callTool('refund_order', { ...REFUND, _kyaos_resume: await token(), _kyaos_delegation: { ...hopFor(AGENT), type: 'DelegationCredential' } }, 'agent');
    expect(single.status).toBe(200);
  });
});

describe('order-management sample with needs_authorization (KYA-OS off)', () => {
  beforeEach(() => start(false));

  it('answers the challenge as a 403 whose body is the challenge, unsigned, and still verifies the retry', async () => {
    const res = await callTool('refund_order', REFUND, 'agent');
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'needs_authorization', authorizationUrl: `${CONSENT}?tool=refund_order&scope=orders:admin`, scopes: ['orders:admin'] });
    expect(res.body).not.toHaveProperty('_meta');
    const ok = await callTool('refund_order', { ...REFUND, _kyaos_resume: res.body.resumeToken, _kyaos_delegation: hopFor(AGENT) }, 'agent');
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body.result.content[0].text).status).toBe('refunded');
  });
});
