// Copyright 2026 DgVerse LLP
// KYA-OS story L3-E: the client side of the signed needs_authorization challenge and the resume retry.
//
// The cross-language fixture fixtures/kya-os-helix/needs-authorization.json is
// generated here (HELIX_WRITE_FIXTURES=1 npx vitest run tests/unit/kyaos/needs-authorization.test.ts)
// from a fixed key, nonce and clock, and otherwise read back and asserted; helix-sdk-py
// reads the same file through the sibling checkout.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  ChallengeReasons,
  DELEGATION_CONTROL_ARGUMENT,
  EnvSigner,
  NEEDS_AUTHORIZATION,
  RESPONSE_PROOF_ENVELOPE_PROFILE,
  RESPONSE_PROOF_META_KEY,
  RESUME_CONTROL_ARGUMENT,
  findChallenge,
  handleNeedsAuthorization,
  hashRequest,
  hashResponse,
  isNeedsAuthorization,
  proofPayload,
  readChallenge,
  retryWithResume,
  signJws,
  withResume,
  type DetachedProof,
  type NeedsAuthorizationChallenge,
  type ProofMeta,
  type ToolCallParams,
} from '../../../src/core/kyaos/index.js';
import { InvalidJWSError, NeedsAuthorizationError, ResponseProofError, kyaos } from '../../../src/index.js';
import { buildDIDDocument } from '../../../src/core/did.js';
import { derivePublicKey } from '../../../src/core/keys.js';

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures/kya-os-helix/needs-authorization.json');

const SERVER = 'did:web:orders.example';
const AGENT = 'did:key:z6Mkagent';
// Fixed material, so the fixture is reproducible: a test key, never a real one.
const PRIVATE_KEY = '0101010101010101010101010101010101010101010101010101010101010101';
const PUBLIC_KEY = derivePublicKey(PRIVATE_KEY);
const NOW = 1_750_000_000_000;
const NONCE = 'b6VZmm9hXn-otOETBkvlvQ';
const RESUME_TOKEN = 'uGb3QKq4D1yXj0r9ZaN2Pw8vLcE5tHsM6nRkF7oJiAw';
const signer = new EnvSigner({ did: SERVER, envVar: 'K', env: { K: PRIVATE_KEY } });
const otherSigner = new EnvSigner({ did: SERVER, envVar: 'K', env: { K: '0202020202020202020202020202020202020202020202020202020202020202' } });
const document = buildDIDDocument(SERVER, PUBLIC_KEY);
const resolveDid = async (did: string) => (did === SERVER ? document : null);

const CALL: ToolCallParams = { name: 'refund_order', arguments: { orderId: 'ORD-1001', reason: 'damaged' } };
const REQUEST = { method: 'tools/call', params: { ...CALL, _meta: { traceparent: 't' } } };
const CHALLENGE: NeedsAuthorizationChallenge = {
  error: NEEDS_AUTHORIZATION,
  message: 'refund_order requires delegation with scope: orders:admin',
  authorizationUrl: 'https://consent.example/authorize?agent=did%3Akey%3Az6Mkagent&tool=refund_order&scope=orders%3Aadmin',
  resumeToken: RESUME_TOKEN,
  expiresAt: Math.floor(NOW / 1000) + 600,
  scopes: ['orders:admin'],
  display: { title: 'Orders', hint: ['link'] },
};
const HOP = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/zcap/v1'],
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:key:z6MkuserConsentKey',
  credentialSubject: { invoker: AGENT, invocationTarget: SERVER, parentCapability: SERVER, allowedAction: ['orders:admin'] },
  proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'assertionMethod', verificationMethod: 'did:key:z6MkuserConsentKey#z6MkuserConsentKey', proofValue: 'z-fixture' },
};

/** The challenge as the middleware's tool result. */
const toolResult = (challenge: unknown) => ({ isError: true, content: [{ type: 'text', text: JSON.stringify(challenge) }], structuredContent: challenge });

/** A proof signed the way the middleware signs it, over `body` (envelope profile) for `request`. */
async function sign(body: Record<string, unknown>, options: { outcome?: ProofMeta['outcome']; by?: EnvSigner; request?: typeof REQUEST; reason?: string } = {}): Promise<DetachedProof> {
  const outcome = options.outcome ?? 'needs_authorization';
  const meta: ProofMeta = {
    did: SERVER,
    kid: `${SERVER}#key-1`,
    ts: Math.floor(NOW / 1000),
    nonce: NONCE,
    audience: SERVER,
    sessionId: 'none',
    requestHash: hashRequest(options.request ?? REQUEST),
    responseHash: hashResponse(body, RESPONSE_PROOF_ENVELOPE_PROFILE),
    outcome,
    ...(options.reason !== undefined ? { reason: options.reason } : {}),
    clientDid: AGENT,
    prf: RESPONSE_PROOF_ENVELOPE_PROFILE,
  };
  return { jws: await signJws(proofPayload(meta), options.by ?? signer), meta };
}

async function signed(body: Record<string, unknown>, options: Parameters<typeof sign>[1] = {}): Promise<Record<string, unknown>> {
  return { ...body, _meta: { [RESPONSE_PROOF_META_KEY]: await sign(body, options) } };
}

interface Case {
  name: string;
  response: unknown;
  expected: { ok: true; challenge: NeedsAuthorizationChallenge } | { ok: false; reason: string };
}

interface Fixture {
  description: string;
  service: { did: string; publicKeyHex: string; didDocument: unknown };
  now: number;
  request: typeof REQUEST;
  cases: Case[];
  retry: { call: ToolCallParams; resumeToken: string; hop: unknown; params: ToolCallParams };
}

async function buildFixture(): Promise<Fixture> {
  const valid = await signed(toolResult(CHALLENGE), { reason: 'requires delegation with scope: orders:admin' });
  const swapUrl = (response: Record<string, unknown>, url: string) => ({ ...response, structuredContent: { ...CHALLENGE, authorizationUrl: url } });
  const cases: Case[] = [
    { name: 'valid', response: valid, expected: { ok: true, challenge: CHALLENGE } },
    { name: 'valid_top_level', response: await signed({ ...CHALLENGE }), expected: { ok: true, challenge: CHALLENGE } },
    { name: 'tampered_authorization_url', response: swapUrl(valid, 'https://evil.example/authorize'), expected: { ok: false, reason: 'response_hash_mismatch' } },
    { name: 'tampered_text_only', response: { ...valid, content: [{ type: 'text', text: JSON.stringify({ ...CHALLENGE, authorizationUrl: 'https://evil.example/' }) }] }, expected: { ok: false, reason: 'response_hash_mismatch' } },
    { name: 'tampered_resume_token', response: { ...valid, structuredContent: { ...CHALLENGE, resumeToken: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }, expected: { ok: false, reason: 'response_hash_mismatch' } },
    { name: 'proof_missing', response: toolResult(CHALLENGE), expected: { ok: false, reason: 'proof_missing' } },
    { name: 'signed_by_another_key', response: await signed(toolResult(CHALLENGE), { by: otherSigner }), expected: { ok: false, reason: 'jws_signature_invalid' } },
    { name: 'proof_for_another_request', response: await signed(toolResult(CHALLENGE), { request: { ...REQUEST, params: { ...CALL, arguments: { orderId: 'ORD-1002' } } } }), expected: { ok: false, reason: 'request_hash_mismatch' } },
    { name: 'outcome_allowed', response: await signed({ content: [{ type: 'text', text: '{"id":"ORD-1001"}' }] }, { outcome: 'allowed' }), expected: { ok: false, reason: ChallengeReasons.OUTCOME_MISMATCH } },
    { name: 'outcome_allowed_challenge_shaped', response: await signed(toolResult(CHALLENGE), { outcome: 'allowed' }), expected: { ok: false, reason: ChallengeReasons.OUTCOME_MISMATCH } },
    { name: 'expired', response: await signed(toolResult({ ...CHALLENGE, expiresAt: Math.floor(NOW / 1000) })), expected: { ok: false, reason: ChallengeReasons.EXPIRED } },
    { name: 'url_not_http', response: await signed(toolResult({ ...CHALLENGE, authorizationUrl: 'javascript:alert(1)' })), expected: { ok: false, reason: ChallengeReasons.URL_INVALID } },
    { name: 'url_relative', response: await signed(toolResult({ ...CHALLENGE, authorizationUrl: '/authorize' })), expected: { ok: false, reason: ChallengeReasons.URL_INVALID } },
    { name: 'scopes_not_strings', response: await signed(toolResult({ ...CHALLENGE, scopes: ['orders:admin', 1] })), expected: { ok: false, reason: ChallengeReasons.MALFORMED } },
    { name: 'resume_token_missing', response: await signed(toolResult({ ...CHALLENGE, resumeToken: '' })), expected: { ok: false, reason: ChallengeReasons.MALFORMED } },
    { name: 'display_hint_unknown', response: await signed(toolResult({ ...CHALLENGE, display: { hint: ['popup'] } })), expected: { ok: false, reason: ChallengeReasons.MALFORMED } },
    { name: 'not_a_challenge', response: await signed({ content: [{ type: 'text', text: 'ok' }], structuredContent: { error: 'other' } }), expected: { ok: false, reason: ChallengeReasons.MISSING } },
  ];
  return {
    description: 'KYA-OS story L3-E: signed needs_authorization challenges as the middleware answers them, verified with handleNeedsAuthorization at `now` against the service DID document; `retry` is withResume(call, resumeToken, hop).',
    service: { did: SERVER, publicKeyHex: PUBLIC_KEY, didDocument: document },
    now: NOW,
    request: REQUEST,
    cases,
    retry: { call: CALL, resumeToken: RESUME_TOKEN, hop: HOP, params: withResume(CALL, RESUME_TOKEN, HOP) },
  };
}

async function reasonOf(run: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof ResponseProofError || error instanceof InvalidJWSError || error instanceof NeedsAuthorizationError) return error.reason;
    throw error;
  }
  return 'ok';
}

describe('the cross-language fixture', () => {
  it('is checked in as generated from the fixed key, nonce and clock', async () => {
    const built = await buildFixture();
    if (process.env['HELIX_WRITE_FIXTURES'] === '1') {
      mkdirSync(dirname(FIXTURE), { recursive: true });
      writeFileSync(FIXTURE, `${JSON.stringify(built, null, 2)}\n`);
    }
    expect(existsSync(FIXTURE), `${FIXTURE} is missing: run with HELIX_WRITE_FIXTURES=1`).toBe(true);
    const stored = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;
    expect(stored).toEqual(built);
  });

  it('is handled as it says, case by case', async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;
    const resolve = async (did: string) => (did === fixture.service.did ? (fixture.service.didDocument as never) : null);
    for (const c of fixture.cases) {
      const outcome = await handleNeedsAuthorization(c.response, fixture.service.did, resolve, { request: fixture.request, now: fixture.now }).then(
        (handled) => ({ ok: true as const, challenge: handled.challenge }),
        (error: unknown) => ({ ok: false as const, reason: (error as { reason: string }).reason }),
      );
      expect(outcome, c.name).toEqual(c.expected);
    }
    expect(withResume(fixture.retry.call, fixture.retry.resumeToken, fixture.retry.hop)).toEqual(fixture.retry.params);
  });
});

describe('handleNeedsAuthorization', () => {
  it('verifies the proof before reading anything: a tampered authorizationUrl is refused with no challenge surfaced', async () => {
    const valid = await signed(toolResult(CHALLENGE));
    const handled = await handleNeedsAuthorization(valid, SERVER, resolveDid, { request: REQUEST, now: NOW });
    expect(handled.challenge).toEqual(CHALLENGE);
    expect(handled.proof).toMatchObject({ outcome: 'needs_authorization', did: SERVER, responseHash: hashResponse(valid, RESPONSE_PROOF_ENVELOPE_PROFILE) });
    const tampered = { ...valid, structuredContent: { ...CHALLENGE, authorizationUrl: 'https://evil.example/authorize' } };
    await expect(handleNeedsAuthorization(tampered, SERVER, resolveDid, { request: REQUEST, now: NOW })).rejects.toMatchObject({ code: 'RESPONSE_PROOF_INVALID', reason: 'response_hash_mismatch' });
    // A proof for another service, or verified with another DID, is the signer's problem before the URL is read.
    expect(await reasonOf(() => handleNeedsAuthorization(valid, 'did:web:other.example', resolveDid, { request: REQUEST, now: NOW }))).toBe('proof_signer_mismatch');
    expect(await reasonOf(() => handleNeedsAuthorization(valid, SERVER, async () => null, { request: REQUEST, now: NOW }))).toBe('jws_did_unresolved');
    expect(await reasonOf(() => handleNeedsAuthorization(valid, SERVER, resolveDid, { request: REQUEST, now: NOW + 121_000 }))).toBe('proof_timestamp_skew');
    expect(await reasonOf(() => handleNeedsAuthorization(valid, SERVER, resolveDid, { request: REQUEST, now: NOW + 121_000, skewSeconds: 600 }))).toBe('ok');
    // An IDidResolver works as well as a function.
    const resolver = { resolve: async (did: string) => ({ didDocument: did === SERVER ? document : null }) };
    expect((await handleNeedsAuthorization(valid, SERVER, resolver as never, { request: REQUEST, now: NOW })).challenge.resumeToken).toBe(RESUME_TOKEN);
  });

  it('refuses a verified response whose outcome is not needs_authorization, and takes the clock from now', async () => {
    const allowed = await signed({ content: [{ type: 'text', text: 'x' }] }, { outcome: 'allowed' });
    await expect(handleNeedsAuthorization(allowed, SERVER, resolveDid, { request: REQUEST, now: NOW })).rejects.toMatchObject({ code: 'NEEDS_AUTHORIZATION_INVALID', reason: 'challenge_outcome_mismatch' });
    const shortLived = await signed(toolResult({ ...CHALLENGE, expiresAt: Math.floor(NOW / 1000) + 1 }));
    expect((await handleNeedsAuthorization(shortLived, SERVER, resolveDid, { request: REQUEST, now: NOW })).challenge.expiresAt).toBe(Math.floor(NOW / 1000) + 1);
    expect(await reasonOf(() => handleNeedsAuthorization(shortLived, SERVER, resolveDid, { request: REQUEST, now: NOW + 1000 }))).toBe('challenge_expired');
    const error = await handleNeedsAuthorization(allowed, SERVER, resolveDid, { request: REQUEST, now: NOW }).catch((e: unknown) => e as NeedsAuthorizationError);
    expect(error).toBeInstanceOf(NeedsAuthorizationError);
    expect((error as NeedsAuthorizationError).details).toEqual({ reason: 'challenge_outcome_mismatch' });
    expect(new NeedsAuthorizationError('x').message).toBe('needs_authorization challenge is invalid');
  });
});

describe('readChallenge', () => {
  const now = NOW;
  it('finds the challenge at the top level or in structuredContent, and nowhere else', () => {
    expect(findChallenge(CHALLENGE)).toBe(CHALLENGE);
    expect(findChallenge(toolResult(CHALLENGE))).toBe((toolResult(CHALLENGE) as { structuredContent: unknown }).structuredContent);
    expect(findChallenge({ content: [] })).toBeUndefined();
    expect(findChallenge({ structuredContent: 'x' })).toBeUndefined();
    expect(findChallenge('needs_authorization')).toBeUndefined();
    expect(findChallenge(null)).toBeUndefined();
    expect(isNeedsAuthorization(toolResult(CHALLENGE))).toBe(true);
    expect(isNeedsAuthorization({ error: 'denied' })).toBe(false);
    expect(readChallenge(toolResult(CHALLENGE), { now })).toEqual(CHALLENGE);
    expect(readChallenge(toolResult(CHALLENGE), { now })).not.toBe(CHALLENGE);
    expect(readChallenge({ ...CHALLENGE, display: undefined }, { now })).not.toHaveProperty('display');
    expect(readChallenge({ ...CHALLENGE, display: { title: 'T', authorizationCode: 'ABCD', qrUrl: 'https://q', hint: ['qr', 'code'] } }, { now }).display).toEqual({ title: 'T', authorizationCode: 'ABCD', qrUrl: 'https://q', hint: ['qr', 'code'] });
    expect(readChallenge({ ...CHALLENGE, display: {} }, { now }).display).toEqual({});
    expect(readChallenge({ ...CHALLENGE, authorizationUrl: 'http://localhost:3700/authorize' }, { now }).authorizationUrl).toBe('http://localhost:3700/authorize');
    expect(readChallenge({ ...CHALLENGE, expiresAt: Math.floor(Date.now() / 1000) + 60 }).scopes).toEqual(['orders:admin']);
  });

  it('refuses a malformed challenge member by member', async () => {
    const bad = async (patch: Record<string, unknown>) => reasonOf(() => readChallenge({ ...CHALLENGE, ...patch }, { now }));
    expect(await bad({ message: 1 })).toBe('challenge_malformed');
    expect(await bad({ authorizationUrl: '' })).toBe('authorization_url_invalid');
    expect(await bad({ authorizationUrl: 'not a url' })).toBe('authorization_url_invalid');
    expect(await bad({ authorizationUrl: 'ftp://consent.example' })).toBe('authorization_url_invalid');
    expect(await bad({ resumeToken: 5 })).toBe('challenge_malformed');
    expect(await bad({ expiresAt: '2026-01-01T00:00:00Z' })).toBe('challenge_malformed');
    expect(await bad({ expiresAt: 1.5 })).toBe('challenge_malformed');
    expect(await bad({ expiresAt: 0 })).toBe('challenge_malformed');
    expect(await bad({ scopes: 'orders:admin' })).toBe('challenge_malformed');
    expect(await bad({ display: 'x' })).toBe('challenge_malformed');
    expect(await bad({ display: { title: 1 } })).toBe('challenge_malformed');
    expect(await bad({ display: { qrUrl: 1 } })).toBe('challenge_malformed');
    expect(await bad({ display: { hint: 'link' } })).toBe('challenge_malformed');
    expect(await bad({ display: { hint: ['popup'] } })).toBe('challenge_malformed');
    expect(await bad({ expiresAt: Math.floor(now / 1000) })).toBe('challenge_expired');
    expect(await reasonOf(() => readChallenge({ error: 'denied' }, { now }))).toBe('challenge_missing');
  });
});

describe('retryWithResume', () => {
  it('sends the same call with the token and the credential as control arguments, and verifies the answer when it can', async () => {
    const params = withResume(CALL, RESUME_TOKEN, HOP);
    expect(params).toEqual({ name: 'refund_order', arguments: { orderId: 'ORD-1001', reason: 'damaged', [RESUME_CONTROL_ARGUMENT]: RESUME_TOKEN, [DELEGATION_CONTROL_ARGUMENT]: HOP } });
    expect(withResume({ name: 'x' }, 't', HOP).arguments).toEqual({ _kyaos_resume: 't', _kyaos_delegation: HOP });
    expect(withResume({ name: 'x', _meta: { k: 1 } }, 't', HOP)._meta).toEqual({ k: 1 });
    expect(() => withResume(CALL, '', HOP)).toThrow(TypeError);
    expect(() => withResume(CALL, RESUME_TOKEN, undefined)).toThrow('must carry the DelegationCredential');
    expect(() => withResume(CALL, RESUME_TOKEN, null)).toThrow(TypeError);

    const body = { content: [{ type: 'text', text: '{"id":"ORD-1001","status":"refunded"}' }] };
    // The server signs over the covered request: control arguments are not part of it.
    const answer = await signed(body, { outcome: 'allowed', request: { method: 'tools/call', params: CALL } as never });
    const sent: ToolCallParams[] = [];
    const retried = await retryWithResume(RESUME_TOKEN, HOP, {
      call: CALL,
      send: async (p) => {
        sent.push(p);
        return answer;
      },
      serviceDid: SERVER,
      resolveDid,
      now: NOW,
    });
    expect(sent).toEqual([params]);
    expect(retried.params).toEqual(params);
    expect(retried.response).toBe(answer);
    expect(retried.proof).toMatchObject({ outcome: 'allowed', requestHash: hashRequest({ method: 'tools/call', params: CALL }) });
    // Without a service DID and resolver the answer is handed back unverified.
    const plain = await retryWithResume(RESUME_TOKEN, HOP, { call: CALL, send: async () => body });
    expect(plain).toEqual({ params, response: body });
    // A swapped answer is refused; so is a second challenge with a bad proof.
    const swapped = { ...answer, content: [{ type: 'text', text: 'swapped' }] };
    await expect(retryWithResume(RESUME_TOKEN, HOP, { call: CALL, send: async () => swapped, serviceDid: SERVER, resolveDid, now: NOW, skewSeconds: 120 })).rejects.toMatchObject({ reason: 'response_hash_mismatch' });
    await expect(retryWithResume(RESUME_TOKEN, HOP, { call: CALL, send: async () => toolResult(CHALLENGE), serviceDid: SERVER, resolveDid, now: NOW })).rejects.toMatchObject({ reason: 'proof_missing' });
    expect(kyaos.retryWithResume).toBe(retryWithResume);
  });
});
