// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// KYA-OS story L3-H, the SDK's side: consent requests and withdrawals (service), the signed root hop and
// its renewal inside the window (agent), against a stand-in for Helix's consent API that signs real hops
// with a did:key.
import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair } from '../../../src/index.js';
import { publicKeyToMultibase } from '../../../src/core/keys.js';
import { ConsentFlowError } from '../../../src/core/HelixError.js';
import { CredentialStore, signAttestationDocument } from '../../../src/core/credential-store.js';
import { EnvSigner, consent, readJwsHeader, verifyJwsByKid } from '../../../src/core/kyaos/index.js';
import { didKeyDocument } from '../../../src/core/kyaos/verifier/resolve.js';

const HELIX = 'https://helix.example';
const SERVICE = 'did:web:shop.example:services:aa';
const AGENT = 'did:web:helix.example:agents:bb';

function didKeySigner(): EnvSigner {
  const keys = generateKeyPair();
  return new EnvSigner({ did: `did:key:${publicKeyToMultibase(keys.publicKey)}`, envVar: 'K', env: { K: keys.privateKey } });
}

const user = didKeySigner();
const agentSigner = new EnvSigner({ did: AGENT, envVar: 'K', env: { K: generateKeyPair().privateKey } });
const serviceSigner = new EnvSigner({ did: SERVICE, envVar: 'K', env: { K: generateKeyPair().privateKey } });

let counter = 0;
async function hop(overrides: { issuer?: EnvSigner; invoker?: string; target?: string; validUntil?: string; allowedAction?: string[]; parent?: string } = {}) {
  counter += 1;
  const signer = overrides.issuer ?? user;
  const target = overrides.target ?? SERVICE;
  const id = `urn:zcap:${counter}`;
  return signAttestationDocument(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1', 'https://kya-os.org/ns/delegation/v1'],
      id,
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: signer.did,
      validUntil: overrides.validUntil ?? new Date(Date.now() + 3_600_000).toISOString(),
      credentialSubject: {
        id,
        invoker: overrides.invoker ?? AGENT,
        parentCapability: overrides.parent ?? target,
        invocationTarget: target,
        allowedAction: overrides.allowedAction ?? ['orders:read'],
      },
      credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: `${HELIX}/v1/status-list/x` },
    },
    signer,
    new Date().toISOString(),
  );
}

type Answer = { status: number; body: unknown };
function helix(routes: Record<string, (body: Record<string, unknown> | undefined) => Answer | Promise<Answer>>) {
  const calls: Array<{ url: string; method: string; request?: string }> = [];
  const fetch: consent.ConsentFetch = vi.fn(async (url, init) => {
    const body = init?.body === undefined ? undefined : (JSON.parse(init.body) as Record<string, unknown>);
    calls.push({ url, method: init?.method ?? 'GET', ...(body === undefined ? {} : { request: body['request'] as string }) });
    const route = routes[`${init?.method ?? 'GET'} ${url}`];
    const answer = route === undefined ? { status: 404, body: { error: { code: 'NOT_FOUND', message: url } } } : await route(body);
    return { ok: answer.status < 300, status: answer.status, json: async () => answer.body };
  });
  return { fetch, calls };
}

const claimsOf = (jws: string): Record<string, unknown> => JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;

describe('service side', () => {
  it('fills the unsigned root grant from its catalog', () => {
    expect(consent.unsignedRootGrant({ agentDid: AGENT, serviceDid: SERVICE, scopes: ['a', 'b'], validUntil: new Date('2027-01-01T00:00:00Z'), caveats: [{ type: 'Expiry' }] })).toEqual({
      validUntil: '2027-01-01T00:00:00.000Z',
      credentialSubject: { invoker: AGENT, invocationTarget: SERVICE, parentCapability: SERVICE, allowedAction: ['a', 'b'], caveats: [{ type: 'Expiry' }] },
    });
    expect(consent.unsignedRootGrant({ agentDid: AGENT, serviceDid: SERVICE, scopes: ['a'], validUntil: '2027-01-01T00:00:00Z' })).toMatchObject({ validUntil: '2027-01-01T00:00:00Z' });
  });

  it('signs the consent request as the service and returns the consent page URL', async () => {
    const page = `${HELIX}/consent/abc`;
    const { fetch, calls } = helix({ [`POST ${HELIX}/v1/consent/requests`]: () => ({ status: 201, body: { id: 'abc', authorizationUrl: page, resultUrl: `${HELIX}/v1/consent/requests/abc`, expiresAt: 1, status: 'pending' } }) });
    const grant = consent.unsignedRootGrant({ agentDid: AGENT, serviceDid: SERVICE, scopes: ['orders:read'], validUntil: new Date(Date.now() + 86_400_000) });
    const created = await consent.createConsentRequest({ helixUrl: `${HELIX}/`, signer: serviceSigner, serviceUserId: 'u1', grant, hopLifetimeSeconds: 600, display: { serviceName: 'Shop' }, returnUrl: 'https://shop.example/back', fetch });
    expect(created.authorizationUrl).toBe(page);
    const jws = calls[0]!.request!;
    expect(readJwsHeader(jws).typ).toBe(consent.CONSENT_REQUEST_TYP);
    expect(claimsOf(jws)).toMatchObject({ iss: SERVICE, aud: `${HELIX}/v1/consent/requests`, serviceUserId: 'u1', grant, hopLifetimeSeconds: 600, display: { serviceName: 'Shop' }, returnUrl: 'https://shop.example/back' });
    expect(claimsOf(jws)['jti']).toMatch(/^urn:uuid:/);
    // No key material in the request (rule 7).
    expect(jws).not.toMatch(/privateKey|"d":/);
    const bare = await consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u1', grant, fetch, now: Date.now() });
    expect(claimsOf(calls[1]!.request!)).not.toHaveProperty('hopLifetimeSeconds');
    expect(bare.id).toBe('abc');
  });

  it('surfaces a refusal and a malformed answer', async () => {
    const grant = consent.unsignedRootGrant({ agentDid: AGENT, serviceDid: SERVICE, scopes: ['x'], validUntil: new Date(Date.now() + 1000) });
    const refused = helix({ [`POST ${HELIX}/v1/consent/requests`]: () => ({ status: 403, body: { error: { code: 'CONSENT_SERVICE_UNKNOWN', message: 'unknown' } } }) });
    await expect(consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u', grant, fetch: refused.fetch })).rejects.toMatchObject({ reason: 'consent_request_refused', httpStatus: 403, helixCode: 'CONSENT_SERVICE_UNKNOWN', message: expect.stringContaining('CONSENT_SERVICE_UNKNOWN') });
    const odd = helix({ [`POST ${HELIX}/v1/consent/requests`]: () => ({ status: 201, body: {} }) });
    await expect(consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u', grant, fetch: odd.fetch })).rejects.toMatchObject({ httpStatus: 502 });
    const broken: consent.ConsentFetch = async () => ({ ok: false, status: 500, json: async () => { throw new Error('not json'); } });
    await expect(consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u', grant, fetch: broken })).rejects.toMatchObject({ message: expect.stringContaining('500'), helixCode: undefined });
    // No answer at all: an outage (503, consent_unreachable), whatever the transport threw.
    const down: consent.ConsentFetch = async () => { throw new TypeError('fetch failed'); };
    await expect(consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u', grant, fetch: down })).rejects.toMatchObject({ reason: 'consent_unreachable', httpStatus: 503, message: 'Helix could not be reached: fetch failed' });
    const odder: consent.ConsentFetch = async () => { throw 'socket closed'; };
    await expect(consent.createConsentRequest({ helixUrl: HELIX, signer: serviceSigner, serviceUserId: 'u', grant, fetch: odder })).rejects.toMatchObject({ reason: 'consent_unreachable', message: 'Helix could not be reached: socket closed' });
  });

  it('withdraws in a request the service signs', async () => {
    const { fetch, calls } = helix({ [`POST ${HELIX}/v1/consent/withdrawals`]: () => ({ status: 200, body: { consentId: 'c1', withdrawn: ['c1'], userDid: user.did, revoked: ['urn:zcap:1'] } }) });
    expect(await consent.withdrawConsent({ helixUrl: HELIX, signer: serviceSigner, consentId: 'c1', fetch })).toMatchObject({ revoked: ['urn:zcap:1'] });
    expect(readJwsHeader(calls[0]!.request!).typ).toBe(consent.CONSENT_WITHDRAWAL_TYP);
    expect(claimsOf(calls[0]!.request!)).toMatchObject({ iss: SERVICE, consentId: 'c1' });
    const refused = helix({});
    await expect(consent.withdrawConsent({ helixUrl: HELIX, signer: serviceSigner, consentId: 'c1', fetch: refused.fetch, now: Date.now() })).rejects.toMatchObject({ reason: 'consent_withdrawal_refused' });
  });
});

describe('agent side', () => {
  it('finds the result of the consent request the page URL names', () => {
    expect(consent.consentResultUrl(`${HELIX}/consent/abc`)).toBe(`${HELIX}/v1/consent/requests/abc`);
    expect(consent.consentResultUrl('http://127.0.0.1:3000/base/consent/x_y')).toBe('http://127.0.0.1:3000/base/v1/consent/requests/x_y');
    expect(consent.helixUrlOf(`${HELIX}/consent/abc`)).toBe(HELIX);
    for (const bad of ['not a url', `${HELIX}/elsewhere/abc`, 'ftp://helix.example/consent/abc']) {
      expect(() => consent.consentResultUrl(bad)).toThrow(ConsentFlowError);
    }
  });

  it('verifies the root hop from the did:key alone', async () => {
    const good = await hop();
    const { credentialSchemaViolations } = await import('../../../src/core/kyaos/verifier/credentials.js');
    expect(credentialSchemaViolations('hop', good)).toEqual([]);
    expect((await consent.verifyConsentHop(good, { agentDid: AGENT, serviceDid: SERVICE })).issuer).toBe(user.did);
    // The DID alone carries the key: what verifyJwsByKid sees for a did:key.
    expect(didKeyDocument(user.did)).toBeDefined();
    const webIssued = await hop({ issuer: serviceSigner });
    const cases: Array<[unknown, RegExp]> = [
      [{ not: 'a hop' }, /DelegationCredential/],
      [webIssued, /user did:key/],
      [await hop({ invoker: 'did:web:someone:else' }), /delegates to/],
      [await hop({ target: 'did:web:other:service' }), /targets/],
      [await hop({ parent: 'urn:zcap:parent' }), /valid root/],
      [{ ...good, credentialSubject: { ...good.credentialSubject, allowedAction: ['orders:write'] } }, /signature/],
      [await hop({ validUntil: new Date(Date.now() - 1000).toISOString() }), /valid root|expired/],
    ];
    for (const [value, message] of cases) await expect(consent.verifyConsentHop(value, { agentDid: AGENT, serviceDid: SERVICE })).rejects.toThrow(message);
    const soon = await hop({ validUntil: new Date(Date.now() + 1000).toISOString() });
    await expect(consent.verifyConsentHop(soon, { agentDid: AGENT, serviceDid: SERVICE, now: Date.now() + 500 })).resolves.toBeDefined();
  });

  it('waits for the click, then returns the checked hop', async () => {
    const signed = await hop();
    let polls = 0;
    const { fetch } = helix({
      [`GET ${HELIX}/v1/consent/requests/abc`]: () => {
        polls += 1;
        return polls < 3 ? { status: 200, body: { id: 'abc', status: 'pending', expiresAt: 1 } } : { status: 200, body: { id: 'abc', status: 'approved', expiresAt: 1, consentId: 'c1', hop: signed, windowUntil: 2_000_000_000 } };
      },
    });
    const sleep = vi.fn(async () => undefined);
    const approved = await consent.awaitConsentHop(`${HELIX}/consent/abc`, { agentDid: AGENT, serviceDid: SERVICE, fetch, sleep, intervalMs: 5 });
    expect(approved).toMatchObject({ consentId: 'c1', windowUntil: 2_000_000_000, helixUrl: HELIX });
    expect(approved.hop.id).toBe(signed.id);
    expect(sleep).toHaveBeenCalledTimes(2);
    const noWindow = helix({ [`GET ${HELIX}/v1/consent/requests/abc`]: () => ({ status: 200, body: { id: 'abc', status: 'approved', expiresAt: 1, consentId: 'c1', hop: signed } }) });
    expect((await consent.awaitConsentHop(`${HELIX}/consent/abc`, { agentDid: AGENT, serviceDid: SERVICE, fetch: noWindow.fetch })).windowUntil).toBe(Math.floor(Date.parse(signed.validUntil as string) / 1000));
  });

  it('gives up when declined, expired, unknown or too slow', async () => {
    for (const status of ['denied', 'expired']) {
      const { fetch } = helix({ [`GET ${HELIX}/v1/consent/requests/abc`]: () => ({ status: 200, body: { id: 'abc', status, expiresAt: 1 } }) });
      await expect(consent.awaitConsentHop(`${HELIX}/consent/abc`, { agentDid: AGENT, serviceDid: SERVICE, fetch })).rejects.toMatchObject({ reason: 'consent_not_approved' });
    }
    await expect(consent.fetchConsentResult(`${HELIX}/consent/none`, helix({}).fetch)).rejects.toMatchObject({ reason: 'consent_not_approved', httpStatus: 404 });
    const broken: consent.ConsentFetch = async () => ({ ok: false, status: 500, json: async () => { throw new Error('x'); } });
    await expect(consent.fetchConsentResult(`${HELIX}/consent/abc`, broken)).rejects.toMatchObject({ httpStatus: 500 });
    const pending = helix({ [`GET ${HELIX}/v1/consent/requests/abc`]: () => ({ status: 200, body: { id: 'abc', status: 'pending', expiresAt: 1 } }) });
    await expect(consent.awaitConsentHop(`${HELIX}/consent/abc`, { agentDid: AGENT, serviceDid: SERVICE, fetch: pending.fetch, timeoutMs: 0 })).rejects.toMatchObject({ reason: 'consent_timeout' });
    vi.useFakeTimers();
    const waiting = consent.awaitConsentHop(`${HELIX}/consent/abc`, { agentDid: AGENT, serviceDid: SERVICE, fetch: pending.fetch, timeoutMs: 1500, intervalMs: 1000 });
    const caught = waiting.catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(3000);
    expect(await caught).toMatchObject({ reason: 'consent_timeout' });
    vi.useRealTimers();
  });

  it('renews with a request the agent signs and maps Helix refusals to reasons', async () => {
    const renewed = await hop();
    const { fetch, calls } = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 200, body: { consentId: 'c1', hop: renewed, windowUntil: 2_000_000_000 } }) });
    const result = await consent.renewConsentHop({ helixUrl: HELIX, consentId: 'c1', signer: agentSigner, serviceDid: SERVICE, allowedAction: ['orders:read'], fetch });
    expect(result).toMatchObject({ windowUntil: 2_000_000_000 });
    expect(readJwsHeader(calls[0]!.request!).typ).toBe(consent.CONSENT_RENEWAL_TYP);
    expect(claimsOf(calls[0]!.request!)).toMatchObject({ iss: AGENT, consentId: 'c1', allowedAction: ['orders:read'] });
    const noWindow = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 200, body: { hop: renewed } }) });
    expect((await consent.renewConsentHop({ helixUrl: HELIX, consentId: 'c1', signer: agentSigner, serviceDid: SERVICE, fetch: noWindow.fetch, now: Date.now() })).windowUntil).toBeGreaterThan(0);
    for (const [code, reason] of [
      ['CONSENT_STEP_UP_REQUIRED', 'step_up_required'],
      ['CONSENT_WINDOW_ENDED', 'consent_window_ended'],
      ['CONSENT_WITHDRAWN', 'consent_withdrawn'],
      ['OTHER', 'consent_renewal_refused'],
    ] as const) {
      const refused = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 403, body: { error: { code } } }) });
      await expect(consent.renewConsentHop({ helixUrl: HELIX, consentId: 'c1', signer: agentSigner, serviceDid: SERVICE, fetch: refused.fetch })).rejects.toMatchObject({ reason });
    }
  });

  it('tells when to renew: a margin before validUntil, never before now', () => {
    expect(consent.renewBefore('2026-01-01T00:10:00Z', 60, Date.parse('2026-01-01T00:00:00Z'))).toBe(Date.parse('2026-01-01T00:09:00Z'));
    expect(consent.renewBefore(new Date('2026-01-01T00:00:30Z'), 60, Date.parse('2026-01-01T00:00:00Z'))).toBe(Date.parse('2026-01-01T00:00:00Z'));
    expect(consent.renewBefore(new Date(Date.now() + 120_000)) ).toBeGreaterThan(Date.now());
    expect(() => consent.renewBefore('soon')).toThrow(ConsentFlowError);
  });

  it('keeps the hop as the root of the chain at the service and renews it when due, inside the window', async () => {
    let now = Date.now();
    const first = await hop({ validUntil: new Date(now + 120_000).toISOString() });
    const second = await hop({ validUntil: new Date(now + 240_000).toISOString() });
    const { fetch } = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 200, body: { hop: second, windowUntil: Math.floor((now + 600_000) / 1000) } }) });
    const keys = generateKeyPair();
    const store = new CredentialStore({
      identity: { id: 'urn:id:1', type: ['VerifiableCredential', 'AgentIdentityCredential'], issuer: 'did:web:helix.example', credentialSubject: { id: AGENT, name: 'Bot', responsibleParty: 'did:web:helix.example:accounts:1' } },
    });
    expect(keys.privateKey).toBeDefined();
    const keeper = new consent.ConsentHopKeeper({
      store,
      signer: agentSigner,
      serviceDid: SERVICE,
      consent: { consentId: 'c1', hop: first as consent.ConsentHop, windowUntil: Math.floor((now + 600_000) / 1000), helixUrl: HELIX },
      fetch,
      clock: () => now,
    });
    expect(keeper.consentId).toBe('c1');
    expect(store.presentChain({ invocationTarget: SERVICE }).hops.map((credential) => credential.id)).toEqual([first.id]);
    expect((await keeper.chain()).map((credential) => credential.id)).toEqual([first.id]);
    now += 61_000;
    expect((await keeper.current()).id).toBe(second.id);
    expect(store.hops.map((credential) => credential.id)).toEqual([second.id]);
    expect(keeper.hop.id).toBe(second.id);
    // Past the window: no renewal is asked for, the last hop stays until it expires.
    now += 600_000;
    expect((await keeper.current()).id).toBe(second.id);
    // An explicit renewal with narrower scopes.
    const narrower = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 200, body: { hop: second } }) });
    const narrowKeeper = new consent.ConsentHopKeeper({ store: new CredentialStore(), signer: agentSigner, serviceDid: SERVICE, consent: { consentId: 'c2', hop: first as consent.ConsentHop, windowUntil: 2_000_000_000, helixUrl: HELIX }, fetch: narrower.fetch });
    await narrowKeeper.renew(['orders:read']);
    expect(claimsOf(narrower.calls[0]!.request!)['allowedAction']).toEqual(['orders:read']);
  });

  it('signs renewals the service can check against the agent DID document', async () => {
    const { fetch, calls } = helix({ [`POST ${HELIX}/v1/consent/renewals`]: async () => ({ status: 200, body: { hop: await hop() } }) });
    const agentKey = didKeySigner();
    const ownHop = await hop({ invoker: agentKey.did });
    const ok = helix({ [`POST ${HELIX}/v1/consent/renewals`]: () => ({ status: 200, body: { hop: ownHop } }) });
    await consent.renewConsentHop({ helixUrl: HELIX, consentId: 'c1', signer: agentKey, serviceDid: SERVICE, fetch: ok.fetch });
    await expect(verifyJwsByKid(ok.calls[0]!.request!, async (did) => didKeyDocument(did), { expectedDid: agentKey.did })).resolves.toBeDefined();
    // A hop for another agent coming back is refused, not stored.
    await expect(consent.renewConsentHop({ helixUrl: HELIX, consentId: 'c1', signer: agentKey, serviceDid: SERVICE, fetch })).rejects.toThrow(/delegates to/);
    expect(calls).toHaveLength(1);
  });
});
