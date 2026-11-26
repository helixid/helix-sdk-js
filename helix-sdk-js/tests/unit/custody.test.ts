// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: helix init, HelixCustodialSigner, the custody client and the agent runtime's Signer, with the self-custody invariant on every request.
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import { afterEach, describe, expect, it } from 'vitest';
import {
  CustodyApiError,
  EnvSigner,
  HelixCustodialSigner,
  HelixCustodyClient,
  activateAgent,
  base64UrlDecode,
  base64UrlEncode,
  changeToSelfCustody,
  checkOwnHosting,
  rotateKey,
  enrollmentProofMessage,
  helixInit,
  kidFragment,
  rotationProof,
  rotationProofMessage,
  verificationMethodOf,
  type FetchLike,
  type Signer,
} from '../../src/core/custody/index.js';
import { toPublicKeyJwk } from '../../src/core/agent-key.js';
import * as kyaos from '../../src/core/kyaos/index.js';

const FIXTURES_DIR = process.env['HELIX_CORE_FIXTURES_DIR'] ?? fileURLToPath(new URL('../../../../helix-core/fixtures', import.meta.url));
const CUSTODY_FIXTURE = join(FIXTURES_DIR, 'kya-os-helix', 'custody.json');

const SEED_HEX = '42'.repeat(32);
const seed = Buffer.from(SEED_HEX, 'hex');
const publicKeyHex = Buffer.from(ed25519.getPublicKey(seed)).toString('hex');
const PRIVATE_FORMS = [SEED_HEX, seed.toString('base64url'), seed.toString('base64')];

const dirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'helix-custody-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

/** A Helix API stand-in: answers by route, records every request exactly as sent. */
function fakeApi(routes: Record<string, (body: Record<string, unknown>) => { status?: number; body: unknown }>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetchLike: FetchLike = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    const path = new URL(url).pathname;
    const route = routes[`${init.method} ${decodeURIComponent(path)}`];
    if (!route) return { ok: false, status: 404, json: async () => ({ error: { code: 'NOT_FOUND', message: path } }) };
    const answer = route(init.body ? (JSON.parse(init.body) as Record<string, unknown>) : {});
    const status = answer.status ?? 200;
    return { ok: status < 400, status, json: async () => answer.body };
  };
  return { fetch: fetchLike, calls };
}

function assertNoPrivateKeyMaterialSent(calls: Call[], forms: string[]): void {
  for (const call of calls) {
    for (const form of forms) expect(call.body ?? '', call.url).not.toContain(form);
    if (call.body) expect(JSON.stringify(JSON.parse(call.body)), call.url).not.toMatch(/"(d|privateKey|privateKeyHex|seed|secret)":/);
  }
}

const DID = 'did:web:helix.example:acme:bot-1';

function agentKeyFrom(hex: string) {
  return () => ({ privateKeyHex: hex, publicKeyHex: Buffer.from(ed25519.getPublicKey(Buffer.from(hex, 'hex'))).toString('hex') });
}

function documentsFor(did: string, kid: string, x: string, origin: string) {
  return {
    didDocument: { id: did, verificationMethod: [{ id: kid, type: 'Ed25519VerificationKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x } }], service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: `${origin}/card.json` }] },
    card: { id: did, entityType: 'agent', name: 'Bot', kid, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x, kid }, proofProfile: 'org.kya-os/proof.v1', didDocument: `${origin}/did.json` },
    didDocumentUrl: `${origin}/did.json`,
    cardUrl: `${origin}/card.json`,
  };
}

describe.skipIf(!existsSync(CUSTODY_FIXTURE))('helix-core fixtures/kya-os-helix/custody.json (cross-language)', () => {
  const fixture = existsSync(CUSTODY_FIXTURE) ? JSON.parse(readFileSync(CUSTODY_FIXTURE, 'utf8')) : {};
  it('builds the same proof messages and signatures as helix-core', async () => {
    const fixtureSeed = Buffer.from(fixture.key.seedHex, 'hex');
    const enrollment = enrollmentProofMessage({ did: fixture.enrollment.did, kid: fixture.enrollment.kid, nonce: fixture.enrollment.nonce });
    expect(new TextDecoder().decode(enrollment)).toBe(fixture.enrollment.message);
    expect(base64UrlEncode(await ed25519.signAsync(enrollment, fixtureSeed))).toBe(fixture.enrollment.signature);
    const rotation = rotationProofMessage({ did: fixture.rotation.did, kid: fixture.rotation.kid, issuedAt: fixture.rotation.issuedAt });
    expect(new TextDecoder().decode(rotation)).toBe(fixture.rotation.message);
    const signer = new EnvSigner({ did: fixture.rotation.did, kid: fixture.rotation.kid, env: { HELIX_SIGNING_KEY: fixture.key.seedHex } });
    expect(await rotationProof(signer, fixture.rotation.did, fixture.rotation.kid, fixture.rotation.issuedAt)).toEqual({ issuedAt: fixture.rotation.issuedAt, signature: fixture.rotation.signature });
    expect(toPublicKeyJwk(fixture.key.publicKeyHex)).toEqual(fixture.key.publicKeyJwk);
  });

  it('HelixCustodialSigner sends the fixture request and reads the fixture response', async () => {
    const api = fakeApi({ [`POST /v1/agents/${fixture.sign.did}/sign`]: () => ({ body: fixture.sign.response }) });
    const signer = new HelixCustodialSigner({ apiUrl: 'https://helix.example', did: fixture.sign.did, fetch: api.fetch, adminApiKey: 'k' });
    const signature = await signer.sign(new TextEncoder().encode(fixture.sign.payloadUtf8));
    expect(JSON.parse(api.calls[0]!.body!)).toEqual({ ...fixture.sign.request, kid: 'key-1' });
    expect(base64UrlEncode(signature)).toBe(fixture.sign.response.signature);
  });
});

describe('EnvSigner and kid handling', () => {
  it('signs with the key in the environment and never holds it', async () => {
    const signer = new EnvSigner({ did: DID, kid: `${DID}#key-1`, env: { HELIX_SIGNING_KEY: SEED_HEX } });
    expect(signer.kid).toBe('key-1');
    expect(verificationMethodOf(signer)).toBe(`${DID}#key-1`);
    expect(signer.publicKeyHex()).toBe(publicKeyHex);
    const data = new Uint8Array([1, 2, 3]);
    expect(await ed25519.verifyAsync(await signer.sign(data), data, publicKeyHex)).toBe(true);
    expect(JSON.stringify(signer)).toBe(`{"did":"${DID}","kid":"key-1"}`);
    await expect(new EnvSigner({ did: DID, env: {} }).sign(data)).rejects.toThrow(/HELIX_SIGNING_KEY is not set/);
    expect(new EnvSigner({ did: DID, envVar: 'OTHER', env: { OTHER: SEED_HEX } }).publicKeyHex()).toBe(publicKeyHex);
    expect(() => new EnvSigner({ did: 'nope' })).toThrow(/did must be a DID/);
    expect(kidFragment(DID, '#k')).toBe('k');
    expect(() => kidFragment(DID, 'did:web:other#k#j')).toThrow(/not a verification-method fragment/);
    expect(() => kidFragment(DID, '')).toThrow();
    expect(base64UrlDecode('a+b')).toBeUndefined();
    expect(base64UrlDecode('a')).toBeUndefined();
    expect(() => enrollmentProofMessage({ did: DID, kid: 'a b', nonce: 'n' })).toThrow(/whitespace/);
    expect((await rotationProof(signer, DID, `${DID}#key-2`)).issuedAt).toMatch(/^\d{4}-/);
  });
});

describe('HelixCustodyClient', () => {
  it('sends the admin key or the account bearer, and maps refusals', async () => {
    const api = fakeApi({
      'GET /v1/custody/defaults': () => ({ body: { custody: { defaultKeyCustody: 'self', defaultDidHosting: 'helix' }, source: 'built-in' } }),
      'POST /v1/agents': () => ({ status: 409, body: { error: { code: 'CUSTODY_STATE_INVALID', message: 'no', details: { status: 'active' } } } }),
      'GET /v1/conformance/report': () => ({ status: 500, body: undefined }),
    });
    const admin = new HelixCustodyClient({ apiUrl: 'https://helix.example/', adminApiKey: 'admin', fetch: api.fetch });
    expect((await admin.defaults()).source).toBe('built-in');
    expect(api.calls[0]).toMatchObject({ url: 'https://helix.example/v1/custody/defaults', headers: { 'x-admin-api-key': 'admin' } });
    const account = new HelixCustodyClient({ apiUrl: 'https://helix.example', apiKey: 'acc', fetch: api.fetch });
    const refused = await account.createAgent({ name: 'x' }).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(CustodyApiError);
    expect(refused).toMatchObject({ status: 409, code: 'CUSTODY_STATE_INVALID', details: { status: 'active' } });
    expect(api.calls[1]!.headers).toMatchObject({ authorization: 'Bearer acc', 'content-type': 'application/json' });
    await expect(account.conformanceReport()).rejects.toMatchObject({ code: 'HTTP_ERROR', status: 500 });
    const bodyless: FetchLike = async () => ({ ok: false, status: 502, json: async () => { throw new Error('html'); } });
    await expect(new HelixCustodyClient({ apiUrl: 'https://h', fetch: bodyless }).defaults()).rejects.toMatchObject({ status: 502 });
    expect(() => new HelixCustodyClient({ apiUrl: '' })).toThrow(/apiUrl/);
  });

  it('refuses to send private key material, whatever the caller hands it', async () => {
    const api = fakeApi({});
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', fetch: api.fetch });
    await expect(client.enroll({ enrollmentToken: 't', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'x', d: 'secret' } as never, signature: 's' })).rejects.toThrow(/never leave the client/);
    await expect(client.createService({ name: 's', domain: 'd', requiredScopes: ['a'], privateKey: 'x' } as never)).rejects.toThrow(/never leave the client/);
    expect(api.calls).toEqual([]);
  });

  it('refuses an own-hosted DID with an unencoded port before any request', async () => {
    const api = fakeApi({});
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', fetch: api.fetch });
    for (const call of [
      () => client.createAgent({ name: 'a', didHosting: 'own', did: 'did:web:localhost:3000:a' }),
      () => client.createService({ name: 's', domain: 'd', requiredScopes: ['x'], didHosting: 'own', did: 'did:web:localhost:3000:s' }),
      () => client.createOwner({ name: 'o', didHosting: 'own', did: 'did:web:localhost:3000' }),
    ]) {
      await expect(call()).rejects.toMatchObject({ name: 'CustodyApiError', status: 400, code: 'VALIDATION_ERROR' });
    }
    expect(api.calls).toEqual([]);
    const ok = fakeApi({ 'POST /v1/agents': (body) => ({ status: 201, body: { did: DID, ...body } }) });
    const sending = new HelixCustodyClient({ apiUrl: 'https://helix.example', fetch: ok.fetch });
    await sending.createAgent({ name: 'a', didHosting: 'own', did: 'did:web:localhost%3A3000:a' });
    await sending.createAgent({ name: 'b', didHosting: 'own' });
    expect(ok.calls).toHaveLength(2);
  });

  it('sends requestedDomains and maxDelegationDepth with createAgent as given', async () => {
    const api = fakeApi({ 'POST /v1/agents': (body) => ({ status: 201, body: { did: DID, ...body } }) });
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', adminApiKey: 'admin', fetch: api.fetch });
    await client.createAgent({ name: 'Router', keyCustody: 'helix', requestedDomains: ['orders.example'], maxDelegationDepth: 2 });
    expect(JSON.parse(api.calls[0]!.body!)).toEqual({ name: 'Router', keyCustody: 'helix', requestedDomains: ['orders.example'], maxDelegationDepth: 2 });
    // Registry v3: "Make discoverable" (default true on the server) is sent only when given.
    await client.createAgent({ name: 'Hidden', discoverable: false });
    expect(JSON.parse(api.calls[1]!.body!)).toEqual({ name: 'Hidden', discoverable: false });
  });

  it('reaches every custody endpoint by subject kind', async () => {
    const seen: string[] = [];
    const fetchLike: FetchLike = async (url, init) => {
      seen.push(`${init.method} ${new URL(url).pathname}`);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const client = new HelixCustodyClient({ apiUrl: 'https://h', fetch: fetchLike });
    await client.createOwner({ name: 'o' });
    await client.createService({ name: 's', domain: 'd', requiredScopes: ['a'] });
    await client.activate(DID, {}, 'service');
    await client.activate(DID);
    await client.getCustody(DID, 'owner');
    await client.getCustody(DID);
    await client.finalizeRotation(DID, { force: true }, 'service');
    await client.finalizeRotation(DID);
    await client.changeCustody(DID, { keyCustody: 'helix' });
    await client.conformanceReport();
    const did = encodeURIComponent(DID);
    expect(seen).toEqual([
      'POST /v1/owners',
      'POST /v1/services',
      `POST /v1/services/${did}/activate`,
      `POST /v1/agents/${did}/activate`,
      `GET /v1/owners/${did}/custody`,
      `GET /v1/agents/${did}/custody`,
      `POST /v1/services/${did}/custody/finalize`,
      `POST /v1/agents/${did}/custody/finalize`,
      `POST /v1/agents/${did}/custody`,
      'GET /v1/conformance/report',
    ]);
  });
});

describe('HelixCustodialSigner', () => {
  const helixSeed = Buffer.from('7e'.repeat(32), 'hex');
  const helixPublic = Buffer.from(ed25519.getPublicKey(helixSeed)).toString('hex');

  function signingApi(kid = `${DID}#key-1`, subject = 'agents') {
    return fakeApi({
      [`POST /v1/${subject}/${DID}/sign`]: (body) => ({
        body: { did: DID, kid, alg: 'EdDSA', signature: base64UrlEncode(ed25519.sign(base64UrlDecode(body['payload'] as string)!, helixSeed)) },
      }),
    });
  }

  it('signs through the API with the Helix-held key and holds nothing itself', async () => {
    const api = signingApi();
    const signer = new HelixCustodialSigner({ apiUrl: 'https://helix.example', did: DID, apiKey: 'acc', fetch: api.fetch });
    const data = new TextEncoder().encode('payload');
    const signature = await signer.sign(data);
    expect(await ed25519.verifyAsync(signature, data, helixPublic)).toBe(true);
    expect(api.calls[0]).toMatchObject({ method: 'POST', headers: { authorization: 'Bearer acc' } });
    expect(JSON.parse(api.calls[0]!.body!)).toEqual({ payload: base64UrlEncode(data), kid: 'key-1' });
    expect(JSON.stringify(signer)).toBe(`{"did":"${DID}","kid":"key-1"}`);
    const owner = signingApi(`${DID}#key-1`, 'owners');
    expect(await new HelixCustodialSigner({ apiUrl: 'https://h', did: DID, subject: 'owner', fetch: owner.fetch }).sign(data)).toHaveLength(64);
    expect(await new HelixCustodialSigner({ apiUrl: 'x', did: DID, client: new HelixCustodyClient({ apiUrl: 'https://h', fetch: api.fetch }) }).sign(data)).toHaveLength(64);
  });

  it('refuses what is not a signature of the key it names', async () => {
    const wrongKid = signingApi(`${DID}#key-9`);
    await expect(new HelixCustodialSigner({ apiUrl: 'https://h', did: DID, fetch: wrongKid.fetch }).sign(new Uint8Array([1]))).rejects.toThrow(/signed with/);
    const short = fakeApi({ [`POST /v1/agents/${DID}/sign`]: () => ({ body: { did: DID, kid: `${DID}#key-1`, alg: 'EdDSA', signature: 'AAAA' } }) });
    await expect(new HelixCustodialSigner({ apiUrl: 'https://h', did: DID, fetch: short.fetch }).sign(new Uint8Array([1]))).rejects.toThrow(/64-byte/);
    const refused = fakeApi({ [`POST /v1/agents/${DID}/sign`]: () => ({ status: 409, body: { error: { code: 'CUSTODIAL_SIGNING_REFUSED', message: 'self' } } }) });
    await expect(new HelixCustodialSigner({ apiUrl: 'https://h', did: DID, fetch: refused.fetch }).sign(new Uint8Array([1]))).rejects.toMatchObject({ code: 'CUSTODIAL_SIGNING_REFUSED' });
    await expect(new HelixCustodialSigner({ apiUrl: 'https://h', did: DID }).sign('text' as never)).rejects.toThrow(/bytes/);
    expect(() => new HelixCustodialSigner({ apiUrl: 'https://h', did: 'x' })).toThrow(/did must be a DID/);
  });
});

describe('the agent runtime takes any Signer (a KYA-OS request proof)', () => {
  const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'o-1' } } };
  const options = { audience: 'did:web:orders.example', nonce: 'n-1', now: Date.parse('2026-11-23T00:00:00Z') };

  /** The application code: the same whichever custody mode the signer stands for. */
  async function prove(signer: Signer) {
    return kyaos.verifier.signRequestProof(request, signer, options);
  }

  it('makes the same request proof for a self-custody and a custodial signer, and it verifies against the public key', async () => {
    const viaEnv = await prove(new EnvSigner({ did: DID, env: { HELIX_SIGNING_KEY: SEED_HEX } }));
    const custodialApi = fakeApi({
      [`POST /v1/agents/${DID}/sign`]: (body) => ({ body: { did: DID, kid: `${DID}#key-1`, alg: 'EdDSA', signature: base64UrlEncode(ed25519.sign(base64UrlDecode(body['payload'] as string)!, seed)) } }),
    });
    const viaHelix = await prove(new HelixCustodialSigner({ apiUrl: 'https://h', did: DID, fetch: custodialApi.fetch }));
    expect(viaHelix).toEqual(viaEnv);
    expect(viaHelix.kid).toBe(`${DID}#key-1`);
    expect(custodialApi.calls.map((call) => call.url)).toEqual([`https://h/v1/agents/${encodeURIComponent(DID)}/sign`]);
    expect(kyaos.verifier.verifyDetachedJws(viaHelix, Buffer.from(publicKeyHex, 'hex'))).toBe(true);
  });
});

describe('helix init (self-custody onboarding)', () => {
  function initApi(did: string, didHosting: 'helix' | 'own', origin: string, status: 'active' | 'pending_resolution', activatedCard?: Record<string, unknown>) {
    const kid = `${did}#key-1`;
    return fakeApi({
      'POST /v1/agents/enroll/challenge': () => ({ body: { did, kid, nonce: 'cd'.repeat(32), keyCustody: 'self', didHosting, name: 'Bot', didDocumentUrl: `${origin}/did.json`, cardUrl: `${origin}/card.json` } }),
      'POST /v1/agents/enroll': (body) => {
        const jwk = body['publicKeyJwk'] as { x: string };
        const ok = ed25519.verify(base64UrlDecode(body['signature'] as string)!, enrollmentProofMessage({ did, kid: `${did}#${String(body['kid'])}`, nonce: 'cd'.repeat(32) }), Buffer.from(jwk.x, 'base64url'));
        if (!ok) return { status: 400, body: { error: { code: 'ENROLLMENT_PROOF_INVALID', message: 'bad proof' } } };
        return { status: 201, body: { did, keyCustody: 'self', didHosting, label: 'custody: self', status, kid, documents: documentsFor(did, kid, jwk.x, origin), ...(status === 'active' ? { vcId: 'vc:1' } : {}) } };
      },
      [`POST /v1/agents/${did}/activate`]: (body) =>
        body['enrollmentToken'] === 'enroll:t'
          ? { body: { did, status: 'active', vcId: 'vc:2', ...(activatedCard ? { documents: { card: activatedCard, didDocumentUrl: `${origin}/did.json`, cardUrl: `${origin}/card.json` } } : {}) } }
          : { status: 403, body: { error: { code: 'ADMIN_AUTH_REQUIRED', message: 'no' } } },
    });
  }

  it('Helix hosting: generates the key here, registers only the public JWK with a proof, writes the files, and is active', async () => {
    const out = await tempDir();
    const api = initApi(DID, 'helix', 'https://helix.example/acme/bot-1', 'active');
    const result = await helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, fetch: api.fetch, generateKey: agentKeyFrom(SEED_HEX) });
    expect(result).toMatchObject({ did: DID, kid: `${DID}#key-1`, keyCustody: 'self', didHosting: 'helix', status: 'active', label: 'custody: self', vcId: 'vc:1', envVar: 'HELIX_SIGNING_KEY' });
    expect(result.publicKeyJwk).toEqual(toPublicKeyJwk(publicKeyHex));
    // The self-custody invariant: no API request carries private key material.
    assertNoPrivateKeyMaterialSent(api.calls, PRIVATE_FORMS);
    expect(api.calls.map((call) => call.url)).toEqual(['https://helix.example/v1/agents/enroll/challenge', 'https://helix.example/v1/agents/enroll']);
    expect(JSON.parse(await readFile(join(out, 'did.json'), 'utf8'))).toMatchObject({ id: DID });
    expect(JSON.parse(await readFile(join(out, 'card.json'), 'utf8'))).toMatchObject({ id: DID, entityType: 'agent' });
    const env = await readFile(join(out, 'signing-key.env'), 'utf8');
    expect(env).toContain(`HELIX_SIGNING_KEY=${SEED_HEX}`);
    expect(env).toContain(`HELIX_AGENT_DID=${DID}`);
    expect((await stat(join(out, 'signing-key.env'))).mode & 0o777).toBe(0o600);
    const summary = await readFile(join(out, 'helix-agent.json'), 'utf8');
    for (const form of PRIVATE_FORMS) expect(summary).not.toContain(form);
    // The written key is what the agent's EnvSigner uses.
    const signer = new EnvSigner({ did: DID, env: { HELIX_SIGNING_KEY: SEED_HEX } });
    expect(signer.publicKeyHex()).toBe(publicKeyHex);
  });

  it('own hosting: pending until the documents resolve from the owner domain, then activated with the token', async () => {
    const out = await tempDir();
    const did = 'did:web:owner.example:agents:bot';
    const origin = 'https://owner.example/agents/bot';
    const api = initApi(did, 'own', origin, 'pending_resolution');
    const served = new Map<string, unknown>();
    const resolveFetch = async (url: string) => (served.has(url) ? { ok: true, status: 200, json: async () => served.get(url) } : { ok: false, status: 404, json: async () => ({}) });
    const pending = await helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, did, fetch: api.fetch, resolveFetch, generateKey: agentKeyFrom(SEED_HEX) });
    expect(pending).toMatchObject({ status: 'pending_resolution', resolution: { ok: false } });
    expect(api.calls.some((call) => call.url.endsWith('/activate'))).toBe(false);
    served.set(`${origin}/did.json`, JSON.parse(await readFile(join(out, 'did.json'), 'utf8')));
    served.set(`${origin}/card.json`, JSON.parse(await readFile(join(out, 'card.json'), 'utf8')));
    const active = await activateAgent({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, fetch: api.fetch, resolveFetch });
    expect(active).toMatchObject({ did, status: 'active', resolution: { ok: true }, vcId: 'vc:2' });
    assertNoPrivateKeyMaterialSent(api.calls, PRIVATE_FORMS);
    const again = await helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: await tempDir(), did, fetch: initApi(did, 'own', origin, 'pending_resolution').fetch, resolveFetch, activate: false });
    expect(again.status).toBe('pending_resolution');
    expect(again.resolution).toBeUndefined();
  });

  it('own hosting: on activation card.json is rewritten with what the credentials put on the card, to republish (F-3 parity)', async () => {
    const out = await tempDir();
    const did = 'did:web:owner.example:agents:carded';
    const origin = 'https://owner.example/agents/carded';
    const carded = { id: did, entityType: 'agent', name: 'Bot', capabilities: [{ name: 'orders:read', attestations: [{ vc: { id: 'att:1' } }] }], responsibleParty: 'did:web:helix.example' };
    const api = initApi(did, 'own', origin, 'pending_resolution', carded);
    const served = new Map<string, unknown>();
    const resolveFetch = async (url: string) => (served.has(url) ? { ok: true, status: 200, json: async () => served.get(url) } : { ok: false, status: 404, json: async () => ({}) });
    const pending = await helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, did, fetch: api.fetch, resolveFetch, generateKey: agentKeyFrom(SEED_HEX) });
    expect(pending.cardUpdated).toBeUndefined();
    served.set(`${origin}/did.json`, JSON.parse(await readFile(join(out, 'did.json'), 'utf8')));
    served.set(`${origin}/card.json`, JSON.parse(await readFile(join(out, 'card.json'), 'utf8')));
    const active = await activateAgent({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, fetch: api.fetch, resolveFetch });
    expect(active).toMatchObject({ status: 'active', cardUpdated: true });
    expect(JSON.parse(await readFile(join(out, 'card.json'), 'utf8'))).toEqual(carded);
  });

  it('checks resolution against the registered key', async () => {
    const did = 'did:web:owner.example:agents:bot';
    const origin = 'https://owner.example/agents/bot';
    const x = toPublicKeyJwk(publicKeyHex).x;
    const docs = documentsFor(did, `${did}#key-1`, x, origin);
    const serve = (document: unknown, card: unknown) => async (url: string) => ({ ok: true, status: 200, json: async () => (url.endsWith('did.json') ? document : card) });
    const key = { kid: `${did}#key-1`, publicKeyJwk: toPublicKeyJwk(publicKeyHex) };
    expect(await checkOwnHosting(did, key, { fetch: serve(docs.didDocument, docs.card) })).toEqual({ ok: true });
    expect(await checkOwnHosting(did, key, { fetch: serve({ ...docs.didDocument, verificationMethod: [] }, docs.card) })).toMatchObject({ ok: false, reason: expect.stringMatching(/does not list/) });
    const otherX = toPublicKeyJwk(Buffer.from(ed25519.getPublicKey(Buffer.alloc(32, 9))).toString('hex')).x;
    expect(await checkOwnHosting(did, key, { fetch: serve(docs.didDocument, { ...docs.card, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: otherX } }) })).toMatchObject({ ok: false, reason: expect.stringMatching(/another key/) });
    expect(await checkOwnHosting(did, key, { fetch: serve({ ...docs.didDocument, id: 'did:web:x' }, docs.card) })).toMatchObject({ ok: false });
    expect(await checkOwnHosting(did, key, { fetch: async () => { throw 'down'; } })).toMatchObject({ ok: false, reason: expect.any(String) });
  });

  it('refuses a token for another DID, a failed proof, and missing input', async () => {
    const out = await tempDir();
    const api = initApi(DID, 'helix', 'https://helix.example/acme/bot-1', 'active');
    await expect(helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: out, did: 'did:web:owner.example:x', fetch: api.fetch })).rejects.toThrow(/is for/);
    await expect(helixInit({ apiUrl: 'https://h', enrollmentToken: '', outDir: out })).rejects.toThrow(/enrollment token/);
    await expect(helixInit({ apiUrl: 'https://h', enrollmentToken: 't', outDir: '' })).rejects.toThrow(/output directory/);
    const noDocs = fakeApi({
      'POST /v1/agents/enroll/challenge': () => ({ body: { did: DID, kid: `${DID}#key-1`, nonce: 'n' } }),
      'POST /v1/agents/enroll': () => ({ status: 201, body: { did: DID, status: 'active' } }),
    });
    await expect(helixInit({ apiUrl: 'https://h', enrollmentToken: 't', outDir: out, fetch: noDocs.fetch })).rejects.toThrow(/did not return/);
    const custom = await helixInit({ apiUrl: 'https://helix.example', enrollmentToken: 'enroll:t', outDir: await tempDir(), kid: 'agent-key', envVar: 'AGENT_KEY', fetch: api.fetch });
    expect(custom).toMatchObject({ kid: `${DID}#agent-key`, envVar: 'AGENT_KEY' });
    expect(await readFile(custom.files.signingKey, 'utf8')).toMatch(/AGENT_KEY=[0-9a-f]{64}/);
  });
});

describe('changeToSelfCustody (custody change to self, a rotation)', () => {
  it('generates the new key here, sends only its public half and a proof, and writes signing-key.env', async () => {
    const out = await tempDir();
    let sent: Record<string, unknown> = {};
    const api = fakeApi({
      [`POST /v1/agents/${DID}/custody`]: (body) => {
        sent = body;
        return {
          body: {
            did: DID,
            keyCustody: 'self',
            didHosting: 'own',
            label: 'custody: self',
            kid: `${DID}#${String(body['kid'])}`,
            previousKid: `${DID}#key-1`,
            previousKeyShredded: true,
            retiresAt: '2026-11-22T00:00:00.000Z',
            hopReissue: { reissued: 0, pending: true },
            publishRequired: true,
            documents: documentsFor(DID, `${DID}#${String(body['kid'])}`, (body['publicKeyJwk'] as { x: string }).x, 'https://owner.example'),
          },
        };
      },
    });
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', adminApiKey: 'admin', fetch: api.fetch });
    const { result, files } = await changeToSelfCustody({ client, did: DID, outDir: out, kid: 'key-2', overlapSeconds: 60, generateKey: agentKeyFrom(SEED_HEX) });
    expect(result).toMatchObject({ keyCustody: 'self', previousKeyShredded: true });
    expect(Object.keys(sent).sort()).toEqual(['keyCustody', 'kid', 'overlapSeconds', 'proof', 'publicKeyJwk']);
    const proof = sent['proof'] as { issuedAt: string; signature: string };
    expect(ed25519.verify(base64UrlDecode(proof.signature)!, rotationProofMessage({ did: DID, kid: `${DID}#key-2`, issuedAt: proof.issuedAt }), publicKeyHex)).toBe(true);
    assertNoPrivateKeyMaterialSent(api.calls, PRIVATE_FORMS);
    expect(await readFile(files.signingKey, 'utf8')).toContain(`HELIX_SIGNING_KEY=${SEED_HEX}`);
    expect(JSON.parse(await readFile(join(out, 'did.json'), 'utf8'))).toMatchObject({ id: DID });
    const helixHosted = fakeApi({
      [`POST /v1/services/${DID}/custody`]: (body) => ({ body: { did: DID, kid: `${DID}#${String(body['kid'])}`, didHosting: 'helix', publishRequired: false, documents: documentsFor(DID, `${DID}#k`, 'x', 'https://h') } }),
    });
    const second = await changeToSelfCustody({ client: new HelixCustodyClient({ apiUrl: 'https://helix.example', fetch: helixHosted.fetch }), did: DID, outDir: await tempDir(), subject: 'service' });
    expect(second.result.kid).toMatch(new RegExp(`^${DID}#key-`));
  });
});

describe('rotateKey (story C-E point 1)', () => {
  const CURRENT_HEX = '17'.repeat(32);
  const currentPublic = Buffer.from(ed25519.getPublicKey(Buffer.from(CURRENT_HEX, 'hex'))).toString('hex');

  it('generates the new key here, sends only its public half, its proof and the current key\'s signature, and writes signing-key.env', async () => {
    const out = await tempDir();
    let sent: Record<string, unknown> = {};
    const api = fakeApi({
      [`POST /v1/agents/${DID}/keys/rotate`]: (body) => {
        sent = body;
        return {
          body: {
            did: DID,
            keyCustody: 'self',
            didHosting: 'helix',
            kid: `${DID}#${String(body['kid'])}`,
            previousKid: `${DID}#key-1`,
            rotationSequence: 2,
            retiresAt: '2026-11-24T00:00:00.000Z',
            hopReissue: { reissued: 1, pending: false, reissuedHops: { a: 'b' }, pendingIssuers: [{ hopId: 'c', issuer: 'did:web:issuer.example' }] },
            publishRequired: false,
            documents: documentsFor(DID, `${DID}#${String(body['kid'])}`, (body['publicKeyJwk'] as { x: string }).x, 'https://helix.example'),
          },
        };
      },
    });
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', fetch: api.fetch });
    const currentSigner = new EnvSigner({ did: DID, kid: 'key-1', envVar: 'K', env: { K: CURRENT_HEX } });
    const now = new Date('2026-11-23T00:00:00.000Z');
    const { result, files } = await rotateKey({ client, did: DID, currentSigner, outDir: out, kid: 'key-2', overlapSeconds: 3600, generateKey: agentKeyFrom(SEED_HEX), now: () => now });
    expect(result).toMatchObject({ kid: `${DID}#key-2`, rotationSequence: 2, hopReissue: { pendingIssuers: [{ hopId: 'c' }] } });
    expect(Object.keys(sent).sort()).toEqual(['currentKeyProof', 'kid', 'overlapSeconds', 'proof', 'publicKeyJwk']);
    const message = rotationProofMessage({ did: DID, kid: `${DID}#key-2`, issuedAt: now.toISOString() });
    expect(ed25519.verify(base64UrlDecode((sent['proof'] as { signature: string }).signature)!, message, publicKeyHex)).toBe(true);
    expect(ed25519.verify(base64UrlDecode((sent['currentKeyProof'] as { signature: string }).signature)!, message, currentPublic)).toBe(true);
    assertNoPrivateKeyMaterialSent(api.calls, [...PRIVATE_FORMS, CURRENT_HEX]);
    expect(api.calls[0]!.headers).not.toHaveProperty('authorization');
    expect(await readFile(files.signingKey, 'utf8')).toContain(`HELIX_SIGNING_KEY=${SEED_HEX}`);
    expect(existsSync(join(out, 'did.json'))).toBe(false);
  });

  it('without a current signer relies on the account key; refuses a signer of another DID; writes own-hosted documents', async () => {
    const out = await tempDir();
    const api = fakeApi({
      [`POST /v1/agents/${DID}/keys/rotate`]: (body) => ({
        body: { did: DID, kid: `${DID}#${String(body['kid'])}`, didHosting: 'own', publishRequired: true, documents: documentsFor(DID, `${DID}#${String(body['kid'])}`, 'x', 'https://owner.example') },
      }),
    });
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', apiKey: 'acct', fetch: api.fetch });
    const { result } = await rotateKey({ client, did: DID, outDir: out });
    expect(result.kid).toMatch(new RegExp(`^${DID}#key-`));
    expect(JSON.parse(api.calls[0]!.body!)).not.toHaveProperty('currentKeyProof');
    expect(JSON.parse(await readFile(join(out, 'did.json'), 'utf8'))).toMatchObject({ id: DID });
    const stranger = new EnvSigner({ did: 'did:web:other.example', envVar: 'K', env: { K: CURRENT_HEX } });
    await expect(rotateKey({ client, did: DID, currentSigner: stranger, outDir: out })).rejects.toThrow(/not did:web:helix.example/);
  });

  it('the client reaches revokeKey and finalizeRotation', async () => {
    const api = fakeApi({
      [`POST /v1/agents/${DID}/keys/revoke`]: (body) => ({ body: { revokedKid: `${DID}#${String(body['kid'])}`, revokedHops: [], rotationSequence: 3 } }),
      [`POST /v1/services/${DID}/custody/finalize`]: () => ({ body: { retired: [`${DID}#key-1`] } }),
    });
    const client = new HelixCustodyClient({ apiUrl: 'https://helix.example', adminApiKey: 'admin', fetch: api.fetch });
    expect(await client.revokeKey(DID, 'key-1')).toMatchObject({ revokedKid: `${DID}#key-1`, rotationSequence: 3 });
    expect(await client.finalizeRotation(DID, { force: true }, 'service')).toEqual({ retired: [`${DID}#key-1`] });
  });
});
