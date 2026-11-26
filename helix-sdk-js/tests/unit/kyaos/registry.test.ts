// Copyright 2026 DgVerse LLP
// Registry v3 (2026-11-24): kyaos.registry -- the Helix agent registry, and the DID check of a service by its URL.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kyaos, EnvSigner, generateAgentKey } from '../../../src/index.js';
import { HELIX_REGISTRY_ORIGIN, RegistryError, createRegistryClient, helixOriginOfDid, helixRegistryOrigin, publish } from '../../../src/core/kyaos/registry.js';

const HELIX = 'http://127.0.0.1:3880';
const AIR = 'did:web:127.0.0.1%3A3880:services:air';
const GHOST = 'did:web:127.0.0.1%3A4540:services:ghost';
const TEST_ONLY = 'HELIX_TEST_ONLY_REGISTRY_ORIGIN';
const AGENT_D = { agentDid: 'did:web:127.0.0.1%3A3880:agents:d', name: 'Agent D', status: 'active', owner: { did: null, name: 'Client D' }, publishedAt: '2026-11-24T10:00:00.000Z', deployment: HELIX };

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** The Helix registry, two services' /.well-known/mcp, and the DID documents Helix serves. */
function world(overrides: Record<string, () => Response | Promise<Response>> = {}) {
  const fetch = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    for (const [prefix, answer] of Object.entries(overrides)) if (url.startsWith(prefix)) return answer();
    if (url === 'http://127.0.0.1:4530/.well-known/mcp') return json(200, { version: '1.0', serverDid: AIR, endpoints: { tools: '/mcp' } });
    if (url === 'http://127.0.0.1:4540/.well-known/mcp') return json(200, { version: '1.0', serverDid: GHOST, endpoints: { tools: '/mcp' } });
    if (url === 'http://127.0.0.1:9000/.well-known/mcp') return json(200, { version: '1.0', serverDid: AIR, endpoints: {} });
    if (url === 'https://127.0.0.1:3880/services/air/did.json') return json(200, { id: AIR, verificationMethod: [] });
    const parsed = new URL(url);
    if (parsed.origin === HELIX && parsed.pathname === '/agent/registry') {
      const q = (parsed.searchParams.get('q') ?? '').toLowerCase();
      return json(200, { agents: [AGENT_D, { name: 'no DID' }].filter((a) => String(a.name).toLowerCase().includes(q)), nextCursor: null });
    }
    if (parsed.origin === HELIX && parsed.pathname === `/agent/registry/${encodeURIComponent(AGENT_D.agentDid)}`) return json(200, { agent: AGENT_D });
    return json(404, {});
  });
  return { fetch };
}

afterEach(() => {
  delete process.env[TEST_ONLY];
});

describe('kyaos.registry', () => {
  it('is exported under kyaos, with the fixed Helix registry and a test-only override', () => {
    expect(kyaos.registry.createRegistryClient).toBe(createRegistryClient);
    expect(HELIX_REGISTRY_ORIGIN).toBe('https://api.helixid.dev');
    expect(helixRegistryOrigin()).toBe(HELIX_REGISTRY_ORIGIN);
    expect(createRegistryClient().registry).toBe(HELIX_REGISTRY_ORIGIN);
    process.env[TEST_ONLY] = `${HELIX}/x`;
    expect(helixRegistryOrigin()).toBe(HELIX);
    expect(kyaos.registry).not.toHaveProperty('findServices');
    expect(kyaos.registry).not.toHaveProperty('createAccountCheck');
  });

  it('reads the deployment of a did:web', () => {
    expect(helixOriginOfDid('did:web:127.0.0.1%3A3880:agents:a')).toBe(HELIX);
    expect(helixOriginOfDid('did:web:helix.example.com:agents:a')).toBe('https://helix.example.com');
    expect(helixOriginOfDid('did:web:%5B%3A%3A1%5D%3A3000:a')).toBe('http://[::1]:3000');
    expect(helixOriginOfDid('did:key:z6Mk')).toBeUndefined();
    expect(helixOriginOfDid('did:web:bad%20host')).toBeUndefined();
  });
});

describe('findAgents and lookup: the Helix agent registry', () => {
  it('searches discoverable agents and looks one up by DID', async () => {
    process.env[TEST_ONLY] = HELIX;
    const { fetch } = world();
    const registry = createRegistryClient({ fetch: fetch as never });
    expect(await registry.findAgents('agent')).toEqual([AGENT_D]);
    expect(String(fetch.mock.calls[0]![0])).toBe(`${HELIX}/agent/registry?q=agent`);
    expect(await registry.lookup(AGENT_D.agentDid)).toEqual(AGENT_D);
    expect(await registry.lookup('did:web:127.0.0.1%3A3200:agents:hidden')).toBeNull();
  });

  it('refuses a registry that answers something else', async () => {
    process.env[TEST_ONLY] = HELIX;
    const odd = createRegistryClient({ fetch: world({ [`${HELIX}/agent/registry`]: () => json(200, { agents: 'x' }) }).fetch as never });
    await expect(odd.findAgents('x')).rejects.toMatchObject({ reason: 'registry_error' });
    await expect(odd.lookup('did:web:x')).resolves.toBeNull();
    const missing = createRegistryClient({ fetch: world({ [`${HELIX}/agent/registry`]: () => json(404, {}) }).fetch as never });
    await expect(missing.findAgents('x')).rejects.toMatchObject({ reason: 'registry_error' });
    const down = createRegistryClient({ fetch: world({ [`${HELIX}/agent/registry`]: () => json(500, {}) }).fetch as never });
    await expect(down.findAgents('x')).rejects.toMatchObject({ reason: 'fetch_failed' });
    const html = createRegistryClient({ fetch: world({ [`${HELIX}/agent/registry`]: () => new Response('<html>', { status: 200 }) }).fetch as never });
    await expect(html.findAgents('x')).rejects.toThrow(/did not answer with JSON/);
    const thrown = createRegistryClient({ fetch: (async () => { throw new Error('ECONNREFUSED'); }) as never });
    await expect(thrown.findAgents('x')).rejects.toMatchObject({ reason: 'fetch_failed', name: 'RegistryError', code: 'REGISTRY_ERROR' });
    const thrownString = createRegistryClient({ fetch: (async () => { throw 'down'; }) as never });
    await expect(thrownString.lookup('did:web:x')).rejects.toThrow(/down/);
  });
});

describe('resolve: a service by its URL, trusted through the DID at its own address', () => {
  it('reads /.well-known/mcp and fetches the DID document it names', async () => {
    const { fetch } = world();
    // Local run: Helix serves its did:web documents over http; a resolver that rewrites stands in.
    const resolveDid = kyaos.verifier.createDidResolver({ fetch: fetch as never, rewriteUrl: (url) => url });
    const registry = createRegistryClient({ fetch: fetch as never, resolveDid });
    const resolved = await registry.resolve('http://127.0.0.1:4530/anything');
    expect(resolved).toMatchObject({ serviceDid: AIR, toolsUrl: 'http://127.0.0.1:4530/mcp', url: 'http://127.0.0.1:4530', didDocument: { id: AIR } });
    expect(await registry.resolve('http://127.0.0.1:4530', { expectedDid: AIR })).toMatchObject({ serviceDid: AIR });
  });

  it('refuses a service whose DID cannot be fetched, another DID than expected, no tools endpoint, or no URL', async () => {
    const { fetch } = world();
    const registry = createRegistryClient({ fetch: fetch as never });
    await expect(registry.resolve('http://127.0.0.1:4540')).rejects.toMatchObject({ reason: 'did_unresolvable', message: expect.stringContaining(GHOST) });
    await expect(registry.resolve('http://127.0.0.1:4530', { expectedDid: 'did:web:other' })).rejects.toMatchObject({ reason: 'did_mismatch' });
    const resolving = createRegistryClient({ fetch: fetch as never, resolveDid: async () => ({ id: AIR }) as never });
    await expect(resolving.resolve('http://127.0.0.1:9000')).rejects.toMatchObject({ reason: 'no_url' });
    await expect(registry.resolve('not a url')).rejects.toMatchObject({ reason: 'no_url' });
    const throwing = createRegistryClient({ fetch: fetch as never, resolveDid: async () => { throw new Error('stale'); } });
    await expect(throwing.resolve('http://127.0.0.1:4530')).rejects.toMatchObject({ reason: 'did_unresolvable', message: expect.stringContaining('stale') });
    const throwingString = createRegistryClient({ fetch: fetch as never, resolveDid: async () => { throw 'x'; } });
    await expect(throwingString.resolve('http://127.0.0.1:4530')).rejects.toMatchObject({ reason: 'did_unresolvable' });
    expect(new RegistryError('no_url', 'x')).toBeInstanceOf(Error);
  });

  it('uses the global fetch by default', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = world().fetch as never;
    try {
      await expect(createRegistryClient().resolve('http://127.0.0.1:4540')).rejects.toMatchObject({ reason: 'did_unresolvable' });
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe('kyaos.registry.publish (a discoverable self-custody agent)', () => {
  const key = generateAgentKey();
  const did = 'did:web:127.0.0.1%3A3200:agents:a';
  const signer = new EnvSigner({ did, env: { HELIX_SIGNING_KEY: key.privateKeyHex } });

  it('signs a registration with its own key and sends it to the Helix registry', async () => {
    process.env[TEST_ONLY] = HELIX;
    const fetch = vi.fn(async () => json(201, { agent: { ...AGENT_D, agentDid: did, name: 'Agent A' } }));
    const listed = await publish({ signer, fetch: fetch as never, now: new Date('2026-11-24T12:00:00Z') });
    expect(listed).toMatchObject({ agentDid: did, name: 'Agent A' });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${HELIX}/agent/registry`);
    const jws = JSON.parse(String(init.body)).registration as string;
    const [header, payload] = jws.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')));
    expect(header).toMatchObject({ alg: 'EdDSA', kid: `${did}#key-1`, typ: 'helix-registration+jwt' });
    expect(payload).toMatchObject({ iss: did, sub: did, aud: HELIX, deployment: 'http://127.0.0.1:3200', iat: 1795521600, exp: 1795521900 });
    expect(payload).not.toHaveProperty('kind');
    const viaUrl = vi.fn(async () => json(201, { agent: { agentDid: did } }));
    await publish({ signer, helixUrl: 'http://127.0.0.1:3200/v1', fetch: viaUrl as never });
    expect(JSON.parse(Buffer.from(JSON.parse(String((viaUrl.mock.calls[0] as unknown as [string, RequestInit])[1].body)).registration.split('.')[1], 'base64url').toString('utf8')).deployment).toBe('http://127.0.0.1:3200');
  });

  it('reports a refusal and a failure, and needs a deployment', async () => {
    process.env[TEST_ONLY] = HELIX;
    await expect(publish({ signer, fetch: (async () => json(403, { error: { message: 'not listed as discoverable' } })) as never })).rejects.toMatchObject({ reason: 'publish_refused', message: expect.stringContaining('not listed as discoverable') });
    await expect(publish({ signer, fetch: (async () => new Response('x', { status: 502 })) as never })).rejects.toThrow(/answered 502/);
    await expect(publish({ signer, fetch: (async () => { throw new Error('down'); }) as never })).rejects.toMatchObject({ reason: 'fetch_failed' });
    await expect(publish({ signer, fetch: (async () => { throw 'down'; }) as never })).rejects.toMatchObject({ reason: 'fetch_failed' });
    const keyed = new EnvSigner({ did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', env: { HELIX_SIGNING_KEY: key.privateKeyHex } });
    await expect(publish({ signer: keyed, fetch: vi.fn() as never })).rejects.toMatchObject({ reason: 'no_helix_link' });
  });
});
