// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// KYA-OS story C-A in the SDK: resolveEntityCard (two-step, bare-host fallback, service entry wins,
// did:key refused), the strict card schema, the server.json projection, and SafeFetch, asserted
// against helix-core's fixtures/kya-os-helix/entity-card.json and the vendored entity-card vectors.

import { createServer, type Server } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  EntityCardError,
  SafeFetchRefusedError,
  buildEntityCard,
  createSafeFetch,
  defaultOutboundFetch,
  didWebCardUrl,
  didWebDocumentUrl,
  didWebFor,
  entityCardSummary,
  fetchEntityCard,
  fetchTransport,
  isPublicUnicastAddress,
  normalizeDid,
  parseDidWeb,
  parseEntityCard,
  resolveEntityCard,
  resolveEntityCardFromServerMeta,
  sameDid,
  serverCardMeta,
  validateEntityCard,
  type EntityCard,
  type SafeFetchTransport,
  type TransportRequest,
} from '../../src/index.js';

const FIXTURES_DIR = process.env['HELIX_CORE_FIXTURES_DIR'] ?? fileURLToPath(new URL('../../../../helix-core/fixtures', import.meta.url));
const FIXTURE = `${FIXTURES_DIR}/kya-os-helix/entity-card.json`;
const SCHEMA = `${FIXTURES_DIR}/kya-os/schemas/kya-os-card.schema.json`;
const VECTORS = `${FIXTURES_DIR}/kya-os/conformance/vectors/entity-card.json`;

interface Fixture {
  host: string;
  user_did_key: string;
  entities: Record<string, { kind: string; did: string; did_document_url: string; card_url: string; did_document: Record<string, unknown>; card: EntityCard; summary: unknown; server_meta: unknown }>;
  served: Record<string, unknown>;
  resolution: { did: string; steps: [string, string]; card_id: string }[];
  refusals: { name: string; did?: string; card?: unknown; served?: Record<string, unknown>; reason: string }[];
  build_cases: { name: string; input: Record<string, unknown>; expected: 'card' | 'refused'; card?: EntityCard; absent?: string[] }[];
  safe_fetch_refusals: { url: string; reason: string }[];
  public_addresses: string[];
  non_public_addresses: string[];
}

const fixture = existsSync(FIXTURE) ? (JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture) : undefined;
const describeFixture = fixture ? describe : describe.skip;

const serving = (map: Record<string, unknown>) =>
  vi.fn(async (url: string) => (map[url] === undefined ? new Response('not found', { status: 404 }) : new Response(JSON.stringify(map[url]), { status: 200 })));

async function reason(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof EntityCardError || error instanceof SafeFetchRefusedError) return error.reason;
    throw error;
  }
  return 'ok';
}

const JWK = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'JUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0' };
const AGENT = 'did:web:helix.test:acme:ledger-agent';

describe('did:web helpers', () => {
  it('derive both URLs, with the well-known fallback for a bare host, and compare DIDs by one spelling', () => {
    expect(didWebFor('Helix.Test', ['acme', 'a b'])).toBe('did:web:helix.test:acme:a%20b');
    expect(parseDidWeb('did:web:localhost%3A3000:acme:a%20b')).toEqual({ host: 'localhost:3000', path: ['acme', 'a b'] });
    expect(parseDidWeb('did:web:helix.test:acme:agent#key-1')).toBeUndefined();
    expect(parseDidWeb('did:web:helix.test::x')).toBeUndefined();
    expect(parseDidWeb('did:web:helix.test:%E0%A4%A')).toBeUndefined();
    expect(parseDidWeb('did:key:z6Mk')).toBeUndefined();
    expect(didWebDocumentUrl(AGENT)).toBe('https://helix.test/acme/ledger-agent/did.json');
    expect(didWebCardUrl(AGENT)).toBe('https://helix.test/acme/ledger-agent/card.json');
    expect(didWebDocumentUrl('did:web:helix.test')).toBe('https://helix.test/.well-known/did.json');
    expect(didWebCardUrl('did:web:helix.test')).toBe('https://helix.test/.well-known/kya-os-card.json');
    expect(didWebCardUrl('did:web:localhost%3A3000:acme'), 'a loopback host serves plain http').toBe('http://localhost:3000/acme/card.json');
    expect(didWebDocumentUrl('did:web:127.0.0.1%3A3580')).toBe('http://127.0.0.1:3580/.well-known/did.json');
    expect(() => didWebCardUrl('did:key:z6Mk')).toThrow(EntityCardError);
    expect(normalizeDid('did:web:HELIX.test:a%3ab')).toBe('did:web:helix.test:a%3Ab');
    expect(sameDid('did:web:HELIX.test', 'did:web:helix.test')).toBe(true);
    expect(sameDid('did:web:helix.test:%E0%A4%A', 'did:web:helix.test:%E0%A4%A')).toBe(false);
    expect(sameDid('did:key:a', 'did:key:b')).toBe(false);
  });
});

describe('the strict card schema', () => {
  it('admits the vendored schema examples and refuses an unknown top-level field in each', () => {
    const schema = JSON.parse(readFileSync(SCHEMA, 'utf8')) as { examples: object[] };
    for (const example of schema.examples) {
      expect(validateEntityCard(example)).toEqual([]);
      expect(validateEntityCard({ ...example, bogusField: true })).toEqual(['/bogusField: must NOT have additional properties']);
    }
  });

  it('refuses each malformed member with its path', () => {
    const base = { id: AGENT, entityType: 'agent', name: 'A' };
    const first = (value: unknown): string => validateEntityCard(value)[0] ?? 'ok';
    expect(first('card')).toBe(': must be of type object');
    expect(first({ id: AGENT })).toBe(": must have required property 'entityType'");
    expect(first({ ...base, id: 'did:hedera:x' })).toBe('/id: must be a did:key or did:web DID');
    expect(first({ ...base, entityType: 'tool' })).toMatch(/^\/entityType: must be one of/);
    expect(first({ ...base, name: '' })).toBe('/name: must be a non-empty string');
    expect(first({ ...base, kid: 1 })).toBe('/kid: must be of type string');
    expect(first({ ...base, publicKeyJwk: { ...JWK, d: 'x' } })).toBe('/publicKeyJwk/d: must NOT have additional properties');
    expect(first({ ...base, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 1, kid: 2 } })).toBe('/publicKeyJwk/kty: must equal "OKP"');
    expect(validateEntityCard({ ...base, publicKeyJwk: 'jwk' })).toEqual(['/publicKeyJwk: must be of type object']);
    expect(first({ ...base, createdAt: 'yesterday' })).toBe('/createdAt: must be an RFC 3339 date-time');
    expect(first({ ...base, capabilities: 'x' })).toBe('/capabilities: must be of type array');
    expect(first({ ...base, capabilities: [''] })).toMatch(/^\/capabilities\/0/);
    expect(first({ ...base, capabilities: [{ name: 'x', attestations: [] }] })).toMatch(/^\/capabilities\/0/);
    expect(first({ ...base, capabilities: [{ name: 'x', attestations: [{ vc: 'jwt' }], extra: 1 }] })).toMatch(/^\/capabilities\/0/);
    expect(first({ ...base, capabilities: ['x', { name: 'y', attestations: [{ vc: { id: 'v' }, note: 1 }] }] })).toBe('ok');
    expect(first({ ...base, conformanceLevel: 'L4' })).toMatch(/^\/conformanceLevel/);
    expect(first({ ...base, responsibleParty: 'acme' })).toBe('/responsibleParty: must be a did:key or did:web DID');
    expect(first({ ...base, principal: 'did:hedera:x' })).toBe('/principal: must be a did:key or did:web DID');
    expect(first({ ...base, attestations: 'x' })).toBe('/attestations: must be of type array');
    expect(first({ ...base, attestations: [{ type: 'KYC', vc: 'x' }] })).toMatch(/^\/attestations\/0\/type/);
    expect(first({ ...base, attestations: [{ type: 'IdentityVerification', vc: 1 }] })).toMatch(/^\/attestations\/0\/vc/);
    expect(first({ ...base, attestations: [{ type: 'IdentityVerification', vc: 'x', issuer: 'nope' }] })).toMatch(/^\/attestations\/0\/issuer/);
    expect(first({ ...base, attestations: ['x'] })).toBe('/attestations/0: must be of type object');
    expect(first({ ...base, didDocument: 'not a uri' })).toBe('/didDocument: must be a URI');
    expect(first({ ...base, proofProfile: 'v2' })).toMatch(/^\/proofProfile/);
    expect(first({ ...base, cimd: { clientId: 'x' } })).toBe('/cimd/jwksUri: must be a non-empty string');
    expect(first({ ...base, revocation: { statusListCredential: 'x', statusListIndex: '0x7' } })).toBe('/revocation/statusListIndex: must match ^[0-9]+$');
    expect(first({ ...base, revocation: { statusListCredential: '', statusListIndex: '7' } })).toBe('/revocation/statusListCredential: must be a non-empty string');
    expect(first({ ...base, revocation: { statusListCredential: 'x', statusListIndex: '7', statusSize: 0 } })).toBe('/revocation/statusSize: must be an integer of at least 1');
    expect(first({ ...base, revocation: { statusListCredential: 'x', statusListIndex: '7', statusMessage: 'm' } })).toBe('/revocation/statusMessage: must be an array');
    expect(first({ ...base, revocation: { statusListCredential: 'x', statusListIndex: '7', statusMessage: [{ status: '0x1' }] } })).toMatch(/^\/revocation\/statusMessage\/0/);
    expect(first({ ...base, revocation: { statusListCredential: 'x', statusListIndex: '7', statusSize: 1, statusMessage: [{ status: '0x1', message: 'revoked' }] } })).toBe('ok');
    expect(() => parseEntityCard({ ...base, bogusField: true })).toThrow(/bogusField/);
    expect(parseEntityCard(base)).toBe(base);
  });

  it('buildEntityCard ignores conformanceLevel, refuses a proof, an unknown member, private material and a foreign kid', () => {
    const card = buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', kid: 'key-1', publicKeyJwk: JWK, capabilities: ['handshake'], conformanceLevel: 'L3' });
    expect(card).toEqual({ id: AGENT, entityType: 'agent', name: 'Ledger', kid: `${AGENT}#key-1`, publicKeyJwk: { ...JWK, kid: `${AGENT}#key-1` }, capabilities: ['handshake'], didDocument: 'https://helix.test/acme/ledger-agent/did.json', proofProfile: 'org.kya-os/proof.v1' });
    expect(buildEntityCard({ id: AGENT, entityType: 'mcp', name: 'S', kid: `${AGENT}#k2`, proofProfile: 'org.kya-os/proof@1', didDocument: 'https://cdn.example/did.json' })).toMatchObject({ kid: `${AGENT}#k2`, proofProfile: 'org.kya-os/proof@1', didDocument: 'https://cdn.example/did.json' });
    expect(buildEntityCard({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice', publicKeyJwk: JWK })).toEqual({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice', publicKeyJwk: JWK, proofProfile: 'org.kya-os/proof.v1' });
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', proof: {} } as never)).toThrow(/unknown members \(proof\)/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', publicKeyJwk: { ...JWK, d: 'x' } as never })).toThrow(/private material/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', publicKeyJwk: { ...JWK, use: 'sig' } as never })).toThrow(/unexpected members/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', publicKeyJwk: 'jwk' as never })).toThrow(/private material/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', kid: 'did:web:other#k' })).toThrow(/does not name/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'L', kid: '#' })).toThrow(/does not name/);
    expect(() => buildEntityCard({ id: AGENT, entityType: 'agent', name: '' })).toThrow(EntityCardError);
    expect(() => buildEntityCard(null as never)).toThrow(/input object/);
  });

  it('projects the claim-minimal summary with the cardRef', () => {
    const card = buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', { name: 'ledger.post', attestations: [{ vc: 'jwt' }] }], responsibleParty: 'did:web:helix.test:acme', delegationRef: 'r>d', revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' } });
    expect(serverCardMeta(card)).toEqual({ 'org.kya-os/card': { id: AGENT, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', 'ledger.post'], responsibleParty: 'did:web:helix.test:acme', delegationRef: 'r>d', proofProfile: 'org.kya-os/proof.v1', revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' }, 'org.kya-os/cardRef': 'https://helix.test/acme/ledger-agent/card.json' } });
    expect(serverCardMeta(card, { byRef: true, cardUrl: 'https://cdn.example/card.json' })).toEqual({ 'org.kya-os/card': { 'org.kya-os/cardRef': 'https://cdn.example/card.json' } });
    const keyCard = buildEntityCard({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice' });
    expect(entityCardSummary(keyCard)).toEqual({ id: keyCard.id, entityType: 'human', name: 'Alice', proofProfile: 'org.kya-os/proof.v1' });
    expect(() => serverCardMeta(keyCard)).toThrow(/did:key/);
  });
});

describeFixture('helix-core fixture: fixtures/kya-os-helix/entity-card.json', () => {
  const f = fixture!;

  it('every entity card validates and its projection matches', () => {
    for (const e of Object.values(f.entities)) {
      expect(validateEntityCard(e.card)).toEqual([]);
      expect(entityCardSummary(e.card)).toEqual(e.summary);
      expect(serverCardMeta(e.card)).toEqual(e.server_meta);
      expect(didWebCardUrl(e.did)).toBe(e.card_url);
      expect(didWebDocumentUrl(e.did)).toBe(e.did_document_url);
    }
    expect(f.entities['agent']!.card.responsibleParty).toBe(f.entities['org']!.did);
    expect(f.entities['agent']!.card.principal).toBe(f.user_did_key);
  });

  it('every DID resolves in two steps over the served map, and through its server.json projection', async () => {
    for (const step of f.resolution) {
      const fetchLike = serving(f.served);
      const resolved = await resolveEntityCard(step.did, { fetch: fetchLike });
      expect(fetchLike.mock.calls.map((call) => call[0])).toEqual(step.steps);
      expect(resolved.card.id).toBe(step.card_id);
      expect((await resolveEntityCardFromServerMeta({ serverMeta: serverCardMeta(resolved.card) }, { fetch: serving(f.served) })).card).toEqual(resolved.card);
      expect((await resolveEntityCardFromServerMeta({ serverMeta: {}, did: step.did }, { fetch: serving(f.served) })).card).toEqual(resolved.card);
    }
  });

  it('every refusal refuses for the recorded reason', async () => {
    for (const refusal of f.refusals) {
      const got = refusal.card !== undefined ? (validateEntityCard(refusal.card).some((issue) => issue.includes('additional properties')) ? 'additionalProperties' : 'accepted') : await reason(() => resolveEntityCard(refusal.did!, { fetch: serving(refusal.served ?? f.served) }));
      expect(got, refusal.name).toBe(refusal.reason);
    }
  });

  it('build cases agree with helix-core', () => {
    for (const build of f.build_cases) {
      if (build.expected === 'card') {
        const card = buildEntityCard(build.input as never);
        expect(card, build.name).toEqual(build.card);
        for (const member of build.absent ?? []) expect(member in card).toBe(false);
      } else {
        expect(() => buildEntityCard(build.input as never), build.name).toThrow();
      }
    }
  });

  it('SafeFetch refuses every recorded URL for the recorded reason, and judges addresses as helix-core does', async () => {
    const safeFetch = createSafeFetch({ lookup: async () => ['93.184.216.34'], transport: async () => ({ status: 200, headers: {}, body: new Uint8Array() }) });
    for (const { url, reason: expected } of f.safe_fetch_refusals) expect(await reason(() => safeFetch(url)), url).toBe(expected);
    for (const address of f.public_addresses) expect(isPublicUnicastAddress(address), address).toBe(true);
    for (const address of f.non_public_addresses) expect(isPublicUnicastAddress(address), address).toBe(false);
  });
});

describeFixture('vendored entity-card vectors: parseCard', () => {
  it('parses every card the suite expects to pass and refuses the malformed one', () => {
    const file = JSON.parse(readFileSync(VECTORS, 'utf8')) as { vectors: { id: string; expected: string; input: { card: unknown } }[] };
    expect(file.vectors).toHaveLength(8);
    for (const vector of file.vectors) {
      if (vector.id === 'entity-card/malformed-unknown-field') expect(() => parseEntityCard(vector.input.card)).toThrow(/bogusField/);
      else expect(validateEntityCard(vector.input.card), vector.id).toEqual([]);
    }
  });
});

describe('resolveEntityCard', () => {
  const agentCard = buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', publicKeyJwk: JWK, kid: 'key-1' });
  const agentDocument = { id: AGENT, service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/acme/ledger-agent/card.json' }] };
  const orgCard = buildEntityCard({ id: 'did:web:helix.test', entityType: 'verifier', name: 'Helix' });

  it('resolves through the service entry, falls back to the well-known path for a bare host, and lets the service entry win', async () => {
    const resolved = await resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': agentCard }) });
    expect(resolved).toEqual({ did: AGENT, card: agentCard, cardUrl: 'https://helix.test/acme/ledger-agent/card.json', didDocument: agentDocument });
    expect((await resolveEntityCard('did:web:helix.test', { fetch: serving({ 'https://helix.test/.well-known/did.json': { id: 'did:web:helix.test' }, 'https://helix.test/.well-known/kya-os-card.json': orgCard }) })).cardUrl).toBe('https://helix.test/.well-known/kya-os-card.json');
    const both = serving({ 'https://helix.test/.well-known/did.json': { id: 'did:web:helix.test', service: [{ type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/cards/org.json' }] }, 'https://helix.test/cards/org.json': orgCard, 'https://helix.test/.well-known/kya-os-card.json': { ...orgCard, name: 'stale' } });
    expect((await resolveEntityCard('did:web:helix.test', { fetch: both })).card.name).toBe('Helix');
    expect(both).toHaveBeenCalledTimes(2);
  });

  it('refuses did:key, a malformed DID, a foreign or missing document, no service entry, a foreign, missing, non-JSON or invalid card', async () => {
    const none = serving({});
    expect(await reason(() => resolveEntityCard('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', { fetch: none }))).toBe('did_key_not_resolvable');
    expect(await reason(() => resolveEntityCard(`${AGENT}#key-1`, { fetch: none }))).toBe('malformed_did');
    expect(await reason(() => resolveEntityCard(5 as never, { fetch: none }))).toBe('malformed_did');
    expect(none).not.toHaveBeenCalled();
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: none }))).toBe('did_document_unavailable');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': { id: 'did:web:other' } }) }))).toBe('did_document_mismatch');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': { id: AGENT, service: 'none' } }) }))).toBe('no_card_service');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument }) }))).toBe('card_unavailable');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': orgCard }) }))).toBe('card_mismatch');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': { ...agentCard, bogus: 1 } }) }))).toBe('card_invalid');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: async () => new Response('<html>', { status: 200 }) }))).toBe('did_document_unavailable');
    expect(await reason(() => resolveEntityCard(AGENT, { fetch: async () => { throw new Error('refused'); } }))).toBe('did_document_unavailable');
    expect(await reason(() => fetchEntityCard('https://helix.test/x', { fetch: async () => new Response('<html>', { status: 200 }) }))).toBe('card_unavailable');
  });

  it('resolves from a server.json projection and refuses what it cannot read', async () => {
    const fetchLike = serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': agentCard, 'https://cdn.example/card.json': agentCard });
    expect((await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { 'org.kya-os/cardRef': 'https://cdn.example/card.json' } } }, { fetch: fetchLike })).cardUrl).toBe('https://cdn.example/card.json');
    expect((await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': entityCardSummary(agentCard) } }, { fetch: fetchLike })).cardUrl).toBe('https://helix.test/acme/ledger-agent/card.json');
    const keyCard = buildEntityCard({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice' });
    expect((await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': entityCardSummary(keyCard) } }, { fetch: fetchLike })).card).toEqual(entityCardSummary(keyCard));
    expect((await resolveEntityCardFromServerMeta({ serverMeta: undefined, did: AGENT }, { fetch: fetchLike })).card).toEqual(agentCard);
    expect(await reason(() => resolveEntityCardFromServerMeta({ serverMeta: {} }, { fetch: fetchLike }))).toBe('no_projection');
    expect(await reason(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { name: 'x' } } }, { fetch: fetchLike }))).toBe('no_projection');
    expect(await reason(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { id: 'did:web:helix.test', 'org.kya-os/cardRef': 'https://cdn.example/card.json' } } }, { fetch: fetchLike }))).toBe('card_mismatch');
    expect(await reason(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', bogus: 1 } } }, { fetch: fetchLike }))).toBe('card_invalid');
  });
});

describe('createSafeFetch', () => {
  const PUBLIC = '93.184.216.34';
  function harness(routes: Record<string, { status: number; headers?: Record<string, string>; body?: string }>, addresses: Record<string, string[]> = { 'helix.test': [PUBLIC] }) {
    const requests: TransportRequest[] = [];
    const lookup = vi.fn(async (hostname: string) => {
      if (!(hostname in addresses)) throw new Error(`ENOTFOUND ${hostname}`);
      return addresses[hostname]!;
    });
    const transport: SafeFetchTransport = vi.fn(async (request: TransportRequest) => {
      requests.push(request);
      const served = routes[request.url] ?? { status: 404 };
      return { status: served.status, headers: served.headers ?? {}, body: new Uint8Array(Buffer.from(served.body ?? '')) };
    });
    return { requests, lookup, transport };
  }

  it('reads, pins, follows same-origin redirects, and refuses everything else', async () => {
    const h = harness({
      'https://helix.test/card.json': { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":1}' },
      'https://helix.test/old': { status: 301, headers: { location: '/card.json' } },
      'https://helix.test/cross': { status: 302, headers: { location: 'https://other.test/' } },
      'https://helix.test/down': { status: 302, headers: { location: 'http://helix.test/' } },
      'https://helix.test/blank': { status: 308 },
      'https://helix.test/bad': { status: 302, headers: { location: 'http://' } },
      'https://helix.test/loop': { status: 302, headers: { location: '/loop' } },
    });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    const response = await safeFetch('https://helix.test/card.json', { headers: { accept: 'application/did+json' } });
    expect(response).toMatchObject({ ok: true, status: 200, url: 'https://helix.test/card.json' });
    expect(await response.json()).toEqual({ ok: 1 });
    expect(await response.text()).toBe('{"ok":1}');
    expect(h.requests[0]).toMatchObject({ address: PUBLIC, headers: { accept: 'application/did+json' } });
    expect((await safeFetch('https://helix.test/old')).url).toBe('https://helix.test/card.json');
    expect((await safeFetch('https://helix.test/missing')).ok).toBe(false);
    expect(await reason(() => safeFetch('https://helix.test/cross'))).toBe('cross_origin_redirect');
    expect(await reason(() => safeFetch('https://helix.test/down'))).toBe('scheme_refused');
    expect(await reason(() => safeFetch('https://helix.test/blank'))).toBe('unavailable');
    expect(await reason(() => safeFetch('https://helix.test/bad'))).toBe('invalid_url');
    expect(await reason(() => safeFetch('https://helix.test/loop'))).toBe('too_many_redirects');
    expect(await reason(() => safeFetch('https://unknown.test/'))).toBe('unresolved');
    expect(await reason(() => createSafeFetch({ lookup: async () => [], transport: h.transport })('https://helix.test/'))).toBe('unresolved');
    expect(await reason(() => createSafeFetch({ lookup: async () => ['10.0.0.1'], transport: h.transport })('https://helix.test/'))).toBe('host_refused');
    expect(await reason(() => createSafeFetch({ lookup: h.lookup, transport: async () => { throw new Error('ECONNRESET'); } })('https://helix.test/'))).toBe('unavailable');
    expect((await createSafeFetch({ lookup: h.lookup, transport: h.transport })(`https://${PUBLIC}/card.json`)).status).toBe(404);
    expect(await reason(() => createSafeFetch({ lookup: h.lookup, transport: h.transport })('https://user:pw@helix.test/'))).toBe('host_refused');
  });

  it('times out, and in development admits http and localhost without a lookup', async () => {
    const slow: SafeFetchTransport = (request) => new Promise((_resolve, reject) => request.signal.addEventListener('abort', () => reject(request.signal.reason)));
    expect(await reason(() => createSafeFetch({ lookup: async () => [PUBLIC], transport: slow, timeoutMs: 20 })('https://helix.test/'))).toBe('deadline_exceeded');
    const h = harness({ 'http://localhost:3000/did.json': { status: 200, body: '{}' } });
    const dev = createSafeFetch({ lookup: h.lookup, transport: h.transport, development: true });
    expect((await dev('http://localhost:3000/did.json')).ok).toBe(true);
    expect(h.lookup).not.toHaveBeenCalled();
    expect(h.requests[0]!.address).toBe('127.0.0.1');
    expect((await createSafeFetch({ lookup: async () => ['10.0.0.1'], transport: h.transport, development: true })('https://internal.test/')).status).toBe(404);
    expect(typeof defaultOutboundFetch()).toBe('function');
    expect(defaultOutboundFetch()).toBe(defaultOutboundFetch());
  });

  it('fetchTransport caps the body and the declared length', async () => {
    const fetchLike = async (url: string): Promise<Response> =>
      url.endsWith('/big') ? new Response('x'.repeat(2 * 1024 * 1024)) : url.endsWith('/declared') ? new Response('s', { headers: { 'content-length': String(2 * 1024 * 1024) } }) : new Response('{"ok":1}', { headers: { 'x-a': 'b' } });
    const safeFetch = createSafeFetch({ lookup: async () => [PUBLIC], transport: fetchTransport(fetchLike) });
    expect(await (await safeFetch('https://helix.test/')).json()).toEqual({ ok: 1 });
    expect(await reason(() => safeFetch('https://helix.test/big'))).toBe('too_large');
    expect(await reason(() => safeFetch('https://helix.test/declared'))).toBe('too_large');
  });

  describe('nodeTransport over a local server', () => {
    let server: Server;
    let origin: string;
    beforeAll(async () => {
      server = createServer((req, res) => {
        if (req.url === '/big') res.writeHead(200).end(Buffer.alloc(2 * 1024 * 1024, 0x41));
        else if (req.url === '/declared') { res.writeHead(200, { 'content-length': String(2 * 1024 * 1024) }); res.write('a'); }
        else if (req.url === '/slow') { /* never answers */ }
        else if (req.url === '/redirect') res.writeHead(302, { location: '/card.json' }).end();
        else res.writeHead(200, { 'content-type': 'application/json', 'x-list': 'a' }).end(JSON.stringify({ path: req.url, host: req.headers.host }));
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    });
    afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

    it('reads, redirects, caps, times out, and pins the connection while the URL keeps its host name', async () => {
      const safeFetch = createSafeFetch({ development: true, timeoutMs: 500 });
      expect(await (await safeFetch(`${origin}/card.json`)).json()).toMatchObject({ path: '/card.json' });
      expect(await (await safeFetch(`${origin}/redirect`)).json()).toMatchObject({ path: '/card.json' });
      expect(await reason(() => safeFetch(`${origin}/big`))).toBe('too_large');
      expect(await reason(() => safeFetch(`${origin}/declared`))).toBe('too_large');
      expect(await reason(() => safeFetch(`${origin}/slow`))).toBe('deadline_exceeded');
      const port = (server.address() as { port: number }).port;
      const pinned = createSafeFetch({ development: true, lookup: async () => ['127.0.0.1'] });
      expect(await (await pinned(`http://pinned.test:${port}/card.json`)).json()).toEqual({ path: '/card.json', host: `pinned.test:${port}` });
      expect(await reason(() => createSafeFetch({ lookup: async () => ['127.0.0.1'] })(`https://pinned.test:${port}/`))).toBe('host_refused');
    });
  });
});
