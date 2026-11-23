// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: the middleware serves the service's own did.json and card.json from its origin
// and projects a claim-minimal summary into server.json _meta["org.kya-os/card"] with a cardRef.
import { createServer, type Server } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { validateEntityCard } from '@helixid/sdk-js';
import { resolveServerCard, serveIdentity } from '../src/identity.js';

const JWK = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'JUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0' };

const serving = (map: Record<string, unknown>) => vi.fn(async (url: string) => (map[url] === undefined ? new Response('no', { status: 404 }) : new Response(JSON.stringify(map[url]), { status: 200 })));

describe('serveIdentity', () => {
  it('derives the did:web from the public origin and path, builds both documents, and anchors the card', () => {
    const identity = serveIdentity({
      publicOrigin: 'https://mcp.example.com',
      path: '/mcp',
      card: { name: 'Orders', kid: 'key-1', publicKeyJwk: JWK, capabilities: ['tools/list', 'tools/call'], responsibleParty: 'did:web:example.com:org:acme' },
      alsoKnownAs: ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'],
      service: [{ id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://example.com' }],
    });
    expect(identity.did).toBe('did:web:mcp.example.com:mcp');
    expect(identity.paths).toEqual({ didDocument: '/mcp/did.json', card: '/mcp/card.json' });
    expect(identity.didDocumentUrl).toBe('https://mcp.example.com/mcp/did.json');
    expect(identity.cardUrl).toBe('https://mcp.example.com/mcp/card.json');
    expect(identity.didDocument).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      id: 'did:web:mcp.example.com:mcp',
      alsoKnownAs: ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'],
      verificationMethod: [{ id: 'did:web:mcp.example.com:mcp#key-1', type: 'Ed25519VerificationKey2020', controller: 'did:web:mcp.example.com:mcp', publicKeyJwk: JWK }],
      authentication: ['did:web:mcp.example.com:mcp#key-1'],
      assertionMethod: ['did:web:mcp.example.com:mcp#key-1'],
      service: [
        { id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://example.com' },
        { id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://mcp.example.com/mcp/card.json' },
      ],
    });
    expect(validateEntityCard(identity.card)).toEqual([]);
    expect(identity.card).toEqual({
      id: 'did:web:mcp.example.com:mcp',
      entityType: 'mcp',
      name: 'Orders',
      kid: 'did:web:mcp.example.com:mcp#key-1',
      publicKeyJwk: { ...JWK, kid: 'did:web:mcp.example.com:mcp#key-1' },
      capabilities: ['tools/list', 'tools/call'],
      responsibleParty: 'did:web:example.com:org:acme',
      didDocument: 'https://mcp.example.com/mcp/did.json',
      proofProfile: 'org.kya-os/proof.v1',
    });
    expect(identity.serverMeta()).toEqual({
      'org.kya-os/card': { id: 'did:web:mcp.example.com:mcp', entityType: 'mcp', name: 'Orders', capabilities: ['tools/list', 'tools/call'], responsibleParty: 'did:web:example.com:org:acme', proofProfile: 'org.kya-os/proof.v1', 'org.kya-os/cardRef': 'https://mcp.example.com/mcp/card.json' },
    });
    expect(identity.serverMeta({ byRef: true })).toEqual({ 'org.kya-os/card': { 'org.kya-os/cardRef': 'https://mcp.example.com/mcp/card.json' } });
    expect(identity.projectServerJson({ name: 'orders', _meta: { 'modelcontextprotocol/mcp': { x: 1 } } })).toEqual({ name: 'orders', _meta: { 'modelcontextprotocol/mcp': { x: 1 }, ...identity.serverMeta() } });
    expect(identity.projectServerJson({ name: 'orders' })._meta).toEqual(identity.serverMeta());
  });

  it('a root origin is a bare did:web served at the well-known paths; the path comes from the origin when not given; a key-less card has no methods', () => {
    const root = serveIdentity({ publicOrigin: 'https://mcp.example.com/', card: { name: 'Root' } });
    expect(root.did).toBe('did:web:mcp.example.com');
    expect(root.paths).toEqual({ didDocument: '/.well-known/did.json', card: '/.well-known/kya-os-card.json' });
    expect(root.cardUrl).toBe('https://mcp.example.com/.well-known/kya-os-card.json');
    expect(root.didDocument).toMatchObject({ verificationMethod: [], authentication: [], assertionMethod: [] });
    expect(serveIdentity({ publicOrigin: 'https://mcp.example.com/api/v2' }).did).toBe('did:web:mcp.example.com:api:v2');
    expect(serveIdentity({ publicOrigin: 'https://mcp.example.com/api/v2' }).card.name).toBe('did:web:mcp.example.com:api:v2');
  });

  it('behind a local http origin the documents name the origin they are reachable at', () => {
    const local = serveIdentity({ publicOrigin: 'http://127.0.0.1:3794', path: '/mcp', card: { name: 'Local' } });
    expect(local.did).toBe('did:web:127.0.0.1%3A3794:mcp');
    expect(local.didDocumentUrl).toBe('http://127.0.0.1:3794/mcp/did.json');
    expect(local.cardUrl).toBe('http://127.0.0.1:3794/mcp/card.json');
    expect(local.card.didDocument).toBe('http://127.0.0.1:3794/mcp/did.json');
    expect(local.didDocument['service']).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'http://127.0.0.1:3794/mcp/card.json' }]);
    const named = serveIdentity({ publicOrigin: 'https://proxy.example.com', path: '/mcp', did: 'did:web:orders.example', card: { name: 'Named' } });
    expect(named.did).toBe('did:web:orders.example');
    expect(named.paths).toEqual({ didDocument: '/.well-known/did.json', card: '/.well-known/kya-os-card.json' });
    expect(named.cardUrl).toBe('https://proxy.example.com/.well-known/kya-os-card.json');
  });

  it('serves documents helix init wrote as they are, and refuses ones for another DID or an invalid card', () => {
    const didDocument = { id: 'did:web:mcp.example.com:mcp', verificationMethod: [], service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://mcp.example.com/mcp/card.json' }] };
    const card = { id: 'did:web:mcp.example.com:mcp', entityType: 'mcp', name: 'Written', proofProfile: 'org.kya-os/proof.v1' };
    const identity = serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', documents: { didDocument, card } });
    expect(identity.didDocument).toBe(didDocument);
    expect(identity.card).toBe(card);
    expect(() => serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', documents: { didDocument: { ...didDocument, id: 'did:web:other' }, card } })).toThrow(/DID document is for/);
    expect(() => serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', documents: { didDocument, card: { ...card, id: 'did:web:other' } } })).toThrow(/card is for/);
    expect(() => serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', documents: { didDocument, card: { ...card, bogusField: 1 } } })).toThrow(/bogusField/);
    expect(() => serveIdentity({ publicOrigin: 'not a url' })).toThrow(/absolute URL/);
    expect(() => serveIdentity({ publicOrigin: 'ftp://mcp.example.com' })).toThrow(/http\(s\) origin/);
    expect(() => serveIdentity({ publicOrigin: 'https://mcp.example.com', did: 'did:key:z6Mk' })).toThrow(/did:web/);
    expect(() => serveIdentity({ publicOrigin: 'http://localhost:3000', did: 'did:web:localhost:3000:mcp' }), 'a raw port names another URL').toThrow(/unencoded port/);
    expect(serveIdentity({ publicOrigin: 'http://localhost:3000', path: '/mcp' }).did, 'the origin port is encoded once').toBe('did:web:localhost%3A3000:mcp');
    expect(() => serveIdentity({ publicOrigin: 'https://mcp.example.com', card: { name: 'X', proof: {} } as never })).toThrow(/proof/);
  });

  it('handle answers the two paths over node:http with JSON and nothing else', async () => {
    const identity = serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', card: { name: 'Orders' } });
    const server: Server = createServer((req, res) => {
      if (identity.handle(new URL(req.url ?? '/', 'http://x').pathname, res)) return;
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const did = await fetch(`${base}/mcp/did.json`);
      expect(did.status).toBe(200);
      expect(did.headers.get('content-type')).toBe('application/json');
      expect(did.headers.get('cache-control')).toBe('public, max-age=300');
      expect(await did.json()).toEqual(identity.didDocument);
      expect(await (await fetch(`${base}/mcp/card.json`)).json()).toEqual(identity.card);
      expect((await fetch(`${base}/mcp/other.json`)).status).toBe(404);
      expect((await fetch(`${base}/.well-known/did.json`)).status).toBe(404);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe('resolveServerCard', () => {
  const identity = serveIdentity({ publicOrigin: 'https://mcp.example.com', path: '/mcp', card: { name: 'Orders', capabilities: ['tools/call'] } });
  const served = { [identity.didDocumentUrl]: identity.didDocument, [identity.cardUrl]: identity.card };

  it('dereferences the projection to the canonical card, and a stripped projection falls back to the DID', async () => {
    const projected = identity.projectServerJson({ name: 'orders' });
    const viaMeta = await resolveServerCard(projected, { fetch: serving(served) });
    expect(viaMeta.card).toEqual(identity.card);
    expect(viaMeta.cardUrl).toBe(identity.cardUrl);
    const fetchLike = serving(served);
    const stripped = await resolveServerCard({ name: 'orders', _meta: { 'modelcontextprotocol/mcp': {} } }, { fetch: fetchLike, did: identity.did });
    expect(stripped.card).toEqual(identity.card);
    expect(fetchLike.mock.calls.map((call) => call[0])).toEqual([identity.didDocumentUrl, identity.cardUrl]);
    expect((await resolveServerCard(undefined, { fetch: serving(served), did: identity.did })).card).toEqual(identity.card);
    await expect(resolveServerCard({ name: 'orders' }, { fetch: serving(served) })).rejects.toMatchObject({ reason: 'no_projection' });
  });
});
