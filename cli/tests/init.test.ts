// KYA-OS story F-3: `helix init`, `helix activate` and `helix custody take` against a local stand-in for the Helix API and an owner's domain.
process.env['HELIX_OUTBOUND_DEVELOPMENT'] = '1';

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed25519 from '@noble/ed25519';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createProgram } from '../src/cli.js';

let server: Server;
let origin: string;
let host: string;
const requests: { method: string; path: string; body: string }[] = [];
const published = new Map<string, unknown>();
let mode: { didHosting: 'helix' | 'own'; did: string; vcId?: boolean; hopsDone?: boolean } = { didHosting: 'helix', did: '' };

function documents(did: string, kid: string, x: string, base: string) {
  return {
    didDocument: { id: did, verificationMethod: [{ id: kid, type: 'Ed25519VerificationKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x } }], service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: `${base}/card.json` }] },
    card: { id: did, entityType: 'agent', name: 'Bot', kid, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x, kid }, proofProfile: 'org.kya-os/proof.v1', didDocument: `${base}/did.json` },
    didDocumentUrl: `${base}/did.json`,
    cardUrl: `${base}/card.json`,
  };
}

beforeAll(async () => {
  server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => (body += chunk));
    request.on('end', () => {
      const path = decodeURIComponent(new URL(request.url ?? '/', 'http://x').pathname);
      requests.push({ method: request.method ?? '', path, body });
      const send = (status: number, value: unknown) => {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      const did = mode.did;
      const kid = `${did}#key-1`;
      const base = `${origin}/agents/bot`;
      if (published.has(path)) return send(200, published.get(path));
      if (path === '/v1/agents/enroll/challenge') return send(200, { did, kid, nonce: 'ab'.repeat(32), keyCustody: 'self', didHosting: mode.didHosting, name: 'Bot', didDocumentUrl: `${base}/did.json`, cardUrl: `${base}/card.json` });
      if (path === '/v1/agents/enroll') {
        const parsed = JSON.parse(body) as { publicKeyJwk: { x: string } };
        const status = mode.didHosting === 'helix' ? 'active' : 'pending_resolution';
        return send(201, { did, kid, keyCustody: 'self', didHosting: mode.didHosting, label: 'custody: self', status, documents: documents(did, kid, parsed.publicKeyJwk.x, base), ...(mode.vcId ? { vcId: 'vc:init' } : {}) });
      }
      if (path === `/v1/agents/${did}/activate`) {
        // F-3 parity: the card comes back with the agent's attestations, for the owner to republish.
        return send(200, { did, status: 'active', vcId: 'vc:cli', documents: { card: { id: did, entityType: 'agent', name: 'Bot', capabilities: [{ name: 'orders:read', attestations: [{ vc: { id: 'att:cli' } }] }] }, didDocumentUrl: `${base}/did.json`, cardUrl: `${base}/card.json` } });
      }
      if (path === `/v1/agents/${did}/custody` || path === `/v1/services/${did}/custody`) {
        const parsed = JSON.parse(body) as { kid: string; publicKeyJwk: { x: string } };
        return send(200, { did, keyCustody: 'self', didHosting: 'helix', label: 'custody: self', kid: `${did}#${parsed.kid}`, previousKid: kid, previousKeyShredded: !mode.hopsDone, retiresAt: '2026-11-22T00:00:00.000Z', hopReissue: mode.hopsDone ? { reissued: 1, pending: false } : { reissued: 0, pending: true, ...(mode.vcId ? {} : { note: 'story C-E' }) }, publishRequired: mode.didHosting === 'own', documents: documents(did, `${did}#${parsed.kid}`, parsed.publicKeyJwk.x, base) });
      }
      return send(404, { error: { code: 'NOT_FOUND', message: path } });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${port}`;
  host = `127.0.0.1%3A${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let out: string;
let stdout: string[];
beforeEach(async () => {
  out = await mkdtemp(join(tmpdir(), 'helix-init-'));
  stdout = [];
  requests.length = 0;
  published.clear();
  vi.spyOn(console, 'log').mockImplementation((...args) => void stdout.push(args.join(' ')));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(out, { recursive: true, force: true });
});

async function run(...args: string[]): Promise<void> {
  await createProgram().exitOverride().parseAsync(['node', 'helix', ...args]);
}

function seedFrom(envFile: string): string {
  return /HELIX_SIGNING_KEY=([0-9a-f]{64})/.exec(envFile)![1]!;
}

describe('helix init', () => {
  it('Helix hosting: enrolls with only the public key, writes the four files, and reports active', async () => {
    mode = { didHosting: 'helix', did: `did:web:${host}:acme:bot` };
    await run('init', '--token', 'enroll:t', '--out', out, '--api-url', origin);
    const seed = seedFrom(await readFile(join(out, 'signing-key.env'), 'utf8'));
    for (const request of requests) {
      expect(request.body).not.toContain(seed);
      expect(request.body).not.toContain(Buffer.from(seed, 'hex').toString('base64url'));
    }
    const enroll = JSON.parse(requests.find((request) => request.path === '/v1/agents/enroll')!.body);
    expect(Object.keys(enroll).sort()).toEqual(['enrollmentToken', 'kid', 'publicKeyJwk', 'signature']);
    expect(enroll.publicKeyJwk.x).toBe(Buffer.from(ed25519.getPublicKey(Buffer.from(seed, 'hex'))).toString('base64url'));
    expect(JSON.parse(await readFile(join(out, 'did.json'), 'utf8')).id).toBe(mode.did);
    expect(stdout.join('\n')).toMatch(/active/);
    expect(stdout.join('\n')).toMatch(/custody: self/);
  });

  it('own hosting: pending until published, then helix activate checks the domain and activates', async () => {
    mode = { didHosting: 'own', did: `did:web:${host}:agents:bot` };
    await run('init', '--token', 'enroll:t', '--out', out, '--api-url', origin, '--did', mode.did);
    expect(stdout.join('\n')).toMatch(/Publish the two documents on your domain/);
    expect(stdout.join('\n')).toMatch(/Helix activates the agent once both resolve/);
    expect(stdout.join('\n')).not.toMatch(/then activate/);
    expect(requests.some((request) => request.path.endsWith('/activate'))).toBe(false);
    published.set('/agents/bot/did.json', JSON.parse(await readFile(join(out, 'did.json'), 'utf8')));
    published.set('/agents/bot/card.json', JSON.parse(await readFile(join(out, 'card.json'), 'utf8')));
    await run('activate', '--token', 'enroll:t', '--out', out, '--api-url', origin);
    expect(requests.some((request) => request.path.endsWith('/activate'))).toBe(true);
    expect(stdout.join('\n')).toMatch(/Agent active/);
    expect(stdout.join('\n')).toMatch(/card\.json now carries the attestations Helix issued; republish it/);
    expect(JSON.parse(await readFile(join(out, 'card.json'), 'utf8')).capabilities).toEqual([{ name: 'orders:read', attestations: [{ vc: { id: 'att:cli' } }] }]);
  });

  it('own hosting with --no-activate, and activate while still unpublished', async () => {
    mode = { didHosting: 'own', did: `did:web:${host}:agents:bot` };
    await run('init', '--token', 'enroll:t', '--out', out, '--api-url', origin, '--no-activate', '--kid', 'key-1', '--env-var', 'HELIX_SIGNING_KEY');
    await run('activate', '--token', 'enroll:t', '--out', out, '--api-url', origin);
    expect(stdout.join('\n')).toMatch(/Not active yet/);
  });
});

describe('helix custody take', () => {
  it('generates the new key here and sends only its public half and a proof', async () => {
    mode = { didHosting: 'own', did: `did:web:${host}:acme:bot` };
    await run('custody', 'take', '--did', mode.did, '--out', out, '--api-url', origin, '--admin-key', 'admin', '--overlap', '60');
    const seed = seedFrom(await readFile(join(out, 'signing-key.env'), 'utf8'));
    const change = requests.find((request) => request.path.endsWith('/custody'))!;
    expect(change.body).not.toContain(seed);
    expect(Object.keys(JSON.parse(change.body)).sort()).toEqual(['keyCustody', 'kid', 'overlapSeconds', 'proof', 'publicKeyJwk']);
    expect(stdout.join('\n')).toMatch(/now custody: self/);
    expect(stdout.join('\n')).toMatch(/shredded in Helix/);
    expect(stdout.join('\n')).toMatch(/not reissued/);
    expect(stdout.join('\n')).toMatch(/Publish the updated/);
  });
});

describe('helix CLI custody, the other branches', () => {
  it('reports the credential when Helix issues one at enrollment', async () => {
    mode = { didHosting: 'helix', did: `did:web:${host}:acme:bot`, vcId: true };
    const { runInit } = await import('../src/commands/init.js');
    const result = await runInit({ token: 'enroll:t', out, apiUrl: origin });
    expect(result.vcId).toBe('vc:init');
    expect(stdout.join('\n')).toMatch(/Credential: vc:init/);
  });

  it('own hosting that never resolves says why', async () => {
    mode = { didHosting: 'own', did: `did:web:${host}:agents:bot` };
    const { runInit } = await import('../src/commands/init.js');
    await runInit({ token: 'enroll:t', out, apiUrl: origin, did: mode.did });
    expect(stdout.join('\n')).toMatch(/not resolving yet/);
  });

  it('custody take for a service, without an overlap, with hops reissued and nothing to publish', async () => {
    mode = { didHosting: 'helix', did: `did:web:${host}:acme:svc`, hopsDone: true };
    const { runCustodyTake } = await import('../src/commands/init.js');
    await runCustodyTake({ did: mode.did, out, apiUrl: origin, apiKey: 'acc', subject: 'service' });
    const text = stdout.join('\n');
    expect(text).not.toMatch(/shredded in Helix/);
    expect(text).not.toMatch(/not reissued/);
    expect(text).not.toMatch(/Publish the updated/);
    mode = { didHosting: 'helix', did: `did:web:${host}:acme:bot`, vcId: true };
    await runCustodyTake({ did: mode.did, out, apiUrl: origin });
    expect(stdout.join('\n')).toMatch(/not reissued \(story C-E\)/);
  });
});
