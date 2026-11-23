// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story L3-C in the middleware: signed status lists read through the local verifier, the shared status
// cache (two instances, one store), the revocation signal over SSE and webhook push, and the resolution fetch guard.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import { MemoryNonceStore } from '../src/kyaos/nonce-store.js';
import { RedisStatusCacheStore } from '../src/kyaos/status-cache-store.js';
import { RevocationSignalClient, SseParser, createRevocationSignalClient, type SignalReport } from '../src/revocation-signals.js';
import { ResolutionRefusedError, createResolutionFetch, isPublicUnicastAddress, resolutionTarget } from '../src/resolution-fetch.js';
import { createLocalVerifier, type LocalVerifier } from '../src/verify-locally.js';
import { NOW_MS, fixtureSigner, haveVerifierFixtures, loadCases, loadEnvironment, proofMeta, type FixtureEnvironment } from './proof-helpers.js';
import { encodedBits, signList } from './revocation-helpers.js';

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** The Helix side of the fixture world: every fixture status list, signed by its issuer's TEST-ONLY key, with bits that can be set. */
class FixtureLists {
  readonly revoked = new Map<string, number[]>();
  readonly asked: string[] = [];
  constructor(private readonly env: FixtureEnvironment) {}

  #signed(url: string): Record<string, unknown> | undefined {
    const list = this.env.status_lists[url];
    if (list?.issuer === undefined) return undefined;
    const key = Object.values(this.env.keys).find((entry) => entry.did === list.issuer)!;
    return signList(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: list.id,
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        issuer: list.issuer,
        validFrom: list.valid_from,
        validUntil: list.valid_until,
        credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: list.status_purpose, encodedList: encodedBits(16, this.revoked.get(url) ?? []) },
      },
      key.private_key_hex,
      `${list.issuer}#key-1`,
    );
  }

  revoke(url: string, index: number): void {
    this.revoked.set(url, [...(this.revoked.get(url) ?? []), index]);
  }

  readonly fetch = async (url: string): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> => {
    this.asked.push(url);
    const body = this.#signed(url);
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => body };
  };
}

describe.skipIf(!haveVerifierFixtures)('revocation through the local verifier (story L3-C)', () => {
  const env = haveVerifierFixtures ? loadEnvironment() : (undefined as never);
  const valid = haveVerifierFixtures ? loadCases('valid').find((entry) => entry.name === 'two_hop_chain')! : (undefined as never);
  const service = haveVerifierFixtures ? env.keys['service']!.did : '';
  const call = { name: 'lookup_order', input: { orderId: 'ORD-1001' } };
  const chain = haveVerifierFixtures ? (valid.input.chain as Array<{ id: string; credentialStatus: { statusListCredential: string; statusListIndex: string } }>) : [];
  const helix = haveVerifierFixtures ? fixtureSigner(env, 'helix') : (undefined as never);
  // The fixture world's DID documents (each lists its key as #key-1), the resolution the verifier and the signal check share.
  const resolveDid: kyaos.verifier.DidResolver = async (did) => (haveVerifierFixtures ? (env.did_documents[did] as never) : undefined) ?? null;

  function instance(lists: FixtureLists, store: kyaos.verifier.StatusCacheStore, clock: () => number, options: Partial<Parameters<typeof createLocalVerifier>[0]> = {}): LocalVerifier {
    return createLocalVerifier({
      serviceDid: service,
      fetch: lists.fetch,
      resolveDid,
      cards: { [env.keys['agent']!.did]: env.cards['attested'] },
      statusCache: { store, statusCacheTtl: 120, clock },
      nonceStore: new MemoryNonceStore({ now: clock }),
      clock,
      reportVerification: () => undefined,
      ...options,
    });
  }

  const present = async (verifier: LocalVerifier, now: number): Promise<kyaos.verifier.VerifierResult> =>
    (await verifier.verifyCall({ ...call, _meta: await proofMeta(fixtureSigner(env, 'agent'), service, call, chain, { now }) }))!;

  it('verifies every list proof live (L3, fresh), then serves the second instance from the shared cache (L2, not fresh)', async () => {
    const lists = new FixtureLists(env);
    const store = new kyaos.verifier.MemoryStatusCacheStore({ now: () => NOW_MS });
    const a = instance(lists, store, () => NOW_MS);
    const b = instance(lists, store, () => NOW_MS);
    expect(await present(a, NOW_MS)).toMatchObject({ ok: true, level: 'L3', fresh: true });
    const asked = lists.asked.length;
    expect(await present(b, NOW_MS)).toMatchObject({ ok: true, level: 'L2', fresh: false });
    expect(lists.asked.length).toBe(asked);
  });

  it('revoke a parent hop: the call is refused once the signal reaches one instance, on both instances sharing the cache', async () => {
    const lists = new FixtureLists(env);
    const store = new kyaos.verifier.MemoryStatusCacheStore({ now: () => NOW_MS });
    const a = instance(lists, store, () => NOW_MS);
    const b = instance(lists, store, () => NOW_MS);
    expect((await present(a, NOW_MS)).ok).toBe(true);
    expect((await present(b, NOW_MS)).ok).toBe(true);
    // Helix revokes the root hop (the child's parent): its bit flips on the owner's list.
    const root = chain[0]!;
    lists.revoke(root.credentialStatus.statusListCredential, Number(root.credentialStatus.statusListIndex));
    // Inside the TTL, with no signal yet, both still read the cached verdict.
    expect((await present(a, NOW_MS)).ok).toBe(true);
    const reports: SignalReport[] = [];
    const client = createRevocationSignalClient(a, { trustedIssuers: [helix.did], resolveDid, onSignal: (report) => void reports.push(report), clock: () => NOW_MS });
    const set = await kyaos.verifier.signRevocationSignal({ credentialId: root.id, iat: NOW_MS / 1000 }, helix);
    expect(await client.handle(set)).toEqual({ accepted: true, credentialId: root.id, invalidated: 'credential' });
    expect(reports[0]).toMatchObject({ accepted: true, credentialId: root.id, via: 'sse', issuer: helix.did });
    expect(client.hasSeen(JSON.parse(Buffer.from(set.split('.')[1]!, 'base64url').toString()).jti)).toBe(true);
    // The signal reached instance A only; B shares the store, so both refuse.
    expect(await present(a, NOW_MS)).toMatchObject({ ok: false, reasons: ['status_revoked'] });
    expect(await present(b, NOW_MS)).toMatchObject({ ok: false, reasons: ['status_revoked'] });
  });

  it('with the signal channel down, a revoked hop is refused no later than statusCacheTtl', async () => {
    const lists = new FixtureLists(env);
    let now = NOW_MS;
    const store = new kyaos.verifier.MemoryStatusCacheStore({ now: () => now });
    const a = instance(lists, store, () => now);
    expect((await present(a, now)).ok).toBe(true);
    const leaf = chain[1]!;
    lists.revoke(leaf.credentialStatus.statusListCredential, Number(leaf.credentialStatus.statusListIndex));
    now += 60_000;
    expect((await present(a, now)).ok).toBe(true);
    now += 61_000;
    expect(await present(a, now)).toMatchObject({ ok: false, reasons: ['status_revoked'] });
  });

  it('a signal with a bad signature or from an unknown issuer is ignored and reported; it revokes nothing', async () => {
    const lists = new FixtureLists(env);
    const store = new kyaos.verifier.MemoryStatusCacheStore({ now: () => NOW_MS });
    const a = instance(lists, store, () => NOW_MS);
    expect((await present(a, NOW_MS)).ok).toBe(true);
    const log = vi.fn();
    const client = createRevocationSignalClient(a, { trustedIssuers: [helix.did], log, clock: () => NOW_MS });
    const stranger = fixtureSigner(env, 'stranger');
    const foreign = await kyaos.verifier.signRevocationSignal({ credentialId: chain[0]!.id, iat: NOW_MS / 1000 }, stranger);
    expect(await client.handle(foreign, 'webhook')).toMatchObject({ accepted: false, reason: 'signal_unknown_issuer' });
    const forged = await kyaos.verifier.signRevocationSignal({ credentialId: chain[0]!.id, iat: NOW_MS / 1000 }, { did: helix.did, kid: helix.kid, sign: (data: Uint8Array) => stranger.sign(data) });
    expect(await client.handle(forged)).toMatchObject({ accepted: false, reason: 'signal_bad_signature' });
    expect(log).toHaveBeenCalledTimes(2);
    expect(log.mock.calls[0]![0]).toMatch(/ignored \(webhook\): signal_unknown_issuer/);
    // The cached verdict is untouched: the next call is still served from the cache.
    expect(await present(a, NOW_MS)).toMatchObject({ ok: true, fresh: false });
  });

  it('reports a cache that cannot be reached, and a report hook that throws never blocks', async () => {
    const failing = new RevocationSignalClient({
      trustedIssuers: [helix.did],
      resolveDid,
      cache: {
        invalidate: async () => {
          throw new Error('redis down');
        },
      },
      onSignal: () => {
        throw new Error('report hook down');
      },
      clock: () => NOW_MS,
    });
    const set = await kyaos.verifier.signRevocationSignal({ credentialId: 'urn:uuid:x', iat: NOW_MS / 1000 }, helix);
    expect(await failing.handle(set)).toEqual({ accepted: false, reason: 'cache_unavailable', message: 'redis down' });
    expect(() => new RevocationSignalClient({ trustedIssuers: [], resolveDid: async () => null, cache: { invalidate: async () => 'all-lists' } })).toThrow(/trustedIssuers/);
    expect(() => failing.start()).toThrow(/eventsUrl/);
    expect(() => createRevocationSignalClient({ seams: {}, statusCache: new kyaos.verifier.StatusCache() }, { trustedIssuers: [helix.did] })).toThrow(/resolveDid/);
  });

  it('receives SETs pushed to its webhook (RFC 8935): 202, or 400 with err', async () => {
    const lists = new FixtureLists(env);
    const a = instance(lists, new kyaos.verifier.MemoryStatusCacheStore(), () => NOW_MS);
    const client = createRevocationSignalClient(a, { trustedIssuers: [helix.did], log: () => undefined, clock: () => NOW_MS });
    const url = await listen((req, res) => void client.webhookHandler()(req, res));
    const post = (body: string, type = 'application/secevent+jwt'): Promise<Response> => fetch(url, { method: 'POST', headers: { 'content-type': type }, body });
    const set = await kyaos.verifier.signRevocationSignal({ credentialId: chain[0]!.id, iat: NOW_MS / 1000 }, helix);
    expect((await post(set)).status).toBe(202);
    const foreign = await kyaos.verifier.signRevocationSignal({ credentialId: 'x', iat: NOW_MS / 1000 }, fixtureSigner(env, 'stranger'));
    const refused = await post(foreign);
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ err: 'invalid_issuer' });
    expect(await (await post('not.a.set')).json()).toMatchObject({ err: 'invalid_request' });
    expect((await post(set, 'application/json')).status).toBe(415);
    expect((await fetch(url)).status).toBe(405);
    expect((await post('x'.repeat(70 * 1024)).catch(() => ({ status: 400 }))).status).toBe(400);
    const down = new RevocationSignalClient({ trustedIssuers: [helix.did], resolveDid, cache: { invalidate: async () => Promise.reject(new Error('down')) }, log: () => undefined, clock: () => NOW_MS });
    const downUrl = await listen((req, res) => void down.webhookHandler()(req, res));
    expect((await fetch(downUrl, { method: 'POST', headers: { 'content-type': 'application/secevent+jwt; charset=utf-8' }, body: set })).status).toBe(503);
  });

  it('keeps one SSE connection open, invalidates on each event, and reconnects with Last-Event-ID after a drop', async () => {
    const lists = new FixtureLists(env);
    const a = instance(lists, new kyaos.verifier.MemoryStatusCacheStore(), () => NOW_MS);
    const first = await kyaos.verifier.signRevocationSignal({ credentialId: 'urn:uuid:first', iat: NOW_MS / 1000, jti: 'j1' }, helix);
    const second = await kyaos.verifier.signRevocationSignal({ credentialId: 'urn:uuid:second', iat: NOW_MS / 1000, jti: 'j2' }, helix);
    const lastEventIds: Array<string | undefined> = [];
    let connections = 0;
    const url = await listen((req, res) => {
      connections += 1;
      lastEventIds.push(req.headers['last-event-id'] as string | undefined);
      if (connections === 1) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(': keep-alive\n\nretry: 10\n');
        res.end(`id: 1\nevent: revocation\ndata: ${first}\n\nevent: other\ndata: ignored\n\n`);
        return;
      }
      if (connections === 2) {
        res.writeHead(503);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' });
      res.write(`id: 2\r\nevent: revocation\r\ndata: ${second}\r\n\r\n`);
    });
    const reports: SignalReport[] = [];
    const states: boolean[] = [];
    const client = createRevocationSignalClient(a, {
      eventsUrl: `${url}/v1/events/revocations`,
      trustedIssuers: [helix.did],
      reconnectDelayMs: 5,
      maxReconnectDelayMs: 20,
      onSignal: (report) => void reports.push(report),
      onConnectionChange: (connected) => void states.push(connected),
      headers: { 'x-api-key': 'k' },
      clock: () => NOW_MS,
    });
    client.start();
    client.start();
    await vi.waitFor(() => expect(reports.map((report) => report.credentialId)).toEqual(['urn:uuid:first', 'urn:uuid:second']), { timeout: 3000 });
    expect(client.connected).toBe(true);
    expect(client.lastEventId).toBe('2');
    expect(lastEventIds.slice(0, 3)).toEqual([undefined, '1', '1']);
    await client.stop();
    expect(client.connected).toBe(false);
    expect(states).toContain(true);
    expect(states[states.length - 1]).toBe(false);
  });

  it('logs ignored signals to the console by default, bounds what it remembers, and refuses an answer with no content type', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const quiet = new RevocationSignalClient({ trustedIssuers: [helix.did], resolveDid, cache: { invalidate: async () => 'credential' }, clock: () => NOW_MS });
    expect(await quiet.handle('not.a.set', 'webhook')).toMatchObject({ accepted: false, reason: 'signal_malformed' });
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/revocation signal ignored \(webhook\): signal_malformed/));
    warn.mockRestore();
    for (let index = 0; index < 1002; index += 1) {
      const set = await kyaos.verifier.signRevocationSignal({ credentialId: `urn:uuid:${index}`, iat: NOW_MS / 1000, jti: `j-${index}` }, helix);
      await quiet.handle(set);
    }
    expect(quiet.hasSeen('j-0')).toBe(false);
    expect(quiet.hasSeen('j-1001')).toBe(true);
    let calls = 0;
    const url = await listen((_req, res) => {
      calls += 1;
      res.writeHead(200);
      res.end();
    });
    const errors: unknown[] = [];
    const client = new RevocationSignalClient({ eventsUrl: url, trustedIssuers: [helix.did], resolveDid, cache: { invalidate: async () => 'credential' }, onConnectionChange: (_c, error) => void errors.push(error) });
    client.start();
    await vi.waitFor(() => expect(calls).toBeGreaterThanOrEqual(1), { timeout: 3000 });
    await client.stop();
    expect(String(errors.find((error) => error !== undefined))).toMatch(/no content type/);
  }, 20_000);

  it('refuses a non-SSE answer and keeps retrying until stopped', async () => {
    const a = instance(new FixtureLists(env), new kyaos.verifier.MemoryStatusCacheStore(), () => NOW_MS);
    let calls = 0;
    const url = await listen((_req, res) => {
      calls += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    const errors: unknown[] = [];
    const client = createRevocationSignalClient(a, { eventsUrl: url, trustedIssuers: [helix.did], reconnectDelayMs: 5, onConnectionChange: (_c, error) => void errors.push(error) });
    client.start();
    await vi.waitFor(() => expect(calls).toBeGreaterThanOrEqual(2), { timeout: 3000 });
    await client.stop();
    expect(String(errors.find((error) => error !== undefined))).toMatch(/not text\/event-stream/);
  });
});

describe('SseParser', () => {
  it('dispatches events per the WHATWG rules', async () => {
    const events: unknown[] = [];
    const parser = new SseParser((event) => void events.push(event));
    await parser.push('data: a\ndata: b\n\n');
    await parser.push('id: 7\nevent: x\ndata\n\r');
    await parser.push('\n');
    await parser.push('id: a\0b\nretry: nope\nretry: 25\nfield-without-colon\n\nevent: dropped\n\n');
    expect(events).toEqual([
      { id: undefined, event: 'message', data: 'a\nb' },
      { id: '7', event: 'x', data: '' },
    ]);
    expect(parser.retry).toBe(25);
  });
});

describe('RedisStatusCacheStore', () => {
  it('speaks GET, SET PX, DEL and INCR', async () => {
    const data = new Map<string, string>();
    const calls: unknown[][] = [];
    const client = {
      get: async (key: string) => data.get(key) ?? null,
      set: async (key: string, value: string, px: 'PX', ms: number) => {
        calls.push(['set', key, px, ms]);
        data.set(key, value);
        return 'OK';
      },
      del: async (key: string) => (data.delete(key) ? 1 : 0),
      incr: async (key: string) => {
        const next = Number(data.get(key) ?? 0) + 1;
        data.set(key, String(next));
        return next;
      },
    };
    const store = new RedisStatusCacheStore({ client });
    await store.set('k', 'v', 0.4);
    expect(calls[0]).toEqual(['set', 'k', 'PX', 1]);
    expect(await store.get('k')).toBe('v');
    expect(await store.get('missing')).toBeUndefined();
    await store.delete('k');
    expect(await store.get('k')).toBeUndefined();
    expect(await store.increment('g')).toBe(1);
    expect(await store.increment('g')).toBe(2);
  });
});

describe('resolution fetch (the SafeFetch rules without DNS pinning)', () => {
  it('knows public unicast from everything else', () => {
    for (const address of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.1', '172.16.0.1', '100.64.0.1', '::1', 'fe80::1', 'fc00::1', '::ffff:10.0.0.1', '::ffff:a00:1', '0.0.0.0', 'not-an-ip']) {
      expect(isPublicUnicastAddress(address), address).toBe(false);
    }
    for (const address of ['8.8.8.8', '2606:4700::1111', '::ffff:8.8.8.8', '::ffff:808:808']) expect(isPublicUnicastAddress(address), address).toBe(true);
    expect(isPublicUnicastAddress('::ffff:zz:1')).toBe(false);
  });

  it('refuses http, credentials, loopback outside development and private IP literals', () => {
    const refused = (url: string, development = false): void => expect(() => resolutionTarget(url, development), url).toThrow(ResolutionRefusedError);
    refused('http://example.com/l');
    refused('ftp://example.com/l');
    refused('not a url');
    refused('https://user:pw@example.com/l');
    refused('https://127.0.0.1/l');
    refused('https://10.0.0.1/l', true);
    refused('https://[fd00::1]/l', true);
    refused('http://10.0.0.1/l', true);
    expect(resolutionTarget('https://127.0.0.1:4000/l', true).toString()).toBe('http://127.0.0.1:4000/l');
    expect(resolutionTarget('http://localhost:4000/l', true).toString()).toBe('http://localhost:4000/l');
    expect(resolutionTarget('https://8.8.8.8/l', false).toString()).toBe('https://8.8.8.8/l');
  });

  it('follows same-origin redirects only, bounds the body, and times out', async () => {
    const big = 'x'.repeat(2048);
    const url = await listen((req, res) => {
      if (req.url === '/hop') {
        res.writeHead(302, { location: '/list' });
        res.end();
      } else if (req.url === '/list') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"ok":true}');
      } else if (req.url === '/away') {
        res.writeHead(302, { location: 'http://localhost:1/elsewhere' });
        res.end();
      } else if (req.url === '/loop') {
        res.writeHead(302, { location: '/loop' });
        res.end();
      } else if (req.url === '/nowhere') {
        res.writeHead(302);
        res.end();
      } else if (req.url === '/declared') {
        res.writeHead(200, { 'content-length': String(big.length) });
        res.end(big);
      } else if (req.url === '/chunked') {
        res.writeHead(200);
        res.write(big);
        res.end(big);
      } else if (req.url === '/slow') {
        setTimeout(() => res.end('{}'), 500);
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    const fetcher = createResolutionFetch({ allowLoopbackHttp: true, maxBytes: 1024, timeoutMs: 100 });
    expect(await (await fetcher(`${url}/hop`)).json()).toEqual({ ok: true });
    expect((await fetcher(`${url}/missing`)).ok).toBe(false);
    await expect(fetcher(`${url}/away`)).rejects.toThrow(/another origin/);
    await expect(fetcher(`${url}/loop`)).rejects.toThrow(/too many/);
    await expect(fetcher(`${url}/nowhere`)).rejects.toThrow(/empty redirects/);
    await expect(fetcher(`${url}/declared`)).rejects.toThrow(/at most 1024/);
    await expect(fetcher(`${url}/chunked`)).rejects.toThrow(/exceeds 1024/);
    await expect(fetcher(`${url}/slow`)).rejects.toThrow();
    await expect(createResolutionFetch()(`${url}/list`)).rejects.toThrow(/only https/);
    await expect(createResolutionFetch()(url.replace('http:', 'https:'))).rejects.toThrow(/a loopback host/);
    const empty = createResolutionFetch({ allowLoopbackHttp: true, fetch: async () => new Response(null, { status: 200 }) });
    await expect((await empty(`${url}/x`)).json()).rejects.toThrow();
  });

  it('a list at a private address is refused before anything is fetched, and the credential reads as revoked', async () => {
    const lists: string[] = [];
    const verifier = createLocalVerifier({ serviceDid: 'did:web:svc.example', resolveDid: async () => null, clock: () => NOW_MS, reportVerification: () => undefined });
    const checker = verifier.seams.checkRevocation!;
    const verdict = await checker(
      { id: 'urn:uuid:c', issuer: 'did:web:issuer.example', credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '1', statusListCredential: 'https://10.0.0.1/status/1' } },
      { now: NOW_MS },
    );
    expect(verdict).toMatchObject({ revoked: true, code: 'status_unavailable' });
    expect(verdict.message).toMatch(/not a public unicast address/);
    expect(lists).toEqual([]);
    const cached = createLocalVerifier({ serviceDid: 'did:web:svc.example', statusCache: verifier.statusCache, reportVerification: () => undefined });
    expect(cached.statusCache).toBe(verifier.statusCache);
    // A cache from another copy of the SDK (no shared class) is used as given.
    const foreign = { invalidate: async () => 'credential' as const, getList: async () => undefined, getVerdict: async () => undefined, setList: async () => undefined, setVerdict: async () => undefined, ttlFor: () => 1 };
    expect(createLocalVerifier({ serviceDid: 'did:web:svc.example', statusCache: foreign as never, reportVerification: () => undefined }).statusCache).toBe(foreign);
    expect(createLocalVerifier({ serviceDid: 'did:web:svc.example', statusCache: { statusCacheTtl: 30 }, maxClockSkewMs: 0, reportVerification: () => undefined }).statusCache.statusCacheTtl).toBe(30);
    // statusListIssuers reaches the revocation checker, which holds it to its own rules (a DID key, origins without a path).
    expect(() => createLocalVerifier({ serviceDid: 'did:web:svc.example', statusListIssuers: { a: ['https://x/'] }, reportVerification: () => undefined })).toThrow(TypeError);
    expect(() => createLocalVerifier({ serviceDid: 'did:web:svc.example', statusListIssuers: { 'did:web:svc.example': ['https://status.svc.example'] }, reportVerification: () => undefined })).not.toThrow();
  });
});
