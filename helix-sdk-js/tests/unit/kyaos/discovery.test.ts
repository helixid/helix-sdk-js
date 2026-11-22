// Copyright 2026 DgVerse LLP
// KYA-OS story L1-D, client side: reading /.well-known/mcp (Core L1.10) and the skew window it advertises.
import { describe, expect, it } from 'vitest';
import { kyaos } from '../../../src/index.js';
import { WELL_KNOWN_MCP_PATH, WellKnownMcpError, fetchWellKnownMcp, readWellKnownMcp, wellKnownMcpUrl } from '../../../src/core/kyaos/index.js';

const ORIGIN = 'https://api.example.com';
const SERVER = 'did:web:api.example.com';
const document = {
  version: '1.0',
  serverDid: SERVER,
  endpoints: { tools: `${ORIGIN}/mcp`, handshake: `${ORIGIN}/mcp#_kyaos_handshake` },
  clockSkewSeconds: 300,
  capabilities: { proofs: true, delegation: false, statusList: false, crisp: false },
  statusListCredential: `${ORIGIN}/credentials/status/1`,
  supportedDidMethods: ['did:web', 'did:key'],
  proofAlgorithms: ['EdDSA'],
};

const reason = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (error) {
    return (error as WellKnownMcpError).reason;
  }
  return undefined;
};

describe('wellKnownMcpUrl', () => {
  it('is /.well-known/mcp at the origin, whatever path the caller holds', () => {
    expect(WELL_KNOWN_MCP_PATH).toBe('/.well-known/mcp');
    expect(wellKnownMcpUrl(ORIGIN)).toBe(`${ORIGIN}/.well-known/mcp`);
    expect(wellKnownMcpUrl(`${ORIGIN}/orders/mcp?x=1`)).toBe(`${ORIGIN}/.well-known/mcp`);
    expect(wellKnownMcpUrl('http://127.0.0.1:3700/mcp')).toBe('http://127.0.0.1:3700/.well-known/mcp');
  });
});

describe('readWellKnownMcp', () => {
  it('returns the document with its skew, and keeps members the schema does not name', () => {
    const read = readWellKnownMcp({ ...document, contact: { name: 'ops' } });
    expect(read).toEqual({ ...document, contact: { name: 'ops' } });
    expect(read.clockSkewSeconds).toBe(300);
    expect(read.endpoints.handshake).toBe(`${ORIGIN}/mcp#_kyaos_handshake`);
  });

  it('fills clockSkewSeconds with 120 when the server advertised none, and accepts a minimal document', () => {
    const minimal = readWellKnownMcp({ version: '1.0.0', serverDid: 'did:key:z6Mkserver', endpoints: {} });
    expect(minimal).toEqual({ version: '1.0.0', serverDid: 'did:key:z6Mkserver', endpoints: {}, clockSkewSeconds: kyaos.DEFAULT_CLOCK_SKEW_SECONDS, capabilities: {} });
    expect(minimal.endpoints.handshake).toBeUndefined();
  });

  it('resolves relative endpoint references against the origin the document came from', () => {
    const read = readWellKnownMcp({ version: '1.0', serverDid: SERVER, endpoints: { tools: '/orders/mcp', handshake: '/orders/mcp#_kyaos_handshake', delegation: 'delegations' } }, { origin: `${ORIGIN}/.well-known/mcp` });
    expect(read.endpoints).toEqual({ tools: `${ORIGIN}/orders/mcp`, handshake: `${ORIGIN}/orders/mcp#_kyaos_handshake`, delegation: `${ORIGIN}/delegations` });
    // Without an origin they are returned as written.
    expect(readWellKnownMcp({ version: '1.0', serverDid: SERVER, endpoints: { tools: '/mcp' } }).endpoints.tools).toBe('/mcp');
  });

  it('refuses what the schema refuses, naming the member', () => {
    expect(reason(() => readWellKnownMcp(null))).toBe('document_not_object');
    expect(reason(() => readWellKnownMcp([]))).toBe('document_not_object');
    expect(reason(() => readWellKnownMcp({ ...document, version: 'one' }))).toBe('version_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, version: undefined }))).toBe('version_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, serverDid: 'did:hedera:testnet:0.0.1' }))).toBe('server_did_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, endpoints: 'x' }))).toBe('endpoints_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, endpoints: { tools: 1 } }))).toBe('endpoints_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, endpoints: { tools: 'http://[bad' } }, { origin: ORIGIN }))).toBe('endpoints_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, clockSkewSeconds: 29 }))).toBe('clock_skew_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, clockSkewSeconds: 601 }))).toBe('clock_skew_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, clockSkewSeconds: '120' }))).toBe('clock_skew_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, capabilities: [] }))).toBe('capabilities_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, capabilities: { proofs: 'yes' } }))).toBe('capabilities_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, statusListCredential: 7 }))).toBe('status_list_credential_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, statusListCredential: '/credentials/status/1' }))).toBe('status_list_credential_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, supportedDidMethods: 'did:web' }))).toBe('advisory_list_invalid');
    expect(reason(() => readWellKnownMcp({ ...document, proofAlgorithms: [1] }))).toBe('advisory_list_invalid');
    expect(() => readWellKnownMcp({ ...document, version: 'one' })).toThrow(WellKnownMcpError);
    expect(() => readWellKnownMcp({ ...document, version: 'one' })).toThrow(/version must look like 1.0/);
    const error = (() => {
      try {
        readWellKnownMcp({});
      } catch (e) {
        return e as WellKnownMcpError;
      }
      return undefined;
    })();
    expect(error).toMatchObject({ name: 'WellKnownMcpError', code: 'WELL_KNOWN_MCP_INVALID', reason: 'version_invalid' });
  });

  it('is what the client hands to the proof verifier and its handshake timing', () => {
    const read = readWellKnownMcp(document);
    // The window the server enforces on the handshake timestamp (L2.3, L2.4).
    const now = 1_750_000_000;
    expect(kyaos.withinSkew(now - read.clockSkewSeconds, now, read.clockSkewSeconds)).toBe(true);
    expect(kyaos.withinSkew(now - read.clockSkewSeconds - 1, now, read.clockSkewSeconds)).toBe(false);
    expect(kyaos.createHandshakeRequest({ audience: read.serverDid, now: now * 1000 })).toMatchObject({ audience: SERVER, timestamp: now });
  });
});

describe('fetchWellKnownMcp', () => {
  const json = (status: number, body: unknown): Response => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  it('GETs <origin>/.well-known/mcp and reads the answer, resolving relative endpoints against the origin', async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      return json(200, { ...document, endpoints: { tools: '/mcp' } });
    };
    const read = await fetchWellKnownMcp(`${ORIGIN}/mcp`, { fetch: fetchImpl });
    expect(calls).toEqual([{ url: `${ORIGIN}/.well-known/mcp`, init: { method: 'GET', headers: { accept: 'application/json' } } }]);
    expect(read.endpoints.tools).toBe(`${ORIGIN}/mcp`);
    expect(read.clockSkewSeconds).toBe(300);
    const controller = new AbortController();
    await fetchWellKnownMcp(ORIGIN, { fetch: fetchImpl, signal: controller.signal });
    expect(calls[1]!.init).toMatchObject({ signal: controller.signal });
  });

  it('refuses a non-200 answer, a non-JSON body and a network failure', async () => {
    await expect(fetchWellKnownMcp(ORIGIN, { fetch: async () => json(404, { error: 'not_found' }) })).rejects.toMatchObject({ reason: 'fetch_failed', message: `GET ${ORIGIN}/.well-known/mcp answered 404` });
    await expect(fetchWellKnownMcp(ORIGIN, { fetch: async () => new Response('<html>', { status: 200 }) })).rejects.toMatchObject({ reason: 'not_json' });
    await expect(fetchWellKnownMcp(ORIGIN, { fetch: async () => Promise.reject(new Error('ECONNREFUSED')) })).rejects.toMatchObject({ reason: 'fetch_failed', message: expect.stringContaining('ECONNREFUSED') });
    await expect(fetchWellKnownMcp(ORIGIN, { fetch: async () => Promise.reject('down') })).rejects.toMatchObject({ reason: 'fetch_failed', message: expect.stringContaining('down') });
    await expect(fetchWellKnownMcp(ORIGIN, { fetch: async () => json(200, { version: '1.0' }) })).rejects.toMatchObject({ reason: 'server_did_invalid' });
  });

  it('is exported on the kyaos namespace', () => {
    expect(kyaos.fetchWellKnownMcp).toBe(fetchWellKnownMcp);
    expect(kyaos.readWellKnownMcp).toBe(readWellKnownMcp);
    expect(kyaos.wellKnownMcpUrl).toBe(wellKnownMcpUrl);
    expect(kyaos.WellKnownMcpError).toBe(WellKnownMcpError);
  });
});
