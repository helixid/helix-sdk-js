// Copyright 2026 DgVerse LLP
// KYA-OS story L1-D: the /.well-known/mcp discovery document, built from config and validated against well-known-mcpi.json.
import { existsSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { describeKyaOs } from '../src/kyaos/index.js';
import {
  DEFAULT_PROOF_ALGORITHMS,
  DEFAULT_SUPPORTED_DID_METHODS,
  WELL_KNOWN_MCP_PATH,
  WellKnownMcpError,
  assertWellKnownMcp,
  buildWellKnownMcp,
  createWellKnownMcp,
  validateWellKnownMcp,
} from '../src/well-known.js';
import * as middleware from '../src/index.js';

const ORIGIN = 'https://api.example.com';
const SERVER = 'did:web:api.example.com';
const base = { publicOrigin: ORIGIN, serverDid: SERVER };

const schemaPath = fileURLToPath(new URL('../schemas/well-known-mcpi.json', import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as { examples: unknown[] };

/** helix-core's vendored suite (stories rule 23), beside this workspace or at HELIX_CORE_FIXTURES_DIR. */
const coreFixturesDir = process.env['HELIX_CORE_FIXTURES_DIR'] ?? resolve(fileURLToPath(new URL('../../', import.meta.url)), '../helix-core/fixtures');
const vendoredSchema = join(coreFixturesDir, 'kya-os/schemas/well-known-mcpi.json');
const describeWithFixtures = existsSync(vendoredSchema) ? describe : describe.skip;
const fixtureSkipReason = existsSync(vendoredSchema) ? '' : ` (skipped: helix-core fixtures not found at ${coreFixturesDir}; check out helix-core beside helix-sdk-js or set HELIX_CORE_FIXTURES_DIR)`;

describe('validateWellKnownMcp', () => {
  it("accepts the schema's own example and refuses a document missing its required members", () => {
    expect(validateWellKnownMcp(schema.examples[0])).toEqual({ ok: true });
    const result = validateWellKnownMcp({ version: 'one' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.problems).toEqual(expect.arrayContaining([expect.stringContaining("required property 'serverDid'"), expect.stringContaining("required property 'endpoints'"), expect.stringContaining('/version must match pattern')]));
    }
    expect(() => assertWellKnownMcp({ version: '1.0', serverDid: 'did:hedera:x', endpoints: {} })).toThrow(WellKnownMcpError);
    expect(() => assertWellKnownMcp({ version: '1.0', serverDid: SERVER, endpoints: {}, clockSkewSeconds: 10 })).toThrow(/clockSkewSeconds must be >= 30/);
    expect(() => assertWellKnownMcp({ version: '1.0', serverDid: SERVER, endpoints: { tools: 'not a uri reference ' } })).toThrow(/endpoints\/tools must match format "uri-reference"/);
    expect(() => assertWellKnownMcp({ version: '1.0', serverDid: SERVER, endpoints: {}, statusListCredential: '/relative' })).toThrow(/statusListCredential must match format "uri"/);
  });

  it('has no vectors in the vendored suite: L1.10 and L1.11 are implementation-specific (CONFORMANCE.md), so the schema and its example are the upstream fixtures', () => {
    // Documented here so the absence of a vector test is a decision, not an omission.
    expect(schema.examples).toHaveLength(1);
  });
});

describeWithFixtures(`schemas/well-known-mcpi.json${fixtureSkipReason}`, () => {
  it('is byte for byte the vendored schema of helix-core/fixtures/kya-os (pin a4d7f61)', () => {
    expect(readFileSync(schemaPath)).toEqual(readFileSync(vendoredSchema));
  });
});

describe('buildWellKnownMcp', () => {
  it('fills every field from config and validates the result (story L1-D points 1 to 3)', () => {
    const kyaos = describeKyaOs({ clockSkewSeconds: 300, toolsEndpoint: `${ORIGIN}/mcp` });
    const document = buildWellKnownMcp({
      ...base,
      kyaos,
      statusListCredential: `${ORIGIN}/credentials/status/1`,
      capabilities: { delegation: true, statusList: true },
    });
    expect(document).toEqual({
      version: '1.0',
      serverDid: SERVER,
      endpoints: { tools: `${ORIGIN}/mcp`, handshake: `${ORIGIN}/mcp#_kyaos_handshake` },
      clockSkewSeconds: 300,
      capabilities: { proofs: true, delegation: true, statusList: true, crisp: false },
      statusListCredential: `${ORIGIN}/credentials/status/1`,
      supportedDidMethods: ['did:web', 'did:key'],
      proofAlgorithms: ['EdDSA'],
    });
    expect(validateWellKnownMcp(document)).toEqual({ ok: true });
    expect(document.supportedDidMethods).toEqual([...DEFAULT_SUPPORTED_DID_METHODS]);
    expect(document.proofAlgorithms).toEqual([...DEFAULT_PROOF_ALGORITHMS]);
  });

  it('sets each capability true only while that feature is enabled; proofs come from the KYA-OS layer', () => {
    const bare = buildWellKnownMcp(base);
    expect(bare.capabilities).toEqual({ proofs: false, delegation: false, statusList: false, crisp: false });
    expect(bare).not.toHaveProperty('statusListCredential');
    expect(bare.endpoints).toEqual({ tools: `${ORIGIN}/mcp` });
    expect(buildWellKnownMcp({ ...base, kyaos: describeKyaOs() }).capabilities.proofs).toBe(true);
    expect(buildWellKnownMcp({ ...base, capabilities: { crisp: true, delegation: false } }).capabilities).toMatchObject({ crisp: true, delegation: false, statusList: false });
  });

  it('advertises endpoints.handshake only while L2-A sessions are enabled', () => {
    expect(buildWellKnownMcp({ ...base, kyaos: describeKyaOs({ session: { enabled: true } }) }).endpoints.handshake).toBe(`${ORIGIN}/mcp#_kyaos_handshake`);
    expect(buildWellKnownMcp({ ...base, kyaos: describeKyaOs({ session: { enabled: false } }) }).endpoints).toEqual({ tools: `${ORIGIN}/mcp` });
    expect(buildWellKnownMcp(base).endpoints).not.toHaveProperty('handshake');
  });

  it('builds endpoints from publicOrigin, never the bind address, behind a proxy on a sub-path', () => {
    // The process listens on 127.0.0.1:3700/mcp and the KYA-OS runtime was described with that endpoint;
    // the proxy exposes it at https://api.example.com/orders/mcp.
    const kyaos = describeKyaOs({ toolsEndpoint: 'http://127.0.0.1:3700/mcp' });
    const document = buildWellKnownMcp({ ...base, kyaos, toolsEndpoint: '/orders/mcp' });
    expect(document.endpoints).toEqual({ tools: `${ORIGIN}/orders/mcp`, handshake: `${ORIGIN}/orders/mcp#_kyaos_handshake` });
    expect(JSON.stringify(document)).not.toContain('127.0.0.1');
    // An absolute toolsEndpoint is fine when it is at publicOrigin; the default is /mcp.
    expect(buildWellKnownMcp({ ...base, toolsEndpoint: `${ORIGIN}/orders/mcp` }).endpoints.tools).toBe(`${ORIGIN}/orders/mcp`);
    expect(buildWellKnownMcp({ ...base, toolsEndpoint: 'mcp' }).endpoints.tools).toBe(`${ORIGIN}/mcp`);
    expect(() => buildWellKnownMcp({ ...base, toolsEndpoint: 'http://127.0.0.1:3700/mcp' })).toThrow(/is not at publicOrigin/);
    expect(() => buildWellKnownMcp({ ...base, toolsEndpoint: 'http://[bad' })).toThrow(/toolsEndpoint must be a path or an absolute URL/);
  });

  it('takes the skew from config or the KYA-OS runtime, default 120, and refuses a mismatch or a value outside 30 to 600', () => {
    expect(buildWellKnownMcp(base).clockSkewSeconds).toBe(120);
    expect(buildWellKnownMcp({ ...base, clockSkewSeconds: 60 }).clockSkewSeconds).toBe(60);
    expect(buildWellKnownMcp({ ...base, kyaos: describeKyaOs({ clockSkewSeconds: 45 }) }).clockSkewSeconds).toBe(45);
    expect(buildWellKnownMcp({ ...base, kyaos: describeKyaOs({ clockSkewSeconds: 45 }), clockSkewSeconds: 45 }).clockSkewSeconds).toBe(45);
    expect(() => buildWellKnownMcp({ ...base, kyaos: describeKyaOs({ clockSkewSeconds: 45 }), clockSkewSeconds: 60 })).toThrow(/differs from the KYA-OS runtime's 45/);
    for (const bad of [29, 601, 120.5, Number.NaN]) {
      expect(() => buildWellKnownMcp({ ...base, clockSkewSeconds: bad })).toThrow(/clockSkewSeconds must be an integer from 30 to 600/);
    }
  });

  it('fails fast, with the reason, on a configuration that cannot make a valid document', () => {
    expect(() => buildWellKnownMcp({ serverDid: SERVER })).toThrow(/publicOrigin is required/);
    expect(() => buildWellKnownMcp({ publicOrigin: '', serverDid: SERVER })).toThrow(/publicOrigin is required/);
    expect(() => buildWellKnownMcp({ publicOrigin: 'api.example.com', serverDid: SERVER })).toThrow(/publicOrigin must be an absolute URL/);
    expect(() => buildWellKnownMcp({ publicOrigin: 'ftp://api.example.com', serverDid: SERVER })).toThrow(/publicOrigin must be http\(s\)/);
    expect(() => buildWellKnownMcp({ publicOrigin: `${ORIGIN}/mcp`, serverDid: SERVER })).toThrow(/put the MCP path in toolsEndpoint/);
    expect(() => buildWellKnownMcp({ publicOrigin: ORIGIN })).toThrow(/serverDid is required/);
    expect(() => buildWellKnownMcp({ publicOrigin: ORIGIN, serverDid: 'did:hedera:testnet:0.0.1' })).toThrow(/serverDid must be a did:web or did:key/);
    // What the schema catches rather than the config checks.
    const error = (() => {
      try {
        buildWellKnownMcp({ ...base, version: 'one' });
      } catch (e) {
        return e as WellKnownMcpError;
      }
      return undefined;
    })();
    expect(error).toBeInstanceOf(WellKnownMcpError);
    expect(error).toMatchObject({ code: 'WELL_KNOWN_MCP_INVALID', name: 'WellKnownMcpError', problems: [expect.stringContaining('/version must match pattern')] });
    expect(error!.message).toContain('does not validate against well-known-mcpi.json: /version');
    expect(() => buildWellKnownMcp({ ...base, statusListCredential: 'credentials/status/1' })).toThrow(/statusListCredential must match format "uri"/);
    expect(() => buildWellKnownMcp({ ...base, version: '2.1.3' })).not.toThrow();
  });
});

describe('createWellKnownMcp', () => {
  let server: Server | undefined;
  afterEach(async () => {
    if (server) await new Promise<void>((done) => server!.close(() => done()));
    server = undefined;
  });

  async function listen(route: ReturnType<typeof createWellKnownMcp>): Promise<string> {
    server = createServer((req, res) => {
      if (route.handle(req, res)) return;
      res.writeHead(418).end('not mine');
    });
    await new Promise<void>((done) => server!.listen(0, '127.0.0.1', done));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it('is on by default and serves the validated document at /.well-known/mcp (GET and HEAD)', async () => {
    const route = createWellKnownMcp({ ...base, kyaos: describeKyaOs() });
    expect(route).toMatchObject({ enabled: true, path: WELL_KNOWN_MCP_PATH });
    expect(route.path).toBe('/.well-known/mcp');
    expect(route.respond()).toEqual({ status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300' }, body: JSON.stringify(route.document) });

    const url = await listen(route);
    const res = await fetch(`${url}/.well-known/mcp?x=1`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/json');
    expect(await res.json()).toEqual(route.document);
    const head = await fetch(`${url}/.well-known/mcp`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe(String(Buffer.byteLength(JSON.stringify(route.document))));
    expect(await head.text()).toBe('');
    // Everything else is left to the host.
    expect((await fetch(`${url}/.well-known/mcp`, { method: 'POST' })).status).toBe(418);
    expect((await fetch(`${url}/.well-known/other`)).status).toBe(418);
    expect((await fetch(`${url}/mcp`)).status).toBe(418);
  });

  it('answers 404 when disabled, and then needs no configuration', async () => {
    const route = createWellKnownMcp({ enabled: false });
    expect(route.enabled).toBe(false);
    expect(route.document).toBeUndefined();
    expect(route.respond()).toEqual({ status: 404, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: '{"error":"not_found"}' });
    const url = await listen(route);
    const res = await fetch(`${url}/.well-known/mcp`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
    expect((await fetch(`${url}/mcp`)).status).toBe(418);
    // Disabled with a bad configuration is still fine: nothing is built.
    expect(() => createWellKnownMcp({ enabled: false, publicOrigin: 'nope' })).not.toThrow();
    expect(() => createWellKnownMcp({ enabled: true, publicOrigin: 'nope', serverDid: SERVER })).toThrow(WellKnownMcpError);
    expect(() => createWellKnownMcp()).toThrow(/publicOrigin is required/);
  });

  it('is exported from the package index', () => {
    expect(middleware.createWellKnownMcp).toBe(createWellKnownMcp);
    expect(middleware.buildWellKnownMcp).toBe(buildWellKnownMcp);
    expect(middleware.validateWellKnownMcp).toBe(validateWellKnownMcp);
    expect(middleware.assertWellKnownMcp).toBe(assertWellKnownMcp);
    expect(middleware.WellKnownMcpError).toBe(WellKnownMcpError);
    expect(middleware.WELL_KNOWN_MCP_PATH).toBe('/.well-known/mcp');
    expect(middleware.DEFAULT_WELL_KNOWN_VERSION).toBe('1.0');
  });
});
