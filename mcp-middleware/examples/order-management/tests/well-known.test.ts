// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story L1-D: the sample serves the discovery document at /.well-known/mcp.

import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPair, kyaos, type HelixClient } from '@helixid/sdk-js';
import { createKyaOs, createWellKnownMcp, validateWellKnownMcp, type KyaOsRuntime, type WellKnownMcp } from '@helixid/mcp-middleware';
import { createOrderServer } from '../src/app.js';
import { describeWellKnown, wellKnownFromEnv } from '../src/well-known-env.js';

const SERVICE = 'did:web:orders.example';
const PUBLIC_ORIGIN = 'https://orders.example';
const keys = generateKeyPair();
const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'SAMPLE_SERVICE_KEY', env: { SAMPLE_SERVICE_KEY: keys.privateKey } });
const fakeClient = { verifyVP: async () => ({ valid: false, error: 'unused' }) } as unknown as HelixClient;

let server: Server | undefined;

async function start(options: { kyaos?: KyaOsRuntime; wellKnown?: WellKnownMcp }): Promise<string> {
  server = createOrderServer({
    resource: 'http://127.0.0.1:3700/orders/mcp',
    auth: { client: fakeClient, serviceDid: SERVICE, validateOAuthToken: async () => ({ sub: 'x', scopes: [] }) },
    ...options,
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

describe('GET /.well-known/mcp', () => {
  it('returns the document, which validates against well-known-mcpi.json and carries the public URLs, not the bind address', async () => {
    const runtime = createKyaOs({ signer, publicOrigin: PUBLIC_ORIGIN, clockSkewSeconds: 60, toolsEndpoint: 'http://127.0.0.1:3700/orders/mcp' });
    const wellKnown = createWellKnownMcp({ publicOrigin: PUBLIC_ORIGIN, serverDid: SERVICE, toolsEndpoint: '/orders/mcp', kyaos: runtime.describe() });
    const base = await start({ kyaos: runtime, wellKnown });
    const res = await fetch(`${base}/.well-known/mcp`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/json');
    const raw: unknown = await res.json();
    expect(validateWellKnownMcp(raw)).toEqual({ ok: true });
    // A client reads it (every endpoint is absolute already, so nothing changes) and takes the skew the handshake enforces.
    const document = kyaos.readWellKnownMcp(raw, { origin: base });
    expect(document).toEqual({
      version: '1.0',
      serverDid: SERVICE,
      endpoints: { tools: `${PUBLIC_ORIGIN}/orders/mcp`, handshake: `${PUBLIC_ORIGIN}/orders/mcp#_kyaos_handshake` },
      clockSkewSeconds: 60,
      capabilities: { proofs: true, delegation: false, statusList: false, crisp: false },
      supportedDidMethods: ['did:web', 'did:key'],
      proofAlgorithms: ['EdDSA'],
    });
    expect(JSON.stringify(raw)).not.toContain('127.0.0.1');
    expect(document.clockSkewSeconds).toBe(runtime.clockSkewSeconds);
    // The rest of the sample is untouched.
    expect((await fetch(`${base}/.well-known/oauth-protected-resource/orders/mcp`)).status).toBe(200);
    expect((await fetch(`${base}/elsewhere`)).status).toBe(404);
  });

  it('shows no proofs and no handshake without the KYA-OS layer, and no handshake while sessions are off', async () => {
    const base = await start({ wellKnown: createWellKnownMcp({ publicOrigin: PUBLIC_ORIGIN, serverDid: SERVICE, toolsEndpoint: '/orders/mcp' }) });
    const document = kyaos.readWellKnownMcp(await (await fetch(`${base}/.well-known/mcp`)).json());
    expect(document.capabilities.proofs).toBe(false);
    expect(document.endpoints).toEqual({ tools: `${PUBLIC_ORIGIN}/orders/mcp` });
    expect(document.clockSkewSeconds).toBe(120);

    const noSessions = createKyaOs({ signer, session: { enabled: false } });
    const withoutHandshake = createWellKnownMcp({ publicOrigin: PUBLIC_ORIGIN, serverDid: SERVICE, kyaos: noSessions.describe() });
    expect(withoutHandshake.document).toMatchObject({ capabilities: { proofs: true }, endpoints: { tools: `${PUBLIC_ORIGIN}/mcp` } });
    expect(withoutHandshake.document!.endpoints).not.toHaveProperty('handshake');
  });

  it('answers 404 when the route is disabled, and when the sample is started without it', async () => {
    const base = await start({ wellKnown: createWellKnownMcp({ enabled: false }) });
    const res = await fetch(`${base}/.well-known/mcp`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    const bare = await start({});
    expect((await fetch(`${bare}/.well-known/mcp`)).status).toBe(404);
  });
});

describe('wellKnownFromEnv (the sample environment; helix-sdk-py: well_known_from_env)', () => {
  const RESOURCE = 'http://127.0.0.1:3700/orders/mcp';

  it('builds the document from the environment and the KYA-OS runtime', () => {
    const runtime = createKyaOs({ signer, publicOrigin: PUBLIC_ORIGIN, clockSkewSeconds: 45 });
    const discovery = wellKnownFromEnv({ KYAOS_PUBLIC_ORIGIN: PUBLIC_ORIGIN, STATUS_LIST_CREDENTIAL: `${PUBLIC_ORIGIN}/status/1` }, RESOURCE, SERVICE, runtime);
    expect(discovery.off).toBeUndefined();
    expect(discovery.wellKnown?.document).toEqual({
      version: '1.0',
      serverDid: SERVICE,
      endpoints: { tools: `${PUBLIC_ORIGIN}/orders/mcp`, handshake: `${PUBLIC_ORIGIN}/orders/mcp#_kyaos_handshake` },
      clockSkewSeconds: 45,
      capabilities: { proofs: true, delegation: false, statusList: false, crisp: false },
      statusListCredential: `${PUBLIC_ORIGIN}/status/1`,
      supportedDidMethods: ['did:web', 'did:key'],
      proofAlgorithms: ['EdDSA'],
    });
    expect(describeWellKnown(discovery)).toBe(
      `${PUBLIC_ORIGIN}/.well-known/mcp, serverDid ${SERVICE}, skew 45 s, handshake advertised (route the path at that origin to this server: see mcp-middleware/docs/well-known.md)`,
    );
  });

  it('defaults to the origin of MCP_RESOURCE without the KYA-OS layer', () => {
    const discovery = wellKnownFromEnv({}, RESOURCE, 'did:key:z6Mkservice', undefined);
    expect(discovery.wellKnown?.document).toMatchObject({ endpoints: { tools: RESOURCE }, capabilities: { proofs: false } });
    expect(describeWellKnown(discovery)).toContain('handshake absent');
  });

  it('stays off with the reason, and WELL_KNOWN_MCP=0 serves 404', () => {
    for (const serviceDid of [undefined, '']) {
      expect(wellKnownFromEnv({}, RESOURCE, serviceDid, undefined)).toEqual({ wellKnown: undefined, off: 'off (set SERVICE_DID)' });
    }
    const hedera = wellKnownFromEnv({}, RESOURCE, 'did:hedera:testnet:0.0.1', undefined);
    expect(hedera.wellKnown).toBeUndefined();
    expect(describeWellKnown(hedera)).toContain('is not a did:web or did:key');
    const disabled = wellKnownFromEnv({ WELL_KNOWN_MCP: '0' }, RESOURCE, SERVICE, undefined);
    expect(disabled.wellKnown?.respond().status).toBe(404);
    expect(describeWellKnown(disabled)).toBe('off (WELL_KNOWN_MCP=0): 404');
    expect(describeWellKnown({ wellKnown: undefined, off: undefined })).toBe('off');
  });

  it('throws for a document that would not validate', () => {
    expect(() => wellKnownFromEnv({ WELL_KNOWN_MCP: '1' }, RESOURCE, 'did:hedera:testnet:0.0.1', undefined)).toThrow(/serverDid must be a did:web or did:key/);
    expect(() => wellKnownFromEnv({ KYAOS_PUBLIC_ORIGIN: 'https://orders.example/mcp' }, RESOURCE, SERVICE, undefined)).toThrow(/put the MCP path in toolsEndpoint/);
    expect(() => wellKnownFromEnv({ STATUS_LIST_CREDENTIAL: 'status/1' }, RESOURCE, SERVICE, undefined)).toThrow(/statusListCredential must match format "uri"/);
  });
});
