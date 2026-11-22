// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: the agent key is generated client side; only its public half leaves.
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { HelixClient } from '../../src/client/HelixClient.js';
import {
  DEFAULT_AGENT_KEY_ID,
  agentKeyRegistration,
  agentPublicKey,
  assertNoPrivateMaterial,
  decodeBase58btc,
  encodeBase58btc,
  generateAgentKey,
  publicKeyFromDidKey,
  publicKeyJwkBytes,
  toDidKey,
  toPublicKeyJwk,
} from '../../src/core/agent-key.js';
import { derivePublicKey, publicKeyToMultibase, signData, verifySignature } from '../../src/core/keys.js';

/** helix-core's cross-language fixture: the sibling checkout, or HELIX_CORE_FIXTURES_DIR. */
const FIXTURES_DIR = process.env['HELIX_CORE_FIXTURES_DIR'] ?? fileURLToPath(new URL('../../../../helix-core/fixtures', import.meta.url));
const DID_FIXTURE = `${FIXTURES_DIR}/kya-os-helix/did.json`;

interface FixtureKey {
  private_key_hex: string;
  public_key_hex: string;
  public_key_jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  public_key_multibase: string;
  did_key: string;
  did_web: string;
  kid_fragment: string;
  kid: string;
  registration_body: { publicKeyJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }; kid: string };
}

interface Fixtures {
  keys: Record<string, FixtureKey>;
  base58btc: { bytes_hex: string; base58btc: string }[];
  did_key_rejections: { name: string; did: string }[];
}

describe('generateAgentKey', () => {
  it('makes a fresh Ed25519 seed and its public key, both 32 bytes, and the seed signs what the public key verifies', () => {
    const key = generateAgentKey();
    expect(key.privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(key.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(derivePublicKey(key.privateKeyHex)).toBe(key.publicKeyHex);
    expect(Buffer.from(agentPublicKey(key.privateKeyHex)).toString('hex')).toBe(key.publicKeyHex);
    expect(generateAgentKey().privateKeyHex).not.toBe(key.privateKeyHex);
    const signature = signData('hello', key.privateKeyHex);
    expect(verifySignature(Buffer.from('hello'), signature, key.publicKeyHex)).toBe(true);
  });

  it('derives the public key from a PKCS8 seed form too, and refuses other forms', () => {
    const key = generateAgentKey();
    expect(Buffer.from(agentPublicKey(`302e020100300506032b657004220420${key.privateKeyHex}`)).toString('hex')).toBe(key.publicKeyHex);
    expect(() => agentPublicKey('nope')).toThrow();
  });
});

describe('toPublicKeyJwk, toDidKey', () => {
  const key = generateAgentKey();
  const bytes = new Uint8Array(Buffer.from(key.publicKeyHex, 'hex'));

  it('write the JWK (kid only when given) and the did:key from hex or bytes alike', () => {
    const x = Buffer.from(bytes).toString('base64url');
    expect(toPublicKeyJwk(key.publicKeyHex)).toEqual({ kty: 'OKP', crv: 'Ed25519', x });
    expect(toPublicKeyJwk(bytes, 'k')).toEqual({ kty: 'OKP', crv: 'Ed25519', x, kid: 'k' });
    expect(toDidKey(key.publicKeyHex)).toBe(`did:key:${publicKeyToMultibase(key.publicKeyHex)}`);
    expect(toDidKey(bytes)).toBe(toDidKey(key.publicKeyHex));
    expect(toDidKey(bytes)).toMatch(/^did:key:z6Mk/);
    expect(publicKeyFromDidKey(toDidKey(bytes))).toEqual(bytes);
  });

  it('refuse a key that is not 32 bytes', () => {
    expect(() => toPublicKeyJwk('abcd')).toThrow(/32 bytes/);
    expect(() => toPublicKeyJwk(bytes.slice(1))).toThrow(/32 bytes/);
    expect(() => toDidKey(`${key.publicKeyHex}zz`)).toThrow(/32 bytes/);
    expect(() => toDidKey('zz'.repeat(32))).toThrow(/32 bytes/);
  });

  it('publicKeyFromDidKey is undefined for anything but an Ed25519 did:key', () => {
    expect(publicKeyFromDidKey('did:web:a')).toBeUndefined();
    expect(publicKeyFromDidKey('did:key:z!!!')).toBeUndefined();
    expect(publicKeyFromDidKey('did:key:z')).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:z${encodeBase58btc(new Uint8Array([0xec, 0x01, ...bytes]))}`)).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:z${encodeBase58btc(new Uint8Array([0xed, 0x01, ...bytes.slice(2)]))}`)).toBeUndefined();
  });
});

describe('agentKeyRegistration and publicKeyJwkBytes', () => {
  const key = generateAgentKey();
  const jwk = toPublicKeyJwk(key.publicKeyHex);

  it('builds {publicKeyJwk, kid} from hex, bytes or a JWK, with the default kid', () => {
    expect(agentKeyRegistration(key.publicKeyHex)).toEqual({ publicKeyJwk: jwk, kid: DEFAULT_AGENT_KEY_ID });
    expect(agentKeyRegistration(new Uint8Array(Buffer.from(key.publicKeyHex, 'hex')), 'k2')).toEqual({ publicKeyJwk: jwk, kid: 'k2' });
    expect(agentKeyRegistration({ ...jwk, kid: 'ignored' })).toEqual({ publicKeyJwk: jwk, kid: DEFAULT_AGENT_KEY_ID });
    expect(() => agentKeyRegistration(key.publicKeyHex, '')).toThrow(/kid/);
  });

  it('refuses any private material and any JWK that is not a public OKP Ed25519 key', () => {
    const d = Buffer.from(key.privateKeyHex, 'hex').toString('base64url');
    expect(() => agentKeyRegistration({ ...jwk, d } as never)).toThrow(/Private key material.*publicKeyJwk\.d|found d/);
    expect(() => publicKeyJwkBytes({ ...jwk, d })).toThrow(/found d/);
    expect(() => publicKeyJwkBytes({ ...jwk, use: 'sig' })).toThrow(/unexpected members \(use\)/);
    expect(() => publicKeyJwkBytes({ ...jwk, kty: 'EC' })).toThrow(/OKP/);
    expect(() => publicKeyJwkBytes({ ...jwk, crv: 'X25519' })).toThrow(/Ed25519/);
    expect(() => publicKeyJwkBytes({ ...jwk, kid: 4 })).toThrow(/kid must be a string/);
    expect(() => publicKeyJwkBytes({ ...jwk, x: `${jwk.x}=` })).toThrow(/strict base64url/);
    expect(() => publicKeyJwkBytes({ ...jwk, x: `${jwk.x}AA` })).toThrow(/strict base64url/);
    expect(() => publicKeyJwkBytes({ ...jwk, x: jwk.x.slice(1) })).toThrow(/32-byte/);
    expect(() => publicKeyJwkBytes({ ...jwk, x: jwk.x.slice(4) })).toThrow(/32-byte/);
    expect(() => publicKeyJwkBytes({ kty: 'OKP', crv: 'Ed25519' })).toThrow(/strict base64url/);
    expect(() => publicKeyJwkBytes(null)).toThrow(/JSON object/);
    expect(() => publicKeyJwkBytes([])).toThrow(/JSON object/);
    expect(publicKeyJwkBytes({ ...jwk, kid: 'k' })).toEqual(new Uint8Array(Buffer.from(key.publicKeyHex, 'hex')));
  });

  it('assertNoPrivateMaterial looks at every depth and ignores scalars', () => {
    expect(() => assertNoPrivateMaterial({ a: { b: [{ seed: 'x' }] } })).toThrow(/found a\.b\.0\.seed/);
    expect(() => assertNoPrivateMaterial({ privateKeyHex: 'x' })).toThrow(/found privateKeyHex/);
    expect(() => assertNoPrivateMaterial({ ok: 1, nested: { x: 'y' } })).not.toThrow();
    expect(() => assertNoPrivateMaterial('string')).not.toThrow();
    expect(() => assertNoPrivateMaterial(null)).not.toThrow();
  });
});

describe('HelixClient.registerAgentKey (self-custody invariant)', () => {
  it('posts the public JWK and kid to /v1/agents/{did}/keys and nothing private is in the payload', async () => {
    const key = generateAgentKey();
    const client = new HelixClient('http://localhost:3000', { adminApiKey: 'admin' });
    const calls: { path: string; payload: unknown }[] = [];
    client.__setTestHttpAdapter({
      post: async (path: string, payload: unknown) => {
        calls.push({ path, payload });
        return { did: 'did:web:x:agents:a', kid: 'did:web:x:agents:a#key-1', didKey: toDidKey(key.publicKeyHex), didDocument: {} };
      },
    } as never);

    const result = await client.registerAgentKey('did:web:x:agents:a', key.publicKeyHex);
    expect(result.kid).toBe('did:web:x:agents:a#key-1');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.path).toBe('/v1/agents/did%3Aweb%3Ax%3Aagents%3Aa/keys');
    expect(calls[0]!.payload).toEqual({ publicKeyJwk: toPublicKeyJwk(key.publicKeyHex), kid: 'key-1' });
    const wire = JSON.stringify(calls[0]!.payload);
    expect(wire).not.toMatch(/"d"/);
    expect(wire).not.toContain(key.privateKeyHex);
    expect(wire).not.toContain(Buffer.from(key.privateKeyHex, 'hex').toString('base64url'));
    expect(Object.keys((calls[0]!.payload as { publicKeyJwk: object }).publicKeyJwk).sort()).toEqual(['crv', 'kty', 'x']);

    await client.registerAgentKey('did:web:x:agents:a', toPublicKeyJwk(key.publicKeyHex), { kid: 'signing' });
    expect(calls[1]!.payload).toEqual({ publicKeyJwk: toPublicKeyJwk(key.publicKeyHex), kid: 'signing' });
  });

  it('never sends a request that would carry private material, and needs an API', async () => {
    const key = generateAgentKey();
    const client = new HelixClient('http://localhost:3000');
    let posted = false;
    client.__setTestHttpAdapter({ post: async () => { posted = true; return {}; } } as never);
    const d = Buffer.from(key.privateKeyHex, 'hex').toString('base64url');
    await expect(client.registerAgentKey('did:web:x', { ...toPublicKeyJwk(key.publicKeyHex), d } as never)).rejects.toThrow(/Private key material/);
    expect(posted).toBe(false);
    await expect(new HelixClient().registerAgentKey('did:web:x', key.publicKeyHex)).rejects.toThrow();
  });
});

describe('base58btc', () => {
  it('encodes leading zeros as 1s and round trips', () => {
    expect(encodeBase58btc(new Uint8Array([]))).toBe('');
    expect(encodeBase58btc(new Uint8Array([0]))).toBe('1');
    expect(encodeBase58btc(new Uint8Array([0, 0, 1, 2, 3]))).toBe('11Ldp');
    expect(decodeBase58btc('')).toEqual(new Uint8Array([]));
    expect(decodeBase58btc('111')).toEqual(new Uint8Array([0, 0, 0]));
    expect(decodeBase58btc('11Ldp')).toEqual(new Uint8Array([0, 0, 1, 2, 3]));
    expect(() => decodeBase58btc('0O')).toThrow(/Invalid base58 character/);
  });
});

describe.skipIf(!existsSync(DID_FIXTURE))('helix-core fixtures/kya-os-helix/did.json (cross-language)', () => {
  const fixtures = existsSync(DID_FIXTURE) ? (JSON.parse(readFileSync(DID_FIXTURE, 'utf8')) as Fixtures) : ({ keys: {}, base58btc: [], did_key_rejections: [] } as Fixtures);

  for (const [name, key] of Object.entries(fixtures.keys)) {
    it(`key ${name}: the same seed gives the same public key, JWK, did:key and registration body as helix-core`, () => {
      expect(Buffer.from(agentPublicKey(key.private_key_hex)).toString('hex')).toBe(key.public_key_hex);
      expect(toPublicKeyJwk(key.public_key_hex)).toEqual(key.public_key_jwk);
      expect(toDidKey(key.public_key_hex)).toBe(key.did_key);
      expect(`z${encodeBase58btc(new Uint8Array([0xed, 0x01, ...Buffer.from(key.public_key_hex, 'hex')]))}`).toBe(key.public_key_multibase);
      expect(Buffer.from(publicKeyFromDidKey(key.did_key)!).toString('hex')).toBe(key.public_key_hex);
      expect(agentKeyRegistration(key.public_key_hex, key.kid_fragment)).toEqual(key.registration_body);
      expect(key.kid).toBe(`${key.did_web}#${key.kid_fragment}`);
    });
  }

  it('base58btc vectors', () => {
    for (const vector of fixtures.base58btc) {
      expect(encodeBase58btc(new Uint8Array(Buffer.from(vector.bytes_hex, 'hex'))), vector.bytes_hex).toBe(vector.base58btc);
      expect(Buffer.from(decodeBase58btc(vector.base58btc)).toString('hex'), vector.base58btc).toBe(vector.bytes_hex);
    }
  });

  it('did:key rejections', () => {
    for (const rejection of fixtures.did_key_rejections) {
      expect(publicKeyFromDidKey(rejection.did), rejection.name).toBeUndefined();
    }
  });
});
