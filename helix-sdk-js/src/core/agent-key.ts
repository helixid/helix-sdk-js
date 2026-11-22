// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The agent's own key (KYA-OS story L1-A): generated here, on the client,
 * and never sent anywhere. What leaves the process is the public half only,
 * as an OKP JWK (`{kty: "OKP", crv: "Ed25519", x}`) that Helix publishes in
 * the agent's did:web document, and the did:key form of the same key.
 *
 * - `generateAgentKey()`: a fresh Ed25519 key. `privateKeyHex` is the
 *   32-byte seed, the value to put in the environment secret a Signer reads
 *   (`HELIX_SIGNING_KEY` for helix-core's EnvSigner); `publicKeyHex` the
 *   public key.
 * - `toPublicKeyJwk()`: the public key as RFC 8037 writes it (L1.8).
 * - `toDidKey()`: `did:key:z6Mk…`, multicodec `0xed01` then base58btc (L1.1).
 * - `agentKeyRegistration()`: the body of `POST /v1/agents/{did}/keys`,
 *   checked to carry no private material (self-custody invariant, rule 7).
 *
 * Byte-compatible with helix-core (`src/core/did/document.ts`) and
 * helix-sdk-py (`helix_sdk.agent_key`), asserted against helix-core's
 * `fixtures/kya-os-helix/did.json`.
 */

import * as ed25519 from '@noble/ed25519';
import { generateKeyPair, normalizeEd25519PrivateKey } from './keys.js';

export interface AgentKey {
  /** The 32-byte Ed25519 seed, hex. Keep it in the Signer's secret; never send it. */
  privateKeyHex: string;
  /** The 32-byte Ed25519 public key, hex. */
  publicKeyHex: string;
}

export interface AgentPublicKeyJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
}

export interface AgentKeyRegistration {
  publicKeyJwk: AgentPublicKeyJwk;
  /** Verification-method fragment: the published id is `<did>#<kid>`. */
  kid: string;
}

export const DEFAULT_AGENT_KEY_ID = 'key-1';

const ED25519_MULTICODEC_PREFIX = [0xed, 0x01] as const;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map<string, number>([...BASE58_ALPHABET].map((char, i) => [char, i]));
const BASE64URL = /^[A-Za-z0-9_-]*$/;
/** Member names that only ever carry private material. */
const PRIVATE_MATERIAL_MEMBERS = new Set(['d', 'privateKey', 'privateKeyHex', 'private_key', 'seed', 'secret']);

/** A fresh Ed25519 key, generated in this process. */
export function generateAgentKey(): AgentKey {
  const pair = generateKeyPair();
  return { privateKeyHex: pair.privateKey, publicKeyHex: pair.publicKey };
}

/** The public key of a seed (raw 32-byte hex, or the PKCS8 seed hex the environment may hold). */
export function agentPublicKey(privateKeyHex: string): Uint8Array {
  return ed25519.getPublicKey(normalizeEd25519PrivateKey(privateKeyHex));
}

function publicKeyBytes(publicKey: string | Uint8Array): Uint8Array {
  const bytes = typeof publicKey === 'string' ? new Uint8Array(Buffer.from(publicKey, 'hex')) : publicKey;
  if (bytes.length !== ED25519_PUBLIC_KEY_LENGTH || (typeof publicKey === 'string' && !/^[0-9a-fA-F]{64}$/.test(publicKey))) {
    throw new Error('An Ed25519 public key is 32 bytes (64 hex characters)');
  }
  return bytes;
}

/** `{kty: "OKP", crv: "Ed25519", x}` of the public key; `kid` only when given. */
export function toPublicKeyJwk(publicKey: string | Uint8Array, kid?: string): AgentPublicKeyJwk {
  const x = Buffer.from(publicKeyBytes(publicKey)).toString('base64url');
  return kid === undefined ? { kty: 'OKP', crv: 'Ed25519', x } : { kty: 'OKP', crv: 'Ed25519', x, kid };
}

/** `did:key:z6Mk…`: multicodec `0xed01` plus the key, base58btc, multibase `z`. */
export function toDidKey(publicKey: string | Uint8Array): string {
  return `did:key:z${encodeBase58btc(new Uint8Array([...ED25519_MULTICODEC_PREFIX, ...publicKeyBytes(publicKey)]))}`;
}

/** The raw public key a did:key names, or undefined when it is not an Ed25519 did:key that decodes. */
export function publicKeyFromDidKey(did: string): Uint8Array | undefined {
  if (!did.startsWith('did:key:z')) return undefined;
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58btc(did.slice('did:key:z'.length));
  } catch {
    return undefined;
  }
  if (
    decoded.length !== ED25519_MULTICODEC_PREFIX.length + ED25519_PUBLIC_KEY_LENGTH ||
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    return undefined;
  }
  return decoded.slice(ED25519_MULTICODEC_PREFIX.length);
}

/** The 32 raw bytes of a public Ed25519 JWK; throws for anything else, a `d` member above all. */
export function publicKeyJwkBytes(jwk: unknown): Uint8Array {
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
    throw new Error('publicKeyJwk must be a JSON object');
  }
  const members = jwk as Record<string, unknown>;
  assertNoPrivateMaterial(members);
  const foreign = Object.keys(members).filter((name) => !['kty', 'crv', 'x', 'kid'].includes(name));
  if (foreign.length > 0) {
    throw new Error(`publicKeyJwk carries unexpected members (${foreign.join(', ')}); only kty, crv, x and kid are allowed`);
  }
  if (members['kty'] !== 'OKP' || members['crv'] !== 'Ed25519') {
    throw new Error('publicKeyJwk must be an OKP key on the Ed25519 curve');
  }
  if (members['kid'] !== undefined && typeof members['kid'] !== 'string') {
    throw new Error('publicKeyJwk kid must be a string');
  }
  const x = members['x'];
  if (typeof x !== 'string' || !BASE64URL.test(x) || x.length % 4 === 1) {
    throw new Error('publicKeyJwk x must be strict base64url');
  }
  const bytes = new Uint8Array(Buffer.from(x, 'base64url'));
  if (bytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error('publicKeyJwk x must be a 32-byte Ed25519 public key');
  }
  return bytes;
}

/**
 * Throws when `value`, at any depth, has a member that only ever carries
 * private material (`d`, `privateKey`, `seed`, …). What the SDK sends to
 * the API goes through this first.
 */
export function assertNoPrivateMaterial(value: unknown, path = ''): void {
  if (typeof value !== 'object' || value === null) return;
  for (const [name, member] of Object.entries(value as Record<string, unknown>)) {
    const here = path ? `${path}.${name}` : name;
    if (PRIVATE_MATERIAL_MEMBERS.has(name)) {
      throw new Error(`Private key material must never leave the client (found ${here})`);
    }
    assertNoPrivateMaterial(member, here);
  }
}

/**
 * The body of `POST /v1/agents/{did}/keys`: the public JWK (`kty`, `crv`,
 * `x`, nothing else) and the verification-method fragment. Takes the public
 * key as hex, bytes or JWK; a JWK with `d` or any other member is refused.
 */
export function agentKeyRegistration(publicKey: string | Uint8Array | AgentPublicKeyJwk, kid: string = DEFAULT_AGENT_KEY_ID): AgentKeyRegistration {
  const bytes = typeof publicKey === 'object' && !(publicKey instanceof Uint8Array) ? publicKeyJwkBytes(publicKey) : publicKeyBytes(publicKey);
  if (typeof kid !== 'string' || kid.length === 0) {
    throw new Error('kid must be a non-empty verification-method fragment');
  }
  const body: AgentKeyRegistration = { publicKeyJwk: toPublicKeyJwk(bytes), kid };
  assertNoPrivateMaterial(body);
  return body;
}

// ── base58btc (conformance L1.9) ────────────────────────────────────────────

/** base58btc: every leading zero byte is one leading `1`, the rest the number in base 58. */
export function encodeBase58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  let n = 0n;
  for (let i = zeros; i < bytes.length; i += 1) n = n * 256n + BigInt(bytes[i]!);
  let digits = '';
  while (n > 0n) {
    digits = BASE58_ALPHABET[Number(n % 58n)] + digits;
    n /= 58n;
  }
  return BASE58_ALPHABET[0]!.repeat(zeros) + digits;
}

export function decodeBase58btc(value: string): Uint8Array {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === BASE58_ALPHABET[0]) zeros += 1;
  let n = 0n;
  for (let i = zeros; i < value.length; i += 1) {
    const digit = BASE58_INDEX.get(value[i]!);
    if (digit === undefined) throw new Error(`Invalid base58 character: ${value[i]}`);
    n = n * 58n + BigInt(digit);
  }
  const rest: number[] = [];
  while (n > 0n) {
    rest.unshift(Number(n % 256n));
    n /= 256n;
  }
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...rest]);
}
