// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Test helpers for story L3-C: did:key issuers, signed status lists in both
 * formats and both proof suites, and a fetch that serves them.
 */

import { gzipSync } from 'node:zlib';
import * as ed25519 from '@noble/ed25519';
import { canonicalize } from '../../../../src/core/kyaos/jcs.js';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { generateKeyPair } from '../../../../src/core/keys.js';
import { base58btcEncode } from '../../../../src/core/vp-crypto.js';

export interface TestIssuer {
  did: string;
  kid: string;
  privateKeyHex: string;
  /** A Signer over the key, for `signJws`. */
  signer: { did: string; kid: string; sign(data: Uint8Array): Promise<Uint8Array> };
}

export function didKeyOf(publicKeyHex: string): string {
  return `did:key:z${base58btcEncode(new Uint8Array([0xed, 0x01, ...Buffer.from(publicKeyHex, 'hex')]))}`;
}

export function makeIssuer(): TestIssuer {
  const pair = generateKeyPair();
  const did = didKeyOf(pair.publicKey);
  const fragment = did.slice('did:key:'.length);
  const privateKey = Buffer.from(pair.privateKey, 'hex').subarray(-32);
  return {
    did,
    kid: `${did}#${fragment}`,
    privateKeyHex: pair.privateKey,
    signer: { did, kid: fragment, sign: async (data) => ed25519.sign(data, privateKey) },
  };
}

/** Resolves did:key offline, the way the verifier's own resolver does. */
export const resolveDidKey: verifier.DidResolver = async (did) => verifier.didKeyDocument(did) ?? null;

export function encodeBits(bytes: number[] | Uint8Array, multibase = true): string {
  const encoded = gzipSync(Buffer.from(bytes)).toString('base64url');
  return multibase ? `u${encoded}` : encoded;
}

/** `length` bytes of zeros with the listed bit indexes set, MSB first. */
export function bitsWith(length: number, set: number[] = []): Uint8Array {
  const bytes = new Uint8Array(length);
  for (const index of set) bytes[Math.floor(index / 8)]! |= 0x80 >> index % 8;
  return bytes;
}

export interface ListInput {
  url: string;
  issuer: TestIssuer;
  bits?: Uint8Array;
  format?: 'bitstring' | 'statuslist2021';
  purpose?: string | string[];
  validFrom?: string;
  validUntil?: string;
  omitId?: boolean;
}

export function unsignedList(input: ListInput): Record<string, unknown> {
  const bitstring = (input.format ?? 'bitstring') === 'bitstring';
  return {
    '@context': bitstring ? ['https://www.w3.org/ns/credentials/v2'] : ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    ...(input.omitId ? {} : { id: input.url }),
    type: ['VerifiableCredential', bitstring ? 'BitstringStatusListCredential' : 'StatusList2021Credential'],
    issuer: input.issuer.did,
    ...(bitstring
      ? { validFrom: input.validFrom ?? '2026-01-01T00:00:00Z', validUntil: input.validUntil ?? '2027-01-01T00:00:00Z' }
      : { issuanceDate: input.validFrom ?? '2026-01-01T00:00:00Z', ...(input.validUntil ? { expirationDate: input.validUntil } : {}) }),
    credentialSubject: {
      id: `${input.url}#list`,
      type: bitstring ? 'BitstringStatusList' : 'StatusList2021',
      statusPurpose: input.purpose ?? 'revocation',
      encodedList: encodeBits(input.bits ?? bitsWith(16)),
    },
  };
}

/** `document` with an `eddsa-jcs-2022` DataIntegrityProof by `issuer`. */
export function signDataIntegrity(document: Record<string, unknown>, issuer: TestIssuer): Record<string, unknown> {
  const config: Record<string, unknown> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-01-01T00:00:00Z',
    verificationMethod: issuer.kid,
    proofPurpose: 'assertionMethod',
  };
  const unsecured = { ...document };
  delete unsecured['proof'];
  const signed = verifier.hashData({ ...config, '@context': unsecured['@context'] }, unsecured);
  const signature = ed25519.sign(signed, Buffer.from(issuer.privateKeyHex, 'hex').subarray(-32));
  return { ...unsecured, proof: { ...config, proofValue: `z${base58btcEncode(signature)}` } };
}

/** `document` with an `Ed25519Signature2020` proof over JCS(document minus proof), the SPEC.md §6.2 suite. */
export function signLegacy(document: Record<string, unknown>, issuer: TestIssuer): Record<string, unknown> {
  const unsecured = { ...document };
  delete unsecured['proof'];
  const signature = ed25519.sign(new TextEncoder().encode(canonicalize(unsecured)), Buffer.from(issuer.privateKeyHex, 'hex').subarray(-32));
  return {
    ...unsecured,
    proof: { type: 'Ed25519Signature2020', created: '2026-01-01T00:00:00Z', verificationMethod: issuer.kid, proofPurpose: 'assertionMethod', proofValue: Buffer.from(signature).toString('base64url') },
  };
}

export function signedList(input: ListInput): Record<string, unknown> {
  return signDataIntegrity(unsignedList(input), input.issuer);
}

/** A fetch over a map of URL to body (or to a status code), counting calls. */
export function servingFetch(bodies: Map<string, unknown>): verifier.StatusListHttpFetch & { calls: string[] } {
  const calls: string[] = [];
  const fetcher = async (url: string): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> => {
    calls.push(url);
    const body = bodies.get(url);
    if (body === undefined) return { ok: false, status: 404, json: async () => ({}) };
    if (typeof body === 'number') return { ok: body < 300, status: body, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => body };
  };
  return Object.assign(fetcher, { calls });
}

export function entryFor(url: string, index: number, purpose: 'revocation' | 'suspension' = 'revocation'): verifier.BitstringStatusEntry {
  return { id: `${url}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: purpose, statusListIndex: String(index), statusListCredential: url };
}
