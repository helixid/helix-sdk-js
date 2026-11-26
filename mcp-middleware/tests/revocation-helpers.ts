// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// KYA-OS story L3-C test helpers: signed status lists (eddsa-jcs-2022) by a did:web issuer, served by a static fetch.

import { gzipSync } from 'node:zlib';
import { base58btcEncode, buildDIDDocument, generateKeyPair, kyaos, signData } from '@helixid/sdk-js';

export interface ListIssuer {
  did: string;
  privateKeyHex: string;
  document: Record<string, unknown>;
  signer: kyaos.Signer;
}

export function listIssuer(did: string): ListIssuer {
  const pair = generateKeyPair();
  return {
    did,
    privateKeyHex: pair.privateKey,
    document: buildDIDDocument(did, pair.publicKey) as unknown as Record<string, unknown>,
    signer: new kyaos.EnvSigner({ did, envVar: 'K', env: { K: pair.privateKey } }),
  };
}

/** `length` bytes with the listed bits set, MSB first, GZIP, multibase `u`. */
export function encodedBits(length: number, set: number[] = []): string {
  const bytes = new Uint8Array(length);
  for (const index of set) bytes[Math.floor(index / 8)]! |= 0x80 >> index % 8;
  return `u${gzipSync(bytes).toString('base64url')}`;
}

export interface ListOptions {
  set?: number[];
  purpose?: string;
  validFrom?: string;
  validUntil?: string;
  unsigned?: boolean;
  signedBy?: ListIssuer;
}

/** A Bitstring Status List v1.0 credential at `url`, signed by `issuer` (or `signedBy`) unless `unsigned`. */
export function bitstringList(url: string, issuer: ListIssuer, options: ListOptions = {}): Record<string, unknown> {
  const list: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: url,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: issuer.did,
    validFrom: options.validFrom ?? '2026-01-01T00:00:00Z',
    validUntil: options.validUntil ?? '2027-01-01T00:00:00Z',
    credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: options.purpose ?? 'revocation', encodedList: encodedBits(16, options.set) },
  };
  if (options.unsigned) return list;
  return signList(list, (options.signedBy ?? issuer).privateKeyHex, `${issuer.did}#key-1`);
}

/** `list` with an eddsa-jcs-2022 DataIntegrityProof by the key `privateKeyHex`, naming `verificationMethod`. */
export function signList(list: Record<string, unknown>, privateKeyHex: string, verificationMethod: string): Record<string, unknown> {
  const unsecured = { ...list };
  delete unsecured['proof'];
  const config = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-01-01T00:00:00Z', verificationMethod, proofPurpose: 'assertionMethod' };
  const signature = signData(kyaos.verifier.hashData({ ...config, '@context': unsecured['@context'] }, unsecured), privateKeyHex);
  return { ...unsecured, proof: { ...config, proofValue: `z${base58btcEncode(new Uint8Array(Buffer.from(signature, 'hex')))}` } };
}


/** The did:web document URL of a bare-host DID, as the resolver asks for it. */
export function wellKnownDidUrl(did: string): string {
  return `https://${decodeURIComponent(did.slice('did:web:'.length))}/.well-known/did.json`;
}
