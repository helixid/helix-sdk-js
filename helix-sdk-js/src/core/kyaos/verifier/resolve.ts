// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The DID resolution a verifier's seams are built from (KYA-OS story F-2):
 * did:key locally, from the DID itself (SPEC.md §4.3), and did:web from the
 * document at its well-known URL (§4.4) over an injected fetch. Nothing
 * here reads a Helix database (stories rule 4): a deployment's agents and
 * services are reached the way any other deployment's are, by public
 * resolution. Where helix-core's SafeFetch is available the caller injects
 * it as `fetch`; the default accepts `https:` only.
 */

import { base64UrlDecodeStrict, verificationMethodToJwk, type Ed25519PublicJwk, type JwsDidDocument, type JwsVerificationMethod } from '../jws.js';
import { base58btcDecode } from '../../vp-crypto.js';

const ED25519_MULTICODEC = [0xed, 0x01] as const;
const ED25519_KEY_LENGTH = 32;
/** Longest base58btc part worth decoding: an Ed25519 did:key is always 47 characters. */
const MAX_DID_KEY_BASE58_LENGTH = 64;

/** The 32 raw bytes of an Ed25519 did:key, or undefined for any other DID. */
export function publicKeyOfDidKey(did: string): Uint8Array | undefined {
  if (!did.startsWith('did:key:z6Mk')) return undefined;
  const encoded = did.slice('did:key:z'.length);
  if (encoded.length > MAX_DID_KEY_BASE58_LENGTH) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base58btcDecode(encoded);
  } catch {
    return undefined;
  }
  if (bytes.length !== ED25519_MULTICODEC.length + ED25519_KEY_LENGTH) return undefined;
  if (bytes[0] !== ED25519_MULTICODEC[0] || bytes[1] !== ED25519_MULTICODEC[1]) return undefined;
  return bytes.slice(ED25519_MULTICODEC.length);
}

/** The DID document an Ed25519 did:key resolves to, or undefined when `did` is not one. */
export function didKeyDocument(did: string): JwsDidDocument | undefined {
  const publicKey = publicKeyOfDidKey(did);
  if (publicKey === undefined) return undefined;
  const fragment = did.slice('did:key:'.length);
  const id = `${did}#${fragment}`;
  const method: JwsVerificationMethod = {
    id,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey).toString('base64url') },
    publicKeyMultibase: fragment,
  };
  return { id: did, verificationMethod: [method], authentication: [id], assertionMethod: [id] };
}

/** A did:web host that is a host and nothing more, with an optional port, or undefined. */
function didWebHost(label: string): string | undefined {
  let host: string;
  try {
    host = decodeURIComponent(label);
  } catch {
    return undefined;
  }
  if (host.length === 0 || /[@/\\?#%\s\p{Cc}]/u.test(host)) return undefined;
  const afterLiteral = host.startsWith('[') ? host.slice(host.indexOf(']') + 1) : host;
  return afterLiteral.split(':').length <= 2 ? host : undefined;
}

/** The HTTPS URL of a did:web document (`/.well-known/did.json`, or `/<path>/did.json`), or undefined. */
export function didWebDocumentUrl(did: string): string | undefined {
  if (!did.startsWith('did:web:')) return undefined;
  const parts = did.slice('did:web:'.length).split(':');
  const host = didWebHost(parts[0] ?? '');
  if (host === undefined) return undefined;
  let path: string[];
  try {
    path = parts.slice(1).map((part) => decodeURIComponent(part));
  } catch {
    return undefined;
  }
  const isSegment = (segment: string): boolean => segment !== '' && segment !== '.' && segment !== '..' && !/[/\\?#%]/.test(segment);
  if (!path.every(isSegment)) return undefined;
  return path.length === 0 ? `https://${host}/.well-known/did.json` : `https://${host}/${path.join('/')}/did.json`;
}

/** The subset of `fetch` the resolver needs; helix-core's SafeFetch fits it. */
export type JsonFetch = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface DidResolverOptions {
  /** How documents are fetched; default the global `fetch`. */
  fetch?: JsonFetch | undefined;
  /** Rewrites a resolution URL before the fetch (a loopback `http:` host in development, say). Default: none. */
  rewriteUrl?: ((url: string) => string) | undefined;
}

/**
 * A `resolveDid` seam: did:key offline, did:web through `fetch`. Resolves
 * to `null` for a DID of another method, a document that cannot be
 * fetched, or one whose `id` is not the DID (a substitution).
 */
export function createDidResolver(options: DidResolverOptions = {}): (did: string) => Promise<JwsDidDocument | null> {
  const doFetch = options.fetch ?? ((url: string): ReturnType<JsonFetch> => fetch(url));
  return async (did: string): Promise<JwsDidDocument | null> => {
    if (did.startsWith('did:key:')) return didKeyDocument(did) ?? null;
    const url = didWebDocumentUrl(did);
    if (url === undefined) return null;
    const response = await doFetch(options.rewriteUrl ? options.rewriteUrl(url) : url);
    if (!response.ok) return null;
    const document = (await response.json()) as JwsDidDocument;
    if (document === null || typeof document !== 'object' || document.id !== did) return null;
    return document;
  };
}

/** Every Ed25519 key a DID document publishes under `verificationMethod`, as public JWKs with their `kid`. */
export function ed25519KeysOf(document: JwsDidDocument): Ed25519PublicJwk[] {
  const keys: Ed25519PublicJwk[] = [];
  for (const method of Array.isArray(document.verificationMethod) ? document.verificationMethod : []) {
    if (method === null || typeof method !== 'object' || typeof method.id !== 'string') continue;
    try {
      const jwk = verificationMethodToJwk(method);
      if (base64UrlDecodeStrict(jwk.x)?.length === 32) keys.push({ ...jwk, kid: method.id.startsWith('#') ? `${document.id}${method.id}` : method.id });
    } catch {
      // A method without a usable Ed25519 key publishes nothing for this check.
    }
  }
  return keys;
}

/** A `resolveDidKeys` seam over a `resolveDid` seam: the Ed25519 keys the DID's document publishes. */
export function createDidKeysResolver(resolveDid: (did: string) => Promise<JwsDidDocument | null | undefined>): (did: string) => Promise<Ed25519PublicJwk[]> {
  return async (did: string): Promise<Ed25519PublicJwk[]> => {
    const document = await resolveDid(did);
    if (document === null || document === undefined) throw new Error(`DID ${did} did not resolve`);
    return ed25519KeysOf(document);
  };
}
