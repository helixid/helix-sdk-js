// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The legacy §6.2 delegation credential (SPEC.md §6.2, §6.4) as the SDK reads
 * it, for the `delegation-chain` and `status-list` vector categories (story
 * F-2): `credentialSubject.delegation`, an Ed25519 signature over the RFC
 * 8785 bytes of the credential without its `proof` (no hash of the proof
 * options), `proofValue` base64url, and the VC-JWT form. Helix issues the
 * §6.10 profile; this reading exists so the SDK passes the vectors written in
 * the earlier shape. The key retrieval follows SPEC §6.2 and W3C Controlled
 * Identifiers §3.3: a method of the issuer, uniquely defined, controlled by
 * the issuer, with a type, listed under `assertionMethod`, carrying an
 * Ed25519 key in any of the forms a DID document writes one.
 */

import * as ed25519 from '@noble/ed25519';
import { canonicalize } from '../jcs.js';
import { base64UrlDecodeStrict, verificationMethodToJwk, type JwsVerificationMethod } from '../jws.js';
import { readSignatureBase64 } from './delegation-binding.js';

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);

/** An identifier written relative to `did` (`#fragment`), or undefined when it names no method of `did`. */
function relative(identifier: unknown, did: string): string | undefined {
  if (typeof identifier !== 'string') return undefined;
  if (identifier.startsWith('#')) return identifier;
  if (identifier === did) return '';
  if (identifier.startsWith(`${did}#`)) return identifier.slice(did.length);
  return undefined;
}

/**
 * The Ed25519 key `name` names among `did`'s assertion methods in `document`
 * (`named` false: the method the first `assertionMethod` entry names), or
 * undefined: the document must be `did`'s, the method listed under
 * `assertionMethod`, defined exactly once among `verificationMethod` and the
 * embedded entries, with a non-empty `id`, `type` and `controller`, the
 * controller `did`, and an Ed25519 public key (`publicKeyJwk`,
 * `publicKeyMultibase` or `publicKeyBase58`).
 */
export function assertionKey(document: unknown, did: string, name: unknown, named: boolean): Uint8Array | undefined {
  if (!isObject(document) || document['id'] !== did || did.includes('#')) return undefined;
  const entries = document['assertionMethod'];
  if (!Array.isArray(entries)) return undefined;
  let wanted: unknown = name;
  if (!named) {
    const first: unknown = entries[0];
    wanted = isObject(first) ? first['id'] : first;
  } else if (typeof wanted !== 'string' || wanted === '') {
    return undefined;
  } else if (!wanted.startsWith('did:') && !wanted.startsWith('#')) {
    wanted = `#${wanted}`;
  }
  const target = relative(wanted, did);
  if (target === undefined) return undefined;
  const published = Array.isArray(document['verificationMethod']) ? (document['verificationMethod'] as unknown[]) : [];
  const definitions = [...published, ...entries].filter((entry): entry is JsonObject => isObject(entry) && relative(entry['id'], did) === target);
  const listed = entries.some((entry) => relative(isObject(entry) ? entry['id'] : entry, did) === target);
  if (!listed || definitions.length !== 1) return undefined;
  const method = definitions[0]!;
  if (!['id', 'type', 'controller'].every((field) => typeof method[field] === 'string' && (method[field] as string).length > 0)) return undefined;
  if (method['controller'] !== did) return undefined;
  try {
    const key = base64UrlDecodeStrict(verificationMethodToJwk(method as JwsVerificationMethod).x);
    return key !== undefined && key.length === 32 ? key : undefined;
  } catch {
    return undefined;
  }
}

/** The issuer DID a credential names: a string, or an object's `id`. */
export function issuerDid(issuer: unknown): string | undefined {
  if (typeof issuer === 'string' && issuer.length > 0) return issuer;
  if (isObject(issuer) && typeof issuer['id'] === 'string' && issuer['id'].length > 0) return issuer['id'];
  return undefined;
}

function verifies(signature: Uint8Array, data: Uint8Array, key: Uint8Array): boolean {
  try {
    return signature.length === 64 && ed25519.verify(signature, data, key);
  } catch {
    return false;
  }
}

/**
 * The embedded §6.2 proof of a credential object (or a status list): type
 * `Ed25519Signature2020` or `DataIntegrityProof`, purpose `assertionMethod`
 * or none, the key `verificationMethod` names in the issuer's document, and
 * an Ed25519 signature over JCS(credential without `proof`).
 */
export function verifyLegacyProof(credential: unknown, documents: Record<string, unknown>): string | undefined {
  if (!isObject(credential)) return 'not a credential object';
  const proof = credential['proof'];
  if (!isObject(proof)) return 'no proof';
  if (proof['type'] !== 'Ed25519Signature2020' && proof['type'] !== 'DataIntegrityProof') return 'unsupported proof type';
  if (proof['proofPurpose'] !== undefined && proof['proofPurpose'] !== 'assertionMethod') return 'proof is not for assertionMethod';
  const did = issuerDid(credential['issuer']);
  if (did === undefined) return 'no issuer';
  const method = proof['verificationMethod'];
  if (method !== undefined && (typeof method !== 'string' || method === '')) return 'verificationMethod names no key';
  const key = assertionKey(documents[did], did, method, method !== undefined);
  if (key === undefined) return 'no assertionMethod key of the issuer';
  const signature = typeof proof['proofValue'] === 'string' ? readSignatureBase64(proof['proofValue'], false) : undefined;
  if (signature === undefined) return 'proofValue is no signature';
  const unsigned: JsonObject = { ...credential };
  delete unsigned['proof'];
  let data: Uint8Array;
  try {
    data = new TextEncoder().encode(canonicalize(unsigned));
  } catch {
    return 'credential has no canonical form';
  }
  return verifies(signature, data, key) ? undefined : 'signature does not verify';
}

/** A VC-JWT, verified: its credential, or the refusal. */
export function verifyVcJwt(jwt: string, documents: Record<string, unknown>, nowMs: number): { credential: JsonObject } | { refusal: string } {
  const segments = jwt.split('.');
  if (segments.length !== 3) return { refusal: 'a VC-JWT is three segments' };
  const read = (segment: string): unknown => {
    const bytes = readSignatureBase64(segment, true);
    if (bytes === undefined) return undefined;
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      return undefined;
    }
  };
  const header = read(segments[0]!);
  const payload = read(segments[1]!);
  if (!isObject(header) || !isObject(payload) || header['alg'] !== 'EdDSA') return { refusal: 'not an EdDSA VC-JWT' };
  if ('kid' in header && (typeof header['kid'] !== 'string' || header['kid'] === '')) return { refusal: 'kid names no key' };
  const vc = payload['vc'];
  const iss = payload['iss'];
  if (!isObject(vc) || typeof iss !== 'string' || issuerDid(vc['issuer']) !== iss) return { refusal: 'the credential is not the iss claim\'s' };
  for (const claim of ['exp', 'nbf'] as const) {
    if (payload[claim] !== undefined && (typeof payload[claim] !== 'number' || !Number.isFinite(payload[claim]))) return { refusal: `${claim} is not a NumericDate` };
  }
  if (typeof payload['exp'] === 'number' && nowMs / 1000 >= payload['exp']) return { refusal: 'expired (exp)' };
  if (typeof payload['nbf'] === 'number' && nowMs / 1000 + 30 < payload['nbf']) return { refusal: 'not yet valid (nbf)' };
  const key = assertionKey(documents[iss], iss, header['kid'], 'kid' in header);
  if (key === undefined) return { refusal: 'no assertionMethod key of the issuer' };
  const signature = readSignatureBase64(segments[2]!, true);
  if (signature === undefined) return { refusal: 'signature segment is not base64url' };
  const data = new TextEncoder().encode(`${segments[0]}.${segments[1]}`);
  return verifies(signature, data, key) ? { credential: vc } : { refusal: 'signature does not verify' };
}

interface Delegation {
  id: string;
  issuerDid: string;
  subjectDid: string;
  parentId?: string;
  scopes?: unknown;
  constraints?: { scopes?: unknown; audience?: unknown; notBefore?: unknown; notAfter?: unknown };
  status?: unknown;
}

/** The shape §6.2 requires of a delegation credential; the delegation, or the refusal. */
export function legacyDelegation(credential: unknown, nowMs: number): { delegation: Delegation } | { refusal: string } {
  if (!isObject(credential)) return { refusal: 'not a credential object' };
  const types = credential['type'];
  if (!Array.isArray(types) || !types.includes('VerifiableCredential') || !types.includes('DelegationCredential')) return { refusal: 'not a DelegationCredential' };
  const subject = credential['credentialSubject'];
  if (!isObject(subject) || Object.keys(subject).some((key) => key !== 'id' && key !== 'delegation')) return { refusal: 'credentialSubject carries more than id and delegation' };
  const delegation = subject['delegation'];
  if (!isObject(delegation) || typeof delegation['id'] !== 'string' || typeof delegation['issuerDid'] !== 'string' || typeof delegation['subjectDid'] !== 'string') {
    return { refusal: 'delegation is malformed' };
  }
  if (delegation['status'] !== 'active') return { refusal: 'delegation is not active' };
  if (issuerDid(credential['issuer']) === undefined) return { refusal: 'no issuer' };
  const expiration = credential['expirationDate'];
  if (typeof expiration === 'string' && Date.parse(expiration) <= nowMs) return { refusal: 'expired' };
  const constraints = isObject(delegation['constraints']) ? delegation['constraints'] : {};
  if (typeof constraints['notAfter'] === 'number' && constraints['notAfter'] * 1000 <= nowMs) return { refusal: 'expired (notAfter)' };
  if (typeof constraints['notBefore'] === 'number' && constraints['notBefore'] * 1000 > nowMs) return { refusal: 'not yet valid (notBefore)' };
  return { delegation: delegation as unknown as Delegation };
}

function scopesOf(delegation: Delegation): string[] {
  const out = new Set<string>();
  for (const list of [delegation.scopes, delegation.constraints?.scopes]) {
    if (Array.isArray(list)) for (const scope of list) if (typeof scope === 'string') out.add(scope);
  }
  return [...out];
}

function audienceAdmits(delegation: Delegation, serverDid: string): boolean {
  const audience = delegation.constraints?.audience;
  if (audience === undefined || audience === null || audience === '') return true;
  if (typeof audience === 'string') return audience === serverDid;
  return Array.isArray(audience) && audience.includes(serverDid);
}

/**
 * A §6.2 chain, root first, against `serverDid`: every credential of the
 * delegation shape and verified, one line of descent (ids unrepeated; the
 * root names no parent and is issued by its `issuerDid`; each child names
 * its parent and is issued by the parent's subject), every audience admits
 * the server, and every re-delegation narrows its parent's scopes (a parent
 * with none grants none). Undefined when it holds, else the refusal.
 */
export function legacyChainRefusal(chain: readonly unknown[], serverDid: string, documents: Record<string, unknown>, nowMs: number, verified: ReadonlySet<unknown> = new Set()): string | undefined {
  const delegations: Delegation[] = [];
  for (const credential of chain) {
    const shaped = legacyDelegation(credential, nowMs);
    if ('refusal' in shaped) return shaped.refusal;
    delegations.push(shaped.delegation);
  }
  const seen = new Set<string>();
  let parent: Delegation | undefined;
  for (const [index, delegation] of delegations.entries()) {
    if (seen.has(delegation.id)) return `delegation ${delegation.id} repeats`;
    seen.add(delegation.id);
    const issuer = issuerDid((chain[index] as JsonObject)['issuer']);
    if (parent === undefined) {
      if (delegation.parentId) return 'the root names a parent';
      if (issuer !== delegation.issuerDid) return 'the root is not issued by its issuerDid';
    } else {
      if (delegation.parentId !== parent.id) return `delegation ${delegation.id} does not name its parent`;
      if (delegation.issuerDid !== parent.subjectDid || issuer !== parent.subjectDid) return `delegation ${delegation.id} is not issued by its parent's subject`;
      const parentScopes = scopesOf(parent);
      const childScopes = scopesOf(delegation);
      if (parentScopes.length === 0 ? childScopes.length > 0 : childScopes.length === 0 || childScopes.some((scope) => !parentScopes.includes(scope))) {
        return `delegation ${delegation.id} widens its parent's scopes`;
      }
    }
    if (!audienceAdmits(delegation, serverDid)) return `delegation ${delegation.id} is for another audience`;
    parent = delegation;
  }
  for (const credential of chain) {
    if (verified.has(credential)) continue;
    const refusal = verifyLegacyProof(credential, documents);
    if (refusal !== undefined) return refusal;
  }
  return undefined;
}
