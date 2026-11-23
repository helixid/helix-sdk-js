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
 * KYA-OS Entity Cards in the SDK (story C-A): `resolveEntityCard(did)`, the
 * two-step discovery of SPEC-ENTITY-CARD §6.5 (`did.json` → the
 * `KyaOsEntityCard` service entry → `card.json`, the `/.well-known/kya-os-card.json`
 * fallback for a bare host, the service entry winning when both exist, a
 * did:key refused by discovery), every read through a SafeFetch (§6.6:
 * https only, public unicast only, the connection pinned to the checked
 * address, same-origin redirects only, a 1 MiB cap, a 5 s deadline), and
 * the strict card schema (§4: an unknown top-level field is refused; a
 * `conformanceLevel` is read but never trusted).
 *
 * Also here, for the MCP middleware that serves a service's own identity:
 * `buildEntityCard`, the `server.json` projection (`serverCardMeta`), and
 * its reverse (`resolveEntityCardFromServerMeta`, which falls back to the
 * canonical card when the projection was stripped).
 *
 * The SDK does not depend on `@helixid/core` (stories rule 24), so this is
 * its own copy of helix-core's `src/core/card/*` and `src/core/net/*`,
 * asserted against the same fixture (`fixtures/kya-os-helix/entity-card.json`).
 */

import { BlockList, isIP } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import { HelixError } from './HelixError.js';

// ── Errors ──────────────────────────────────────────────────────────────────

export class EntityCardError extends HelixError {
  constructor(
    public readonly reason: string,
    message: string,
  ) {
    super('ENTITY_CARD_INVALID', message, 400, { reason });
  }
}

export class SafeFetchRefusedError extends HelixError {
  constructor(
    public readonly reason: string,
    message: string,
  ) {
    super('SAFE_FETCH_REFUSED', message, 502, { reason });
  }
}

// ── did:web ─────────────────────────────────────────────────────────────────

export const KYA_OS_CARD_SERVICE_TYPE = 'KyaOsEntityCard';
export const KYA_OS_CARD_SERVICE_ID = '#kya-os-card';
export const KYA_OS_CARD_META_KEY = 'org.kya-os/card';
export const KYA_OS_CARD_REF_KEY = 'org.kya-os/cardRef';
export const KYA_OS_CARD_WELL_KNOWN_PATH = '.well-known/kya-os-card.json';
export const PROOF_PROFILE_V1 = 'org.kya-os/proof.v1';

export interface ParsedDidWeb {
  host: string;
  path: string[];
}

export function parseDidWeb(did: string): ParsedDidWeb | undefined {
  if (typeof did !== 'string' || !did.startsWith('did:web:')) return undefined;
  const parts = did.slice('did:web:'.length).split(':');
  if (parts.some((part) => part.length === 0)) return undefined;
  let decoded: string[];
  try {
    decoded = parts.map(decodeURIComponent);
  } catch {
    return undefined;
  }
  const [host, ...path] = decoded;
  if (host === undefined || host.length === 0 || /[/#?]/.test(host)) return undefined;
  if (path.some((segment) => segment.length === 0 || /[/#?]/.test(segment) || segment === '.' || segment === '..')) return undefined;
  return { host, path };
}

function requireDidWeb(did: string): ParsedDidWeb {
  const parsed = parseDidWeb(did);
  if (parsed === undefined) throw new EntityCardError('malformed_did', `${did} is not a did:web DID that names a URL`);
  return parsed;
}

/** `did:web:<host>:<seg>…`, every segment percent-encoded, the host lowercased. */
export function didWebFor(host: string, segments: readonly string[] = []): string {
  return ['did:web', encodeURIComponent(host.toLowerCase()), ...segments.map(encodeURIComponent)].join(':');
}

/** A loopback host (a local stack) serves plain http; SafeFetch admits it only in development mode. */
export function isLoopbackHost(host: string): boolean {
  const hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

const schemeFor = (host: string): string => (isLoopbackHost(host) ? 'http' : 'https');

export function didWebDocumentUrl(did: string): string {
  const { host, path } = requireDidWeb(did);
  return path.length === 0 ? `${schemeFor(host)}://${host}/.well-known/did.json` : `${schemeFor(host)}://${host}/${path.map(encodeURIComponent).join('/')}/did.json`;
}

export function didWebCardUrl(did: string): string {
  const { host, path } = requireDidWeb(did);
  return path.length === 0 ? `${schemeFor(host)}://${host}/${KYA_OS_CARD_WELL_KNOWN_PATH}` : `${schemeFor(host)}://${host}/${path.map(encodeURIComponent).join('/')}/card.json`;
}

export function normalizeDid(did: string): string {
  if (!did.startsWith('did:web:')) return did;
  const [host = '', ...path] = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  return `did:web:${[host.toLowerCase(), ...path].map(encodeURIComponent).join(':')}`;
}

export function sameDid(a: string, b: string): boolean {
  try {
    return normalizeDid(a) === normalizeDid(b);
  } catch {
    return false;
  }
}

/** The `KyaOsEntityCard` service endpoint a DID document anchors, or undefined. */
export function cardEndpointOf(document: unknown): string | undefined {
  const services = (document as { service?: unknown })?.service;
  if (!Array.isArray(services)) return undefined;
  for (const entry of services) {
    if (typeof entry === 'object' && entry !== null && (entry as { type?: unknown }).type === KYA_OS_CARD_SERVICE_TYPE) {
      const endpoint = (entry as { serviceEndpoint?: unknown }).serviceEndpoint;
      if (typeof endpoint === 'string') return endpoint;
    }
  }
  return undefined;
}

export function kyaOsCardServiceEntry(serviceEndpoint: string): { id: string; type: string; serviceEndpoint: string } {
  return { id: KYA_OS_CARD_SERVICE_ID, type: KYA_OS_CARD_SERVICE_TYPE, serviceEndpoint };
}

// ── The card ────────────────────────────────────────────────────────────────

export type EntityType = 'mcp' | 'agent' | 'client' | 'verifier' | 'human';
export const ENTITY_TYPES: readonly EntityType[] = ['mcp', 'agent', 'client', 'verifier', 'human'];

export interface BitstringStatusListEntry {
  statusListCredential: string;
  statusListIndex: string;
  statusSize?: number;
  statusMessage?: { status: string; message: string }[];
}

export interface Level2Capability {
  name: string;
  attestations: { vc: string | Record<string, unknown>; [member: string]: unknown }[];
}

export type Capability = string | Level2Capability;

export interface EntityCard {
  id: string;
  entityType: EntityType;
  name: string;
  kid?: string;
  publicKeyJwk?: { kty: 'OKP'; crv: 'Ed25519'; x: string; kid?: string; use?: string };
  createdAt?: string;
  capabilities?: Capability[];
  /** Read, never trusted: a verifier recomputes the level. */
  conformanceLevel?: 'L1' | 'L2' | 'L3';
  responsibleParty?: string;
  principal?: string;
  delegationRef?: string;
  attestations?: { type: 'IdentityVerification' | 'CapabilityAttestation'; vc: string | Record<string, unknown>; subject?: string; issuer?: string }[];
  didDocument?: string;
  proofProfile?: 'org.kya-os/proof.v1' | 'org.kya-os/proof@1';
  cimd?: { clientId: string; jwksUri: string };
  revocation?: BitstringStatusListEntry;
}

const DID_PATTERN = /^did:(?:key|web):(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;
const CARD_MEMBERS = new Set(['id', 'entityType', 'name', 'kid', 'publicKeyJwk', 'createdAt', 'capabilities', 'conformanceLevel', 'responsibleParty', 'principal', 'delegationRef', 'attestations', 'didDocument', 'proofProfile', 'cimd', 'revocation']);

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

function strictObject(value: unknown, path: string, allowed: readonly string[], issues: string[]): Record<string, unknown> | undefined {
  if (!isRecord(value)) {
    issues.push(`${path}: must be of type object`);
    return undefined;
  }
  for (const member of Object.keys(value)) {
    if (!allowed.includes(member)) issues.push(`${path}/${member}: must NOT have additional properties`);
  }
  return value;
}

function checkDid(value: unknown, path: string, issues: string[]): void {
  if (typeof value !== 'string' || !DID_PATTERN.test(value)) issues.push(`${path}: must be a did:key or did:web DID`);
}

function checkStatusEntry(value: unknown, path: string, issues: string[]): void {
  const entry = strictObject(value, path, ['statusListCredential', 'statusListIndex', 'statusSize', 'statusMessage'], issues);
  if (!entry) return;
  if (!isNonEmptyString(entry['statusListCredential'])) issues.push(`${path}/statusListCredential: must be a non-empty string`);
  if (typeof entry['statusListIndex'] !== 'string' || !/^[0-9]+$/.test(entry['statusListIndex'])) issues.push(`${path}/statusListIndex: must match ^[0-9]+$`);
  if (entry['statusSize'] !== undefined && (!Number.isInteger(entry['statusSize']) || (entry['statusSize'] as number) < 1)) issues.push(`${path}/statusSize: must be an integer of at least 1`);
  if (entry['statusMessage'] !== undefined) {
    if (!Array.isArray(entry['statusMessage'])) issues.push(`${path}/statusMessage: must be an array`);
    else entry['statusMessage'].forEach((message, index) => {
      if (!isRecord(message) || typeof message['status'] !== 'string' || typeof message['message'] !== 'string') issues.push(`${path}/statusMessage/${index}: must have string status and message`);
    });
  }
}

/** The issues `value` has against the strict card schema (empty: it is a card). */
export function validateEntityCard(value: unknown): string[] {
  const issues: string[] = [];
  const card = strictObject(value, '', [...CARD_MEMBERS], issues);
  if (!card) return issues;
  for (const required of ['id', 'entityType', 'name']) if (!(required in card)) issues.push(`: must have required property '${required}'`);
  if ('id' in card) checkDid(card['id'], '/id', issues);
  if ('entityType' in card && !ENTITY_TYPES.includes(card['entityType'] as EntityType)) issues.push(`/entityType: must be one of ${JSON.stringify(ENTITY_TYPES)}`);
  if ('name' in card && !isNonEmptyString(card['name'])) issues.push('/name: must be a non-empty string');
  for (const member of ['kid', 'delegationRef']) if (card[member] !== undefined && typeof card[member] !== 'string') issues.push(`/${member}: must be of type string`);
  if (card['publicKeyJwk'] !== undefined) {
    const jwk = strictObject(card['publicKeyJwk'], '/publicKeyJwk', ['kty', 'crv', 'x', 'kid', 'use'], issues);
    if (jwk) {
      if (jwk['kty'] !== 'OKP') issues.push('/publicKeyJwk/kty: must equal "OKP"');
      if (jwk['crv'] !== 'Ed25519') issues.push('/publicKeyJwk/crv: must equal "Ed25519"');
      if (typeof jwk['x'] !== 'string') issues.push('/publicKeyJwk/x: must be of type string');
      for (const member of ['kid', 'use']) if (jwk[member] !== undefined && typeof jwk[member] !== 'string') issues.push(`/publicKeyJwk/${member}: must be of type string`);
    }
  }
  if (card['createdAt'] !== undefined && (typeof card['createdAt'] !== 'string' || !RFC3339.test(card['createdAt']) || Number.isNaN(Date.parse(card['createdAt'])))) issues.push('/createdAt: must be an RFC 3339 date-time');
  if (card['capabilities'] !== undefined) {
    if (!Array.isArray(card['capabilities'])) issues.push('/capabilities: must be of type array');
    else card['capabilities'].forEach((capability, index) => {
      if (isNonEmptyString(capability)) return;
      const level2 = isRecord(capability) ? capability : undefined;
      const ok = level2 !== undefined && Object.keys(level2).every((member) => member === 'name' || member === 'attestations') && isNonEmptyString(level2['name']) && Array.isArray(level2['attestations']) && level2['attestations'].length > 0 && level2['attestations'].every((attestation) => isRecord(attestation) && (typeof attestation['vc'] === 'string' || isRecord(attestation['vc'])));
      if (!ok) issues.push(`/capabilities/${index}: must be a non-empty capability name or {name, attestations[]}`);
    });
  }
  if (card['conformanceLevel'] !== undefined && !['L1', 'L2', 'L3'].includes(card['conformanceLevel'] as string)) issues.push('/conformanceLevel: must be one of ["L1","L2","L3"]');
  for (const member of ['responsibleParty', 'principal']) if (card[member] !== undefined) checkDid(card[member], `/${member}`, issues);
  if (card['attestations'] !== undefined) {
    if (!Array.isArray(card['attestations'])) issues.push('/attestations: must be of type array');
    else card['attestations'].forEach((attestation, index) => {
      const entry = strictObject(attestation, `/attestations/${index}`, ['type', 'vc', 'subject', 'issuer'], issues);
      if (!entry) return;
      if (!['IdentityVerification', 'CapabilityAttestation'].includes(entry['type'] as string)) issues.push(`/attestations/${index}/type: must be one of ["IdentityVerification","CapabilityAttestation"]`);
      if (typeof entry['vc'] !== 'string' && !isRecord(entry['vc'])) issues.push(`/attestations/${index}/vc: must be a string or an object`);
      for (const member of ['subject', 'issuer']) if (entry[member] !== undefined) checkDid(entry[member], `/attestations/${index}/${member}`, issues);
    });
  }
  if (card['didDocument'] !== undefined) {
    try {
      new URL(card['didDocument'] as string);
    } catch {
      issues.push('/didDocument: must be a URI');
    }
  }
  if (card['proofProfile'] !== undefined && !['org.kya-os/proof.v1', 'org.kya-os/proof@1'].includes(card['proofProfile'] as string)) issues.push('/proofProfile: must be one of ["org.kya-os/proof.v1","org.kya-os/proof@1"]');
  if (card['cimd'] !== undefined) {
    const cimd = strictObject(card['cimd'], '/cimd', ['clientId', 'jwksUri'], issues);
    if (cimd) for (const member of ['clientId', 'jwksUri']) if (!isNonEmptyString(cimd[member])) issues.push(`/cimd/${member}: must be a non-empty string`);
  }
  if (card['revocation'] !== undefined) checkStatusEntry(card['revocation'], '/revocation', issues);
  return issues;
}

/** `parseCard`: the value as a card, or `EntityCardError` (reason `card_invalid`) naming the first issue. */
export function parseEntityCard(value: unknown): EntityCard {
  const issues = validateEntityCard(value);
  if (issues.length > 0) throw new EntityCardError('card_invalid', `Entity Card is invalid: ${issues.join('; ')}`);
  return value as EntityCard;
}

export const capabilityName = (capability: Capability): string => (typeof capability === 'string' ? capability : capability.name);

export interface BuildEntityCardInput {
  id: string;
  entityType: EntityType;
  name: string;
  /** Verification-method fragment (`key-1`) or full id (`<did>#key-1`). */
  kid?: string | undefined;
  /** The public half only: `{kty: "OKP", crv: "Ed25519", x}`; a `d` member is refused. */
  publicKeyJwk?: { kty: 'OKP'; crv: 'Ed25519'; x: string; kid?: string } | undefined;
  capabilities?: readonly Capability[] | undefined;
  responsibleParty?: string | undefined;
  principal?: string | undefined;
  delegationRef?: string | undefined;
  revocation?: BitstringStatusListEntry | undefined;
  didDocument?: string | undefined;
  createdAt?: string | undefined;
  attestations?: EntityCard['attestations'] | undefined;
  cimd?: EntityCard['cimd'] | undefined;
  proofProfile?: EntityCard['proofProfile'] | undefined;
  /** Ignored: never written to a card. */
  conformanceLevel?: unknown;
}

const INPUT_MEMBERS = new Set(['id', 'entityType', 'name', 'kid', 'publicKeyJwk', 'capabilities', 'responsibleParty', 'principal', 'delegationRef', 'revocation', 'didDocument', 'createdAt', 'attestations', 'cimd', 'proofProfile', 'conformanceLevel']);

/**
 * `card.json` for an entity: never a `conformanceLevel` (one on input is
 * ignored), never a proof (one on input, or any unknown member, is refused),
 * `proofProfile` v1 by default, the DID document URL derived for a did:web.
 */
export function buildEntityCard(input: BuildEntityCardInput): EntityCard {
  if (!isRecord(input)) throw new EntityCardError('card_invalid', 'buildEntityCard needs an input object');
  const foreign = Object.keys(input).filter((member) => !INPUT_MEMBERS.has(member));
  if (foreign.length > 0) throw new EntityCardError('card_invalid', `Entity Card input carries unknown members (${foreign.join(', ')}); a card never carries a proof or an unknown field`);
  if (input.publicKeyJwk !== undefined) {
    if (!isRecord(input.publicKeyJwk) || 'd' in input.publicKeyJwk) throw new EntityCardError('card_invalid', 'publicKeyJwk carries private material (d); only the public key is accepted');
    const foreignJwk = Object.keys(input.publicKeyJwk).filter((member) => !['kty', 'crv', 'x', 'kid'].includes(member));
    if (foreignJwk.length > 0) throw new EntityCardError('card_invalid', `publicKeyJwk carries unexpected members (${foreignJwk.join(', ')})`);
  }
  let kid = input.kid;
  if (kid !== undefined) {
    const hash = kid.indexOf('#');
    const owner = hash === -1 ? input.id : kid.slice(0, hash);
    const fragment = hash === -1 ? kid : kid.slice(hash + 1);
    if ((hash > 0 && owner !== input.id) || fragment.length === 0 || fragment.includes('#')) throw new EntityCardError('card_invalid', `kid ${kid} does not name one verification method of ${input.id}`);
    kid = `${input.id}#${fragment}`;
  }
  const publicKeyJwk = input.publicKeyJwk === undefined ? undefined : { kty: 'OKP' as const, crv: 'Ed25519' as const, x: input.publicKeyJwk.x, ...(kid === undefined ? {} : { kid }) };
  const didDocument = input.didDocument ?? (parseDidWeb(input.id) === undefined ? undefined : didWebDocumentUrl(input.id));
  const card: EntityCard = {
    id: input.id,
    entityType: input.entityType,
    name: input.name,
    ...(kid === undefined ? {} : { kid }),
    ...(publicKeyJwk === undefined ? {} : { publicKeyJwk }),
    ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
    ...(input.capabilities === undefined ? {} : { capabilities: [...input.capabilities] }),
    ...(input.responsibleParty === undefined ? {} : { responsibleParty: input.responsibleParty }),
    ...(input.principal === undefined ? {} : { principal: input.principal }),
    ...(input.delegationRef === undefined ? {} : { delegationRef: input.delegationRef }),
    ...(input.attestations === undefined ? {} : { attestations: [...input.attestations] }),
    ...(didDocument === undefined ? {} : { didDocument }),
    proofProfile: input.proofProfile ?? PROOF_PROFILE_V1,
    ...(input.cimd === undefined ? {} : { cimd: input.cimd }),
    ...(input.revocation === undefined ? {} : { revocation: input.revocation }),
  };
  return parseEntityCard(card);
}

// ── The server.json projection ──────────────────────────────────────────────

export interface EntityCardSummary {
  id: string;
  entityType: EntityType;
  name: string;
  capabilities?: string[];
  responsibleParty?: string;
  delegationRef?: string;
  proofProfile?: string;
  revocation?: BitstringStatusListEntry;
}

export type ServerCardMeta = { 'org.kya-os/card': (EntityCardSummary & { 'org.kya-os/cardRef': string }) | { 'org.kya-os/cardRef': string } };

export function entityCardSummary(card: EntityCard): EntityCardSummary {
  return {
    id: card.id,
    entityType: card.entityType,
    name: card.name,
    ...(card.capabilities === undefined ? {} : { capabilities: card.capabilities.map(capabilityName) }),
    ...(card.responsibleParty === undefined ? {} : { responsibleParty: card.responsibleParty }),
    ...(card.delegationRef === undefined ? {} : { delegationRef: card.delegationRef }),
    ...(card.proofProfile === undefined ? {} : { proofProfile: card.proofProfile }),
    ...(card.revocation === undefined ? {} : { revocation: card.revocation }),
  };
}

/** `{ "org.kya-os/card": { …claim-minimal summary, "org.kya-os/cardRef": url } }` for `server.json` `_meta`. */
export function serverCardMeta(card: EntityCard, options: { cardUrl?: string | undefined; byRef?: boolean | undefined } = {}): ServerCardMeta {
  const cardUrl = options.cardUrl ?? (parseDidWeb(card.id) === undefined ? undefined : didWebCardUrl(card.id));
  if (cardUrl === undefined) throw new EntityCardError('card_invalid', 'a did:key card has no card URL; pass cardUrl');
  const ref = { [KYA_OS_CARD_REF_KEY]: cardUrl } as { 'org.kya-os/cardRef': string };
  return { [KYA_OS_CARD_META_KEY]: options.byRef ? ref : { ...entityCardSummary(card), ...ref } };
}

// ── SafeFetch ───────────────────────────────────────────────────────────────

export const SAFE_FETCH_MAX_BYTES = 1024 * 1024;
export const SAFE_FETCH_TIMEOUT_MS = 5_000;
export const SAFE_FETCH_MAX_REDIRECTS = 3;

const NON_PUBLIC = new BlockList();
for (const [net, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 32], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv6');
}

/** True for a public unicast IPv4 or IPv6 address (an IPv4-mapped one judged by its IPv4). */
export function isPublicUnicastAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !NON_PUBLIC.check(address, 'ipv4');
  if (family === 6) {
    const mapped = /^(?:0*:)*ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped?.[1]) return isPublicUnicastAddress(mapped[1]);
    return !NON_PUBLIC.check(address, 'ipv6');
  }
  return false;
}

export interface SafeFetchResponse {
  ok: boolean;
  status: number;
  url: string;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export type SafeFetch = (url: string, init?: { headers?: Record<string, string> }) => Promise<SafeFetchResponse>;
export type DnsLookup = (hostname: string) => Promise<string[]>;

export interface TransportRequest {
  url: string;
  headers: Record<string, string>;
  address: string | undefined;
  signal: AbortSignal;
  maxBytes: number;
}

export type SafeFetchTransport = (request: TransportRequest) => Promise<{ status: number; headers: Record<string, string>; body: Uint8Array }>;

export interface SafeFetchOptions {
  lookup?: DnsLookup;
  transport?: SafeFetchTransport;
  /** Admits http and non-public addresses. Local stacks only. */
  development?: boolean;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

/** `node:https` (or `node:http` in development) with the connection's lookup pinned to the checked address. */
export const nodeTransport: SafeFetchTransport = (request) =>
  new Promise((resolve, reject) => {
    const url = new URL(request.url);
    const options: RequestOptions = {
      method: 'GET',
      headers: request.headers,
      signal: request.signal,
      ...(request.address === undefined
        ? {}
        : {
            lookup: ((_hostname: string, opts: unknown, callback: (...args: unknown[]) => void): void => {
              const family = isIP(request.address!);
              if (typeof opts === 'object' && opts !== null && (opts as { all?: boolean }).all === true) callback(null, [{ address: request.address, family }]);
              else callback(null, request.address, family);
            }) as unknown as RequestOptions['lookup'],
          }),
    };
    const req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, options, (res) => {
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(res.headers)) headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '');
      const declared = Number(headers['content-length']);
      if (Number.isFinite(declared) && declared > request.maxBytes) {
        res.destroy();
        reject(new SafeFetchRefusedError('too_large', `SafeFetch: declared content-length ${declared} exceeds the cap of ${request.maxBytes} bytes`));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > request.maxBytes) {
          res.destroy();
          reject(new SafeFetchRefusedError('too_large', `SafeFetch: response body exceeds the cap of ${request.maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers, body: new Uint8Array(Buffer.concat(chunks)) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });

/** A transport over a `fetch`-compatible function (tests); it cannot pin the connection. */
export function fetchTransport(fetchLike: (url: string, init: RequestInit) => Promise<Response>): SafeFetchTransport {
  return async (request) => {
    const response = await fetchLike(request.url, { headers: request.headers, redirect: 'manual', signal: request.signal });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    const declared = Number(headers['content-length']);
    if (Number.isFinite(declared) && declared > request.maxBytes) throw new SafeFetchRefusedError('too_large', `SafeFetch: declared content-length ${declared} exceeds the cap of ${request.maxBytes} bytes`);
    const body = new Uint8Array(await response.arrayBuffer());
    if (body.length > request.maxBytes) throw new SafeFetchRefusedError('too_large', `SafeFetch: response body exceeds the cap of ${request.maxBytes} bytes`);
    return { status: response.status, headers, body };
  };
}

const defaultLookup: DnsLookup = async (hostname) => (await dnsLookup(hostname, { all: true })).map((entry) => entry.address);
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const isLocalName = (hostname: string): boolean => /^(?:.*\.)?localhost\.?$/i.test(hostname);
const ipLiteral = (hostname: string): string | undefined => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return isIP(bare) ? bare : undefined;
};

export function createSafeFetch(options: SafeFetchOptions = {}): SafeFetch {
  const lookup = options.lookup ?? defaultLookup;
  const transport = options.transport ?? nodeTransport;
  const development = options.development === true;
  const maxBytes = options.maxBytes ?? SAFE_FETCH_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? SAFE_FETCH_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? SAFE_FETCH_MAX_REDIRECTS;

  const admitScheme = (url: URL): void => {
    if (url.protocol === 'https:' || (url.protocol === 'http:' && development)) return;
    throw new SafeFetchRefusedError('scheme_refused', `SafeFetch: only https is allowed (got ${url.protocol.replace(/:$/, '')}://${url.host})`);
  };

  async function pin(url: URL): Promise<string | undefined> {
    if (url.username || url.password) throw new SafeFetchRefusedError('host_refused', 'SafeFetch: a URL with credentials is refused');
    const literal = ipLiteral(url.hostname);
    if (literal !== undefined) {
      if (!development && !isPublicUnicastAddress(literal)) throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${literal} is not a public unicast address`);
      return undefined;
    }
    if (isLocalName(url.hostname)) {
      if (!development) throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${url.hostname} is a local host name`);
      return '127.0.0.1';
    }
    let addresses: string[];
    try {
      addresses = await lookup(url.hostname);
    } catch (error) {
      throw new SafeFetchRefusedError('unresolved', `SafeFetch: ${url.hostname} did not resolve: ${(error as Error).message}`);
    }
    if (addresses.length === 0) throw new SafeFetchRefusedError('unresolved', `SafeFetch: ${url.hostname} resolved to no address`);
    if (!development && addresses.some((address) => !isPublicUnicastAddress(address))) {
      throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${url.hostname} resolves to a non-public address`);
    }
    return addresses[0];
  }

  return async (raw, init = {}) => {
    let origin: URL;
    try {
      origin = new URL(raw);
    } catch {
      throw new SafeFetchRefusedError('invalid_url', `SafeFetch: not a URL: ${raw}`);
    }
    admitScheme(origin);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new SafeFetchRefusedError('deadline_exceeded', `SafeFetch: read of ${origin.href} exceeded ${timeoutMs} ms`)), timeoutMs);
    const headers = { accept: 'application/json', ...(init.headers ?? {}) };
    try {
      let current = origin;
      for (let hop = 0; ; hop += 1) {
        const address = await pin(current);
        let response: Awaited<ReturnType<SafeFetchTransport>>;
        try {
          response = await transport({ url: current.href, headers, address, signal: controller.signal, maxBytes });
        } catch (error) {
          if (controller.signal.aborted) throw controller.signal.reason;
          if (error instanceof SafeFetchRefusedError) throw error;
          throw new SafeFetchRefusedError('unavailable', `SafeFetch: ${current.href} could not be read: ${(error as Error).message}`);
        }
        if (REDIRECTS.has(response.status)) {
          const location = response.headers['location'];
          if (location === undefined) throw new SafeFetchRefusedError('unavailable', `SafeFetch: ${response.status} from ${current.href} without a Location header`);
          if (hop >= maxRedirects) throw new SafeFetchRefusedError('too_many_redirects', `SafeFetch: more than ${maxRedirects} redirects from ${origin.href}`);
          let target: URL;
          try {
            target = new URL(location, current);
          } catch {
            throw new SafeFetchRefusedError('invalid_url', `SafeFetch: redirect from ${current.href} to a malformed location`);
          }
          if (target.protocol !== 'https:' && !(development && target.protocol === 'http:')) throw new SafeFetchRefusedError('scheme_refused', `SafeFetch: redirect from ${current.href} to a non-https target refused`);
          if (target.origin !== origin.origin) throw new SafeFetchRefusedError('cross_origin_redirect', `SafeFetch: cross-origin redirect from ${origin.origin} refused`);
          current = target;
          continue;
        }
        const text = Buffer.from(response.body).toString('utf8');
        return {
          ok: response.status >= 200 && response.status < 300,
          status: response.status,
          url: current.href,
          json: () => Promise.resolve(JSON.parse(text) as unknown),
          text: () => Promise.resolve(text),
        };
      }
    } finally {
      clearTimeout(timer);
    }
  };
}

let defaultSafeFetch: SafeFetch | undefined;
/** The SDK's SafeFetch: strict unless `HELIX_OUTBOUND_DEVELOPMENT=1` (local stacks). */
export function defaultOutboundFetch(): SafeFetch {
  defaultSafeFetch ??= createSafeFetch({ development: process.env['HELIX_OUTBOUND_DEVELOPMENT'] === '1' });
  return defaultSafeFetch;
}

// ── Resolution ──────────────────────────────────────────────────────────────

export interface ResolveEntityCardOptions {
  /** Replaces the SDK's SafeFetch; a `fetch`-compatible function that returns a `Response` qualifies. */
  fetch?: ((url: string, init?: { headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>) | undefined;
}

export interface ResolvedEntityCard {
  did: string;
  card: EntityCard;
  cardUrl: string;
  didDocument?: unknown;
}

async function readJson(url: string, options: ResolveEntityCardOptions, what: string): Promise<unknown> {
  const fetchLike = options.fetch ?? defaultOutboundFetch();
  let response: { ok: boolean; status: number; json(): Promise<unknown> };
  try {
    response = await fetchLike(url, { headers: { accept: 'application/json' } });
  } catch (error) {
    throw new EntityCardError(`${what}_unavailable`, `${what} at ${url} could not be read: ${(error as Error).message}`);
  }
  if (!response.ok) throw new EntityCardError(`${what}_unavailable`, `${what} at ${url} answered HTTP ${response.status}`);
  try {
    return await response.json();
  } catch {
    throw new EntityCardError(`${what}_unavailable`, `${what} at ${url} is not JSON`);
  }
}

/** `card.json` at `url`, parsed and, when `expectedDid` is known, bound to it. */
export async function fetchEntityCard(url: string, options: ResolveEntityCardOptions & { expectedDid?: string | undefined } = {}): Promise<ResolvedEntityCard> {
  const card = parseEntityCard(await readJson(url, options, 'card'));
  if (options.expectedDid !== undefined && !sameDid(card.id, options.expectedDid)) throw new EntityCardError('card_mismatch', `card at ${url} is for ${card.id}, not ${options.expectedDid}`);
  return { did: card.id, card, cardUrl: url };
}

/** Two-step resolution of a did:web: `did.json` → `KyaOsEntityCard` service → `card.json`. */
export async function resolveEntityCard(did: string, options: ResolveEntityCardOptions = {}): Promise<ResolvedEntityCard> {
  if (typeof did !== 'string') throw new EntityCardError('malformed_did', 'did must be a string');
  if (did.startsWith('did:key:')) throw new EntityCardError('did_key_not_resolvable', `${did} has no web home: a did:key card is supplied directly, never discovered`);
  const parsed = parseDidWeb(did);
  if (parsed === undefined) throw new EntityCardError('malformed_did', `${did} is not a did:web DID that names a URL`);
  const documentUrl = didWebDocumentUrl(did);
  const document = await readJson(documentUrl, options, 'did_document');
  const servedId = (document as { id?: unknown })?.id;
  if (typeof servedId !== 'string' || !sameDid(servedId, did)) throw new EntityCardError('did_document_mismatch', `DID document at ${documentUrl} is not for ${did}`);
  const endpoint = cardEndpointOf(document) ?? (parsed.path.length === 0 ? didWebCardUrl(did) : undefined);
  if (endpoint === undefined) throw new EntityCardError('no_card_service', `DID document for ${did} has no KyaOsEntityCard service entry`);
  return { ...(await fetchEntityCard(endpoint, { ...options, expectedDid: did })), did, didDocument: document };
}

/**
 * A card from an MCP `server.json` `_meta` projection: a `cardRef` is
 * fetched; an inline did:web summary is an index, so the canonical card is
 * fetched and bound to its id; an inline did:key summary is parsed in place;
 * a stripped projection falls back to the two-step resolution of `did`.
 */
export async function resolveEntityCardFromServerMeta(input: { serverMeta: unknown; did?: string | undefined }, options: ResolveEntityCardOptions = {}): Promise<ResolvedEntityCard> {
  const entry = isRecord(input.serverMeta) ? input.serverMeta[KYA_OS_CARD_META_KEY] : undefined;
  if (entry === undefined) {
    if (input.did !== undefined) return resolveEntityCard(input.did, options);
    throw new EntityCardError('no_projection', `server metadata carries no ${KYA_OS_CARD_META_KEY} and no DID is known`);
  }
  const record = isRecord(entry) ? entry : {};
  const ref = record[KYA_OS_CARD_REF_KEY];
  if (typeof ref === 'string') return fetchEntityCard(ref, { ...options, expectedDid: typeof record['id'] === 'string' ? record['id'] : input.did });
  const id = record['id'];
  if (typeof id !== 'string') throw new EntityCardError('no_projection', `${KYA_OS_CARD_META_KEY} summary has no id and no cardRef`);
  if (id.startsWith('did:web:')) return fetchEntityCard(didWebCardUrl(id), { ...options, expectedDid: id });
  const summary = { ...record };
  delete summary[KYA_OS_CARD_REF_KEY];
  const card = parseEntityCard(summary);
  return { did: card.id, card, cardUrl: '' };
}
