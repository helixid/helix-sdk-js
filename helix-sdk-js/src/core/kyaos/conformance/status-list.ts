// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The keeper and acceptance rules follow the KYA-OS suite's independent reading
// (decentralized-identity/kya-os-mcp, conformance/status_list.py at a4d7f61,
// MIT licensed, Copyright (c) 2026 KYA-OS).

/**
 * A status list held to SPEC.md §6.6 for a §6.2 credential (story F-2, the
 * `status-list` vector category): the one keeper of the entry's URL (the
 * configured exact URL, the configured `https:` origin, the pinned root when
 * its own credential names the URL, else the credential's issuer), the
 * list's `id` (only the credential's own issuer may leave it out, and only
 * when nobody else keeps any URL), its `statusPurpose` (an array only on a
 * Bitstring Status List v1.0 list), both proofs, the list's validity window,
 * a one-bit entry, a whole decimal index and the indexed bit.
 */

import { gunzipSync } from 'node:zlib';
import { issuerDid, verifyLegacyProof } from './legacy.js';
import type { StatusListInput } from './types.js';

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);

const ORIGIN = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/;
const ORIGIN_IN_ANY_FORM = /^https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?(\/?)$/;
const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

export interface StatusConfiguration {
  root: string | undefined;
  rootList: string | undefined;
  services: Record<string, string[]>;
}

/** The words a binding §6.6 says is mistaken is refused in, or undefined. */
export function mistakenBinding(binding: string): string | undefined {
  const written = ORIGIN_IN_ANY_FORM.exec(binding);
  if (written !== null && written[1] === '/') return 'statusListIssuers binds an origin followed by "/"';
  if (written !== null && /[A-Z]/.test(binding)) return 'statusListIssuers binds an origin whose host is not in lower case';
  if (binding.endsWith('/')) return 'statusListIssuers binds a URL that ends in "/"';
  return undefined;
}

/** The configuration a status-list input states, or a thrown `TypeError` for one that is not well formed. */
export function statusConfiguration(input: Partial<StatusListInput>): StatusConfiguration {
  for (const member of ['trustedRootIssuer', 'trustedRootStatusList'] as const) {
    const value = input[member];
    if (value !== undefined && (typeof value !== 'string' || value.length === 0)) throw new TypeError(`${member} is not a non-empty string`);
  }
  const services = input.statusListIssuers ?? {};
  if (!isObject(services)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
  const bound = new Map<string, string>();
  for (const [did, bindings] of Object.entries(services)) {
    if (did === '' || !Array.isArray(bindings)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
    for (const binding of bindings as unknown[]) {
      if (typeof binding !== 'string' || !/^https?:\/\//.test(binding)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
      const mistaken = mistakenBinding(binding);
      if (mistaken !== undefined) throw new TypeError(mistaken);
      if ((bound.get(binding) ?? did) !== did) throw new TypeError('statusListIssuers binds one URL to two issuers');
      bound.set(binding, did);
    }
  }
  return { root: input.trustedRootIssuer, rootList: input.trustedRootStatusList, services: services as Record<string, string[]> };
}

/** The one issuer whose list is read at `url`, and whether no binding names it. */
export function keeper(url: string, owner: string, config: StatusConfiguration): { did: string; unbound: boolean } {
  for (const [did, bindings] of Object.entries(config.services)) if (bindings.includes(url)) return { did, unbound: false };
  for (const [did, bindings] of Object.entries(config.services)) {
    for (const binding of bindings) {
      if (ORIGIN.test(binding) && ['/', '?', '#'].some((mark) => url.startsWith(binding + mark))) return { did, unbound: false };
    }
  }
  if (config.root !== undefined && config.rootList === url) return { did: config.root, unbound: true };
  return { did: owner, unbound: true };
}

/** Whether `document` is a list §6.6 reads at `url` for a credential `owner` issued, of `purpose`. */
export function acceptsList(document: unknown, owner: string, url: string, purpose: string, config: StatusConfiguration): boolean {
  if (!isObject(document) || owner === '') return false;
  const signer = issuerDid(document['issuer']);
  if (signer === undefined) return false;
  const kept = keeper(url, owner, config);
  if (signer !== kept.did) return false;
  if ('id' in document) {
    if (document['id'] !== url) return false;
  } else if (!kept.unbound || (config.root !== undefined && config.root !== owner) || Object.keys(config.services).some((did) => did !== owner)) {
    return false;
  }
  const subject = document['credentialSubject'];
  if (!isObject(subject)) return false;
  const declared = subject['statusPurpose'];
  if (typeof declared === 'string') return declared === purpose;
  const types = document['type'];
  return (
    Array.isArray(declared) &&
    declared.length > 0 &&
    declared.every((entry) => typeof entry === 'string') &&
    declared.includes(purpose) &&
    Array.isArray(types) &&
    types.includes('BitstringStatusListCredential') &&
    subject['type'] === 'BitstringStatusList'
  );
}

const DATE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$/;

/** The instant a list's bound states, by its VC 2.0 member or else its VC 1.1 one; null when neither; throws for a bound that is no date. */
function windowBound(document: JsonObject, current: string, legacy: string): number | null {
  const member = current in document ? current : legacy in document ? legacy : undefined;
  if (member === undefined) return null;
  const stated = document[member];
  if (typeof stated !== 'string' || !DATE_TIME.test(stated)) throw new RangeError(`${member} is not a date`);
  // A day no calendar has (the 30th of February) is no date, though Date.parse rolls it over.
  const [year, month, day] = stated.slice(0, 10).split('-').map(Number) as [number, number, number];
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) throw new RangeError(`${member} is not a date`);
  // Date.parse reads at most millisecond digits; RFC 3339 allows more, which name an instant within that millisecond.
  const ms = Date.parse(stated.replace(/(\.\d{3})\d+/, '$1'));
  if (Number.isNaN(ms)) throw new RangeError(`${member} is not a date`);
  return ms;
}

/** A list is read only inside the window it states, bounds included (§6.6). */
export function withinWindow(document: JsonObject, nowMs: number): boolean {
  const until = windowBound(document, 'validUntil', 'expirationDate');
  const start = windowBound(document, 'validFrom', 'issuanceDate');
  return (until === null || nowMs <= until) && (start === null || start <= nowMs);
}

/** The whole decimal index an entry names, leading zeros read as nothing, or undefined. */
export function statusIndex(raw: unknown): number | undefined {
  if (typeof raw !== 'string' || !/^[0-9]+$/.test(raw)) return undefined;
  const digits = raw.replace(/^0+/, '') || '0';
  if (digits.length > 16) return undefined;
  const index = Number(digits);
  return Number.isSafeInteger(index) ? index : undefined;
}

/** The bits an `encodedList` holds, multibase `u` or bare base64url, inflated with a bound. */
export function listBits(encoded: string): Uint8Array {
  const payload = encoded.startsWith('u') ? encoded.slice(1) : encoded;
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(payload)) throw new RangeError('encodedList is not base64url');
  return new Uint8Array(gunzipSync(Buffer.from(payload, 'base64url'), { maxOutputLength: MAX_STATUS_LIST_BYTES }));
}

/**
 * The verdict of a `status-list` vector: undefined when the credential is
 * active, else why it is refused (fail-closed on anything unreadable).
 */
export function statusListRefusal(input: StatusListInput, nowMs: number): string | undefined {
  try {
    const credential = input.credential as JsonObject;
    const entry = credential['credentialStatus'] as JsonObject;
    if (!isObject(entry)) return 'the credential has no credentialStatus';
    const url = entry['statusListCredential'];
    if (typeof url !== 'string') return 'the entry names no list';
    const document = input.statusLists[url];
    const purpose = entry['statusPurpose'];
    const config = statusConfiguration(input);
    const owner = issuerDid(credential['issuer']);
    if (typeof purpose !== 'string' || owner === undefined || !acceptsList(document, owner, url, purpose, config)) return 'the list is not one §6.6 reads for the credential';
    const credentialProof = verifyLegacyProof(credential, input.didDocuments);
    if (credentialProof !== undefined) return `credential: ${credentialProof}`;
    const listProof = verifyLegacyProof(document, input.didDocuments);
    if (listProof !== undefined) return `list: ${listProof}`;
    if (!withinWindow(document as JsonObject, nowMs)) return 'the list is outside the window it states';
    const size = entry['statusSize'] ?? 1;
    if (size !== 1) return 'the entry is not one bit';
    const index = statusIndex(entry['statusListIndex']);
    if (index === undefined) return 'statusListIndex is not a whole decimal';
    const subject = (document as JsonObject)['credentialSubject'] as JsonObject;
    const bits = listBits(subject['encodedList'] as string);
    const byte = bits[Math.floor(index / 8)];
    if (byte === undefined) return 'statusListIndex is outside the list';
    return (byte & (0x80 >> index % 8)) !== 0 ? 'revoked' : undefined;
  } catch (error) {
    return `unreadable: ${(error as Error).message}`;
  }
}
