// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Status lists as the local verifier reads them (KYA-OS story F-2; SPEC.md
 * §6.6 for the rules, story L3-C for the signed per-issuer lists).
 *
 * The verifier never fetches: the `fetchStatusList` seam hands it a
 * {@link StatusListRead}, the list already decoded to its bits, with the
 * members of the list the verifier still holds the credential to (issuer,
 * purpose, id, validity window) and whether the read was live. The seam is
 * where L3-C verifies the list's own proof; what is here is the part that
 * follows from the entry and the bits alone, fail-closed:
 *
 * - the entry names a whole decimal index, a `statusSize` of 1 or none;
 * - the list's `issuer`, when the seam reports it, is the URL's keeper
 *   (./keeper.ts: configured bindings, the pinned root, else the
 *   credential's own issuer), and a list may leave out its `id` only when
 *   the credential's own issuer keeps the URL and nobody else keeps any;
 * - the list's `statusPurpose` includes the entry's; its `id`, when
 *   stated, is the URL it was read from;
 * - a live read is inside the window it states (else `status_stale`); a
 *   cached read was held to its window by the cache (story L3-C);
 * - the bit at the index is clear (else `status_revoked`).
 *
 * `decodeStatusListCredential` is what a seam uses to turn a fetched
 * W3C Bitstring Status List v1.0 (or StatusList2021) credential into a read.
 */

import { gunzipSync } from 'node:zlib';
import { ReasonCodes, type ReasonCode } from './codes.js';
import { windowVerdict, type BitstringStatusEntry } from './credentials.js';

/** Hard ceiling on an inflated status bitstring (16 MiB), the reference's bound against decompression bombs. */
export const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/** A status list as the `fetchStatusList` seam returns it: decoded bits plus what the verifier still checks. */
export interface StatusListRead {
  /** The inflated bitstring, MSB first within each byte. */
  bits: Uint8Array;
  /** The list's `issuer` DID, when the seam read a signed list. */
  issuer?: string | undefined;
  /** The list's `statusPurpose`, when the seam read one: one purpose, or several for a Bitstring v1.0 list. */
  statusPurpose?: string | string[] | undefined;
  /** The list's `id`, when it states one. */
  id?: string | undefined;
  /** The window the list states (`validFrom`/`validUntil`, or `issuanceDate`/`expirationDate`). */
  validFrom?: string | undefined;
  validUntil?: string | undefined;
  /** True when the list was read live from its issuer for this verification; false for a cached copy. Default true. */
  fresh?: boolean | undefined;
  /** True when the reader verified the list's own proof before decoding its bits (story L3-C's readers always do). */
  proofVerified?: boolean | undefined;
}

/** Resolves a `statusListCredential` URL to its decoded list; `undefined` when it cannot be read. */
export type FetchStatusList = (url: string) => Promise<StatusListRead | undefined>;

export type StatusVerdict =
  | { ok: true; fresh: boolean }
  | { ok: false; code: ReasonCode; message: string; fresh: boolean };

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** The base64url (or base64) bytes of `encodedList`, with or without the multibase `u` prefix. */
function statusListPayload(encodedList: string): Uint8Array {
  const payload = encodedList.startsWith('u') && BASE64URL.test(encodedList) ? encodedList.slice(1) : encodedList;
  return new Uint8Array(Buffer.from(payload, 'base64url'));
}

/** Inflates an `encodedList` to its bits, bounded; throws when it is not GZIP or exceeds the bound. */
export function decodeStatusListBits(encodedList: string): Uint8Array {
  const compressed = statusListPayload(encodedList);
  if (compressed[0] !== 0x1f || compressed[1] !== 0x8b) throw new Error('status list encodedList is not GZIP');
  const inflated = gunzipSync(compressed, { maxOutputLength: MAX_STATUS_LIST_BYTES });
  return new Uint8Array(inflated);
}

/** The bit at `index`, MSB first; undefined when the list has no such bit. */
export function readStatusBit(bits: Uint8Array, index: number): 0 | 1 | undefined {
  const byte = bits[Math.floor(index / 8)];
  if (byte === undefined) return undefined;
  return (byte & (0x80 >> index % 8)) !== 0 ? 1 : 0;
}

/**
 * A status-list credential, as fetched, decoded to a {@link StatusListRead}.
 * Reads the Bitstring v1.0 window first and the VC 1.1 members only when
 * the v2 ones are absent. Throws on a list without a readable bitstring.
 */
export function decodeStatusListCredential(list: unknown, options: { fresh?: boolean } = {}): StatusListRead {
  if (list === null || typeof list !== 'object' || Array.isArray(list)) throw new Error('status list is not an object');
  const record = list as Record<string, unknown>;
  const subject = record['credentialSubject'];
  const encodedList = subject !== null && typeof subject === 'object' ? (subject as Record<string, unknown>)['encodedList'] : undefined;
  if (typeof encodedList !== 'string' || encodedList.length === 0) throw new Error('status list has no credentialSubject.encodedList');
  const purpose = (subject as Record<string, unknown>)['statusPurpose'];
  const issuer = record['issuer'];
  const issuerDid = typeof issuer === 'string' ? issuer : issuer !== null && typeof issuer === 'object' ? (issuer as { id?: unknown }).id : undefined;
  const bound = (current: string, legacy: string): string | undefined => {
    const value = record[current] !== undefined ? record[current] : record[legacy];
    return value === undefined ? undefined : typeof value === 'string' ? value : '';
  };
  return {
    bits: decodeStatusListBits(encodedList),
    ...(typeof issuerDid === 'string' ? { issuer: issuerDid } : {}),
    ...(typeof purpose === 'string' || Array.isArray(purpose) ? { statusPurpose: purpose as string | string[] } : {}),
    ...(typeof record['id'] === 'string' ? { id: record['id'] } : {}),
    ...(bound('validFrom', 'issuanceDate') === undefined ? {} : { validFrom: bound('validFrom', 'issuanceDate') }),
    ...(bound('validUntil', 'expirationDate') === undefined ? {} : { validUntil: bound('validUntil', 'expirationDate') }),
    fresh: options.fresh ?? true,
  };
}

/** The whole decimal index an entry names, or undefined for any other form (never coerced). */
export function parseStatusListIndex(raw: unknown): number | undefined {
  if (typeof raw !== 'string' || !/^[0-9]+$/.test(raw)) return undefined;
  const digits = raw.replace(/^0+(?=\d)/, '');
  if (digits.length > 16) return undefined;
  const index = Number(digits);
  return Number.isSafeInteger(index) ? index : undefined;
}

export interface CheckStatusOptions {
  /** Epoch ms. */
  now: number;
  /** Clock tolerance on the list's window; default 120,000 ms. */
  maxClockSkewMs?: number | undefined;
  /** The one issuer whose list is read at the entry's URL (SPEC.md §6.6, ./keeper.ts); default the credential's issuer. */
  keeper?: string | undefined;
  /** False when the list must state the entry's URL as its `id` (a keeper other than the credential's issuer, say); default true. */
  mayOmitId?: boolean | undefined;
  /**
   * False for a cached read the cache already held to its window: kept only
   * when read inside it, served past its end no longer than the staleness
   * window (story L3-C point 6). Default true: a live read is held to the window.
   */
  checkWindow?: boolean | undefined;
}

/**
 * Holds `entry` of a credential issued by `credentialIssuer` to the list
 * `read` at the entry's URL, per the rules above. The seam that produced
 * `read` verified the list's proof; this reads the rest.
 */
export function checkStatusEntry(
  entry: BitstringStatusEntry,
  credentialIssuer: string,
  read: StatusListRead | undefined,
  options: CheckStatusOptions,
): StatusVerdict {
  const fresh = read?.fresh !== false;
  const refuse = (code: ReasonCode, message: string): StatusVerdict => ({ ok: false, code, message, fresh });
  if (entry.statusSize !== undefined && entry.statusSize !== 1) {
    return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, 'statusSize must be 1 for a revocation entry');
  }
  const index = parseStatusListIndex(entry.statusListIndex);
  if (index === undefined) {
    return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, 'statusListIndex is not a non-negative decimal string');
  }
  if (read === undefined) {
    return refuse(ReasonCodes.STATUS_UNAVAILABLE, `status list ${entry.statusListCredential} could not be read`);
  }
  const keeper = options.keeper ?? credentialIssuer;
  if (read.issuer !== undefined && read.issuer !== keeper) {
    return refuse(
      ReasonCodes.STATUS_LIST_MISMATCH,
      keeper === credentialIssuer
        ? `status list is signed by ${read.issuer}, not the credential issuer ${credentialIssuer}`
        : `status list is signed by ${read.issuer}, not ${keeper}, who keeps ${entry.statusListCredential}`,
    );
  }
  if (read.statusPurpose !== undefined) {
    const purposes = Array.isArray(read.statusPurpose) ? read.statusPurpose : [read.statusPurpose];
    if (!purposes.includes(entry.statusPurpose)) {
      return refuse(ReasonCodes.STATUS_LIST_MISMATCH, `status list purpose does not include ${entry.statusPurpose}`);
    }
  }
  if (read.id !== undefined && read.id !== entry.statusListCredential) {
    return refuse(ReasonCodes.STATUS_LIST_MISMATCH, `status list id ${read.id} is not the URL it was read from`);
  }
  if (read.id === undefined && options.mayOmitId === false) {
    return refuse(ReasonCodes.STATUS_LIST_MISMATCH, `status list states no id, and only the credential issuer's own list may leave it out`);
  }
  if (options.checkWindow !== false) {
    const window = windowVerdict(read.validFrom, read.validUntil, options.now, options.maxClockSkewMs);
    if (window !== 'inside') {
      return refuse(ReasonCodes.STATUS_STALE, `status list is outside the window it states (${window})`);
    }
  }
  const bit = readStatusBit(read.bits, index);
  if (bit === undefined) {
    return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, `statusListIndex ${index} is outside the list`);
  }
  if (bit === 1) {
    return refuse(ReasonCodes.STATUS_REVOKED, `the status list marks the credential ${entry.statusPurpose === 'suspension' ? 'suspended' : 'revoked'}`);
  }
  return { ok: true, fresh };
}
