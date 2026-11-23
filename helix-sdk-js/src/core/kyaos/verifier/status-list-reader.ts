// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Reading a fetched status-list credential (KYA-OS story L3-C, SPEC.md §6.6).
 *
 * Two formats, one bit logic:
 *
 * - W3C Bitstring Status List v1.0 (`BitstringStatusListCredential` with a
 *   `BitstringStatusList` subject): what Helix issues, one list per issuer
 *   DID, `validFrom`/`validUntil` set, `DataIntegrityProof` `eddsa-jcs-2022`;
 *   `statusPurpose` may be one string or several.
 * - StatusList2021 (`StatusList2021Credential` with a `StatusList2021`
 *   subject): read so the Core L3.11 vectors pass; Helix never issues it.
 *   `statusPurpose` is one string, the window `issuanceDate`/`expirationDate`.
 *
 * Order, fail-closed at every step: the list's shape, then its proof by the
 * list's own `issuer` (for `assertionMethod`), and only then its bits:
 * multibase `u` plus GZIP, inflated with a bound, read MSB first. A list
 * with no proof, a proof that does not verify, a wrong type, a purpose of
 * the wrong form or bits that do not inflate is a {@link StatusListError};
 * the caller reads the credential it covers as revoked.
 *
 * Proof suites: `DataIntegrityProof` / `eddsa-jcs-2022` (Helix's, verified
 * as the cryptosuite says), and `Ed25519Signature2020` over the JCS bytes of
 * the list without its proof (the SPEC.md §6.2 suite the reference and its
 * vectors sign lists with).
 */

import { verifyLegacyProof } from '../conformance/legacy.js';
import { ReasonCodes, type ReasonCode } from './codes.js';
import { issuerOf, verifyDataIntegrity, type DidResolver } from './data-integrity.js';
import { DATE_TIME_PATTERN, parseDateTime } from './json-schema.js';
import { decodeStatusListBits, type FetchStatusList, type StatusListRead } from './status.js';

export const BITSTRING_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential';
export const BITSTRING_LIST_SUBJECT_TYPE = 'BitstringStatusList';
export const STATUS_LIST_2021_CREDENTIAL_TYPE = 'StatusList2021Credential';
export const STATUS_LIST_2021_SUBJECT_TYPE = 'StatusList2021';

export type StatusListFormat = 'bitstring' | 'statuslist2021';

/** Why a fetched list could not be read; the credential it covers is then read as revoked. */
export class StatusListError extends Error {
  readonly code: ReasonCode;
  constructor(code: ReasonCode, message: string) {
    super(message);
    this.name = 'StatusListError';
    this.code = code;
  }
}

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);

const malformed = (message: string): StatusListError => new StatusListError(ReasonCodes.STATUS_LIST_MALFORMED, message);

/** The format a list's `type` and subject `type` name, or undefined when they name neither or disagree. */
export function statusListFormat(document: unknown): StatusListFormat | undefined {
  if (!isObject(document)) return undefined;
  const types = document['type'];
  const subject = document['credentialSubject'];
  if (!Array.isArray(types) || !isObject(subject)) return undefined;
  if (types.includes(BITSTRING_LIST_CREDENTIAL_TYPE) && subject['type'] === BITSTRING_LIST_SUBJECT_TYPE) return 'bitstring';
  if (types.includes(STATUS_LIST_2021_CREDENTIAL_TYPE) && subject['type'] === STATUS_LIST_2021_SUBJECT_TYPE) return 'statuslist2021';
  return undefined;
}

export type ListProofVerdict = { ok: true; issuer: string } | { ok: false; message: string };

/**
 * Verifies the one proof on a status list against the key its `issuer`
 * lists under `assertionMethod`. A list with no proof is unsigned, and an
 * unsigned list is never read.
 */
export async function verifyStatusListProof(document: JsonObject, resolveDid: DidResolver): Promise<ListProofVerdict> {
  const proof = document['proof'];
  if (proof === undefined || proof === null) return { ok: false, message: 'the list is unsigned' };
  if (!isObject(proof)) return { ok: false, message: 'the list carries no single proof object' };
  const issuer = issuerOf(document['issuer']);
  if (issuer === undefined) return { ok: false, message: 'the list names no issuer DID' };
  if (proof['type'] === 'DataIntegrityProof') {
    const verdict = await verifyDataIntegrity(document, resolveDid);
    return verdict.ok ? { ok: true, issuer } : { ok: false, message: `${verdict.reason}: ${verdict.message}` };
  }
  if (proof['type'] === 'Ed25519Signature2020') {
    let resolved: unknown;
    try {
      resolved = await resolveDid(issuer);
    } catch (error) {
      return { ok: false, message: `could not resolve ${issuer}: ${(error as Error).message}` };
    }
    if (resolved === null || resolved === undefined) return { ok: false, message: `${issuer} did not resolve` };
    const refusal = verifyLegacyProof(document, { [issuer]: resolved });
    return refusal === undefined ? { ok: true, issuer } : { ok: false, message: refusal };
  }
  return { ok: false, message: `proof type ${String(proof['type'])} is not one a status list is read under` };
}

export interface ReadStatusListOptions {
  /** How the list's issuer DID resolves, for its proof. */
  resolveDid: DidResolver;
  /** Whether the read is live (default) or a cached copy. */
  fresh?: boolean | undefined;
}

/** Whether `value` is an RFC 3339 date-time with offset that a calendar has (no 30th of February, no 60th second). */
export function isCalendarDateTime(value: string): boolean {
  if (!DATE_TIME_PATTERN.test(value)) return false;
  const [year, month, day] = value.slice(0, 10).split('-').map(Number) as [number, number, number];
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) return false;
  return parseDateTime(value) !== undefined;
}

/**
 * A bound the list states (VC 2.0 member, else the VC 1.1 one), as written.
 * A bound that is not a date-time a calendar has leaves the window unknown,
 * so the list is unresolvable (SPEC.md §6.6).
 */
function windowBound(document: JsonObject, current: string, legacy: string): string | undefined {
  const member = current in document ? current : legacy in document ? legacy : undefined;
  if (member === undefined) return undefined;
  const value = document[member];
  if (typeof value !== 'string' || !isCalendarDateTime(value)) throw malformed(`${member} is not an RFC 3339 date-time with offset`);
  return value;
}

async function readList(document: unknown, format: StatusListFormat, options: ReadStatusListOptions): Promise<StatusListRead> {
  if (!isObject(document)) throw malformed('the status list is not a JSON object');
  if (statusListFormat(document) !== format) {
    throw malformed(
      format === 'bitstring'
        ? `the list is not a ${BITSTRING_LIST_CREDENTIAL_TYPE} with a ${BITSTRING_LIST_SUBJECT_TYPE} subject`
        : `the list is not a ${STATUS_LIST_2021_CREDENTIAL_TYPE} with a ${STATUS_LIST_2021_SUBJECT_TYPE} subject`,
    );
  }
  const subject = document['credentialSubject'] as JsonObject;
  const purpose = subject['statusPurpose'];
  if (format === 'bitstring') {
    const fine =
      (typeof purpose === 'string' && purpose.length > 0) ||
      (Array.isArray(purpose) && purpose.length > 0 && purpose.every((entry) => typeof entry === 'string' && entry.length > 0));
    if (!fine) throw malformed('statusPurpose is not a purpose or a non-empty list of purposes');
  } else if (typeof purpose !== 'string' || purpose.length === 0) {
    // VC Status List v2021 §2.2: one string; an array is refused whatever it holds (SPEC.md §6.6).
    throw malformed('a StatusList2021 list states one statusPurpose string');
  }
  const encodedList = subject['encodedList'];
  if (typeof encodedList !== 'string' || encodedList.length === 0) throw malformed('the list has no credentialSubject.encodedList');
  const id = document['id'];
  if (id !== undefined && typeof id !== 'string') throw malformed('the list id is not a string');

  const validFrom = windowBound(document, 'validFrom', 'issuanceDate');
  const validUntil = windowBound(document, 'validUntil', 'expirationDate');

  // The proof, before any bit is read (§6.6).
  const proof = await verifyStatusListProof(document, options.resolveDid);
  if (!proof.ok) throw new StatusListError(ReasonCodes.STATUS_LIST_PROOF_INVALID, proof.message);

  let bits: Uint8Array;
  try {
    bits = decodeStatusListBits(encodedList);
  } catch (error) {
    throw malformed(`encodedList does not inflate: ${(error as Error).message}`);
  }
  return {
    bits,
    issuer: proof.issuer,
    statusPurpose: purpose as string | string[],
    ...(id === undefined ? {} : { id }),
    ...(validFrom === undefined ? {} : { validFrom }),
    ...(validUntil === undefined ? {} : { validUntil }),
    fresh: options.fresh ?? true,
    proofVerified: true,
  };
}

/** Reads a W3C Bitstring Status List v1.0 credential: shape, proof, then bits. */
export function readBitstringStatusList(document: unknown, options: ReadStatusListOptions): Promise<StatusListRead> {
  return readList(document, 'bitstring', options);
}

/** Reads a StatusList2021 credential (Core L3.11): same bit logic, its own type names and window members. */
export function readStatusList2021(document: unknown, options: ReadStatusListOptions): Promise<StatusListRead> {
  return readList(document, 'statuslist2021', options);
}

/** Reads a list of either format, by the types it states; a list of neither is malformed. */
export function readStatusListCredential(document: unknown, options: ReadStatusListOptions): Promise<StatusListRead> {
  const format = statusListFormat(document);
  if (format === undefined) return Promise.reject(malformed('the document is neither a Bitstring Status List nor a StatusList2021 credential'));
  return readList(document, format, options);
}

/** The subset of `fetch` a status-list read needs; a SafeFetch fits it. */
export type StatusListHttpFetch = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface StatusListFetcherOptions {
  /** How the list is fetched: the host's SafeFetch (https only, public unicast, size and time bounds). */
  fetch: StatusListHttpFetch;
  /** How the list issuer's DID resolves, for the list's proof. */
  resolveDid: DidResolver;
}

/**
 * A `fetchStatusList` seam that fetches the list at its URL and reads it
 * with {@link readStatusListCredential}: proof first, then bits. An
 * unreachable list, a non-2xx answer or a body that is not JSON is
 * `status_unavailable`; every other failure keeps its reader's code.
 */
export function createStatusListFetcher(options: StatusListFetcherOptions): FetchStatusList {
  return async (url: string): Promise<StatusListRead> => {
    let body: unknown;
    try {
      const response = await options.fetch(url);
      if (!response.ok) throw new Error(`answered ${response.status}`);
      body = await response.json();
    } catch (error) {
      throw new StatusListError(ReasonCodes.STATUS_UNAVAILABLE, `status list ${url} could not be read: ${(error as Error).message}`);
    }
    return readStatusListCredential(body, { resolveDid: options.resolveDid, fresh: true });
  };
}
