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
 * A status list held to SPEC.md §6.6 for a §6.2 credential (the
 * `status-list` vector category, stories F-2 and L3-C), judged by the same
 * code the middleware's revocation checker runs: the one keeper of the
 * entry's URL (./../verifier/keeper.ts), the list read by
 * `readStatusListCredential` (shape, its proof, then its bits; Bitstring
 * Status List v1.0 or StatusList2021), and `checkStatusEntry` (the list's
 * `issuer` is the keeper, its `id`, its `statusPurpose`, its window, a
 * one-bit entry, a whole decimal index, the indexed bit).
 */

import { ReasonCodes } from '../verifier/codes.js';
import type { BitstringStatusEntry } from '../verifier/credentials.js';
import { keeper, mayOmitListId, statusConfiguration } from '../verifier/keeper.js';
import { StatusListError, readStatusListCredential } from '../verifier/status-list-reader.js';
import { checkStatusEntry } from '../verifier/status.js';
import { issuerDid, verifyLegacyProof } from './legacy.js';
import type { StatusListInput } from './types.js';

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);

// The keeper rules live with the production verifier (story L3-C); re-exported for the adapter's callers.
export { keeper, mistakenBinding, statusConfiguration, type StatusConfiguration } from '../verifier/keeper.js';

/**
 * The verdict of a `status-list` vector through the production path (story
 * L3-C): the credential's own §6.2 proof, then the keeper, then
 * `readStatusListCredential` (shape, the list's proof, then its bits) and
 * `checkStatusEntry` (keeper, `id`, purpose, window, entry, bit) exactly as
 * the middleware's revocation checker runs them. Undefined when active.
 */
export async function statusListRefusal(input: StatusListInput, nowMs: number): Promise<string | undefined> {
  try {
    const credential = input.credential as JsonObject;
    const entry = credential['credentialStatus'] as JsonObject;
    if (!isObject(entry)) return 'the credential has no credentialStatus';
    const url = entry['statusListCredential'];
    if (typeof url !== 'string') return 'the entry names no list';
    const purpose = entry['statusPurpose'];
    const config = statusConfiguration(input);
    const owner = issuerDid(credential['issuer']);
    if (typeof purpose !== 'string' || owner === undefined) return 'the entry names no purpose or the credential no issuer';
    const credentialProof = verifyLegacyProof(credential, input.didDocuments);
    if (credentialProof !== undefined) return `credential: ${credentialProof}`;
    const document = input.statusLists[url];
    if (document === undefined) return `${ReasonCodes.STATUS_UNAVAILABLE}: no list at ${url}`;
    const read = await readStatusListCredential(document, {
      resolveDid: async (did) => (input.didDocuments[did] as never) ?? null,
    });
    const verdict = checkStatusEntry(
      {
        type: entry['type'],
        statusPurpose: purpose,
        statusListIndex: entry['statusListIndex'],
        statusListCredential: url,
        ...(entry['statusSize'] === undefined ? {} : { statusSize: entry['statusSize'] }),
      } as unknown as BitstringStatusEntry,
      owner,
      read,
      { now: nowMs, keeper: keeper(url, owner, config).did, mayOmitId: mayOmitListId(url, owner, config) },
    );
    return verdict.ok ? undefined : `${verdict.code}: ${verdict.message}`;
  } catch (error) {
    return error instanceof StatusListError ? `${error.code}: ${error.message}` : `unreadable: ${(error as Error).message}`;
  }
}
