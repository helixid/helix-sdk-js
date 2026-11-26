// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The downstream delegation headers (KYA-OS story L3-D, SPEC.md §8.1) and
 * how the credential travels in them.
 *
 * Authoritative: `KYA-OS-Delegation-Credential` (the delegation the agent
 * presented, or the service's own hop appended when it re-delegates),
 * `KYA-OS-Delegation-Proof` (the forwarding service's JWT, §8.2) and
 * `KYA-OS-Agent-DID`. Anchor: `KYA-OS-Session-Id`. Advisory, never read for
 * a decision: `KYA-OS-Delegation-Chain` and `KYA-OS-Granted-Scopes`.
 *
 * Helix's delegations are VC 2.0 hops with an embedded `eddsa-jcs-2022`
 * proof (SPEC.md §6.10), not VC-JWTs, so the credential header carries the
 * whole chain, root to leaf, as base64url (no padding) of its UTF-8 JSON
 * array: the downstream service verifies every hop itself.
 */

import type { HeadersLike } from '@helixid/sdk-js';

export const DELEGATION_HEADERS = {
  credential: 'KYA-OS-Delegation-Credential',
  proof: 'KYA-OS-Delegation-Proof',
  agentDid: 'KYA-OS-Agent-DID',
  sessionId: 'KYA-OS-Session-Id',
  chain: 'KYA-OS-Delegation-Chain',
  grantedScopes: 'KYA-OS-Granted-Scopes',
} as const;

/** The largest credential header read, in characters; a chain of ten hops fits well inside. */
export const MAX_CREDENTIAL_HEADER_LENGTH = 64 * 1024;

/** The chain as the credential header carries it: base64url of the JSON array, root first. */
export function encodeDelegationCredential(chain: readonly unknown[]): string {
  return Buffer.from(JSON.stringify(chain), 'utf8').toString('base64url');
}

/**
 * The chain a credential header carries, or undefined when it is not
 * strict base64url of a non-empty JSON array (a single credential object is
 * read as a chain of one).
 */
export function decodeDelegationCredential(value: string): unknown[] | undefined {
  if (value.length === 0 || value.length > MAX_CREDENTIAL_HEADER_LENGTH || !/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
  if (Array.isArray(parsed)) return parsed.length > 0 ? parsed : undefined;
  return typeof parsed === 'object' && parsed !== null ? [parsed] : undefined;
}

/** Every value of a header, case-insensitively, trimmed; empty values dropped. */
export function headerValues(headers: HeadersLike | undefined, name: string): string[] {
  if (headers === undefined) return [];
  const lower = name.toLowerCase();
  const values: string[] = [];
  if (typeof (headers as Headers).get === 'function') {
    const value = (headers as Headers).get(name);
    if (value !== null) values.push(value);
  } else {
    for (const [key, value] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
      if (key.toLowerCase() !== lower || value === undefined) continue;
      values.push(...(Array.isArray(value) ? value : [value]));
    }
  }
  return values.map((value) => value.trim()).filter((value) => value.length > 0);
}

/** Whether a request carries downstream delegation headers (the credential or the proof). */
export function hasDelegationHeaders(headers: HeadersLike | undefined): boolean {
  return headerValues(headers, DELEGATION_HEADERS.credential).length > 0 || headerValues(headers, DELEGATION_HEADERS.proof).length > 0;
}
