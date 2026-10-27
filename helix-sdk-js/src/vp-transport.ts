// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// Where a signed VP travels with a request. There is exactly one place per
// transport, and never inside tool arguments or a request body:
//   - HTTP: the X-Helix-VP header.
//   - MCP (any transport, including stdio): params._meta["x-helix-vp"].
// Both carry the same value: the signed VP as base64url-encoded JSON.

import { VPInvalidStructureError } from './core/HelixError.js';
import type { SignedVP } from './core/schemas/vp.js';

export const HELIX_VP_HEADER = 'X-Helix-VP';
export const HELIX_VP_META_KEY = 'x-helix-vp';

export function encodeHelixVP(vp: SignedVP): string {
  return Buffer.from(JSON.stringify(vp), 'utf8').toString('base64url');
}

export function decodeHelixVP(value: string): SignedVP {
  try {
    return JSON.parse(Buffer.from(value.trim(), 'base64url').toString('utf8')) as SignedVP;
  } catch {
    throw new VPInvalidStructureError(`${HELIX_VP_HEADER} is not base64url-encoded JSON`);
  }
}

/** Headers to send with an HTTP request: `fetch(url, { headers: helixVPHeaders(vp) })`. */
export function helixVPHeaders(vp: SignedVP): Record<string, string> {
  return { [HELIX_VP_HEADER]: encodeHelixVP(vp) };
}

export type HeadersLike = Headers | Record<string, string | string[] | undefined>;

/** Reads the VP from the X-Helix-VP header (case-insensitive); undefined when absent. */
export function readHelixVPHeader(headers: HeadersLike | undefined): SignedVP | undefined {
  if (!headers) return undefined;
  let raw: string | string[] | null | undefined;
  if (typeof (headers as Headers).get === 'function') {
    raw = (headers as Headers).get(HELIX_VP_HEADER);
  } else {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === HELIX_VP_META_KEY);
    raw = key === undefined ? undefined : (headers as Record<string, string | string[] | undefined>)[key];
  }
  if (Array.isArray(raw)) raw = raw[0];
  return raw ? decodeHelixVP(raw) : undefined;
}

/** Reads the VP from an MCP request's `_meta`; undefined when absent. */
export function readHelixVPMeta(meta: Record<string, unknown> | undefined): SignedVP | undefined {
  const raw = meta?.[HELIX_VP_META_KEY];
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'string') {
    throw new VPInvalidStructureError(`_meta["${HELIX_VP_META_KEY}"] must be a base64url-encoded string`);
  }
  return decodeHelixVP(raw);
}
