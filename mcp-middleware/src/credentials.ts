// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { HELIX_VP_META_KEY, VPInvalidStructureError } from '@helixid/sdk-js';
import type { HeadersLike } from '@helixid/sdk-js';
import { MCPAuthError } from './errors.js';

export type ExtractedCredential =
  | { kind: 'vp'; encoded: string }
  | { kind: 'oauth'; token: string };

const VP_SCHEME = 'helixvp';
const BEARER_SCHEME = 'bearer';
const VP_HEADER = 'x-helix-vp';

/** All values of a header, case-insensitively; empty values are dropped. */
function readHeaderValues(headers: HeadersLike | undefined, name: string): string[] {
  if (!headers) return [];
  const out: string[] = [];
  if (typeof (headers as Headers).get === 'function') {
    const value = (headers as Headers).get(name);
    if (value !== null) out.push(value);
  } else {
    for (const [key, value] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
      if (key.toLowerCase() !== name || value === undefined) continue;
      out.push(...(Array.isArray(value) ? value : [value]));
    }
  }
  return out.map((v) => v.trim()).filter((v) => v.length > 0);
}

/**
 * Finds the caller's credential: `Authorization: HelixVP <vp>`, the legacy
 * `X-Helix-VP` header, or MCP `_meta["x-helix-vp"]` (stdio) for a HelixID VP,
 * or `Authorization: Bearer <token>` for OAuth. Tool arguments are never read.
 *
 * Ambiguity is rejected, never resolved by picking one: two different VPs,
 * two Authorization headers, or a VP together with a bearer token all throw
 * CREDENTIAL_CONFLICT. The same VP repeated in several places is accepted.
 */
export function extractCredential(input: {
  headers?: HeadersLike | undefined;
  _meta?: Record<string, unknown> | undefined;
}): ExtractedCredential | undefined {
  const vps = new Set<string>();
  let bearer: string | undefined;

  const authorization = readHeaderValues(input.headers, 'authorization');
  if (authorization.length > 1) {
    throw new MCPAuthError('CREDENTIAL_CONFLICT', 'Multiple Authorization headers were provided');
  }
  const authValue = authorization[0];
  if (authValue !== undefined) {
    const match = /^(\S+)\s+(\S+)$/.exec(authValue);
    if (!match) {
      throw new MCPAuthError('CREDENTIAL_CONFLICT', 'Malformed Authorization header');
    }
    const scheme = (match[1] as string).toLowerCase();
    const credential = match[2] as string;
    if (scheme === VP_SCHEME) vps.add(credential);
    else if (scheme === BEARER_SCHEME) bearer = credential;
    // Any other scheme is not ours; treated as no credential.
  }

  for (const value of readHeaderValues(input.headers, VP_HEADER)) vps.add(value);

  const raw = input._meta?.[HELIX_VP_META_KEY];
  if (raw !== undefined && raw !== null && raw !== '') {
    if (typeof raw !== 'string') {
      throw new VPInvalidStructureError(`_meta["${HELIX_VP_META_KEY}"] must be a base64url-encoded string`);
    }
    vps.add(raw.trim());
  }

  if (vps.size > 1) {
    throw new MCPAuthError('CREDENTIAL_CONFLICT', 'Conflicting VPs were provided in more than one location');
  }
  if (vps.size === 1 && bearer !== undefined) {
    throw new MCPAuthError(
      'CREDENTIAL_CONFLICT',
      'Both a HelixID VP and an OAuth bearer token were provided; send exactly one',
    );
  }
  const [encoded] = vps;
  if (encoded !== undefined) return { kind: 'vp', encoded };
  if (bearer !== undefined) return { kind: 'oauth', token: bearer };
  return undefined;
}
