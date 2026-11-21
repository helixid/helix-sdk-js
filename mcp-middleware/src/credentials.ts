// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { kyaos, type HeadersLike } from '@helixid/sdk-js';
import { MCPAuthError } from './errors.js';

/**
 * What a tool call carries to identify its caller: a KYA-OS request proof
 * (and, with it, the chain the request carries) in `params._meta`, or an
 * OAuth bearer token in the `Authorization` header. Story F-2 retired the
 * Helix VP (`X-Helix-VP`, `_meta["x-helix-vp"]`) with no backward
 * compatibility: those are no longer read.
 */
export type ExtractedCredential =
  | { kind: 'proof'; proof: unknown; chain: unknown }
  | { kind: 'oauth'; token: string };

const BEARER_SCHEME = 'bearer';

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
 * Finds the caller's credential: the request proof at
 * `_meta["org.kya-os/request-proof"]` (or the legacy `org.kya-os/proof@1`
 * key, the canonical one winning when both are present), with the carried
 * chain at `_meta["org.kya-os/delegation-chain"]`; or `Authorization:
 * Bearer <token>` for OAuth. Tool arguments are never read.
 *
 * Ambiguity is rejected, never resolved by picking one: two Authorization
 * headers, or a proof together with a bearer token, throw
 * CREDENTIAL_CONFLICT.
 */
export function extractCredential(input: {
  headers?: HeadersLike | undefined;
  _meta?: Record<string, unknown> | undefined;
}): ExtractedCredential | undefined {
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
    if ((match[1] as string).toLowerCase() === BEARER_SCHEME) bearer = match[2] as string;
    // Any other scheme is not ours; treated as no credential.
  }

  const proof = kyaos.verifier.readRequestProof(input._meta);
  if (proof !== undefined && bearer !== undefined) {
    throw new MCPAuthError('CREDENTIAL_CONFLICT', 'Both a KYA-OS request proof and an OAuth bearer token were provided; send exactly one');
  }
  if (proof !== undefined) return { kind: 'proof', proof, chain: kyaos.verifier.readCarriedChain(input._meta) };
  if (bearer !== undefined) return { kind: 'oauth', token: bearer };
  return undefined;
}
