// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The agent side of the per-request holder-of-key proof (KYA-OS story C-C,
 * SPEC-ENTITY-CARD.md §8, §10.5): every tool call carries an
 * `org.kya-os/proof.v1` signed by the agent's own key through its Signer
 * (story L1-A), bound to that request (`requestHash`) and that recipient
 * (`audience`, the service DID from its card), and, when the agent acts for
 * someone, the delegation chain root to leaf.
 *
 * - `mintRequestProof(call, signer, {audience, cnfJkt?})`: the proof, at most
 *   60 s long, with a fresh 128-bit nonce.
 * - `requestHashContentDigest(call)`: `sha-256=:<base64>:` over the JCS of
 *   `{method, params}` with `params._meta` removed (a second hash format
 *   next to L1-B's `sha256:<hex>`).
 * - `attachChain(hops)`: the `_meta` member `org.kya-os/delegation-chain`,
 *   each hop a §6.10 credential with its own `eddsa-jcs-2022` proof.
 * - `withRequestProof(call, signer, options)`: the call with both in
 *   `params._meta`, ready to send.
 *
 * Both ride in `params._meta`, which `requestHash` does not cover, so
 * adding them never changes the hash. The Helix VP and its carriers
 * (`X-Helix-VP`, `_meta["x-helix-vp"]`) are gone: there are no Helix-format
 * callers. The Signer keeps the private key; nothing here sees it (stories
 * rule 7).
 */

import type { Signer } from './signer.js';
import {
  DELEGATION_CHAIN_META_KEY,
  MAX_PROOF_TTL_SECONDS,
  REQUEST_PROOF_META_KEY,
  requestHashContentDigest as contentDigestOfRequest,
  signRequestProof,
  type ProofRequest,
  type RequestProof,
} from './verifier/request-proof.js';
import { MAX_DELEGATION_DEPTH } from './verifier/credentials.js';

// `REQUEST_PROOF_META_KEY` is exported once, by response-proof.ts (story L2-A), with the same value.
export { DELEGATION_CHAIN_META_KEY, type ProofRequest, type RequestProof };

/** An MCP tool call as an agent builds it: `tools/call` with `name` and `arguments`. */
export interface ToolCall {
  name: string;
  arguments?: Record<string, unknown> | undefined;
  _meta?: Record<string, unknown> | undefined;
}

/** What a proof can be minted for: a JSON-RPC `{method, params}`, or a tool call. */
export type ProofCall = ProofRequest | ToolCall;

export interface MintRequestProofOptions {
  /** The service's DID, from its Entity Card (or its `/.well-known/mcp` `serverDid`). */
  audience: string;
  /** The RFC 7638 thumbprint of the signing key, carried as `cnf.jkt` for the §8.6 fusion. */
  cnfJkt?: string | undefined;
  /** Epoch ms of `created`; default now. */
  now?: number | undefined;
  /** Lifetime in seconds, 1 to 60; default 60. */
  ttlSeconds?: number | undefined;
  /** A base64url nonce of at least 128 bits; default 16 fresh random bytes. */
  nonce?: string | undefined;
}

export class RequestProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RequestProofError';
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A tool call as the JSON-RPC request it is sent as; a JSON-RPC request as is. */
export function toProofRequest(call: ProofCall): ProofRequest {
  if ('method' in call && typeof call.method === 'string') return call;
  const tool = call as ToolCall;
  if (typeof tool.name !== 'string' || tool.name.length === 0) throw new RequestProofError('a tool call needs a name');
  return {
    method: 'tools/call',
    params: {
      name: tool.name,
      ...(tool.arguments === undefined ? {} : { arguments: tool.arguments }),
      ...(tool._meta === undefined ? {} : { _meta: tool._meta }),
    },
  };
}

/** `sha-256=:<base64>:` over the JCS of the covered request: `{method, params}`, `params._meta` removed (§8.3). */
export function requestHashContentDigest(call: ProofCall): string {
  return contentDigestOfRequest(toProofRequest(call));
}

const NONCE = /^[A-Za-z0-9_-]{22,}$/;

/**
 * Mints the `org.kya-os/proof.v1` for one call, signed by `signer` (a
 * detached EdDSA JWS over the covered claims). One proof per call: the
 * nonce is fresh and the verifier refuses it a second time.
 */
export async function mintRequestProof(call: ProofCall, signer: Signer, options: MintRequestProofOptions): Promise<RequestProof> {
  if (typeof options.audience !== 'string' || !/^did:[a-z0-9]+:.+$/.test(options.audience)) {
    throw new RequestProofError('audience must be the service DID');
  }
  const ttlSeconds = options.ttlSeconds ?? MAX_PROOF_TTL_SECONDS;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_PROOF_TTL_SECONDS) {
    throw new RequestProofError(`ttlSeconds must be a whole number from 1 to ${MAX_PROOF_TTL_SECONDS}`);
  }
  if (options.nonce !== undefined && !NONCE.test(options.nonce)) {
    throw new RequestProofError('nonce must be base64url and at least 128 bits (22 characters)');
  }
  if (options.cnfJkt !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(options.cnfJkt)) {
    throw new RequestProofError('cnfJkt must be an RFC 7638 SHA-256 thumbprint (43 base64url characters)');
  }
  return signRequestProof(toProofRequest(call), signer, {
    audience: options.audience,
    ttlSeconds,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    ...(options.cnfJkt === undefined ? {} : { cnfJkt: options.cnfJkt }),
  });
}

/**
 * The `_meta` member carrying the delegation chain, root to leaf (§10.5):
 * `{ "org.kya-os/delegation-chain": hops }`. Refuses what every verifier
 * would: an empty chain, one longer than 10 hops, or a hop without its own
 * `eddsa-jcs-2022` `DataIntegrityProof` for `assertionMethod`.
 */
export function attachChain(hops: readonly unknown[]): Record<string, unknown[]> {
  if (!Array.isArray(hops) || hops.length === 0) throw new RequestProofError('a delegation chain is a non-empty array, root to leaf');
  if (hops.length > MAX_DELEGATION_DEPTH) throw new RequestProofError(`a carried chain has at most ${MAX_DELEGATION_DEPTH} hops`);
  hops.forEach((hop, index) => {
    const proof = isRecord(hop) ? hop['proof'] : undefined;
    if (!isRecord(proof) || proof['type'] !== 'DataIntegrityProof' || proof['cryptosuite'] !== 'eddsa-jcs-2022' || proof['proofPurpose'] !== 'assertionMethod') {
      throw new RequestProofError(`hop ${index} carries no eddsa-jcs-2022 DataIntegrityProof for assertionMethod`);
    }
  });
  return { [DELEGATION_CHAIN_META_KEY]: [...hops] };
}

export interface WithRequestProofOptions extends MintRequestProofOptions {
  /** The delegation chain, root to leaf; omitted when the agent acts on its own. */
  chain?: readonly unknown[] | undefined;
}

/**
 * The call as it is sent: `params._meta` gains the proof
 * (`org.kya-os/request-proof`) and, when given, the chain
 * (`org.kya-os/delegation-chain`); every other `_meta` member is kept.
 */
export async function withRequestProof(call: ProofCall, signer: Signer, options: WithRequestProofOptions): Promise<ProofRequest> {
  const request = toProofRequest(call);
  if (request.params !== undefined && !isRecord(request.params)) throw new RequestProofError('params must be an object to carry _meta');
  const chainMeta = options.chain === undefined ? {} : attachChain(options.chain);
  // The request is signed as it is sent: absent params become `{}` once `_meta` rides in them (§8.3 step 3).
  const params: Record<string, unknown> = request.params ?? {};
  const proof = await mintRequestProof({ method: request.method, params }, signer, options);
  const meta = isRecord(params['_meta']) ? params['_meta'] : {};
  return {
    method: request.method,
    params: { ...params, _meta: { ...meta, ...chainMeta, [REQUEST_PROOF_META_KEY]: proof } },
  };
}
