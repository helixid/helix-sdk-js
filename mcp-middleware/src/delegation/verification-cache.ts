// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The verification cache (KYA-OS story L3-D point 6, conformance L3.12):
 * the outcome of verifying a forwarded chain (every hop's signature, the
 * chain rules, every status) kept under the leaf credential's id, for no
 * longer than the revocation propagation target: the status cache's TTL,
 * and at most 60 s when the chain touches a high-privilege scope.
 *
 * An entry is served only for the very chain it was made for (its JCS
 * digest must match), never for a tool whose minimum level is L3 (story
 * L3-C, P1: those read status live), and is reported not fresh. A
 * revocation signal for any credential of the chain drops the entry at
 * once: `invalidate(id)` walks the delegation graph and drops the entries of
 * the credential and of every descendant. Per instance, in memory: each
 * instance receives every signal on its own connection.
 */

import { createHash } from 'node:crypto';
import { kyaos } from '@helixid/sdk-js';
import { DelegationGraph } from './graph.js';

export interface VerificationCacheOptions {
  /** Entry lifetime, seconds; default 300 (the status cache's default). */
  ttlSeconds?: number | undefined;
  /** Lifetime for a chain touching a high-privilege scope, seconds; default and maximum 60 (SPEC.md §6.5.2). */
  highPrivilegeTtl?: number | undefined;
  highPrivilegeScopes?: readonly string[] | undefined;
  /** The graph entries are registered in; default a new one. */
  graph?: DelegationGraph | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
}

/** What a cached verification holds: the verifier's result for the chain alone. */
export type CachedChainVerification = kyaos.verifier.VerifierResult;

interface Entry {
  chainDigest: string;
  result: CachedChainVerification;
  expiresAt: number;
  ids: string[];
}

export const MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS = 60;

/** The JCS sha-256 of a chain: an entry answers only for the chain it was made for. */
export function chainDigestOf(chain: readonly unknown[]): string {
  return createHash('sha256').update(kyaos.canonicalize(chain), 'utf8').digest('hex');
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function idsOf(chain: readonly unknown[]): string[] {
  return chain.map((hop) => (isRecord(hop) && typeof hop['id'] === 'string' ? hop['id'] : undefined)).filter((id): id is string => id !== undefined);
}

export class VerificationCache {
  readonly ttlSeconds: number;
  readonly highPrivilegeTtl: number;
  readonly highPrivilegeScopes: ReadonlySet<string>;
  readonly graph: DelegationGraph;
  readonly #clock: () => number;
  readonly #entries = new Map<string, Entry>();

  constructor(options: VerificationCacheOptions = {}) {
    const ttl = options.ttlSeconds ?? kyaos.verifier.DEFAULT_STATUS_CACHE_TTL_SECONDS;
    if (!(ttl > 0)) throw new RangeError('ttlSeconds must be a positive number of seconds');
    const high = options.highPrivilegeTtl ?? MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS;
    if (!(high > 0) || high > MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS) {
      throw new RangeError(`highPrivilegeTtl must be from 0 to ${MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS} seconds (SPEC.md §6.5.2)`);
    }
    this.ttlSeconds = ttl;
    this.highPrivilegeTtl = Math.min(high, ttl);
    this.highPrivilegeScopes = new Set(options.highPrivilegeScopes ?? []);
    this.graph = options.graph ?? new DelegationGraph();
    this.#clock = options.clock ?? Date.now;
  }

  /**
   * A cache no longer lived than `statusCache`: its TTL, high-privilege TTL
   * and scopes, so a verdict never outlives the revocation target the
   * status reads it rests on.
   */
  static forStatusCache(statusCache: kyaos.verifier.StatusCache, options: Omit<VerificationCacheOptions, 'ttlSeconds' | 'highPrivilegeTtl' | 'highPrivilegeScopes'> = {}): VerificationCache {
    const cache = new VerificationCache({
      ...options,
      ttlSeconds: statusCache.statusCacheTtl,
      highPrivilegeTtl: statusCache.highPrivilegeTtl,
      highPrivilegeScopes: [...statusCache.highPrivilegeScopes],
    });
    linkVerificationCache(statusCache, cache);
    return cache;
  }

  get size(): number {
    return this.#entries.size;
  }

  /** The lifetime for a chain granting `scopes`, seconds. */
  ttlFor(scopes: readonly string[]): number {
    return scopes.some((scope) => this.highPrivilegeScopes.has(scope)) ? this.highPrivilegeTtl : this.ttlSeconds;
  }

  /** The cached verification of `chain` under its leaf credential id, if any and still alive. */
  get(chain: readonly unknown[]): CachedChainVerification | undefined {
    const ids = idsOf(chain);
    const leaf = ids[ids.length - 1];
    if (leaf === undefined || ids.length !== chain.length) return undefined;
    const entry = this.#entries.get(leaf);
    if (entry === undefined) return undefined;
    if (this.#clock() >= entry.expiresAt) {
      this.#entries.delete(leaf);
      return undefined;
    }
    if (entry.chainDigest !== chainDigestOf(chain)) return undefined;
    return entry.result;
  }

  /** Stores a successful verification of `chain`; a refusal, or a chain whose hops show no ids, is never stored. */
  set(chain: readonly unknown[], result: CachedChainVerification): void {
    const ids = idsOf(chain);
    if (!result.ok || ids.length === 0 || ids.length !== chain.length) return;
    try {
      this.graph.registerChain(chain);
    } catch {
      // A chain the graph cannot hold (an id registered under another parent) is not cached.
      return;
    }
    const ttl = this.ttlFor([...result.chainSummary.allowedAction, ...result.effectiveScopes]);
    this.#entries.set(ids[ids.length - 1]!, { chainDigest: chainDigestOf(chain), result, expiresAt: this.#clock() + ttl * 1000, ids });
  }

  /**
   * Drops at once every entry that rests on `credentialId`: its own and its
   * descendants' (a revocation signal, story L3-C point 7). Returns how many
   * entries were dropped.
   */
  invalidate(credentialId: string): number {
    const affected = new Set<string>([credentialId, ...this.graph.getDescendants(credentialId).map((node) => node.id)]);
    let dropped = 0;
    for (const [key, entry] of this.#entries) {
      if (entry.ids.some((id) => affected.has(id))) {
        this.#entries.delete(key);
        dropped += 1;
      }
    }
    return dropped;
  }

  clear(): void {
    this.#entries.clear();
  }
}

const linked = new WeakMap<object, Set<Pick<VerificationCache, 'invalidate'>>>();

/** Links `cache` to `statusCache`: a revocation signal that invalidates the one invalidates the other (`revocationInvalidation`). */
export function linkVerificationCache(statusCache: object, cache: Pick<VerificationCache, 'invalidate'>): void {
  const caches = linked.get(statusCache) ?? new Set();
  caches.add(cache);
  linked.set(statusCache, caches);
}

/**
 * What a `RevocationSignalClient` invalidates: the status cache (its answer
 * is reported), every verification cache linked to it
 * (`VerificationCache.forStatusCache`, which the guard's default is), and any
 * given here. `createRevocationSignalClient` uses it by default.
 */
export function revocationInvalidation(
  statusCache: Pick<kyaos.verifier.StatusCache, 'invalidate'>,
  ...verificationCaches: Array<Pick<VerificationCache, 'invalidate'>>
): Pick<kyaos.verifier.StatusCache, 'invalidate'> {
  return {
    invalidate: async (credentialId: string): Promise<'credential' | 'all-lists'> => {
      for (const cache of new Set([...(linked.get(statusCache) ?? []), ...verificationCaches])) cache.invalidate(credentialId);
      return statusCache.invalidate(credentialId);
    },
  };
}
