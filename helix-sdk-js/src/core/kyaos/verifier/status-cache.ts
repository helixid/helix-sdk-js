// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The status cache (KYA-OS story L3-C points 6 and 7; SPEC.md §6.5.2, §6.6):
 * verified status lists by URL, and per-credential verdicts by credential
 * id, each with a TTL at or below the revocation propagation target.
 *
 * - `statusCacheTtl` (seconds, default 300) bounds every entry.
 * - `highPrivilegeScopes`: a read for a request that touches one of them is
 *   held to `highPrivilegeTtl` (default and ceiling 60 s, §6.5.2).
 * - A list is kept only when it was read inside the window it states, and
 *   served past the window's end for no longer than `maxStaleSeconds`
 *   (default 60), never past its TTL (§6.6).
 * - Anything the cache serves is a cached read: `fresh: false`, which
 *   demotes a Card L3 request to L2 (story L3-C point 4). Only a live read
 *   is fresh.
 * - `invalidate(credentialId)` (a revocation signal, point 7) deletes the
 *   credential's verdict and the list it was read from. A signal for a
 *   credential this cache holds no verdict for drops every cached list, so
 *   the next read of any list is live; a duplicate delete is harmless.
 *
 * The cache lives in a {@link StatusCacheStore}: memory for one instance,
 * the shared Redis next to the nonce store for several (the middleware's
 * `RedisStatusCacheStore`), so one delete is seen by every instance. The
 * cache is a hint only: authority still comes from the chain and the list.
 */

import { clockSkewMs } from './credentials.js';
import type { StatusListRead } from './status.js';

/** The four operations the cache needs from a key-value store; values are strings, TTLs milliseconds. */
export interface StatusCacheStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
  /** Atomically adds one to an integer value (missing reads as 0) and returns the result. */
  increment(key: string): Promise<number>;
}

/** One instance's store: a map with expiries, swept on access. */
export class MemoryStatusCacheStore implements StatusCacheStore {
  readonly #entries = new Map<string, { value: string; expiresAt: number }>();
  readonly #now: () => number;

  constructor(options: { now?: (() => number) | undefined } = {}) {
    this.#now = options.now ?? Date.now;
  }

  async get(key: string): Promise<string | undefined> {
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    if (entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlMs: number): Promise<void> {
    this.#entries.set(key, { value, expiresAt: this.#now() + Math.max(1, ttlMs) });
  }

  async delete(key: string): Promise<void> {
    this.#entries.delete(key);
  }

  async increment(key: string): Promise<number> {
    const current = Number((await this.get(key)) ?? '0');
    const next = (Number.isSafeInteger(current) ? current : 0) + 1;
    this.#entries.set(key, { value: String(next), expiresAt: Number.POSITIVE_INFINITY });
    return next;
  }

  get size(): number {
    return this.#entries.size;
  }
}

export const DEFAULT_STATUS_CACHE_TTL_SECONDS = 300;
/** SPEC.md §6.5.2: ≤ 60 s for high-privilege scopes. */
export const MAX_HIGH_PRIVILEGE_TTL_SECONDS = 60;
export const DEFAULT_MAX_STALE_SECONDS = 60;

export interface StatusCacheOptions {
  store?: StatusCacheStore | undefined;
  /** Seconds every entry lives at most; default 300. */
  statusCacheTtl?: number | undefined;
  /** Scopes whose reads are held to `highPrivilegeTtl`. */
  highPrivilegeScopes?: readonly string[] | undefined;
  /** Seconds, at most 60 and at most `statusCacheTtl`; default the smaller of 60 and `statusCacheTtl`. */
  highPrivilegeTtl?: number | undefined;
  /** Seconds a list read inside its window may be served past its `validUntil`; default 60. */
  maxStaleSeconds?: number | undefined;
  /** Clock tolerance on the list window, ms (the reader's `maxClockSkewMs`); default 120,000. */
  maxClockSkewMs?: number | undefined;
  /** Default `kyaos:status:`. */
  keyPrefix?: string | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
}

/** What a verdict entry pins, so an entry for the same id read from another list, index, purpose or keeper is a miss. */
export interface VerdictKey {
  credentialId: string;
  url: string;
  index: string;
  purpose: string;
  issuer: string;
  keeper: string;
}

export interface CachedVerdict {
  revoked: boolean;
  code?: string | undefined;
  message?: string | undefined;
}

interface StoredList {
  bits: string;
  issuer?: string;
  statusPurpose?: string | string[];
  id?: string;
  validFrom?: string;
  validUntil?: string;
  readAt: number;
}

interface StoredVerdict extends CachedVerdict {
  fingerprint: string;
  url: string;
  readAt: number;
}

const positive = (value: number | undefined, name: string): number | undefined => {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) throw new RangeError(`${name} must be a positive number of seconds`);
  return value;
};

const fingerprintOf = (key: VerdictKey): string => JSON.stringify([key.url, key.index, key.purpose, key.issuer, key.keeper]);

export class StatusCache {
  readonly statusCacheTtl: number;
  readonly highPrivilegeTtl: number;
  readonly highPrivilegeScopes: ReadonlySet<string>;
  readonly maxStaleSeconds: number;
  readonly #store: StatusCacheStore;
  readonly #prefix: string;
  readonly #clock: () => number;
  readonly #skewMs: number;

  constructor(options: StatusCacheOptions = {}) {
    this.statusCacheTtl = positive(options.statusCacheTtl, 'statusCacheTtl') ?? DEFAULT_STATUS_CACHE_TTL_SECONDS;
    const high = positive(options.highPrivilegeTtl, 'highPrivilegeTtl');
    if (high !== undefined && high > MAX_HIGH_PRIVILEGE_TTL_SECONDS) {
      throw new RangeError(`highPrivilegeTtl must be at most ${MAX_HIGH_PRIVILEGE_TTL_SECONDS} seconds (SPEC.md §6.5.2)`);
    }
    this.highPrivilegeTtl = Math.min(high ?? MAX_HIGH_PRIVILEGE_TTL_SECONDS, this.statusCacheTtl);
    this.highPrivilegeScopes = new Set(options.highPrivilegeScopes ?? []);
    const stale = options.maxStaleSeconds;
    if (stale !== undefined && (typeof stale !== 'number' || !Number.isFinite(stale) || stale < 0)) {
      throw new RangeError('maxStaleSeconds must be a non-negative number of seconds');
    }
    this.maxStaleSeconds = stale ?? DEFAULT_MAX_STALE_SECONDS;
    const skew = clockSkewMs(options.maxClockSkewMs);
    if (skew === undefined) throw new RangeError('maxClockSkewMs must be from 0 to 600000');
    this.#skewMs = skew;
    this.#store = options.store ?? new MemoryStatusCacheStore({ now: options.clock });
    this.#prefix = options.keyPrefix ?? 'kyaos:status:';
    this.#clock = options.clock ?? Date.now;
  }

  /** The TTL, in seconds, for a read made for a request that touches `scopes`. */
  ttlFor(scopes: readonly string[] = []): number {
    return scopes.some((scope) => this.highPrivilegeScopes.has(scope)) ? this.highPrivilegeTtl : this.statusCacheTtl;
  }

  async #generation(): Promise<string> {
    return (await this.#store.get(`${this.#prefix}generation`)) ?? '0';
  }

  #listKey(generation: string, url: string): string {
    return `${this.#prefix}list:${generation}:${url}`;
  }

  #verdictKey(credentialId: string): string {
    return `${this.#prefix}verdict:${credentialId}`;
  }

  /** The latest a list read at `readAt` stating `validUntil` may be served, ms; `undefined` when it may not be cached at all. */
  #servableUntil(readAt: number, validUntil: string | undefined, ttlSeconds: number): number | undefined {
    const byTtl = readAt + ttlSeconds * 1000;
    if (validUntil === undefined) return byTtl;
    const until = Date.parse(validUntil);
    if (Number.isNaN(until)) return undefined;
    return Math.min(byTtl, until + this.#skewMs + this.maxStaleSeconds * 1000);
  }

  /** A cached list for `url`, as a cached read (`fresh: false`), or undefined when there is none still servable for `scopes`. */
  async getList(url: string, scopes: readonly string[] = []): Promise<StatusListRead | undefined> {
    const raw = await this.#store.get(this.#listKey(await this.#generation(), url));
    if (raw === undefined) return undefined;
    let stored: StoredList;
    try {
      stored = JSON.parse(raw) as StoredList;
    } catch {
      return undefined;
    }
    const until = this.#servableUntil(stored.readAt, stored.validUntil, this.ttlFor(scopes));
    if (until === undefined || this.#clock() > until) return undefined;
    return {
      bits: new Uint8Array(Buffer.from(stored.bits, 'base64')),
      ...(stored.issuer === undefined ? {} : { issuer: stored.issuer }),
      ...(stored.statusPurpose === undefined ? {} : { statusPurpose: stored.statusPurpose }),
      ...(stored.id === undefined ? {} : { id: stored.id }),
      ...(stored.validFrom === undefined ? {} : { validFrom: stored.validFrom }),
      ...(stored.validUntil === undefined ? {} : { validUntil: stored.validUntil }),
      fresh: false,
      proofVerified: true,
    };
  }

  /** Keeps a live, proof-verified read made inside its window; anything else is not kept. */
  async setList(url: string, read: StatusListRead): Promise<void> {
    if (read.proofVerified !== true || read.fresh === false) return;
    const readAt = this.#clock();
    const until = this.#servableUntil(readAt, read.validUntil, this.statusCacheTtl);
    if (until === undefined || until <= readAt) return;
    const stored: StoredList = {
      bits: Buffer.from(read.bits).toString('base64'),
      ...(read.issuer === undefined ? {} : { issuer: read.issuer }),
      ...(read.statusPurpose === undefined ? {} : { statusPurpose: read.statusPurpose }),
      ...(read.id === undefined ? {} : { id: read.id }),
      ...(read.validFrom === undefined ? {} : { validFrom: read.validFrom }),
      ...(read.validUntil === undefined ? {} : { validUntil: read.validUntil }),
      readAt,
    };
    await this.#store.set(this.#listKey(await this.#generation(), url), JSON.stringify(stored), until - readAt);
  }

  /** A cached verdict for the credential under `key`, or undefined when there is none still servable for `scopes`. */
  async getVerdict(key: VerdictKey, scopes: readonly string[] = []): Promise<CachedVerdict | undefined> {
    const raw = await this.#store.get(this.#verdictKey(key.credentialId));
    if (raw === undefined) return undefined;
    let stored: StoredVerdict;
    try {
      stored = JSON.parse(raw) as StoredVerdict;
    } catch {
      return undefined;
    }
    if (stored.fingerprint !== fingerprintOf(key)) return undefined;
    if (this.#clock() > stored.readAt + this.ttlFor(scopes) * 1000) return undefined;
    return { revoked: stored.revoked, ...(stored.code === undefined ? {} : { code: stored.code }), ...(stored.message === undefined ? {} : { message: stored.message }) };
  }

  /** Keeps the verdict a live read gave, for at most `statusCacheTtl`. */
  async setVerdict(key: VerdictKey, verdict: CachedVerdict): Promise<void> {
    const stored: StoredVerdict = {
      revoked: verdict.revoked,
      ...(verdict.code === undefined ? {} : { code: verdict.code }),
      ...(verdict.message === undefined ? {} : { message: verdict.message }),
      fingerprint: fingerprintOf(key),
      url: key.url,
      readAt: this.#clock(),
    };
    await this.#store.set(this.#verdictKey(key.credentialId), JSON.stringify(stored), this.statusCacheTtl * 1000);
  }

  /**
   * A revocation signal for `credentialId`: deletes its cached verdict and
   * the list it was read from; with no verdict held, drops every cached list.
   * Returns which of the two it did.
   */
  async invalidate(credentialId: string): Promise<'credential' | 'all-lists'> {
    const raw = await this.#store.get(this.#verdictKey(credentialId));
    let url: string | undefined;
    if (raw !== undefined) {
      try {
        url = (JSON.parse(raw) as StoredVerdict).url;
      } catch {
        url = undefined;
      }
    }
    await this.#store.delete(this.#verdictKey(credentialId));
    if (typeof url === 'string') {
      await this.#store.delete(this.#listKey(await this.#generation(), url));
      return 'credential';
    }
    await this.#store.increment(`${this.#prefix}generation`);
    return 'all-lists';
  }
}
