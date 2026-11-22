// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { randomBytes } from 'node:crypto';

/**
 * The resume-token store of the `needs_authorization` flow (KYA-OS story
 * L3-E, SPEC §9.2 and §9.3). A token is opaque (base64url of 32 random
 * bytes), bound to the agent DID, the tool and the scopes the challenge asked
 * for, single-use, and gone at `expiresAt`. `issue` records the binding and
 * `consume` hands it back exactly once: a replayed, expired or unknown token
 * resolves to nothing, and the caller refuses.
 *
 * `MemoryResumeTokenStore` serves one instance. `RedisResumeTokenStore`
 * (`SET NX PX` to issue, `GETDEL` to consume) serves several instances
 * sharing one Redis, the same pattern as L2-A's `NonceStore`.
 *
 * Cross-border rule (stories, rule 4): this store is local state next to
 * the nonce store, never a Helix database; nothing here asks Helix anything.
 */

export interface ResumeTokenBinding {
  /** The agent the challenge was issued to; only that agent may resume. */
  agentDid: string;
  /** The tool the call was for; only a retry of that tool may resume. */
  tool: string;
  /** The scopes the challenge asked for; the retry must ask for no more. */
  scopes: string[];
}

export interface ResumeTokenRecord extends ResumeTokenBinding {
  /** Milliseconds since the epoch; the token is refused from this instant on. */
  expiresAt: number;
}

export interface ResumeTokenStore {
  /** Records `binding` under a fresh opaque token that expires at `expiresAt` (ms) and resolves the token. */
  issue(binding: ResumeTokenBinding, expiresAt: number): Promise<string>;
  /**
   * Resolves the record of `token` and removes it, atomically: of two
   * concurrent consumers exactly one gets the record. Resolves undefined for
   * a token that is unknown, already consumed or expired.
   */
  consume(token: string): Promise<ResumeTokenRecord | undefined>;
}

/** 32 random bytes as base64url: 43 characters, no padding. */
export function generateResumeToken(random: (size: number) => Uint8Array = randomBytes): string {
  return Buffer.from(random(32)).toString('base64url');
}

const TOKEN = /^[A-Za-z0-9_-]{22,}$/;

/** Whether `value` looks like a token this store issues; anything else is refused before any lookup. */
export function isResumeToken(value: unknown): value is string {
  return typeof value === 'string' && TOKEN.test(value);
}

export function serializeRecord(record: ResumeTokenRecord): string {
  return JSON.stringify({ agentDid: record.agentDid, tool: record.tool, scopes: [...record.scopes], expiresAt: record.expiresAt });
}

export function parseRecord(text: string): ResumeTokenRecord {
  const value = JSON.parse(text) as Record<string, unknown>;
  const { agentDid, tool, scopes, expiresAt } = value;
  if (typeof agentDid !== 'string' || typeof tool !== 'string' || !Array.isArray(scopes) || typeof expiresAt !== 'number') {
    throw new Error('resume token record is malformed');
  }
  return { agentDid, tool, scopes: scopes.filter((s): s is string => typeof s === 'string'), expiresAt };
}

export interface MemoryResumeTokenStoreOptions {
  /** Milliseconds since the epoch; default `Date.now`. Injectable for tests. */
  now?: () => number;
  random?: (size: number) => Uint8Array;
}

/** Single-instance store: a map of token to record, swept of expired entries on every call. */
export class MemoryResumeTokenStore implements ResumeTokenStore {
  readonly #entries = new Map<string, ResumeTokenRecord>();
  readonly #now: () => number;
  readonly #random: (size: number) => Uint8Array;

  constructor(options: MemoryResumeTokenStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#random = options.random ?? randomBytes;
  }

  #sweep(): void {
    const now = this.#now();
    for (const [token, record] of this.#entries) {
      if (record.expiresAt <= now) this.#entries.delete(token);
    }
  }

  async issue(binding: ResumeTokenBinding, expiresAt: number): Promise<string> {
    this.#sweep();
    let token = generateResumeToken(this.#random);
    while (this.#entries.has(token)) token = generateResumeToken(this.#random);
    this.#entries.set(token, { agentDid: binding.agentDid, tool: binding.tool, scopes: [...binding.scopes], expiresAt });
    return token;
  }

  async consume(token: string): Promise<ResumeTokenRecord | undefined> {
    this.#sweep();
    const record = this.#entries.get(token);
    if (record === undefined) return undefined;
    this.#entries.delete(token);
    return record;
  }

  /** Whether `token` is live (for tests and diagnostics). */
  has(token: string): boolean {
    const record = this.#entries.get(token);
    return record !== undefined && record.expiresAt > this.#now();
  }

  get size(): number {
    return this.#entries.size;
  }
}

/** The two Redis commands the store needs, as ioredis and compatible clients expose them. */
export interface ResumeRedisLikeClient {
  set(key: string, value: string, px: 'PX', milliseconds: number, nx: 'NX'): Promise<'OK' | null>;
  /** Redis 6.2+: returns the value and deletes the key in one step. */
  getdel(key: string): Promise<string | null>;
}

export interface RedisResumeTokenStoreOptions {
  client: ResumeRedisLikeClient;
  /** Default `kyaos:resume:`. */
  keyPrefix?: string;
  /** Milliseconds since the epoch; default `Date.now`. */
  now?: () => number;
  random?: (size: number) => Uint8Array;
}

/** Multi-instance store on Redis: `SET NX PX` records the binding until `expiresAt`, `GETDEL` consumes it atomically. */
export class RedisResumeTokenStore implements ResumeTokenStore {
  readonly #client: ResumeRedisLikeClient;
  readonly #prefix: string;
  readonly #now: () => number;
  readonly #random: (size: number) => Uint8Array;

  constructor(options: RedisResumeTokenStoreOptions) {
    this.#client = options.client;
    this.#prefix = options.keyPrefix ?? 'kyaos:resume:';
    this.#now = options.now ?? Date.now;
    this.#random = options.random ?? randomBytes;
  }

  async issue(binding: ResumeTokenBinding, expiresAt: number): Promise<string> {
    const ttl = Math.max(1, expiresAt - this.#now());
    const value = serializeRecord({ ...binding, expiresAt });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const token = generateResumeToken(this.#random);
      if ((await this.#client.set(`${this.#prefix}${token}`, value, 'PX', ttl, 'NX')) === 'OK') return token;
    }
    throw new Error('RedisResumeTokenStore: could not record a fresh resume token');
  }

  async consume(token: string): Promise<ResumeTokenRecord | undefined> {
    const text = await this.#client.getdel(`${this.#prefix}${token}`);
    if (text === null) return undefined;
    const record = parseRecord(text);
    // Redis expires on its own clock; the injected one is the one the challenge promised.
    return record.expiresAt > this.#now() ? record : undefined;
  }
}
