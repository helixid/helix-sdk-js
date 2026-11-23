// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The status cache on Redis (KYA-OS story L3-C point 7): in multi-instance
 * mode the verified status lists and per-credential verdicts live in the
 * shared Redis next to the nonce store, so the one delete a revocation
 * signal causes on whichever instance received it is seen by every
 * instance, and a duplicate delete is harmless. Values are strings with a
 * `PX` expiry; the list namespace's generation counter is a plain `INCR`.
 */

import type { kyaos } from '@helixid/sdk-js';

/** The four Redis commands the store needs, as ioredis and compatible clients expose them. */
export interface RedisStatusCacheClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, px: 'PX', milliseconds: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
}

export class RedisStatusCacheStore implements kyaos.verifier.StatusCacheStore {
  readonly #client: RedisStatusCacheClient;

  constructor(options: { client: RedisStatusCacheClient }) {
    this.#client = options.client;
  }

  async get(key: string): Promise<string | undefined> {
    return (await this.#client.get(key)) ?? undefined;
  }

  async set(key: string, value: string, ttlMs: number): Promise<void> {
    await this.#client.set(key, value, 'PX', Math.max(1, Math.ceil(ttlMs)));
  }

  async delete(key: string): Promise<void> {
    await this.#client.del(key);
  }

  increment(key: string): Promise<number> {
    return this.#client.incr(key);
  }
}
