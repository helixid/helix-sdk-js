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

/**
 * The last-seen DID document version on Redis (KYA-OS story C-E point 2): in
 * multi-instance mode every instance's resolver reads and raises the same
 * `rotationSequence` per DID, so a stale document replayed to one instance
 * is refused there once any instance has seen a newer one. The raise is one
 * atomic script (keep the higher), so two instances never lower it.
 */

import type { kyaos } from '@helixid/sdk-js';

/** The Redis commands the store needs, as ioredis exposes them. */
export interface RedisRotationSequenceClient {
  get(key: string): Promise<string | null>;
  eval(script: string, keys: number, key: string, value: string): Promise<unknown>;
}

/** Keeps the higher of the stored and the given sequence, atomically. */
export const RAISE_TO_MAX_SCRIPT =
  "local kept = redis.call('GET', KEYS[1]) if (not kept) or tonumber(kept) < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end return 1";

export const ROTATION_SEQUENCE_KEY_PREFIX = 'kyaos:did-rotation-sequence:';

export class RedisRotationSequenceStore implements kyaos.verifier.RotationSequenceStore {
  readonly #client: RedisRotationSequenceClient;
  readonly #prefix: string;

  constructor(options: { client: RedisRotationSequenceClient; keyPrefix?: string }) {
    this.#client = options.client;
    this.#prefix = options.keyPrefix ?? ROTATION_SEQUENCE_KEY_PREFIX;
  }

  async get(did: string): Promise<number | undefined> {
    const value = await this.#client.get(`${this.#prefix}${did}`);
    const sequence = value === null ? Number.NaN : Number(value);
    return Number.isSafeInteger(sequence) ? sequence : undefined;
  }

  async raise(did: string, sequence: number): Promise<void> {
    await this.#client.eval(RAISE_TO_MAX_SCRIPT, 1, `${this.#prefix}${did}`, String(sequence));
  }
}
