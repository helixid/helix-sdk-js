// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** KYA-OS story C-E point 2: the last-seen DID document version shared on Redis, and the local verifier's seam for it. */

import { describe, expect, it } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import { RAISE_TO_MAX_SCRIPT, RedisRotationSequenceStore, ROTATION_SEQUENCE_KEY_PREFIX, type RedisRotationSequenceClient } from '../src/kyaos/rotation-sequence-store.js';
import { createLocalVerifier } from '../src/verify-locally.js';

/** A Redis stand-in that runs the raise script's semantics. */
function fakeRedis(): RedisRotationSequenceClient & { data: Map<string, string>; scripts: string[] } {
  const data = new Map<string, string>();
  const scripts: string[] = [];
  return {
    data,
    scripts,
    get: async (key) => data.get(key) ?? null,
    eval: async (script, _keys, key, value) => {
      scripts.push(script);
      const kept = data.get(key);
      if (kept === undefined || Number(kept) < Number(value)) data.set(key, value);
      return 1;
    },
  };
}

const DID = 'did:web:agent.example:agents:01';

describe('RedisRotationSequenceStore', () => {
  it('keeps the highest sequence per DID under its prefix, with one atomic script', async () => {
    const redis = fakeRedis();
    const store = new RedisRotationSequenceStore({ client: redis });
    expect(await store.get(DID)).toBeUndefined();
    await store.raise(DID, 3);
    await store.raise(DID, 2);
    expect(await store.get(DID)).toBe(3);
    expect([...redis.data.keys()]).toEqual([`${ROTATION_SEQUENCE_KEY_PREFIX}${DID}`]);
    expect(redis.scripts.every((script) => script === RAISE_TO_MAX_SCRIPT)).toBe(true);
    redis.data.set(`custom:${DID}`, 'junk');
    expect(await new RedisRotationSequenceStore({ client: redis, keyPrefix: 'custom:' }).get(DID)).toBeUndefined();
  });

  it('two instances sharing it: a document older than one either has seen is refused by both', async () => {
    const shared = new RedisRotationSequenceStore({ client: fakeRedis() });
    const served = (sequence: number) => async () => ({ ok: true, status: 200, json: async () => ({ id: DID, rotationSequence: sequence }) });
    const first = kyaos.verifier.createDidResolver({ fetch: served(4), sequenceGuard: new kyaos.verifier.RotationSequenceGuard(shared) });
    const second = kyaos.verifier.createDidResolver({ fetch: served(3), sequenceGuard: new kyaos.verifier.RotationSequenceGuard(shared) });
    await first(DID);
    await expect(second(DID)).rejects.toMatchObject({ reason: 'did_document_stale' });
  });

  it('the local verifier takes the store for its default resolver', async () => {
    const store = new RedisRotationSequenceStore({ client: fakeRedis() });
    await store.raise(DID, 5);
    const fetch = async () => ({ ok: true, status: 200, json: async () => ({ id: DID, rotationSequence: 4 }) });
    const verifier = createLocalVerifier({ serviceDid: 'did:web:orders.example', fetch, rotationSequenceStore: store });
    await expect(verifier.seams.resolveDid!(DID)).rejects.toMatchObject({ reason: 'did_document_stale' });
  });
});
