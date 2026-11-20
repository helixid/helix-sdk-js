// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the replay store (L2.5), in memory, on Redis and on DynamoDB.
import { describe, expect, it } from 'vitest';
import { DynamoNonceStore, MemoryNonceStore, RedisNonceStore, nonceKey } from '../../src/kyaos/index.js';
import { AGENT, FakeDynamo, FakeRedis, NOW, clock } from './helpers.js';

const NONCE = 'k7Hy9mNpQrStUvWxYz01Aa';
const SKEW = 120;
const ts = Math.floor(NOW / 1000);
/** The retention the middleware uses: ts + skew + 1 s. */
const expiry = (ts + SKEW + 1) * 1000;

describe('nonceKey', () => {
  it('is one key per (nonce, agentDid), anonymous included', () => {
    expect(nonceKey(NONCE, AGENT)).toBe(`${AGENT}|${NONCE}`);
    expect(nonceKey(NONCE, undefined)).toBe(`|${NONCE}`);
    expect(nonceKey(NONCE, AGENT)).not.toBe(nonceKey(NONCE, 'did:key:z6Mkother'));
  });
});

describe('MemoryNonceStore', () => {
  it('accepts a nonce once and refuses the replay (L2.5)', async () => {
    const store = new MemoryNonceStore({ now: clock().now });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    expect(store.has(NONCE, AGENT)).toBe(true);
    expect(store.size).toBe(1);
  });

  it('keeps nonces per agent: the same nonce from another agent, or anonymous, is a different entry', async () => {
    const store = new MemoryNonceStore({ now: clock().now });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    expect(await store.insert(NONCE, 'did:key:z6Mkother', expiry)).toBe(true);
    expect(await store.insert(NONCE, undefined, expiry)).toBe(true);
    expect(await store.insert(NONCE, undefined, expiry)).toBe(false);
    expect(store.size).toBe(3);
  });

  it('retains an entry until ts + skew + 1 s and never evicts it early', async () => {
    const time = clock();
    const store = new MemoryNonceStore({ now: time.now });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    // The acceptance window ends at ts + skew; the entry must outlive it.
    time.set((ts + SKEW) * 1000);
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    time.set(expiry - 1);
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    expect(store.has(NONCE, AGENT)).toBe(true);
    time.set(expiry);
    expect(store.has(NONCE, AGENT)).toBe(false);
    // Expired entries are swept on the next insert, then the nonce (now outside any window) could be recorded again.
    expect(await store.insert('AAAAAAAAAAAAAAAAAAAAAA', AGENT, expiry + 10_000)).toBe(true);
    expect(store.size).toBe(1);
    expect(await store.insert(NONCE, AGENT, expiry + 10_000)).toBe(true);
  });

  it('is atomic under concurrent inserts of the same pair: exactly one wins', async () => {
    const store = new MemoryNonceStore();
    const results = await Promise.all(Array.from({ length: 100 }, () => store.insert(NONCE, AGENT, Date.now() + 60_000)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(store.has(NONCE, AGENT)).toBe(true);
  });

  it('defaults to the wall clock', async () => {
    const store = new MemoryNonceStore();
    expect(await store.insert(NONCE, AGENT, Date.now() - 1)).toBe(true);
    // Already expired by the wall clock: not reported as held, and the next insert sweeps it.
    expect(store.has(NONCE, AGENT)).toBe(false);
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(true);
  });
});

/**
 * Tested against an in-process fake with Redis's `SET NX PX` semantics (see
 * helpers.ts), not a live Redis: no Redis and no Docker daemon were
 * available where this suite was written. The e2e suite runs the same store
 * against a real Redis shared by two middleware instances.
 */
describe('RedisNonceStore (in-process fake of SET NX PX)', () => {
  it('inserts with SET NX PX, the TTL running to expiresAt, under the key prefix', async () => {
    const time = clock();
    const redis = new FakeRedis(time.now);
    const store = new RedisNonceStore({ client: redis, now: time.now });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    expect(redis.commands).toEqual([`SET kyaos:nonce:${AGENT}|${NONCE} ${expiry} PX ${expiry - NOW} NX`]);
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    const custom = new RedisNonceStore({ client: redis, keyPrefix: 'app:', now: time.now });
    expect(await custom.insert(NONCE, AGENT, expiry)).toBe(true);
    expect(redis.commands[2]).toBe(`SET app:${AGENT}|${NONCE} ${expiry} PX ${expiry - NOW} NX`);
  });

  it('refuses a replay at a second instance sharing the store, under concurrent load', async () => {
    const time = clock();
    const redis = new FakeRedis(time.now);
    const first = new RedisNonceStore({ client: redis, now: time.now });
    const second = new RedisNonceStore({ client: redis, now: time.now });
    const attempts = await Promise.all(Array.from({ length: 50 }, (_, i) => (i % 2 ? first : second).insert(NONCE, AGENT, expiry)));
    expect(attempts.filter(Boolean)).toHaveLength(1);
    expect(await second.insert(NONCE, AGENT, expiry)).toBe(false);
    expect(await first.insert(NONCE, undefined, expiry)).toBe(true);
  });

  it('lets Redis expire the key at expiresAt and not before, and keeps a past expiry one tick', async () => {
    const time = clock();
    const redis = new FakeRedis(time.now);
    const store = new RedisNonceStore({ client: redis, now: time.now });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    time.set(expiry - 1);
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    time.set(expiry);
    expect(await store.insert(NONCE, AGENT, expiry + 1)).toBe(true);
    expect(await store.insert('AAAAAAAAAAAAAAAAAAAAAA', AGENT, time.now() - 5000)).toBe(true);
    expect(redis.commands.at(-1)).toContain('PX 1 NX');
  });

  it('defaults to the wall clock', async () => {
    const redis = new FakeRedis(Date.now);
    const store = new RedisNonceStore({ client: redis });
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(true);
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(false);
  });
});

describe('DynamoNonceStore (in-process fake of a conditional PutItem)', () => {
  it('writes the item conditioned on the key being absent, with the expiry in seconds for the table TTL', async () => {
    const dynamo = new FakeDynamo();
    const store = new DynamoNonceStore({ client: dynamo, tableName: 'kyaos-nonces' });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(true);
    expect(dynamo.puts[0]).toEqual({
      TableName: 'kyaos-nonces',
      Item: { pk: `${AGENT}|${NONCE}`, nonce: NONCE, agentDid: AGENT, expiresAt: Math.ceil(expiry / 1000) },
      ConditionExpression: 'attribute_not_exists(#pk)',
      ExpressionAttributeNames: { '#pk': 'pk' },
    });
    expect(await store.insert(NONCE, AGENT, expiry)).toBe(false);
    expect(await store.insert(NONCE, undefined, expiry + 1)).toBe(true);
    expect((dynamo.puts[2] as { Item: Record<string, unknown> }).Item).toEqual({ pk: `|${NONCE}`, nonce: NONCE, expiresAt: Math.ceil((expiry + 1) / 1000) });
  });

  it('takes custom key and TTL attribute names, and is shared across instances', async () => {
    const dynamo = new FakeDynamo();
    const first = new DynamoNonceStore({ client: dynamo, tableName: 't', keyAttribute: 'id', ttlAttribute: 'ttl' });
    const second = new DynamoNonceStore({ client: dynamo, tableName: 't', keyAttribute: 'id', ttlAttribute: 'ttl' });
    const attempts = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? first : second).insert(NONCE, AGENT, expiry)));
    expect(attempts.filter(Boolean)).toHaveLength(1);
    expect((dynamo.puts[0] as { Item: Record<string, unknown>; ExpressionAttributeNames: unknown }).Item['id']).toBe(`${AGENT}|${NONCE}`);
    expect((dynamo.puts[0] as { Item: Record<string, unknown> }).Item['ttl']).toBe(Math.ceil(expiry / 1000));
    expect((dynamo.puts[0] as { ExpressionAttributeNames: unknown }).ExpressionAttributeNames).toEqual({ '#pk': 'id' });
  });

  it('passes any failure other than the condition through', async () => {
    const dynamo = new FakeDynamo();
    dynamo.failWith = Object.assign(new Error('throttled'), { name: 'ProvisionedThroughputExceededException' });
    const store = new DynamoNonceStore({ client: dynamo, tableName: 't' });
    await expect(store.insert(NONCE, AGENT, expiry)).rejects.toThrow('throttled');
    dynamo.failWith = new Error('no name');
    await expect(store.insert(NONCE, AGENT, expiry)).rejects.toThrow('no name');
  });
});
