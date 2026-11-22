// Copyright 2026 DgVerse LLP
// KYA-OS story L3-E: the resume-token store (opaque, bound, single-use, expiring).
import { describe, expect, it } from 'vitest';
import {
  MemoryResumeTokenStore,
  RedisResumeTokenStore,
  generateResumeToken,
  isResumeToken,
  parseRecord,
  serializeRecord,
  type ResumeTokenBinding,
} from '../../src/resume-token-store.js';
import { AGENT, NOW, clock } from './helpers.js';

const BINDING: ResumeTokenBinding = { agentDid: AGENT, tool: 'refund_order', scopes: ['orders:admin'] };
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** A byte source that repeats its first value `repeats` times, then counts up: forces collisions on demand. */
function countingRandom(repeats = 0): (size: number) => Uint8Array {
  let calls = 0;
  return (size) => {
    const n = calls < repeats ? 0 : calls - repeats;
    calls += 1;
    return Uint8Array.from({ length: size }, (_, i) => (i === 0 ? n & 0xff : 7));
  };
}

/** FakeRedis of helpers.ts plus GETDEL, which the resume store needs. */
class FakeRedisWithGetDel {
  readonly entries = new Map<string, { value: string; expiresAt: number }>();
  readonly commands: string[] = [];
  constructor(readonly now: () => number) {}

  async set(key: string, value: string, px: 'PX', milliseconds: number, nx: 'NX'): Promise<'OK' | null> {
    this.commands.push(`SET ${key} ${px} ${milliseconds} ${nx}`);
    const existing = this.entries.get(key);
    if (existing !== undefined && existing.expiresAt > this.now()) return null;
    this.entries.set(key, { value, expiresAt: this.now() + milliseconds });
    return 'OK';
  }

  async getdel(key: string): Promise<string | null> {
    this.commands.push(`GETDEL ${key}`);
    const existing = this.entries.get(key);
    this.entries.delete(key);
    return existing !== undefined && existing.expiresAt > this.now() ? existing.value : null;
  }
}

describe('resume tokens', () => {
  it('are 32 random bytes as base64url, and only such strings are looked up', () => {
    const token = generateResumeToken();
    expect(token).toMatch(TOKEN);
    expect(generateResumeToken()).not.toBe(token);
    expect(isResumeToken(token)).toBe(true);
    expect(isResumeToken('k7Hy9mNpQrStUvWxYz01AB')).toBe(true);
    expect(isResumeToken('short')).toBe(false);
    expect(isResumeToken(`${token}=`)).toBe(false);
    expect(isResumeToken(42)).toBe(false);
    expect(isResumeToken(undefined)).toBe(false);
  });

  it('serialise their record and refuse a malformed one', () => {
    const record = { ...BINDING, expiresAt: NOW + 1000 };
    expect(parseRecord(serializeRecord(record))).toEqual(record);
    expect(parseRecord('{"agentDid":"did:key:z","tool":"t","scopes":["a",1,"b"],"expiresAt":5}')).toEqual({ agentDid: 'did:key:z', tool: 't', scopes: ['a', 'b'], expiresAt: 5 });
    expect(() => parseRecord('{"agentDid":"x"}')).toThrow('malformed');
    expect(() => parseRecord('{"agentDid":"x","tool":"t","scopes":"a","expiresAt":1}')).toThrow('malformed');
  });
});

describe('MemoryResumeTokenStore', () => {
  it('hands a record back exactly once, and never after it expired', async () => {
    const time = clock();
    const store = new MemoryResumeTokenStore({ now: time.now });
    const token = await store.issue(BINDING, NOW + 10_000);
    expect(token).toMatch(TOKEN);
    expect(store.has(token)).toBe(true);
    expect(store.size).toBe(1);
    expect(await store.consume(token)).toEqual({ ...BINDING, expiresAt: NOW + 10_000 });
    expect(await store.consume(token)).toBeUndefined();
    expect(store.has(token)).toBe(false);
    // The record is a copy: the caller's array is not shared.
    const scopes = ['orders:read'];
    const other = await store.issue({ ...BINDING, scopes }, NOW + 10_000);
    scopes.push('orders:admin');
    expect((await store.consume(other))!.scopes).toEqual(['orders:read']);
    // Expiry, by the injected clock.
    const expiring = await store.issue(BINDING, NOW + 1_000);
    time.advance(999);
    expect(store.has(expiring)).toBe(true);
    time.advance(1);
    expect(store.has(expiring)).toBe(false);
    expect(await store.consume(expiring)).toBeUndefined();
    expect(store.size).toBe(0);
    expect(await store.consume('not-a-token')).toBeUndefined();
  });

  it('never hands out a token twice, even when the byte source repeats', async () => {
    const store = new MemoryResumeTokenStore({ now: () => NOW, random: countingRandom(1) });
    const first = await store.issue(BINDING, NOW + 10_000);
    const second = await store.issue(BINDING, NOW + 10_000);
    expect(second).not.toBe(first);
    expect(store.size).toBe(2);
    expect(new MemoryResumeTokenStore().size).toBe(0);
  });
});

describe('RedisResumeTokenStore', () => {
  it('issues with SET NX PX for the token lifetime and consumes with GETDEL, once', async () => {
    const time = clock();
    const redis = new FakeRedisWithGetDel(time.now);
    const store = new RedisResumeTokenStore({ client: redis, now: time.now });
    const token = await store.issue(BINDING, NOW + 10_000);
    expect(redis.commands).toEqual([`SET kyaos:resume:${token} PX 10000 NX`]);
    expect(await store.consume(token)).toEqual({ ...BINDING, expiresAt: NOW + 10_000 });
    expect(redis.commands[1]).toBe(`GETDEL kyaos:resume:${token}`);
    expect(await store.consume(token)).toBeUndefined();
    // Another instance on the same Redis sees the same single use.
    const peer = new RedisResumeTokenStore({ client: redis, now: time.now, keyPrefix: 'kyaos:resume:' });
    const shared = await store.issue(BINDING, NOW + 10_000);
    expect(await peer.consume(shared)).toEqual({ ...BINDING, expiresAt: NOW + 10_000 });
    expect(await store.consume(shared)).toBeUndefined();
  });

  it('refuses a record past its promised expiry even when Redis still holds it, and keeps an already-due token one tick', async () => {
    const time = clock();
    const redis = new FakeRedisWithGetDel(() => NOW); // Redis's own clock stands still
    const store = new RedisResumeTokenStore({ client: redis, now: time.now, keyPrefix: 'r:' });
    const token = await store.issue(BINDING, NOW + 1_000);
    time.advance(1_000);
    expect(await store.consume(token)).toBeUndefined();
    const due = await store.issue(BINDING, NOW); // expiresAt already in the past
    expect(redis.commands.at(-1)).toBe(`SET r:${due} PX 1 NX`);
  });

  it('retries a colliding token and gives up after three', async () => {
    const redis = new FakeRedisWithGetDel(() => NOW);
    const store = new RedisResumeTokenStore({ client: redis, random: countingRandom(1), now: () => NOW });
    const first = await store.issue(BINDING, NOW + 10_000);
    const second = await store.issue(BINDING, NOW + 10_000);
    expect(second).not.toBe(first);
    expect(redis.commands).toHaveLength(3); // one collision on the way to the second token
    const stuck = new RedisResumeTokenStore({ client: new FakeRedisWithGetDel(() => NOW), random: countingRandom(10), now: () => NOW });
    await stuck.issue(BINDING, NOW + 10_000);
    await expect(stuck.issue(BINDING, NOW + 10_000)).rejects.toThrow('could not record a fresh resume token');
  });
});
