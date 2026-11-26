// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: sessions (L2.7, L2.8, L2.10).
import { describe, expect, it } from 'vitest';
import { MemorySessionStore } from '../../src/kyaos/index.js';
import { AGENT, NOW, SERVER } from './helpers.js';

const input = { agentDid: AGENT, identityState: 'authenticated' as const, audience: SERVER, nonce: 'k7Hy9mNpQrStUvWxYz01Aa', now: NOW };

describe('MemorySessionStore', () => {
  it('creates kyaos_<uuid-v4> sessions with a 30 minute idle TTL by default (L2.7, L2.8)', async () => {
    const store = new MemorySessionStore();
    expect(store.ttlMinutes).toBe(30);
    const session = await store.create(input);
    expect(session).toEqual({
      id: session.id,
      agentDid: AGENT,
      identityState: 'authenticated',
      audience: SERVER,
      nonce: input.nonce,
      createdAt: NOW,
      lastActivity: NOW,
      expiresAt: NOW + 30 * 60_000,
    });
    expect(session.id).toMatch(/^kyaos_[0-9a-f-]{36}$/);
    expect((await store.create(input)).id).not.toBe(session.id);
    expect(store.size).toBe(2);
    const anonymous = await store.create({ identityState: 'anonymous', audience: SERVER, nonce: input.nonce, now: NOW });
    expect(anonymous).not.toHaveProperty('agentDid');
    expect(anonymous.identityState).toBe('anonymous');
  });

  it('returns copies: a caller cannot change the stored session', async () => {
    const store = new MemorySessionStore({ generateId: () => 'kyaos_11111111-2222-4333-8444-555555555555' });
    const created = await store.create(input);
    created.lastActivity = 0;
    const fetched = (await store.get(created.id, NOW))!;
    expect(fetched.lastActivity).toBe(NOW);
    fetched.expiresAt = 0;
    expect((await store.get(created.id, NOW))!.expiresAt).toBe(NOW + 30 * 60_000);
  });

  it('expires an idle session after the TTL, exactly at the boundary (L2.8)', async () => {
    const store = new MemorySessionStore({ ttlMinutes: 1 });
    const { id } = await store.create(input);
    expect(await store.get(id, NOW + 59_999)).toBeDefined();
    expect(await store.get(id, NOW + 60_000)).toBeUndefined();
    expect(store.size).toBe(0);
    expect(await store.get(id, NOW)).toBeUndefined();
    expect(await store.get('kyaos_unknown', NOW)).toBeUndefined();
  });

  it('touch moves lastActivity and the expiry out by the TTL (L2.10), and refuses an expired session', async () => {
    const store = new MemorySessionStore({ ttlMinutes: 1 });
    const { id } = await store.create(input);
    const touched = (await store.touch(id, NOW + 30_000))!;
    expect(touched.lastActivity).toBe(NOW + 30_000);
    expect(touched.expiresAt).toBe(NOW + 90_000);
    expect(touched.createdAt).toBe(NOW);
    expect(await store.get(id, NOW + 89_999)).toBeDefined();
    expect(await store.touch(id, NOW + 90_000)).toBeUndefined();
    expect(await store.get(id, NOW + 90_001)).toBeUndefined();
    expect(await store.touch('kyaos_unknown', NOW)).toBeUndefined();
  });

  it('delete forgets a session', async () => {
    const store = new MemorySessionStore();
    const { id } = await store.create(input);
    await store.delete(id);
    expect(await store.get(id, NOW)).toBeUndefined();
    await store.delete(id);
  });

  it('refuses a TTL that is not a positive number', () => {
    for (const ttl of [0, -1, NaN, Infinity]) {
      expect(() => new MemorySessionStore({ ttlMinutes: ttl }), String(ttl)).toThrow(RangeError);
    }
    expect(new MemorySessionStore({ ttlMinutes: 0.5 }).ttlMinutes).toBe(0.5);
  });
});
