// Copyright 2026 DgVerse LLP
// KYA-OS story L3-E on L2-A's environment: the resume-token store follows KYAOS_NONCE_STORE.
import { describe, expect, it, vi } from 'vitest';
import { NonceStoreConfigError, readNonceStoreConfig, type NonceStoreLog } from '../../src/kyaos/index.js';
import { MemoryResumeTokenStore, RedisResumeTokenStore } from '../../src/resume-token-store.js';
import {
  DEFAULT_RESUME_KEY_PREFIX,
  deferredResumeTokenStoreFromEnv,
  describeResumeTokenStore,
  importOptional,
  resumeTokenStoreFromConfig,
  resumeTokenStoreFromEnv,
} from '../../src/resume-token-store-env.js';
import { createNeedsAuthorization } from '../../src/needs-authorization.js';
import { AGENT, NOW } from './helpers.js';

const BINDING = { agentDid: AGENT, tool: 'refund_order', scopes: ['orders:admin'] };
const REDIS = { KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://user:secret@127.0.0.1:6380' };

function recorder(): NonceStoreLog & { info_: string[]; warn_: string[] } {
  const info_: string[] = [];
  const warn_: string[] = [];
  return { info_, warn_, info: (l) => void info_.push(l), warn: (l) => void warn_.push(l) };
}

/** A stand-in for ioredis with SET NX PX and GETDEL over one shared key space. */
function fakeIoredis() {
  const built: string[] = [];
  const entries = new Map<string, string>();
  class FakeRedis {
    listeners: Record<string, (error: Error) => void> = {};
    constructor(url: string) {
      built.push(url);
      instances.push(this);
    }
    on(event: string, listener: (error: Error) => void) {
      this.listeners[event] = listener;
      return this;
    }
    async set(key: string, value: string) {
      if (entries.has(key)) return null;
      entries.set(key, value);
      return 'OK' as const;
    }
    async getdel(key: string) {
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return value;
    }
  }
  const instances: FakeRedis[] = [];
  return { built, entries, instances, importModule: async (name: string) => (name === 'ioredis' ? { default: FakeRedis } : Promise.reject(new Error(name))) };
}

const missing = async () => Promise.reject(Object.assign(new Error("Cannot find package 'ioredis'"), { code: 'ERR_MODULE_NOT_FOUND' }));

describe('describeResumeTokenStore', () => {
  it('names the store without secrets', () => {
    expect(describeResumeTokenStore({ kind: 'memory' })).toBe('KYA-OS resume-token store: memory (this process only)');
    expect(describeResumeTokenStore(readNonceStoreConfig(REDIS))).toBe('KYA-OS resume-token store: redis redis://user:***@127.0.0.1:6380 (key prefix kyaos:resume:)');
    expect(describeResumeTokenStore(readNonceStoreConfig(REDIS), 'p:')).toContain('(key prefix p:)');
    expect(DEFAULT_RESUME_KEY_PREFIX).toBe('kyaos:resume:');
  });
});

describe('deferredResumeTokenStoreFromEnv', () => {
  it('is memory by default and for dynamo (with a warning), ready at once', async () => {
    const log = recorder();
    const store = deferredResumeTokenStoreFromEnv({}, { log, now: () => NOW });
    expect(store).toBeInstanceOf(MemoryResumeTokenStore);
    await expect(store.ready).resolves.toBeUndefined();
    expect(log.info_).toEqual(['KYA-OS resume-token store: memory (this process only)']);
    expect(log.warn_).toEqual([]);
    const dynamo = deferredResumeTokenStoreFromEnv({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't' }, { log });
    expect(dynamo).toBeInstanceOf(MemoryResumeTokenStore);
    expect(log.warn_[0]).toContain('no DynamoDB resume-token store');
    // A bad replay-store setting is refused here too, at startup.
    expect(() => deferredResumeTokenStoreFromEnv({ KYAOS_NONCE_STORE: 'redis' }, { log })).toThrow(NonceStoreConfigError);
  });

  it('is Redis on KYAOS_REDIS_URL when the replay store is Redis, single-use across instances, with its own key prefix', async () => {
    const redis = fakeIoredis();
    const log = recorder();
    const store = deferredResumeTokenStoreFromEnv({ ...REDIS, KYAOS_RESUME_KEY_PREFIX: 'r:' }, { log, importModule: redis.importModule, now: () => NOW });
    // Usable before it is ready: calls wait for the client.
    const token = await store.issue(BINDING, NOW + 60_000);
    await expect(store.ready).resolves.toBeUndefined();
    expect(redis.built).toEqual(['redis://user:secret@127.0.0.1:6380']);
    expect([...redis.entries.keys()]).toEqual([`r:${token}`]);
    expect(log.info_).toEqual(['KYA-OS resume-token store: redis redis://user:***@127.0.0.1:6380 (key prefix r:)']);
    const peer = await resumeTokenStoreFromEnv({ ...REDIS, KYAOS_RESUME_KEY_PREFIX: 'r:' }, { log, importModule: redis.importModule, now: () => NOW });
    expect(await peer.consume(token)).toEqual({ ...BINDING, expiresAt: NOW + 60_000 });
    expect(await store.consume(token)).toBeUndefined();
    // ioredis errors are logged without the URL.
    redis.instances[0]!.listeners['error']!(new Error('ECONNREFUSED'));
    expect(log.warn_).toEqual(['KYA-OS resume-token store: redis error: ECONNREFUSED']);
  });

  it('rejects ready, and every call, when ioredis is missing; other import failures pass through', async () => {
    const store = deferredResumeTokenStoreFromEnv(REDIS, { log: recorder(), importModule: missing });
    await expect(store.ready).rejects.toThrow('needs the optional package ioredis');
    await expect(store.issue(BINDING, NOW)).rejects.toBeInstanceOf(NonceStoreConfigError);
    await expect(store.consume('x')).rejects.toBeInstanceOf(NonceStoreConfigError);
    await expect(resumeTokenStoreFromConfig(readNonceStoreConfig(REDIS), { importModule: async () => Promise.reject(new Error('boom')) })).rejects.toThrow('boom');
    expect(await resumeTokenStoreFromConfig({ kind: 'memory' })).toBeInstanceOf(MemoryResumeTokenStore);
    const built = await resumeTokenStoreFromConfig(readNonceStoreConfig(REDIS), { importModule: fakeIoredis().importModule });
    expect(built).toBeInstanceOf(RedisResumeTokenStore);
  });
});

describe('importOptional', () => {
  it('is a dynamic import', async () => {
    expect(((await importOptional('node:path')) as { sep: string }).sep).toBe('/');
  });
});

describe('the default log', () => {
  it('is the console: the startup line on info, the dynamo warning on warn', () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      deferredResumeTokenStoreFromEnv({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't' });
      expect(info).toHaveBeenCalledWith('KYA-OS resume-token store: memory (this process only)');
      expect(warn.mock.calls[0]![0]).toContain('no DynamoDB resume-token store');
    } finally {
      info.mockRestore();
      warn.mockRestore();
    }
  });
});

describe('createNeedsAuthorization default store', () => {
  it('comes from the environment, and ready() reports it', async () => {
    const memory = createNeedsAuthorization({ authorizationUrl: 'https://consent.example', env: {}, log: recorder() });
    expect(memory.store).toBeInstanceOf(MemoryResumeTokenStore);
    await expect(memory.ready()).resolves.toBeUndefined();
    // A bad replay-store setting fails the layer at construction, as it fails createKyaOs.
    expect(() => createNeedsAuthorization({ authorizationUrl: 'https://consent.example', env: { KYAOS_NONCE_STORE: 'postgres' }, log: recorder() })).toThrow(NonceStoreConfigError);
    const explicit = createNeedsAuthorization({ authorizationUrl: 'https://consent.example', store: new MemoryResumeTokenStore() });
    await expect(explicit.ready()).resolves.toBeUndefined();
  });
});
