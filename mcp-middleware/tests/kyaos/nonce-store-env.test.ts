// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the replay store chosen by environment variables (KYAOS_NONCE_STORE and friends).
import { connect } from 'node:net';
import { describe, expect, it } from 'vitest';
import {
  DynamoNonceStore,
  MemoryNonceStore,
  NonceStoreConfigError,
  RedisNonceStore,
  createKyaOs,
  deferredNonceStoreFromEnv,
  describeNonceStore,
  nonceStoreFromConfig,
  nonceStoreFromEnv,
  readNonceStoreConfig,
  redactUrl,
  type NonceStoreLog,
} from '../../src/kyaos/index.js';
import { AGENT, NOW, SERVER, handshakeArgs, signer } from './helpers.js';

const NONCE = 'k7Hy9mNpQrStUvWxYz01Aa';

function recorder(): NonceStoreLog & { info_: string[]; warn_: string[] } {
  const info_: string[] = [];
  const warn_: string[] = [];
  return { info_, warn_, info: (l) => void info_.push(l), warn: (l) => void warn_.push(l) };
}

const missing = (name: string) => Object.assign(new Error(`Cannot find package '${name}'`), { code: 'ERR_MODULE_NOT_FOUND' });

/** Stand-ins for ioredis and the AWS SDK modules, recording how they were built. */
function fakeModules(overrides: Record<string, unknown> = {}) {
  const built: Record<string, unknown[]> = { redis: [], dynamo: [], document: [] };
  class FakeRedis {
    listeners: Record<string, (error: Error) => void> = {};
    constructor(url: string) {
      built['redis']!.push(url);
    }
    on(event: string, listener: (error: Error) => void) {
      this.listeners[event] = listener;
      return this;
    }
    async set() {
      return 'OK' as const;
    }
  }
  class FakeDynamoDBClient {
    constructor(config: unknown) {
      built['dynamo']!.push(config);
    }
  }
  const DynamoDBDocument = {
    from: (client: unknown) => {
      built['document']!.push(client);
      return { put: async () => ({}) };
    },
  };
  const modules: Record<string, unknown> = {
    ioredis: { Redis: FakeRedis },
    '@aws-sdk/client-dynamodb': { DynamoDBClient: FakeDynamoDBClient },
    '@aws-sdk/lib-dynamodb': { DynamoDBDocument },
    ...overrides,
  };
  const importModule = async (name: string) => {
    const found = modules[name];
    if (found instanceof Error) throw found;
    if (found === undefined) throw missing(name);
    return found;
  };
  return { built, importModule, FakeRedis };
}

describe('readNonceStoreConfig', () => {
  it('defaults to memory, and reads the store name case- and space-insensitively', () => {
    expect(readNonceStoreConfig({})).toEqual({ kind: 'memory' });
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: '' })).toEqual({ kind: 'memory' });
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: ' Memory ' })).toEqual({ kind: 'memory' });
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: 'REDIS', KYAOS_REDIS_URL: 'redis://h:6379' })).toMatchObject({ kind: 'redis' });
  });

  it('refuses an unknown store, never falling back to memory', () => {
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'postgres' })).toThrow(NonceStoreConfigError);
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'postgres' })).toThrow('KYAOS_NONCE_STORE must be one of memory, redis, dynamo; got "postgres"');
  });

  it('redis: needs a redis:// or rediss:// KYAOS_REDIS_URL; the prefix defaults to kyaos:nonce:', () => {
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis' })).toThrow('KYAOS_NONCE_STORE=redis needs KYAOS_REDIS_URL');
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: '  ' })).toThrow('needs KYAOS_REDIS_URL');
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'not a url' })).toThrow('KYAOS_REDIS_URL is not a URL');
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'http://h:6379' })).toThrow('KYAOS_REDIS_URL must be a redis:// or rediss:// URL');
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h:6379' })).toEqual({ kind: 'redis', url: 'redis://h:6379', keyPrefix: 'kyaos:nonce:' });
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'rediss://h', KYAOS_NONCE_KEY_PREFIX: 'app:' })).toEqual({
      kind: 'redis',
      url: 'rediss://h',
      keyPrefix: 'app:',
    });
  });

  it('dynamo: needs KYAOS_DYNAMO_TABLE; attributes default to pk and expiresAt; region and endpoint are optional', () => {
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'dynamo' })).toThrow('KYAOS_NONCE_STORE=dynamo needs KYAOS_DYNAMO_TABLE');
    expect(readNonceStoreConfig({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't' })).toEqual({ kind: 'dynamo', table: 't', keyAttribute: 'pk', ttlAttribute: 'expiresAt' });
    expect(
      readNonceStoreConfig({
        KYAOS_NONCE_STORE: 'dynamo',
        KYAOS_DYNAMO_TABLE: 't',
        KYAOS_DYNAMO_KEY_ATTRIBUTE: 'id',
        KYAOS_DYNAMO_TTL_ATTRIBUTE: 'ttl',
        KYAOS_DYNAMO_REGION: 'eu-west-1',
        KYAOS_DYNAMO_ENDPOINT: 'http://127.0.0.1:8000',
      }),
    ).toEqual({ kind: 'dynamo', table: 't', keyAttribute: 'id', ttlAttribute: 'ttl', region: 'eu-west-1', endpoint: 'http://127.0.0.1:8000' });
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't', KYAOS_DYNAMO_ENDPOINT: 'nope' })).toThrow('KYAOS_DYNAMO_ENDPOINT is not a URL');
    expect(() => readNonceStoreConfig({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't', KYAOS_DYNAMO_ENDPOINT: 'ftp://x' })).toThrow('must be a http:// or https:// URL');
  });

  it('reads process.env by default', () => {
    expect(readNonceStoreConfig().kind).toBe(process.env['KYAOS_NONCE_STORE']?.trim() ? process.env['KYAOS_NONCE_STORE'].trim().toLowerCase() : 'memory');
  });
});

describe('the startup line', () => {
  it('names the store and never a secret', () => {
    expect(describeNonceStore({ kind: 'memory' })).toBe('KYA-OS replay store: memory (this process only)');
    const redis = describeNonceStore({ kind: 'redis', url: 'redis://user:s3cr3t-pass@cache.internal:6379/2', keyPrefix: 'kyaos:nonce:' });
    expect(redis).toBe('KYA-OS replay store: redis redis://user:***@cache.internal:6379/2 (key prefix kyaos:nonce:)');
    expect(redis).not.toContain('s3cr3t');
    expect(describeNonceStore({ kind: 'redis', url: 'redis://:only-pass@h', keyPrefix: 'p:' })).toBe('KYA-OS replay store: redis redis://:***@h (key prefix p:)');
    expect(describeNonceStore({ kind: 'dynamo', table: 't', keyAttribute: 'pk', ttlAttribute: 'expiresAt' })).toBe(
      'KYA-OS replay store: dynamo table t (key pk, ttl expiresAt)',
    );
    expect(describeNonceStore({ kind: 'dynamo', table: 't', keyAttribute: 'id', ttlAttribute: 'ttl', region: 'eu-west-1', endpoint: 'http://a:b@local:8000' })).toBe(
      'KYA-OS replay store: dynamo table t (key id, ttl ttl, region eu-west-1, endpoint http://a:***@local:8000/)',
    );
    expect(redactUrl('redis://h:6379')).toBe('redis://h:6379');
  });
});

describe('nonceStoreFromEnv', () => {
  it('memory: logs the line, and warns in production and when a shared store is configured but not chosen', async () => {
    const log = recorder();
    expect(await nonceStoreFromEnv({}, { log })).toBeInstanceOf(MemoryNonceStore);
    expect(log.info_).toEqual(['KYA-OS replay store: memory (this process only)']);
    expect(log.warn_).toEqual([]);
    for (const env of [{ NODE_ENV: 'production' }, { ENV: ' Production ' }]) {
      const warned = recorder();
      await nonceStoreFromEnv(env, { log: warned });
      expect(warned.warn_).toHaveLength(1);
      expect(warned.warn_[0]).toContain('memory in production covers this process only');
    }
    const quiet = recorder();
    await nonceStoreFromEnv({ NODE_ENV: 'development' }, { log: quiet });
    expect(quiet.warn_).toEqual([]);
    const unused = recorder();
    await nonceStoreFromEnv({ KYAOS_REDIS_URL: 'redis://u:secret@h', KYAOS_DYNAMO_TABLE: 't' }, { log: unused });
    expect(unused.warn_).toEqual([
      'KYA-OS replay store: KYAOS_REDIS_URL is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays',
      'KYA-OS replay store: KYAOS_DYNAMO_TABLE is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays',
    ]);
    expect(unused.warn_.join(' ')).not.toContain('secret');
  });

  it('redis: builds an ioredis client from the URL (named or default export) and reports its errors without the URL', async () => {
    const { built, importModule, FakeRedis } = fakeModules();
    const log = recorder();
    const store = await nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://u:pw@h:6379', KYAOS_NONCE_KEY_PREFIX: 'app:' }, { log, importModule });
    expect(store).toBeInstanceOf(RedisNonceStore);
    expect(built['redis']).toEqual(['redis://u:pw@h:6379']);
    expect(log.info_).toEqual(['KYA-OS replay store: redis redis://u:***@h:6379 (key prefix app:)']);
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(true);
    const defaultExport = fakeModules({ ioredis: { default: FakeRedis } });
    expect(await nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log, importModule: defaultExport.importModule })).toBeInstanceOf(RedisNonceStore);
  });

  it('redis: the error listener logs the message', async () => {
    let instance: { listeners: Record<string, (error: Error) => void> } | undefined;
    class Capturing {
      listeners: Record<string, (error: Error) => void> = {};
      constructor() {
        // eslint-disable-next-line @typescript-eslint/no-this-alias -- the test reads the instance's listeners
        instance = this;
      }
      on(event: string, listener: (error: Error) => void) {
        this.listeners[event] = listener;
      }
      async set() {
        return null;
      }
    }
    const log = recorder();
    await nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log, importModule: async () => ({ Redis: Capturing }) });
    instance!.listeners['error']!(new Error('connect ECONNREFUSED 127.0.0.1:6379'));
    expect(log.warn_).toEqual(['KYA-OS replay store: redis error: connect ECONNREFUSED 127.0.0.1:6379']);
  });

  it('dynamo: builds the document client with region and endpoint only (credentials: the SDK chain)', async () => {
    const { built, importModule } = fakeModules();
    const log = recorder();
    const env = { KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 'nonces', KYAOS_DYNAMO_REGION: 'eu-west-1', KYAOS_DYNAMO_ENDPOINT: 'http://127.0.0.1:8000', AWS_ACCESS_KEY_ID: 'AKIA-never-logged' };
    const store = await nonceStoreFromEnv(env, { log, importModule });
    expect(store).toBeInstanceOf(DynamoNonceStore);
    expect(built['dynamo']).toEqual([{ region: 'eu-west-1', endpoint: 'http://127.0.0.1:8000' }]);
    expect(built['document']).toHaveLength(1);
    expect(log.info_).toEqual(['KYA-OS replay store: dynamo table nonces (key pk, ttl expiresAt, region eu-west-1, endpoint http://127.0.0.1:8000/)']);
    expect(log.info_.join(' ')).not.toContain('AKIA');
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(true);
    const bare = fakeModules();
    await nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 'nonces' }, { log, importModule: bare.importModule });
    expect(bare.built['dynamo']).toEqual([{}]);
  });

  it('a missing optional package is a clear error naming what to install', async () => {
    const log = recorder();
    const none = async (name: string): Promise<never> => {
      throw missing(name);
    };
    await expect(nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log, importModule: none })).rejects.toThrow(
      new NonceStoreConfigError('KYAOS_NONCE_STORE=redis needs the optional package ioredis: npm install ioredis'),
    );
    const withoutDocuments = fakeModules({ '@aws-sdk/lib-dynamodb': undefined });
    await expect(nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't' }, { log, importModule: withoutDocuments.importModule })).rejects.toThrow(
      'KYAOS_NONCE_STORE=dynamo needs the optional package @aws-sdk/lib-dynamodb: npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb',
    );
    const commonJs = async (): Promise<never> => {
      throw Object.assign(new Error('Cannot find module'), { code: 'MODULE_NOT_FOUND' });
    };
    await expect(nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log, importModule: commonJs })).rejects.toBeInstanceOf(NonceStoreConfigError);
    // Any other failure while loading is not dressed up as a missing package.
    const broken = async (): Promise<never> => {
      throw new SyntaxError('bad module');
    };
    await expect(nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log, importModule: broken })).rejects.toThrow(SyntaxError);
  });

  it('bad settings reject before anything is loaded', async () => {
    let loaded = false;
    const importModule = async () => {
      loaded = true;
      return {};
    };
    await expect(nonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis' }, { importModule })).rejects.toBeInstanceOf(NonceStoreConfigError);
    expect(loaded).toBe(false);
  });

  it('loads the real packages with the default import (they are dev dependencies here)', async () => {
    const log = recorder();
    const store = await nonceStoreFromConfig({ kind: 'dynamo', table: 't', keyAttribute: 'pk', ttlAttribute: 'expiresAt', region: 'us-east-1', endpoint: 'http://127.0.0.1:1' }, { log });
    expect(store).toBeInstanceOf(DynamoNonceStore);
    expect(await nonceStoreFromConfig({ kind: 'memory' })).toBeInstanceOf(MemoryNonceStore);
  });
});

describe('deferredNonceStoreFromEnv', () => {
  it('memory is ready at once', async () => {
    const store = deferredNonceStoreFromEnv({}, { log: recorder() });
    expect(store).toBeInstanceOf(MemoryNonceStore);
    await expect(store.ready).resolves.toBeUndefined();
  });

  it('redis and dynamo: inserts wait for the client; a missing package rejects ready and every insert', async () => {
    const { importModule } = fakeModules();
    const store = deferredNonceStoreFromEnv({ KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: 'redis://h' }, { log: recorder(), importModule });
    expect(await store.insert(NONCE, AGENT, Date.now() + 1000)).toBe(true);
    await expect(store.ready).resolves.toBeUndefined();
    const none = async (name: string): Promise<never> => {
      throw missing(name);
    };
    const broken = deferredNonceStoreFromEnv({ KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: 't' }, { log: recorder(), importModule: none });
    await expect(broken.ready).rejects.toThrow('npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb');
    await expect(broken.insert(NONCE, AGENT, Date.now() + 1000)).rejects.toBeInstanceOf(NonceStoreConfigError);
  });

  it('bad settings throw synchronously', () => {
    expect(() => deferredNonceStoreFromEnv({ KYAOS_NONCE_STORE: 'nope' })).toThrow(NonceStoreConfigError);
  });
});

describe('createKyaOs default store', () => {
  it('uses the store the environment names; an explicit store wins and the environment is then not read', async () => {
    const log = recorder();
    const fromEnv = createKyaOs({ signer, env: {}, log, now: () => NOW });
    expect(fromEnv.nonceStore).toBeInstanceOf(MemoryNonceStore);
    await expect(fromEnv.ready()).resolves.toBeUndefined();
    expect(log.info_).toEqual(['KYA-OS replay store: memory (this process only)']);
    expect(() => createKyaOs({ signer, env: { KYAOS_NONCE_STORE: 'bogus' }, log })).toThrow(NonceStoreConfigError);
    expect(() => createKyaOs({ signer, env: { KYAOS_NONCE_STORE: 'redis' }, log })).toThrow('needs KYAOS_REDIS_URL');
    const explicit = new MemoryNonceStore();
    const quiet = recorder();
    const kya = createKyaOs({ signer, nonceStore: explicit, env: { KYAOS_NONCE_STORE: 'bogus' }, log: quiet });
    expect(kya.nonceStore).toBe(explicit);
    expect(quiet.info_).toEqual([]);
    await expect(kya.ready()).resolves.toBeUndefined();
    // Without env or log: process.env and the console.
    expect(createKyaOs({ signer }).nonceStore).toBeDefined();
  });
});

// ── against real servers ─────────────────────────────────────────────────────

const REDIS_URL = process.env['KYAOS_TEST_REDIS_URL'] ?? 'redis://127.0.0.1:6380';
const DYNAMO_ENDPOINT = process.env['KYAOS_TEST_DYNAMO_ENDPOINT'] ?? 'http://127.0.0.1:8001';

async function reachable(url: string): Promise<boolean> {
  const { hostname, port } = new URL(url);
  return new Promise((resolve) => {
    const socket = connect({ host: hostname, port: Number(port) });
    socket.setTimeout(500, () => (socket.destroy(), resolve(false)));
    socket.once('connect', () => (socket.destroy(), resolve(true)));
    socket.once('error', () => resolve(false));
  });
}

const redisUp = await reachable(REDIS_URL);
const dynamoUp = await reachable(DYNAMO_ENDPOINT);
// eslint-disable-next-line no-console -- say loudly which integration cases were skipped
if (!redisUp) console.warn(`[nonce-store-env] Redis integration skipped: nothing at ${REDIS_URL} (e2e-playwright: pnpm redis:up, or set KYAOS_TEST_REDIS_URL)`);
// eslint-disable-next-line no-console
if (!dynamoUp) console.warn(`[nonce-store-env] DynamoDB integration skipped: nothing at ${DYNAMO_ENDPOINT} (docker run -p 8001:8000 amazon/dynamodb-local, or set KYAOS_TEST_DYNAMO_ENDPOINT)`);

describe.skipIf(!redisUp)('KYAOS_NONCE_STORE=redis against a real Redis', () => {
  it('two runtimes built from the same environment refuse each other\'s replays under concurrent load', async () => {
    const env = { KYAOS_NONCE_STORE: 'redis', KYAOS_REDIS_URL: REDIS_URL, KYAOS_NONCE_KEY_PREFIX: `l2a-test:${Date.now()}:` };
    const first = createKyaOs({ signer, env, log: recorder() });
    const second = createKyaOs({ signer, env, log: recorder() });
    await Promise.all([first.ready(), second.ready()]);
    const args = handshakeArgs({ timestamp: Math.floor(Date.now() / 1000), agentDid: AGENT });
    const attempts = await Promise.allSettled(Array.from({ length: 40 }, (_, i) => (i % 2 ? first : second).handshake(args)));
    expect(attempts.filter((a) => a.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((a) => a.status === 'rejected' && (a.reason as { reason?: string }).reason === 'nonce_replayed')).toHaveLength(39);
    const { Redis } = (await import('ioredis')) as unknown as { Redis: new (url: string) => { pttl(key: string): Promise<number>; quit(): Promise<unknown> } };
    const probe = new Redis(REDIS_URL);
    const ttl = await probe.pttl(`${env.KYAOS_NONCE_KEY_PREFIX}${AGENT}|${args['nonce'] as string}`);
    expect(ttl).toBeGreaterThan(115_000);
    expect(ttl).toBeLessThanOrEqual(122_000);
    await probe.quit();
  });
});

describe.skipIf(!dynamoUp)('KYAOS_NONCE_STORE=dynamo against DynamoDB Local', () => {
  it('two runtimes built from the same environment refuse each other\'s replays; the item carries the TTL', async () => {
    // DynamoDB Local takes any credentials; they reach the SDK through its standard chain (these environment variables).
    process.env['AWS_ACCESS_KEY_ID'] ??= 'local';
    process.env['AWS_SECRET_ACCESS_KEY'] ??= 'local';
    const table = `kyaos-nonces-${Date.now()}`;
    const { DynamoDBClient, CreateTableCommand, GetItemCommand } = (await import('@aws-sdk/client-dynamodb')) as typeof import('@aws-sdk/client-dynamodb');
    const admin = new DynamoDBClient({ region: 'us-east-1', endpoint: DYNAMO_ENDPOINT });
    await admin.send(
      new CreateTableCommand({ TableName: table, AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }], KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }], BillingMode: 'PAY_PER_REQUEST' }),
    );
    const env = { KYAOS_NONCE_STORE: 'dynamo', KYAOS_DYNAMO_TABLE: table, KYAOS_DYNAMO_REGION: 'us-east-1', KYAOS_DYNAMO_ENDPOINT: DYNAMO_ENDPOINT };
    const first = createKyaOs({ signer, env, log: recorder() });
    const second = createKyaOs({ signer, env, log: recorder() });
    await Promise.all([first.ready(), second.ready()]);
    const ts = Math.floor(Date.now() / 1000);
    const args = handshakeArgs({ timestamp: ts, agentDid: AGENT });
    const attempts = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => (i % 2 ? first : second).handshake(args)));
    expect(attempts.filter((a) => a.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((a) => a.status === 'rejected' && (a.reason as { reason?: string }).reason === 'nonce_replayed')).toHaveLength(19);
    const item = await admin.send(new GetItemCommand({ TableName: table, Key: { pk: { S: `${AGENT}|${args['nonce'] as string}` } } }));
    expect(item.Item?.['expiresAt']).toEqual({ N: String(ts + 120 + 1) });
    expect(item.Item?.['agentDid']).toEqual({ S: AGENT });
    admin.destroy();
  });
});

it('exports the factory from the package index', async () => {
  const index = await import('../../src/index.js');
  expect(index.nonceStoreFromEnv).toBe(nonceStoreFromEnv);
  expect(index.NonceStoreConfigError).toBe(NonceStoreConfigError);
  expect(SERVER).toMatch(/^did:web:/);
});
