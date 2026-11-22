// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import {
  NonceStoreConfigError,
  readNonceStoreConfig,
  redactUrl,
  type NonceStoreConfig,
  type NonceStoreFromEnvOptions,
  type NonceStoreLog,
} from './kyaos/nonce-store-env.js';
import { MemoryResumeTokenStore, RedisResumeTokenStore, type ResumeRedisLikeClient, type ResumeTokenStore } from './resume-token-store.js';

/**
 * The resume-token store chosen by the same environment variables as the
 * replay store (story L3-E on L2-A's `KYAOS_NONCE_STORE`): a service that
 * shares its replay store across instances shares its resume tokens the
 * same way, with no further setting.
 *
 * | `KYAOS_NONCE_STORE` | Resume-token store |
 * |---|---|
 * | `memory` (default) | `MemoryResumeTokenStore`, this process only |
 * | `redis` | `RedisResumeTokenStore` on `KYAOS_REDIS_URL`, key prefix `KYAOS_RESUME_KEY_PREFIX` (default `kyaos:resume:`) |
 * | `dynamo` | `MemoryResumeTokenStore`, with a warning: there is no DynamoDB resume store yet |
 *
 * Memory under a multi-instance deployment fails closed: a token is known
 * only to the instance that issued it, so a retry that lands elsewhere is
 * refused (`resume_token_unknown`), never accepted twice. `ioredis` is the
 * same optional peer dependency the replay store loads; a missing package is
 * an error, never a silent fall back.
 */

export const DEFAULT_RESUME_KEY_PREFIX = 'kyaos:resume:';

type Env = Readonly<Record<string, string | undefined>>;

const consoleLog: NonceStoreLog = {
  info: (line) => console.info(line), // eslint-disable-line no-console
  warn: (line) => console.warn(line), // eslint-disable-line no-console
};

/** Loads an optional package by name: the default `importModule`. */
export const importOptional = (name: string): Promise<unknown> => import(name);

/** One secret-free line naming the resume-token store `config` leads to. */
export function describeResumeTokenStore(config: NonceStoreConfig, keyPrefix = DEFAULT_RESUME_KEY_PREFIX): string {
  return config.kind === 'redis'
    ? `KYA-OS resume-token store: redis ${redactUrl(config.url)} (key prefix ${keyPrefix})`
    : 'KYA-OS resume-token store: memory (this process only)';
}

/** Builds the store `config` leads to, loading `ioredis` for redis. Does not log; see resumeTokenStoreFromEnv. */
export async function resumeTokenStoreFromConfig(
  config: NonceStoreConfig,
  options: NonceStoreFromEnvOptions & { keyPrefix?: string | undefined } = {},
): Promise<ResumeTokenStore> {
  const now = options.now ?? Date.now;
  if (config.kind !== 'redis') return new MemoryResumeTokenStore({ now });
  const importModule = options.importModule ?? importOptional;
  let mod: Record<string, unknown>;
  try {
    mod = (await importModule('ioredis')) as Record<string, unknown>;
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') {
      throw new NonceStoreConfigError('KYAOS_NONCE_STORE=redis needs the optional package ioredis: npm install ioredis');
    }
    throw error;
  }
  const Redis = (mod['Redis'] ?? mod['default']) as new (url: string) => ResumeRedisLikeClient & { on(event: 'error', listener: (error: Error) => void): unknown };
  const client = new Redis(config.url);
  const log = options.log ?? consoleLog;
  // Without a listener ioredis prints its own unhandled-error line; ours carries no URL.
  client.on('error', (error): void => log.warn(`KYA-OS resume-token store: redis error: ${error.message}`));
  return new RedisResumeTokenStore({ client, keyPrefix: options.keyPrefix ?? DEFAULT_RESUME_KEY_PREFIX, now });
}

function announce(config: NonceStoreConfig, keyPrefix: string, log: NonceStoreLog): void {
  log.info(describeResumeTokenStore(config, keyPrefix));
  if (config.kind === 'dynamo') {
    log.warn('KYA-OS resume-token store: there is no DynamoDB resume-token store; tokens stay in this process, so a retry must reach the instance that issued the challenge');
  }
}

/**
 * The store the environment names, usable at once, as
 * deferredNonceStoreFromEnv: settings are checked and announced now (a bad
 * one throws here, at startup); a Redis store is built in the background
 * and every call waits for it. `ready` settles when it is built and rejects
 * when `ioredis` is missing.
 */
export function deferredResumeTokenStoreFromEnv(env: Env = process.env, options: NonceStoreFromEnvOptions = {}): ResumeTokenStore & { ready: Promise<void> } {
  const config = readNonceStoreConfig(env);
  const keyPrefix = env['KYAOS_RESUME_KEY_PREFIX']?.trim() || DEFAULT_RESUME_KEY_PREFIX;
  announce(config, keyPrefix, options.log ?? consoleLog);
  if (config.kind !== 'redis') return Object.assign(new MemoryResumeTokenStore({ now: options.now ?? Date.now }), { ready: Promise.resolve() });
  const building = resumeTokenStoreFromConfig(config, { ...options, keyPrefix });
  // The rejection reaches whoever awaits `ready` or calls the store; never an unhandled one.
  building.catch(() => undefined);
  return {
    ready: building.then(() => undefined),
    issue: async (binding, expiresAt) => (await building).issue(binding, expiresAt),
    consume: async (token) => (await building).consume(token),
  };
}

/** The store the environment names, built and announced; rejects with NonceStoreConfigError for a bad setting or a missing package. */
export async function resumeTokenStoreFromEnv(env: Env = process.env, options: NonceStoreFromEnvOptions = {}): Promise<ResumeTokenStore> {
  const store = deferredResumeTokenStoreFromEnv(env, options);
  await store.ready;
  return store;
}
