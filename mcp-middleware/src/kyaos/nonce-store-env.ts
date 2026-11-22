// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { DynamoNonceStore, MemoryNonceStore, RedisNonceStore, type DynamoLikeClient, type NonceStore, type RedisLikeClient } from './nonce-store.js';

/**
 * The replay store chosen by environment variables (story L2-A):
 *
 * | Variable | Values | Default |
 * |---|---|---|
 * | `KYAOS_NONCE_STORE` | `memory`, `redis`, `dynamo` | `memory` |
 * | `KYAOS_REDIS_URL` | `redis://` or `rediss://` URL; required for `redis` | |
 * | `KYAOS_NONCE_KEY_PREFIX` | Redis key prefix | `kyaos:nonce:` |
 * | `KYAOS_DYNAMO_TABLE` | table name; required for `dynamo` | |
 * | `KYAOS_DYNAMO_KEY_ATTRIBUTE` | partition key attribute | `pk` |
 * | `KYAOS_DYNAMO_TTL_ATTRIBUTE` | TTL attribute (Unix seconds) | `expiresAt` |
 * | `KYAOS_DYNAMO_REGION` | AWS region | the AWS SDK's own |
 * | `KYAOS_DYNAMO_ENDPOINT` | endpoint URL, for DynamoDB Local | the AWS SDK's own |
 *
 * AWS credentials come from the AWS SDK's standard chain, never from these
 * variables. The clients are optional peer dependencies, loaded with a
 * dynamic import only when chosen: `ioredis` for `redis`,
 * `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb` for `dynamo`.
 *
 * Fail closed: an unknown store, a missing required variable or a missing
 * package is an error at startup, never a silent fall back to memory. One
 * startup line names the store in use, without secrets; memory under
 * `NODE_ENV` or `ENV` = `production` also logs a warning that it covers one
 * process only.
 */

export const NONCE_STORE_KINDS = ['memory', 'redis', 'dynamo'] as const;
export type NonceStoreKind = (typeof NONCE_STORE_KINDS)[number];

export const DEFAULT_NONCE_KEY_PREFIX = 'kyaos:nonce:';
export const DEFAULT_DYNAMO_KEY_ATTRIBUTE = 'pk';
export const DEFAULT_DYNAMO_TTL_ATTRIBUTE = 'expiresAt';

export type NonceStoreConfig =
  | { kind: 'memory' }
  | { kind: 'redis'; url: string; keyPrefix: string }
  | { kind: 'dynamo'; table: string; keyAttribute: string; ttlAttribute: string; region?: string; endpoint?: string };

/** A replay store setting that cannot work: an unknown store, a missing variable or a missing package. */
export class NonceStoreConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NonceStoreConfigError';
  }
}

export interface NonceStoreLog {
  info(line: string): void;
  warn(line: string): void;
}

export interface NonceStoreFromEnvOptions {
  /** Where the startup line and warnings go; default `console`. */
  log?: NonceStoreLog | undefined;
  /** Milliseconds since the epoch, for the stores; default `Date.now`. */
  now?: (() => number) | undefined;
  /** Loads an optional package; default a dynamic `import()`. Injectable for tests. */
  importModule?: ((name: string) => Promise<unknown>) | undefined;
}

type Env = Readonly<Record<string, string | undefined>>;

// The default sink is the console on purpose: the startup line is for the operator.
const consoleLog: NonceStoreLog = {
  info: (line) => console.info(line), // eslint-disable-line no-console
  warn: (line) => console.warn(line), // eslint-disable-line no-console
};

const value = (env: Env, name: string): string | undefined => {
  const raw = env[name]?.trim();
  return raw ? raw : undefined;
};

function required(env: Env, name: string, kind: NonceStoreKind): string {
  const found = value(env, name);
  if (found === undefined) throw new NonceStoreConfigError(`KYAOS_NONCE_STORE=${kind} needs ${name}`);
  return found;
}

function parsedUrl(raw: string, name: string, protocols: readonly string[]): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new NonceStoreConfigError(`${name} is not a URL`);
  }
  if (!protocols.includes(url.protocol)) {
    throw new NonceStoreConfigError(`${name} must be a ${protocols.map((p) => `${p}//`).join(' or ')} URL`);
  }
  return url;
}

/**
 * Reads and checks the replay store settings; throws NonceStoreConfigError
 * for an unknown store or a missing or malformed required variable. Nothing
 * is connected or loaded here, so this runs synchronously at startup.
 */
export function readNonceStoreConfig(env: Env = process.env): NonceStoreConfig {
  const kind = (value(env, 'KYAOS_NONCE_STORE') ?? 'memory').toLowerCase();
  switch (kind) {
    case 'memory':
      return { kind: 'memory' };
    case 'redis': {
      const url = required(env, 'KYAOS_REDIS_URL', 'redis');
      parsedUrl(url, 'KYAOS_REDIS_URL', ['redis:', 'rediss:']);
      return { kind: 'redis', url, keyPrefix: env['KYAOS_NONCE_KEY_PREFIX'] || DEFAULT_NONCE_KEY_PREFIX };
    }
    case 'dynamo': {
      const endpoint = value(env, 'KYAOS_DYNAMO_ENDPOINT');
      if (endpoint !== undefined) parsedUrl(endpoint, 'KYAOS_DYNAMO_ENDPOINT', ['http:', 'https:']);
      const region = value(env, 'KYAOS_DYNAMO_REGION');
      return {
        kind: 'dynamo',
        table: required(env, 'KYAOS_DYNAMO_TABLE', 'dynamo'),
        keyAttribute: value(env, 'KYAOS_DYNAMO_KEY_ATTRIBUTE') ?? DEFAULT_DYNAMO_KEY_ATTRIBUTE,
        ttlAttribute: value(env, 'KYAOS_DYNAMO_TTL_ATTRIBUTE') ?? DEFAULT_DYNAMO_TTL_ATTRIBUTE,
        ...(region !== undefined ? { region } : {}),
        ...(endpoint !== undefined ? { endpoint } : {}),
      };
    }
    default:
      throw new NonceStoreConfigError(`KYAOS_NONCE_STORE must be one of ${NONCE_STORE_KINDS.join(', ')}; got ${JSON.stringify(kind)}`);
  }
}

/** A URL without its password (and the username kept), for logs. */
export function redactUrl(raw: string): string {
  const url = new URL(raw);
  if (url.password) url.password = '***';
  return url.toString();
}

/** One secret-free line naming the store. */
export function describeNonceStore(config: NonceStoreConfig): string {
  switch (config.kind) {
    case 'memory':
      return 'KYA-OS replay store: memory (this process only)';
    case 'redis':
      return `KYA-OS replay store: redis ${redactUrl(config.url)} (key prefix ${config.keyPrefix})`;
    case 'dynamo':
      return (
        `KYA-OS replay store: dynamo table ${config.table} (key ${config.keyAttribute}, ttl ${config.ttlAttribute}` +
        `${config.region !== undefined ? `, region ${config.region}` : ''}` +
        `${config.endpoint !== undefined ? `, endpoint ${redactUrl(config.endpoint)}` : ''})`
      );
  }
}

async function load(importModule: (name: string) => Promise<unknown>, name: string, kind: NonceStoreKind, install: string): Promise<Record<string, unknown>> {
  try {
    return (await importModule(name)) as Record<string, unknown>;
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') {
      throw new NonceStoreConfigError(`KYAOS_NONCE_STORE=${kind} needs the optional package ${name}: npm install ${install}`);
    }
    throw error;
  }
}

/** Logs the startup line (and the warnings) for `config`. */
function announce(config: NonceStoreConfig, env: Env, log: NonceStoreLog): void {
  log.info(describeNonceStore(config));
  if (config.kind !== 'memory') return;
  const production = [env['NODE_ENV'], env['ENV']].some((v) => v?.trim().toLowerCase() === 'production');
  if (production) {
    log.warn(
      'KYA-OS replay store: memory in production covers this process only; a nonce replayed at another instance is not refused. ' +
        'Set KYAOS_NONCE_STORE=redis or dynamo when more than one instance serves this DID.',
    );
  }
  for (const name of ['KYAOS_REDIS_URL', 'KYAOS_DYNAMO_TABLE']) {
    if (value(env, name) !== undefined) {
      log.warn(`KYA-OS replay store: ${name} is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays`);
    }
  }
}

/** The memory store for `config`, or undefined when the store needs a package (redis, dynamo). */
export function memoryNonceStoreFor(config: NonceStoreConfig, options: NonceStoreFromEnvOptions = {}): MemoryNonceStore | undefined {
  return config.kind === 'memory' ? new MemoryNonceStore({ now: options.now ?? Date.now }) : undefined;
}

/** Builds the store `config` names, loading its client package. Does not log; see nonceStoreFromEnv. */
export async function nonceStoreFromConfig(config: NonceStoreConfig, options: NonceStoreFromEnvOptions = {}): Promise<NonceStore> {
  const importModule = options.importModule ?? ((name: string): Promise<unknown> => import(name));
  const log = options.log ?? consoleLog;
  const now = options.now ?? Date.now;
  switch (config.kind) {
    case 'memory':
      return new MemoryNonceStore({ now });
    case 'redis': {
      const mod = await load(importModule, 'ioredis', 'redis', 'ioredis');
      const Redis = (mod['Redis'] ?? mod['default']) as new (url: string) => RedisLikeClient & { on(event: 'error', listener: (error: Error) => void): unknown };
      const client = new Redis(config.url);
      // Without a listener ioredis prints its own unhandled-error line; ours carries no URL.
      client.on('error', (error): void => log.warn(`KYA-OS replay store: redis error: ${error.message}`));
      return new RedisNonceStore({ client, keyPrefix: config.keyPrefix, now });
    }
    case 'dynamo': {
      const dynamo = await load(importModule, '@aws-sdk/client-dynamodb', 'dynamo', '@aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb');
      const documents = await load(importModule, '@aws-sdk/lib-dynamodb', 'dynamo', '@aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb');
      const DynamoDBClient = dynamo['DynamoDBClient'] as new (config: Record<string, unknown>) => unknown;
      const DynamoDBDocument = documents['DynamoDBDocument'] as { from(client: unknown): DynamoLikeClient };
      // Credentials: the AWS SDK's default chain. Only where to connect is ours.
      const client = new DynamoDBClient({
        ...(config.region !== undefined ? { region: config.region } : {}),
        ...(config.endpoint !== undefined ? { endpoint: config.endpoint } : {}),
      });
      return new DynamoNonceStore({
        client: DynamoDBDocument.from(client),
        tableName: config.table,
        keyAttribute: config.keyAttribute,
        ttlAttribute: config.ttlAttribute,
      });
    }
  }
}

/**
 * The replay store the environment names, built and announced: reads the
 * settings (readNonceStoreConfig), logs one secret-free line naming the
 * store and any warning, and loads the client package for redis or dynamo.
 * Rejects with NonceStoreConfigError for an unknown store, a missing
 * variable or a missing package.
 */
export async function nonceStoreFromEnv(env: Env = process.env, options: NonceStoreFromEnvOptions = {}): Promise<NonceStore> {
  const config = readNonceStoreConfig(env);
  announce(config, env, options.log ?? consoleLog);
  return nonceStoreFromConfig(config, options);
}

/**
 * The store the environment names, usable at once: settings are checked and
 * announced now (a bad one throws here, at startup); a store that needs a
 * package is loaded in the background and every insert waits for it.
 * `ready` settles when it is built, and rejects when its package is
 * missing, so a host can fail its startup on it.
 */
export function deferredNonceStoreFromEnv(env: Env = process.env, options: NonceStoreFromEnvOptions = {}): NonceStore & { ready: Promise<void> } {
  const config = readNonceStoreConfig(env);
  announce(config, env, options.log ?? consoleLog);
  const memory = memoryNonceStoreFor(config, options);
  if (memory !== undefined) return Object.assign(memory, { ready: Promise.resolve() });
  const building = nonceStoreFromConfig(config, options);
  // The rejection reaches whoever awaits `ready` or inserts; never an unhandled one.
  building.catch(() => undefined);
  return {
    ready: building.then(() => undefined),
    insert: async (nonce, agentDid, expiresAt) => (await building).insert(nonce, agentDid, expiresAt),
  };
}
