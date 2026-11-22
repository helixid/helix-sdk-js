// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

export { createKyaOs, HANDSHAKE_INPUT_SCHEMA, NO_SESSION_ID } from './runtime.js';
export type {
  AuthorizedCaller,
  HandshakeOptions,
  KyaOsAllowed,
  KyaOsCallInput,
  KyaOsDenied,
  KyaOsNeedsAuthorization,
  KyaOsOptions,
  KyaOsRuntime,
  KyaOsSessionOptions,
  KyaOsStartOptions,
  KyaOsStarted,
} from './runtime.js';
export { describeKyaOs } from './describe.js';
export type { DescribeKyaOsOptions, KyaOsDescription } from './describe.js';
export { KyaOsError } from './errors.js';
export type { KyaOsReason } from './errors.js';
export { MemoryNonceStore, RedisNonceStore, DynamoNonceStore, nonceKey } from './nonce-store.js';
export type { NonceStore, MemoryNonceStoreOptions, RedisLikeClient, RedisNonceStoreOptions, DynamoLikeClient, DynamoPutInput, DynamoNonceStoreOptions } from './nonce-store.js';
export {
  nonceStoreFromEnv,
  nonceStoreFromConfig,
  deferredNonceStoreFromEnv,
  readNonceStoreConfig,
  describeNonceStore,
  redactUrl,
  NonceStoreConfigError,
  NONCE_STORE_KINDS,
  DEFAULT_NONCE_KEY_PREFIX,
  DEFAULT_DYNAMO_KEY_ATTRIBUTE,
  DEFAULT_DYNAMO_TTL_ATTRIBUTE,
} from './nonce-store-env.js';
export type { NonceStoreConfig, NonceStoreKind, NonceStoreLog, NonceStoreFromEnvOptions } from './nonce-store-env.js';
export { MemorySessionStore } from './session-store.js';
export type { SessionStore, KyaOsSession, CreateSessionInput, IdentityState, MemorySessionStoreOptions } from './session-store.js';
export { buildResponseProof, attachResponseProof, RESPONSE_PROOF_META_KEY } from './response-proof.js';
export type { ProofMeta, DetachedProof, ProofOutcome } from './response-proof.js';
