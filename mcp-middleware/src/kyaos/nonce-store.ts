// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * The replay store (KYA-OS story L2-A, conformance L2.5): `(nonce, agentDid,
 * expiry)` tuples with one atomic conditional insert. A nonce is accepted
 * the first time a given agent presents it and refused every time after,
 * until `expiry`, which the caller sets to `ts + skew + 1 s` so the entry
 * outlives the acceptance window; nothing is evicted before that.
 *
 * `MemoryNonceStore` serves one instance. `RedisNonceStore` (`SET NX PX`)
 * and `DynamoNonceStore` (conditional `PutItem`) serve several instances
 * sharing one store, so a nonce replayed at a second instance is refused
 * there too. The same store takes the nonces of the response proofs the
 * server signs, and is where a presented request proof's nonce is checked.
 *
 * Cross-border rule (stories, rule 4): this store and the local config are
 * the only state the verify path touches; it is never a Helix database.
 */

export interface NonceStore {
  /**
   * Records `(nonce, agentDid)` until `expiresAt` (milliseconds since the
   * epoch) and resolves true, or resolves false when that pair is already
   * recorded and not yet expired. Atomic: of two concurrent inserts of the
   * same pair exactly one resolves true.
   */
  insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean>;
}

/** One key per `(nonce, agentDid)` pair; the separator cannot occur in a base64url nonce. */
export function nonceKey(nonce: string, agentDid: string | undefined): string {
  return `${agentDid ?? ''}|${nonce}`;
}

export interface MemoryNonceStoreOptions {
  /** Milliseconds since the epoch; default `Date.now`. Injectable for tests. */
  now?: () => number;
}

/** Single-instance store: a map of key to expiry, swept of expired entries on every insert, never earlier. */
export class MemoryNonceStore implements NonceStore {
  readonly #entries = new Map<string, number>();
  readonly #now: () => number;

  constructor(options: MemoryNonceStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
  }

  async insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean> {
    const now = this.#now();
    for (const [key, expiry] of this.#entries) {
      if (expiry <= now) this.#entries.delete(key);
    }
    const key = nonceKey(nonce, agentDid);
    if (this.#entries.has(key)) return false;
    this.#entries.set(key, expiresAt);
    return true;
  }

  /** Whether the pair is currently recorded (for tests and diagnostics). */
  has(nonce: string, agentDid: string | undefined): boolean {
    const expiry = this.#entries.get(nonceKey(nonce, agentDid));
    return expiry !== undefined && expiry > this.#now();
  }

  get size(): number {
    return this.#entries.size;
  }
}

/** The one Redis command the store needs, as ioredis and compatible clients expose it: `SET key value PX ms NX`. */
export interface RedisLikeClient {
  set(key: string, value: string, px: 'PX', milliseconds: number, nx: 'NX'): Promise<'OK' | null>;
}

export interface RedisNonceStoreOptions {
  client: RedisLikeClient;
  /** Default `kyaos:nonce:`. */
  keyPrefix?: string;
  /** Milliseconds since the epoch; default `Date.now`. */
  now?: () => number;
}

/** Multi-instance store on Redis: `SET NX PX` is the atomic conditional insert, Redis expires the key at `expiresAt`. */
export class RedisNonceStore implements NonceStore {
  readonly #client: RedisLikeClient;
  readonly #prefix: string;
  readonly #now: () => number;

  constructor(options: RedisNonceStoreOptions) {
    this.#client = options.client;
    this.#prefix = options.keyPrefix ?? 'kyaos:nonce:';
    this.#now = options.now ?? Date.now;
  }

  async insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean> {
    // An entry due to expire in the past still has to refuse a concurrent duplicate: keep it one tick.
    const ttl = Math.max(1, expiresAt - this.#now());
    const reply = await this.#client.set(`${this.#prefix}${nonceKey(nonce, agentDid)}`, String(expiresAt), 'PX', ttl, 'NX');
    return reply === 'OK';
  }
}

export interface DynamoPutInput {
  TableName: string;
  Item: Record<string, unknown>;
  ConditionExpression: string;
  ExpressionAttributeNames: Record<string, string>;
}

/** The one call the store needs: a conditional `PutItem`, as `DynamoDBDocument.put` (lib-dynamodb) exposes it. */
export interface DynamoLikeClient {
  put(input: DynamoPutInput): Promise<unknown>;
}

export interface DynamoNonceStoreOptions {
  client: DynamoLikeClient;
  tableName: string;
  /** Partition key attribute; default `pk`. */
  keyAttribute?: string;
  /** Attribute holding the expiry in Unix seconds, for the table's TTL setting; default `expiresAt`. */
  ttlAttribute?: string;
}

/** Multi-instance store on DynamoDB: a `PutItem` conditioned on the key's absence; the table's TTL removes expired items. */
export class DynamoNonceStore implements NonceStore {
  readonly #client: DynamoLikeClient;
  readonly #table: string;
  readonly #key: string;
  readonly #ttl: string;

  constructor(options: DynamoNonceStoreOptions) {
    this.#client = options.client;
    this.#table = options.tableName;
    this.#key = options.keyAttribute ?? 'pk';
    this.#ttl = options.ttlAttribute ?? 'expiresAt';
  }

  async insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean> {
    try {
      await this.#client.put({
        TableName: this.#table,
        Item: {
          [this.#key]: nonceKey(nonce, agentDid),
          nonce,
          ...(agentDid !== undefined ? { agentDid } : {}),
          // DynamoDB TTL is in seconds; round up so the item never leaves before expiresAt.
          [this.#ttl]: Math.ceil(expiresAt / 1000),
        },
        ConditionExpression: 'attribute_not_exists(#pk)',
        ExpressionAttributeNames: { '#pk': this.#key },
      });
      return true;
    } catch (error) {
      if ((error as { name?: unknown } | null)?.name === 'ConditionalCheckFailedException') return false;
      throw error;
    }
  }
}
