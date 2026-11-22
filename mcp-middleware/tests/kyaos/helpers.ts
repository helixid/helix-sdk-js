// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { buildDIDDocument, generateKeyPair, kyaos } from '@helixid/sdk-js';

export const SERVER = 'did:web:orders.example';
export const ORIGIN = 'https://orders.example';
export const AGENT = 'did:key:z6Mkagent';
export const NOW = 1_750_000_000_000;

export const keys = generateKeyPair();
export const otherKeys = generateKeyPair();
export const signer = new kyaos.EnvSigner({ did: SERVER, envVar: 'TEST_SERVICE_KEY', env: { TEST_SERVICE_KEY: keys.privateKey } });
export const document = buildDIDDocument(SERVER, keys.publicKey);
export const resolveDid = async (did: string): Promise<unknown> => (did === SERVER ? document : null);

/** A clock the tests move by hand. */
export function clock(start = NOW): { now: () => number; set(ms: number): void; advance(ms: number): void } {
  let current = start;
  return { now: () => current, set: (ms) => void (current = ms), advance: (ms) => void (current += ms) };
}

export function handshakeArgs(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { nonce: kyaos.generateNonce(), audience: SERVER, timestamp: Math.floor(NOW / 1000), ...overrides };
}

/**
 * An in-process Redis with exactly the `SET key value PX ms NX` semantics the
 * store relies on: one key space, expiry by the injected clock, and a
 * synchronous check-and-set, so concurrent inserts resolve to one winner
 * the way Redis's single-threaded command loop does.
 */
export class FakeRedis {
  readonly entries = new Map<string, { value: string; expiresAt: number }>();
  readonly commands: string[] = [];
  constructor(readonly now: () => number) {}

  async set(key: string, value: string, px: 'PX', milliseconds: number, nx: 'NX'): Promise<'OK' | null> {
    this.commands.push(`SET ${key} ${value} ${px} ${milliseconds} ${nx}`);
    const existing = this.entries.get(key);
    if (existing !== undefined && existing.expiresAt > this.now()) return null;
    this.entries.set(key, { value, expiresAt: this.now() + milliseconds });
    return 'OK';
  }
}

/** A DynamoDB table with a conditional put: `attribute_not_exists(#pk)` refuses a second item with the same key. */
export class FakeDynamo {
  readonly items = new Map<string, Record<string, unknown>>();
  readonly puts: unknown[] = [];
  failWith: Error | undefined;

  async put(input: { TableName: string; Item: Record<string, unknown>; ConditionExpression: string; ExpressionAttributeNames: Record<string, string> }): Promise<unknown> {
    this.puts.push(input);
    if (this.failWith) throw this.failWith;
    if (input.ConditionExpression !== 'attribute_not_exists(#pk)') throw new Error(`unexpected condition ${input.ConditionExpression}`);
    const keyAttribute = input.ExpressionAttributeNames['#pk']!;
    const key = `${input.TableName}/${String(input.Item[keyAttribute])}`;
    if (this.items.has(key)) throw Object.assign(new Error('The conditional request failed'), { name: 'ConditionalCheckFailedException' });
    this.items.set(key, input.Item);
    return {};
  }
}
