// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// The sample's minimal RESP client, against an in-process RESP server with SET NX PX semantics.

import { createServer, type AddressInfo, type Server } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { RedisNonceStore } from '@helixid/mcp-middleware';
import { createRedisClient } from '../src/redis-client.js';

/** Parses one RESP array command. */
function parseCommand(text: string): string[] {
  const lines = text.split('\r\n');
  const count = Number(lines[0]!.slice(1));
  const parts: string[] = [];
  for (let i = 0; i < count; i += 1) parts.push(lines[2 + i * 2]!);
  return parts;
}

let server: Server;
let url: string;
const entries = new Map<string, number>();
let reply: string | undefined;

beforeEach(async () => {
  entries.clear();
  reply = undefined;
  server = createServer((socket) => {
    socket.on('data', (chunk) => {
      const [command, key, , px, ms, nx] = parseCommand(chunk.toString('utf8'));
      if (reply !== undefined) return void socket.write(reply);
      // A server-side disconnect after the reply: the client must notice and reconnect on the next command.
      if (key === 'drop') return void socket.end('+OK\r\n');
      // A hang-up with no reply at all.
      if (key === 'hangup') return void socket.destroy();
      if (command !== 'SET' || px !== 'PX' || nx !== 'NX') return void socket.write('-ERR syntax error\r\n');
      const expiry = entries.get(key!);
      if (expiry !== undefined && expiry > Date.now()) return void socket.write('$-1\r\n');
      entries.set(key!, Date.now() + Number(ms));
      socket.write('+OK\r\n');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `redis://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('createRedisClient', () => {
  it('sends SET key value PX ms NX and reads OK or the null bulk reply', async () => {
    const client = createRedisClient(url);
    expect(await client.set('k', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    expect(await client.set('k', 'v', 'PX', 60_000, 'NX')).toBeNull();
    expect(await client.set('k2', 'v', 'PX', 1, 'NX')).toBe('OK');
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(await client.set('k2', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    client.close();
    // Reopens the socket on the next command, after its own close and after the server hung up.
    expect(await client.set('k3', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    expect(await client.set('drop', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(await client.set('k4', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    await expect(client.set('hangup', 'v', 'PX', 60_000, 'NX')).rejects.toThrow('closed before a reply');
    expect(await client.set('k5', 'v', 'PX', 60_000, 'NX')).toBe('OK');
    client.close();
  });

  it('backs a RedisNonceStore shared by two instances under concurrent load', async () => {
    const clients = [createRedisClient(url), createRedisClient(url)];
    const first = new RedisNonceStore({ client: clients[0]! });
    const second = new RedisNonceStore({ client: clients[1]! });
    const results = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? first : second).insert('k7Hy9mNpQrStUvWxYz01Aa', 'did:key:z6Mkagent', Date.now() + 60_000)));
    expect(results.filter(Boolean)).toHaveLength(1);
    for (const client of clients) client.close();
  });

  it('surfaces errors and unexpected replies, and refuses a non-redis URL', async () => {
    const client = createRedisClient(url);
    reply = '-ERR nope\r\n';
    await expect(client.set('k', 'v', 'PX', 1, 'NX')).rejects.toThrow('redis: ERR nope');
    reply = ':1\r\n';
    await expect(client.set('k', 'v', 'PX', 1, 'NX')).rejects.toThrow('unexpected reply');
    reply = '_\r\n';
    expect(await client.set('k', 'v', 'PX', 1, 'NX')).toBeNull();
    client.close();
    expect(() => createRedisClient('http://x')).toThrow('redis://');
    const closed = createRedisClient('redis://127.0.0.1:1');
    await expect(closed.set('k', 'v', 'PX', 1, 'NX')).rejects.toThrow();
    closed.close();
    expect(createRedisClient('redis://').set).toBeDefined();
  });
});
