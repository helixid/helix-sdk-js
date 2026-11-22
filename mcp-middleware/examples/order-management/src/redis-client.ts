// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createConnection, type Socket } from 'node:net';
import type { RedisLikeClient, RedisStatusCacheClient } from '@helixid/mcp-middleware';

/**
 * The Redis commands the sample's shared stores need, spoken over RESP2 on a
 * plain socket: `SET key value PX ms NX` for the replay store (KYA-OS story
 * L2-A), and `GET`, `SET key value PX ms`, `DEL`, `INCR` for the status
 * cache (story L3-C), so the sample shares both between instances without a
 * client library. A
 * production server would hand the store an ioredis client instead; this is
 * deliberately tiny: one connection, commands sent one at a time, no auth,
 * no TLS, no reconnect beyond opening the socket again on the next command.
 */
export function createRedisClient(url: string): RedisLikeClient & RedisStatusCacheClient & { close(): void } {
  const parsed = new URL(url);
  if (parsed.protocol !== 'redis:') throw new Error(`redis client: expected a redis:// URL, got ${url}`);
  const host = parsed.hostname || '127.0.0.1';
  const port = Number(parsed.port || 6379);
  let socket: Socket | undefined;
  let queue: Promise<unknown> = Promise.resolve();

  const connect = (): Promise<Socket> =>
    new Promise((resolve, reject) => {
      const s = createConnection({ host, port });
      s.once('connect', () => resolve(s));
      s.once('error', reject);
      s.once('close', () => {
        if (socket === s) socket = undefined;
      });
    });

  /** Sends one command and reads one reply: a simple string, an integer, a bulk string, a null, or an error. */
  const send = async (parts: string[]): Promise<string | number | null> => {
    socket ??= await connect();
    const s = socket;
    const payload = `*${parts.length}\r\n${parts.map((p) => `$${Buffer.byteLength(p)}\r\n${p}\r\n`).join('')}`;
    return new Promise((resolve, reject) => {
      let buffered = Buffer.alloc(0);
      const settle = (): void => {
        s.off('data', onData);
        s.off('error', onError);
        s.off('close', onClose);
      };
      const onData = (chunk: Buffer): void => {
        buffered = Buffer.concat([buffered, chunk]);
        const reply = parseReply(buffered);
        if (reply === undefined) return;
        settle();
        if (reply instanceof Error) reject(reply);
        else resolve(reply);
      };
      const onError = (error: Error): void => {
        settle();
        reject(error);
      };
      // The server hung up before answering: fail the command instead of waiting forever.
      const onClose = (): void => {
        settle();
        reject(new Error('redis: connection closed before a reply'));
      };
      s.on('data', onData);
      s.once('error', onError);
      s.once('close', onClose);
      s.write(payload);
    });
  };

  /** Commands are sent one at a time, in order, on the one connection. */
  const command = <T>(parts: string[]): Promise<T> => {
    const next = queue.then(() => send(parts)) as Promise<T>;
    queue = next.catch(() => undefined);
    return next;
  };

  return {
    set: (key: string, value: string, px: 'PX', milliseconds: number, nx?: 'NX'): Promise<'OK' | null> =>
      command<'OK' | null>(['SET', key, value, px, String(milliseconds), ...(nx ? [nx] : [])]),
    get: (key: string): Promise<string | null> => command<string | null>(['GET', key]),
    del: (key: string): Promise<number> => command<number>(['DEL', key]),
    incr: (key: string): Promise<number> => command<number>(['INCR', key]),
    close: (): void => {
      socket?.destroy();
      socket = undefined;
    },
  };
}

/**
 * One RESP2 reply from the start of `buffer`: the value, an `Error` for an
 * error reply, or undefined while the reply is incomplete.
 */
export function parseReply(buffer: Buffer): string | number | null | Error | undefined {
  const end = buffer.indexOf('\r\n');
  if (end === -1) return undefined;
  const head = buffer.subarray(1, end).toString('utf8');
  switch (String.fromCharCode(buffer[0]!)) {
    case '+':
      return head;
    case '-':
      return new Error(`redis: ${head.trim()}`);
    case ':':
      return Number(head);
    case '_':
      return null;
    case '$': {
      const length = Number(head);
      if (length < 0) return null;
      if (buffer.length < end + 2 + length + 2) return undefined;
      return buffer.subarray(end + 2, end + 2 + length).toString('utf8');
    }
    default:
      return new Error(`redis: unexpected reply ${JSON.stringify(buffer.toString('utf8'))}`);
  }
}
