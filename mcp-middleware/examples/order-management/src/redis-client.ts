// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createConnection, type Socket } from 'node:net';
import type { RedisLikeClient, ResumeRedisLikeClient } from '@helixid/mcp-middleware';

/**
 * The two Redis commands the stores need, `SET key value PX ms NX` for
 * `RedisNonceStore` and `RedisResumeTokenStore` and `GETDEL key` for the
 * latter (story L3-E), spoken over RESP2 on a plain socket, so the sample can share its replay
 * store between instances (KYA-OS story L2-A) without a client library. A
 * production server would hand the store an ioredis client instead; this is
 * deliberately tiny: one connection, commands sent one at a time, no auth,
 * no TLS, no reconnect beyond opening the socket again on the next command.
 */
export function createRedisClient(url: string): RedisLikeClient & ResumeRedisLikeClient & { close(): void } {
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

  /** Sends one command and reads one reply: `+OK`, a null bulk (`$-1`), a bulk string, or `-ERR`. */
  const send = async (parts: string[]): Promise<string | null> => {
    socket ??= await connect();
    const s = socket;
    const payload = `*${parts.length}\r\n${parts.map((p) => `$${Buffer.byteLength(p)}\r\n${p}\r\n`).join('')}`;
    return new Promise((resolve, reject) => {
      let buffered = '';
      const settle = (): void => {
        s.off('data', onData);
        s.off('error', onError);
        s.off('close', onClose);
      };
      const onData = (chunk: Buffer): void => {
        buffered += chunk.toString('utf8');
        if (!buffered.endsWith('\r\n')) return;
        const bulk = /^\$(\d+)\r\n/.exec(buffered);
        if (bulk) {
          // A bulk string: wait until the whole value has arrived.
          const length = Number(bulk[1]);
          const value = Buffer.from(buffered.slice(bulk[0].length), 'utf8');
          if (value.length < length + 2) return;
          settle();
          resolve(value.subarray(0, length).toString('utf8'));
          return;
        }
        settle();
        if (buffered === '+OK\r\n') resolve('OK');
        else if (buffered === '$-1\r\n' || buffered === '_\r\n') resolve(null);
        else if (buffered.startsWith('-')) reject(new Error(`redis: ${buffered.slice(1).trim()}`));
        else reject(new Error(`redis: unexpected reply ${JSON.stringify(buffered)}`));
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

  /** Commands go out one at a time, in order, each waiting for the previous reply. */
  const enqueue = <T>(parts: string[]): Promise<T> => {
    const next = queue.then(() => send(parts)) as Promise<T>;
    queue = next.catch(() => undefined);
    return next;
  };

  return {
    set: (key, value, px, milliseconds, nx): Promise<'OK' | null> => enqueue(['SET', key, value, px, String(milliseconds), nx]),
    getdel: (key): Promise<string | null> => enqueue(['GETDEL', key]),
    close: (): void => {
      socket?.destroy();
      socket = undefined;
    },
  };
}
