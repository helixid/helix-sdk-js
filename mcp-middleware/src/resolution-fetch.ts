// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The middleware's default fetch for public resolution (KYA-OS stories F-2,
 * L3-C): DID documents, Entity Cards and status lists. It applies the
 * SafeFetch rules that need no DNS control (story C-A, SPEC.md §6.6):
 *
 * - `https:` only (an `http:` loopback URL only with `allowLoopbackHttp`, in
 *   development);
 * - a host written as an IP address must be public unicast (no private,
 *   loopback, link-local, CGNAT, documentation, multicast or reserved
 *   ranges; IPv4-mapped IPv6 is unwrapped first), loopback only in development;
 * - same-origin redirects only, at most three;
 * - a 5 s timeout and a 1 MiB body cap.
 *
 * What it cannot do is pin the address a host name resolves to: a public
 * name pointing at a private address is still connected to. helix-core's
 * SafeFetch (story C-A) pins the connection; a host that has it passes it as
 * `createLocalVerifier({ fetch })`, which replaces this default.
 */

import { BlockList, isIP } from 'node:net';

export const RESOLUTION_TIMEOUT_MS = 5_000;
export const RESOLUTION_MAX_BYTES = 1024 * 1024;
const MAX_REDIRECTS = 3;

/** The `fetch` the resolvers use: answers `ok`, `status` and the JSON body. */
export type ResolverFetch = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export class ResolutionRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResolutionRefusedError';
  }
}

const NON_PUBLIC = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  NON_PUBLIC.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  NON_PUBLIC.addSubnet(network, prefix, 'ipv6');
}

/** The IPv4 address an IPv4-mapped IPv6 address (`::ffff:a.b.c.d` or `::ffff:xxxx:xxxx`) carries, else the address. */
function unwrapMapped(address: string): string {
  const lower = address.toLowerCase();
  if (!lower.startsWith('::ffff:')) return address;
  const rest = lower.slice('::ffff:'.length);
  if (isIP(rest) === 4) return rest;
  const words = rest.split(':');
  if (words.length !== 2 || !words.every((word) => /^[0-9a-f]{1,4}$/.test(word))) return address;
  const [high, low] = words.map((word) => parseInt(word, 16)) as [number, number];
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** Whether `address` (an IP literal) is public unicast. */
export function isPublicUnicastAddress(address: string): boolean {
  const unwrapped = unwrapMapped(address);
  const family = isIP(unwrapped);
  if (family === 0) return false;
  return !NON_PUBLIC.check(unwrapped, family === 4 ? 'ipv4' : 'ipv6');
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** The URL to fetch for `url` under the rules above, or a thrown {@link ResolutionRefusedError}. */
export function resolutionTarget(url: string, allowLoopbackHttp: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ResolutionRefusedError(`refusing to fetch ${url}: not a URL`);
  }
  const loopback = LOOPBACK_HOSTS.has(parsed.hostname);
  if (parsed.protocol === 'http:') {
    if (!(loopback && allowLoopbackHttp)) throw new ResolutionRefusedError(`refusing to fetch ${url}: only https: URLs are read`);
  } else if (parsed.protocol !== 'https:') {
    throw new ResolutionRefusedError(`refusing to fetch ${url}: only https: URLs are read`);
  }
  if (parsed.username !== '' || parsed.password !== '') throw new ResolutionRefusedError(`refusing to fetch ${url}: credentials in the URL`);
  const host = parsed.hostname.startsWith('[') ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (loopback) {
    if (!allowLoopbackHttp) throw new ResolutionRefusedError(`refusing to fetch ${url}: a loopback host`);
    // Development: an https: loopback URL is read over http:, as the F-2 resolvers always did.
    parsed.protocol = 'http:';
    return parsed;
  }
  if (isIP(host) !== 0 && !isPublicUnicastAddress(host)) throw new ResolutionRefusedError(`refusing to fetch ${url}: ${host} is not a public unicast address`);
  return parsed;
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) throw new ResolutionRefusedError(`the body is ${declared} bytes; at most ${maxBytes} are read`);
  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new ResolutionRefusedError(`the body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export interface ResolutionFetchOptions {
  allowLoopbackHttp?: boolean | undefined;
  /** The transport; default the global `fetch`. */
  fetch?: typeof fetch | undefined;
  timeoutMs?: number | undefined;
  maxBytes?: number | undefined;
}

/** A {@link ResolverFetch} under the rules above. */
export function createResolutionFetch(options: ResolutionFetchOptions = {}): ResolverFetch {
  const allowLoopbackHttp = options.allowLoopbackHttp ?? false;
  const transport = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? RESOLUTION_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? RESOLUTION_MAX_BYTES;
  return async (url) => {
    let target = resolutionTarget(url, allowLoopbackHttp);
    const origin = target.origin;
    const signal = AbortSignal.timeout(timeoutMs);
    for (let hop = 0; ; hop += 1) {
      const response = await transport(target.toString(), { redirect: 'manual', signal, headers: { accept: 'application/json, application/did+json, */*;q=0.1' } });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location === null || hop >= MAX_REDIRECTS) throw new ResolutionRefusedError(`${url}: too many or empty redirects`);
        const next = new URL(location, target);
        if (next.origin !== origin) throw new ResolutionRefusedError(`${url}: redirect to another origin (${next.origin})`);
        target = next;
        continue;
      }
      const text = response.ok ? await readCapped(response, maxBytes) : '';
      return {
        ok: response.ok,
        status: response.status,
        json: async (): Promise<unknown> => JSON.parse(text) as unknown,
      };
    }
  };
}
