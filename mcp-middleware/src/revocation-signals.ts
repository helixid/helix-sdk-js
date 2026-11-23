// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The revocation signal, received (KYA-OS story L3-C point 7; SPEC.md
 * §6.5.2 "honor explicit revocation signals immediately").
 *
 * Helix emits one Security Event Token (RFC 8417) per revoked credential,
 * carrying only the credential id. The middleware receives them either way:
 *
 * - **SSE (default)**: one outbound connection per instance to Helix's
 *   `GET /v1/events/revocations`, reconnecting on drop with backoff and
 *   `Last-Event-ID`, so nothing inbound is opened and nothing is polled;
 * - **webhook push (RFC 8935)**, for services that prefer inbound: mount
 *   `webhookHandler()` at the URL registered with Helix; it answers 202, or
 *   400 with `{err, description}`.
 *
 * Each SET is verified (an issuer on `trustedIssuers`, checked before any
 * resolution, and its signature under that issuer's `assertionMethod` key);
 * a valid one deletes the cached verdict and status entry for the
 * credential (`StatusCache.invalidate`). A signal with a bad signature or
 * from an unknown issuer is ignored and reported through `onSignal`; it
 * never revokes anything. The signal is a cache hint only: the next call is
 * judged by the chain and the list, read live.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { kyaos } from '@helixid/sdk-js';
import { revocationInvalidation } from './delegation/verification-cache.js';

export interface SignalReport {
  /** ISO 8601 time the signal was handled. */
  timestamp: string;
  via: 'sse' | 'webhook';
  /** True when the SET verified and the cache was invalidated. */
  accepted: boolean;
  credentialId?: string | undefined;
  jti?: string | undefined;
  issuer?: string | undefined;
  /** What the cache dropped: the credential's entries, or every list (a credential it held nothing for). */
  invalidated?: 'credential' | 'all-lists' | undefined;
  /** Why the signal was ignored (`signal_unknown_issuer`, `signal_bad_signature`, ...). */
  reason?: string | undefined;
  message?: string | undefined;
}

export type SignalOutcome = { accepted: true; credentialId: string; invalidated: 'credential' | 'all-lists' } | { accepted: false; reason: string; message: string };

export interface RevocationSignalClientOptions {
  /** Helix's SSE endpoint (`<api>/v1/events/revocations`); without it only the webhook receives signals. */
  eventsUrl?: string | undefined;
  /** The issuer DIDs whose signals are honoured: the Helix issuer of the deployment this service listens to. */
  trustedIssuers: readonly string[];
  /** How a trusted issuer's DID resolves: the local verifier's `seams.resolveDid`. */
  resolveDid: kyaos.verifier.DidResolver;
  /** What a valid signal invalidates: the local verifier's `statusCache`. */
  cache: Pick<kyaos.verifier.StatusCache, 'invalidate'>;
  /** Headers sent on the SSE request (an API key, say). */
  headers?: Record<string, string> | undefined;
  /** Streaming fetch; default the global one. */
  fetch?: typeof fetch | undefined;
  /** First reconnect delay, ms (default 1,000), doubled per failure up to `maxReconnectDelayMs` (default 30,000). */
  reconnectDelayMs?: number | undefined;
  maxReconnectDelayMs?: number | undefined;
  /** Every signal handled, accepted or ignored: the audit hook. Default: ignored signals logged. */
  onSignal?: ((report: SignalReport) => void | Promise<void>) | undefined;
  /** Connection state changes, for health checks and logs. */
  onConnectionChange?: ((connected: boolean, error?: unknown) => void) | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
  /** Where the default `onSignal` logs; default `console.warn`. */
  log?: ((message: string) => void) | undefined;
}

/** RFC 8935 §2.3 error codes. */
const PUSH_ERRORS: Record<string, string> = {
  [kyaos.verifier.SignalReasons.MALFORMED]: 'invalid_request',
  [kyaos.verifier.SignalReasons.WRONG_EVENT]: 'invalid_request',
  [kyaos.verifier.SignalReasons.STALE]: 'invalid_request',
  [kyaos.verifier.SignalReasons.UNKNOWN_ISSUER]: 'invalid_issuer',
  [kyaos.verifier.SignalReasons.BAD_SIGNATURE]: 'invalid_key',
};

const MAX_PUSH_BYTES = 64 * 1024;

interface SseEvent {
  id?: string | undefined;
  event: string;
  data: string;
}

/** Splits an SSE byte stream into events (WHATWG HTML §9.2), calling `onEvent` per dispatched event. */
export class SseParser {
  #buffer = '';
  #data: string[] = [];
  #event = '';
  #id: string | undefined;
  #retry: number | undefined;

  constructor(private readonly onEvent: (event: SseEvent) => void | Promise<void>) {}

  /** The last `retry:` value the stream set, ms. */
  get retry(): number | undefined {
    return this.#retry;
  }

  async push(chunk: string): Promise<void> {
    this.#buffer += chunk;
    for (;;) {
      const match = /\r\n|\r|\n/.exec(this.#buffer);
      if (match === null) return;
      // A lone `\r` at the end may be the first half of `\r\n`: wait for more.
      if (match[0] === '\r' && match.index === this.#buffer.length - 1) return;
      const line = this.#buffer.slice(0, match.index);
      this.#buffer = this.#buffer.slice(match.index + match[0].length);
      await this.#line(line);
    }
  }

  async #line(line: string): Promise<void> {
    if (line === '') {
      if (this.#data.length > 0) {
        const event: SseEvent = { id: this.#id, event: this.#event || 'message', data: this.#data.join('\n') };
        this.#data = [];
        this.#event = '';
        await this.onEvent(event);
      } else {
        this.#event = '';
      }
      return;
    }
    if (line.startsWith(':')) return;
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'data') this.#data.push(value);
    else if (field === 'event') this.#event = value;
    else if (field === 'id' && !value.includes('\0')) this.#id = value;
    else if (field === 'retry' && /^\d+$/.test(value)) this.#retry = Number(value);
  }
}

/** Receives Helix's revocation signals and invalidates the status cache on each valid one. */
export class RevocationSignalClient {
  readonly #options: RevocationSignalClientOptions;
  readonly #clock: () => number;
  readonly #onSignal: (report: SignalReport) => void | Promise<void>;
  readonly #seen = new Set<string>();
  #abort: AbortController | undefined;
  #running = false;
  #connected = false;
  #lastEventId: string | undefined;
  #loop: Promise<void> | undefined;
  #wake: (() => void) | undefined;

  constructor(options: RevocationSignalClientOptions) {
    if (!Array.isArray(options.trustedIssuers) || options.trustedIssuers.length === 0) {
      throw new Error('RevocationSignalClient: trustedIssuers must name the issuer whose signals are honoured');
    }
    this.#options = options;
    this.#clock = options.clock ?? Date.now;
    // eslint-disable-next-line no-console -- the default audit hook's one line per ignored signal goes to the console
    const log = options.log ?? ((message: string): void => console.warn(message));
    this.#onSignal =
      options.onSignal ??
      ((report): void => {
        if (!report.accepted) log(`[kya-os] revocation signal ignored (${report.via}): ${report.reason}: ${report.message}`);
      });
  }

  /** True while the SSE stream is open. */
  get connected(): boolean {
    return this.#connected;
  }

  /** The id of the last SSE event received, sent as `Last-Event-ID` on reconnect. */
  get lastEventId(): string | undefined {
    return this.#lastEventId;
  }

  /** Verifies one SET and, when it holds, invalidates the cache for its credential. Never throws. */
  async handle(set: unknown, via: SignalReport['via'] = 'sse'): Promise<SignalOutcome> {
    const timestamp = new Date(this.#clock()).toISOString();
    let outcome: SignalOutcome;
    let report: SignalReport;
    const verdict = await kyaos.verifier.verifyRevocationSignal(set, {
      trustedIssuers: this.#options.trustedIssuers,
      resolveDid: this.#options.resolveDid,
      now: this.#clock(),
    });
    if (!verdict.ok) {
      outcome = { accepted: false, reason: verdict.reason, message: verdict.message };
      report = { timestamp, via, accepted: false, reason: verdict.reason, message: verdict.message };
    } else {
      const { signal } = verdict;
      try {
        // A duplicate (the same jti over SSE and webhook, or replayed after a reconnect) deletes again: harmless.
        const invalidated = await this.#options.cache.invalidate(signal.credentialId);
        this.#remember(signal.jti);
        outcome = { accepted: true, credentialId: signal.credentialId, invalidated };
        report = { timestamp, via, accepted: true, credentialId: signal.credentialId, jti: signal.jti, issuer: signal.iss, invalidated };
      } catch (error) {
        outcome = { accepted: false, reason: 'cache_unavailable', message: (error as Error).message };
        report = { timestamp, via, accepted: false, credentialId: signal.credentialId, jti: signal.jti, issuer: signal.iss, reason: 'cache_unavailable', message: (error as Error).message };
      }
    }
    try {
      await this.#onSignal(report);
    } catch {
      // Reporting never blocks the invalidation.
    }
    return outcome;
  }

  /** Whether a signal with this `jti` was accepted recently (for diagnostics; duplicates are handled again regardless). */
  hasSeen(jti: string): boolean {
    return this.#seen.has(jti);
  }

  #remember(jti: string): void {
    this.#seen.add(jti);
    if (this.#seen.size > 1000) this.#seen.delete(this.#seen.values().next().value as string);
  }

  /** Opens the SSE stream and keeps it open, reconnecting on drop, until `stop()`. */
  start(): void {
    if (this.#running) return;
    if (this.#options.eventsUrl === undefined) throw new Error('RevocationSignalClient: start() needs eventsUrl (SSE); use webhookHandler() for push');
    this.#running = true;
    this.#loop = this.#run();
  }

  /** Closes the stream and stops reconnecting. */
  async stop(): Promise<void> {
    this.#running = false;
    this.#abort?.abort();
    this.#wake?.();
    await this.#loop;
    this.#loop = undefined;
  }

  #setConnected(connected: boolean, error?: unknown): void {
    if (this.#connected === connected && error === undefined) return;
    this.#connected = connected;
    this.#options.onConnectionChange?.(connected, error);
  }

  async #sleep(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      this.#wake = (): void => {
        clearTimeout(timer);
        resolve();
      };
    });
    this.#wake = undefined;
  }

  async #run(): Promise<void> {
    const initial = this.#options.reconnectDelayMs ?? 1_000;
    const ceiling = this.#options.maxReconnectDelayMs ?? 30_000;
    let delay = initial;
    while (this.#running) {
      let parser: SseParser | undefined;
      try {
        parser = await this.#stream(() => {
          delay = initial;
        });
        this.#setConnected(false);
      } catch (error) {
        this.#setConnected(false, error);
      }
      if (!this.#running) break;
      await this.#sleep(parser?.retry ?? delay);
      delay = Math.min(delay * 2, ceiling);
    }
    this.#setConnected(false);
  }

  /** One SSE connection, read to its end; resolves with its parser when the server closes it. */
  async #stream(onOpen: () => void): Promise<SseParser> {
    const doFetch = this.#options.fetch ?? fetch;
    this.#abort = new AbortController();
    const response = await doFetch(this.#options.eventsUrl!, {
      headers: {
        accept: 'text/event-stream',
        'cache-control': 'no-cache',
        ...(this.#lastEventId === undefined ? {} : { 'last-event-id': this.#lastEventId }),
        ...(this.#options.headers ?? {}),
      },
      signal: this.#abort.signal,
    });
    if (!response.ok || response.body === null) throw new Error(`revocation events answered ${response.status}`);
    const type = response.headers.get('content-type') ?? '';
    if (!type.startsWith('text/event-stream')) throw new Error(`revocation events answered ${type || 'no content type'}, not text/event-stream`);
    this.#setConnected(true);
    onOpen();
    const parser = new SseParser(async (event) => {
      if (event.id !== undefined) this.#lastEventId = event.id;
      if (event.event === 'revocation') await this.handle(event.data, 'sse');
    });
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      await parser.push(decoder.decode(value, { stream: true }));
    }
    return parser;
  }

  /**
   * An RFC 8935 push receiver: `POST` with `Content-Type:
   * application/secevent+jwt` and the SET as the body; 202 when it verified,
   * 400 `{err, description}` when it did not, 405/415 otherwise.
   */
  webhookHandler(): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
    return async (req, res) => {
      const send = (status: number, body?: Record<string, string>, headers: Record<string, string> = {}): void => {
        res.writeHead(status, { ...(body ? { 'content-type': 'application/json' } : {}), ...headers });
        res.end(body ? JSON.stringify(body) : undefined);
      };
      if (req.method !== 'POST') {
        send(405, { err: 'invalid_request', description: 'POST a SET' }, { allow: 'POST' });
        return;
      }
      const type = (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
      if (type !== kyaos.verifier.SECEVENT_JWT_MEDIA_TYPE) {
        send(415, { err: 'invalid_request', description: `Content-Type must be ${kyaos.verifier.SECEVENT_JWT_MEDIA_TYPE}` });
        return;
      }
      let body: string;
      try {
        body = await readBody(req, MAX_PUSH_BYTES);
      } catch (error) {
        send(400, { err: 'invalid_request', description: (error as Error).message });
        return;
      }
      const outcome = await this.handle(body.trim(), 'webhook');
      if (outcome.accepted) {
        send(202);
        return;
      }
      send(outcome.reason === 'cache_unavailable' ? 503 : 400, { err: PUSH_ERRORS[outcome.reason] ?? 'invalid_request', description: outcome.message });
    };
  }
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error(`the SET exceeds ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** Builds a {@link RevocationSignalClient} for a local verifier: its resolver, its status cache. */
export function createRevocationSignalClient(
  verifier: { seams: kyaos.verifier.VerifierSeams; statusCache: kyaos.verifier.StatusCache },
  options: Omit<RevocationSignalClientOptions, 'resolveDid' | 'cache'> & Partial<Pick<RevocationSignalClientOptions, 'resolveDid' | 'cache'>>,
): RevocationSignalClient {
  const resolveDid = options.resolveDid ?? verifier.seams.resolveDid;
  if (resolveDid === undefined) throw new Error('createRevocationSignalClient: the verifier has no resolveDid seam');
  // Story L3-D: the default also drops the verdicts of every verification cache linked to the status cache.
  return new RevocationSignalClient({ ...options, resolveDid, cache: options.cache ?? revocationInvalidation(verifier.statusCache) });
}
