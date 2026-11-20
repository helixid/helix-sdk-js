// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { kyaos } from '@helixid/sdk-js';

/**
 * KYA-OS sessions (story L2-A; conformance L2.7, L2.8, L2.10). A session is
 * created by a valid handshake, named `kyaos_<uuid-v4>`, and lives while
 * calls keep coming: every valid call moves `lastActivity` and the expiry
 * out by the idle TTL (default 30 minutes). Sessions are optional: a call
 * that names none is still authorised from its credentials alone.
 */

export type IdentityState = 'anonymous' | 'authenticated';

export interface KyaOsSession {
  id: string;
  /** The DID the session is for: verified by the host at the handshake, or claimed in it. */
  agentDid?: string;
  /** `authenticated` only when the host verified the agent at the handshake. */
  identityState: IdentityState;
  /** What the handshake was addressed to: the server DID or its public origin. */
  audience: string;
  /** The handshake nonce. */
  nonce: string;
  /** Milliseconds since the epoch. */
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
}

export interface CreateSessionInput {
  agentDid?: string | undefined;
  identityState: IdentityState;
  audience: string;
  nonce: string;
  /** Milliseconds since the epoch. */
  now: number;
}

export interface SessionStore {
  /** Idle TTL, what the handshake response advertises as `sessionTtl`. */
  readonly ttlMinutes: number;
  create(input: CreateSessionInput): Promise<KyaOsSession>;
  /** The live session `id` names at `now`, or undefined when there is none or it has expired. */
  get(id: string, now: number): Promise<KyaOsSession | undefined>;
  /** Records activity at `now` on a live session and resolves it, or undefined when there is none. */
  touch(id: string, now: number): Promise<KyaOsSession | undefined>;
  delete(id: string): Promise<void>;
}

export interface MemorySessionStoreOptions {
  /** Idle TTL in minutes; default 30. */
  ttlMinutes?: number;
  /** Session id generator; default `kyaos_<uuid-v4>`. Injectable for tests. */
  generateId?: () => string;
}

/** Single-instance store; expired sessions are dropped when looked up. */
export class MemorySessionStore implements SessionStore {
  readonly ttlMinutes: number;
  readonly #sessions = new Map<string, KyaOsSession>();
  readonly #generateId: () => string;

  constructor(options: MemorySessionStoreOptions = {}) {
    const ttl = options.ttlMinutes ?? kyaos.DEFAULT_SESSION_TTL_MINUTES;
    if (!(ttl > 0) || !Number.isFinite(ttl)) throw new RangeError('session.ttlMinutes must be a positive number');
    this.ttlMinutes = ttl;
    this.#generateId = options.generateId ?? kyaos.generateSessionId;
  }

  get #ttlMs(): number {
    return this.ttlMinutes * 60_000;
  }

  async create(input: CreateSessionInput): Promise<KyaOsSession> {
    const session: KyaOsSession = {
      id: this.#generateId(),
      ...(input.agentDid !== undefined ? { agentDid: input.agentDid } : {}),
      identityState: input.identityState,
      audience: input.audience,
      nonce: input.nonce,
      createdAt: input.now,
      lastActivity: input.now,
      expiresAt: input.now + this.#ttlMs,
    };
    this.#sessions.set(session.id, session);
    return { ...session };
  }

  async get(id: string, now: number): Promise<KyaOsSession | undefined> {
    const session = this.#sessions.get(id);
    if (session === undefined) return undefined;
    if (session.expiresAt <= now) {
      this.#sessions.delete(id);
      return undefined;
    }
    return { ...session };
  }

  async touch(id: string, now: number): Promise<KyaOsSession | undefined> {
    const session = this.#sessions.get(id);
    if (session === undefined || session.expiresAt <= now) {
      this.#sessions.delete(id);
      return undefined;
    }
    session.lastActivity = now;
    session.expiresAt = now + this.#ttlMs;
    return { ...session };
  }

  async delete(id: string): Promise<void> {
    this.#sessions.delete(id);
  }

  get size(): number {
    return this.#sessions.size;
  }
}
