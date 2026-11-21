// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { kyaos } from '@helixid/sdk-js';
import { describeKyaOs, type KyaOsDescription } from './describe.js';
import { KyaOsError } from './errors.js';
import { MemoryNonceStore, type NonceStore } from './nonce-store.js';
import { attachResponseProof, buildResponseProof, type DetachedProof, type ProofMeta } from './response-proof.js';
import { MemorySessionStore, type KyaOsSession, type SessionStore } from './session-store.js';
import { challengeToolResult, isNeedsAuthorizationError, type NeedsAuthorizationChallenge } from '../needs-authorization.js';

/**
 * The KYA-OS session, replay and response-proof layer of the middleware
 * (story L2-A). One runtime per server:
 *
 * - `handshake(args)` answers the `_kyaos_handshake` tool: nonce format,
 *   timestamp within the skew, audience the server DID or public origin,
 *   nonce never seen before (the replay store), then a session.
 * - `start(call)` runs before a tool handler: it hashes the covered request,
 *   looks up the session the `_kyaos_session` control argument names, runs
 *   the host's authorization and strips the control arguments. A refusal
 *   comes back as a signed `denied` proof; an allowed call comes back with
 *   `finish(result)`, which hashes the result and signs the proof into
 *   `_meta["org.kya-os/response-proof"]`.
 * - `call(call, run)` is `start` then the handler then `finish`.
 *
 * Only KYA-OS `_meta` keys are ever read; everything else in `_meta` is
 * ignored (L2.17). The VP path is gone: nothing reads `x-helix-vp`.
 */

export interface KyaOsSessionOptions {
  /** Default true. When false the handshake tool is refused and `_kyaos_session` is not looked up. */
  enabled?: boolean | undefined;
  /** Idle TTL; default 30. */
  ttlMinutes?: number | undefined;
  store?: SessionStore | undefined;
}

export interface KyaOsOptions {
  /** The service's Signer: signs every response proof. Its DID is the server DID. */
  signer: kyaos.Signer;
  /** This server's DID; default `signer.did`, and must equal it. */
  serverDid?: string | undefined;
  /** The origin agents connect to; accepted as a handshake audience next to the server DID. */
  publicOrigin?: string | undefined;
  /** Default 120; 30 to 600. */
  clockSkewSeconds?: number | undefined;
  /** Default `MemoryNonceStore` (one instance). Share a `RedisNonceStore` or `DynamoNonceStore` across instances. */
  nonceStore?: NonceStore | undefined;
  session?: KyaOsSessionOptions | undefined;
  /** The MCP endpoint, for `describe()`. */
  toolsEndpoint?: string | undefined;
  /** Milliseconds since the epoch; default `Date.now`. Injectable for tests. */
  now?: (() => number) | undefined;
}

export interface HandshakeOptions {
  /** The agent DID the host verified on the handshake call (its credentials), making the session `authenticated`. */
  authenticatedAgentDid?: string | undefined;
}

export interface KyaOsCallInput {
  name: string;
  arguments?: Record<string, unknown> | undefined;
  /** The request's `params._meta`. Only KYA-OS keys are read; the rest is ignored. */
  _meta?: Record<string, unknown> | undefined;
}

export interface AuthorizedCaller {
  agentDid?: string | undefined;
}

export interface KyaOsStartOptions {
  /** The host's authorization of this call (the `helixidMCPMiddleware` guard, say). A throw is a denial; a returned `agentDid` names the client in the proof. */
  authorize?: (() => Promise<AuthorizedCaller | void> | AuthorizedCaller | void) | undefined;
  /** The client DID, when the host already knows it. */
  clientDid?: string | undefined;
}

export interface KyaOsDenied {
  outcome: 'denied';
  reason: string;
  /** What `authorize` threw, or the `KyaOsError` of the session layer. */
  error: unknown;
  proof: DetachedProof;
  requestHash: string;
  session?: KyaOsSession | undefined;
}

export interface KyaOsAllowed {
  outcome: 'allowed';
  /** The tool's arguments with every `_kyaos*` member removed: what the handler sees. */
  arguments: Record<string, unknown>;
  requestHash: string;
  session?: KyaOsSession | undefined;
  clientDid?: string | undefined;
  /** Signs the proof over `result` and returns `result` with it in `_meta`. */
  finish<T extends Record<string, unknown>>(result: T): Promise<T & { _meta: Record<string, unknown> }>;
}

/** KYA-OS story L3-E: the call lacks authority; `result` is the signed challenge to answer with (a tool result). */
export interface KyaOsNeedsAuthorization {
  outcome: 'needs_authorization';
  challenge: NeedsAuthorizationChallenge;
  /** The `NeedsAuthorizationError` the host's authorization threw. */
  error: unknown;
  proof: DetachedProof;
  requestHash: string;
  session?: KyaOsSession | undefined;
  /** `challengeToolResult(challenge)` with the proof at `_meta["org.kya-os/response-proof"]`; `responseHash` covers all of it. */
  result: Record<string, unknown> & { _meta: Record<string, unknown> };
}

export type KyaOsStarted = KyaOsDenied | KyaOsAllowed | KyaOsNeedsAuthorization;

export interface KyaOsRuntime {
  readonly serverDid: string;
  readonly clockSkewSeconds: number;
  readonly sessionsEnabled: boolean;
  readonly nonceStore: NonceStore;
  readonly sessionStore: SessionStore;
  readonly handshakeToolName: typeof kyaos.HANDSHAKE_TOOL_NAME;
  describe(): KyaOsDescription;
  /** Whether `name` is the handshake tool, which the host answers with `handshake()` and never passes to its own tools. */
  isHandshake(name: string | undefined): boolean;
  /** Answers a handshake request; throws `KyaOsError` on refusal. */
  handshake(args: unknown, options?: HandshakeOptions): Promise<kyaos.HandshakeResponse>;
  /** `handshake()` as a tool result: the response as `structuredContent` (and text), or an `isError` result naming the reason. */
  handshakeToolResult(args: unknown, options?: HandshakeOptions): Promise<Record<string, unknown>>;
  start(call: KyaOsCallInput, options?: KyaOsStartOptions): Promise<KyaOsStarted>;
  /** `start`, then `run` on the stripped arguments, then `finish`; a denial resolves to the denied outcome instead of running. */
  call<T extends Record<string, unknown>>(
    call: KyaOsCallInput,
    run: (args: Record<string, unknown>, context: { session?: KyaOsSession | undefined; clientDid?: string | undefined }) => Promise<T> | T,
    options?: KyaOsStartOptions,
  ): Promise<KyaOsDenied | KyaOsNeedsAuthorization | (KyaOsAllowed & { result: T & { _meta: Record<string, unknown> } })>;
}

/** The `sessionId` a proof carries for a call that named no session. */
export const NO_SESSION_ID = 'none';

const JSON_SCHEMA = 'https://json-schema.org/draft/2020-12/schema';

/** The handshake tool's input, as `handshake-request.json` defines it, for hosts that register tools with JSON schema. */
export const HANDSHAKE_INPUT_SCHEMA = {
  $schema: JSON_SCHEMA,
  type: 'object',
  required: ['nonce', 'audience', 'timestamp'],
  properties: {
    nonce: { type: 'string', minLength: kyaos.NONCE_MIN_LENGTH },
    audience: { type: 'string' },
    timestamp: { type: 'integer', minimum: 0 },
    agentDid: { type: 'string', pattern: '^did:[a-z0-9]+:.+$' },
    clientInfo: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
    clientProtocolVersion: { type: 'string', pattern: '^\\d+\\.\\d+$' },
    clientCapabilities: { type: 'object' },
  },
  additionalProperties: false,
} as const;

const reasonOf = (error: unknown): string => {
  if (error instanceof KyaOsError) return error.reason;
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && code.length > 0) return code;
  return error instanceof Error && error.message.length > 0 ? error.message : 'denied';
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export function createKyaOs(options: KyaOsOptions): KyaOsRuntime {
  const signer = options.signer;
  const serverDid = options.serverDid ?? signer.did;
  if (serverDid !== signer.did) throw new Error(`createKyaOs: serverDid ${serverDid} is not the signer's DID ${signer.did}`);
  if (!kyaos.isDid(serverDid)) throw new Error('createKyaOs: serverDid must be a DID');
  const skew = kyaos.clockSkewSeconds(options.clockSkewSeconds);
  const sessionsEnabled = options.session?.enabled ?? true;
  const nonceStore = options.nonceStore ?? new MemoryNonceStore({ now: options.now ?? Date.now });
  const sessionStore =
    options.session?.store ??
    new MemorySessionStore(options.session?.ttlMinutes !== undefined ? { ttlMinutes: options.session.ttlMinutes } : {});
  const now = options.now ?? Date.now;
  const audiences = new Set([serverDid, ...(options.publicOrigin !== undefined ? [options.publicOrigin] : [])]);
  const kid = `${serverDid}#${signer.kid.replace(/^#/, '')}`;

  /** Retention of a nonce whose timestamp is `tsSeconds`: until `ts + skew + 1 s`, never less. */
  const retainUntil = (tsSeconds: number): number => (tsSeconds + skew + 1) * 1000;

  /** A fresh nonce for a proof, recorded in the same store the handshake uses, so no proof nonce is ever reused. */
  const proofNonce = async (tsSeconds: number): Promise<string> => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const nonce = kyaos.generateNonce();
      if (await nonceStore.insert(nonce, serverDid, retainUntil(tsSeconds))) return nonce;
    }
    throw new Error('createKyaOs: could not record a fresh proof nonce');
  };

  const sign = async (meta: Omit<ProofMeta, 'did' | 'kid' | 'ts' | 'nonce' | 'audience'> & { audience?: string | undefined }): Promise<DetachedProof> => {
    const ts = Math.floor(now() / 1000);
    const nonce = await proofNonce(ts);
    const { audience, ...rest } = meta;
    return buildResponseProof({ did: serverDid, kid, ts, nonce, audience: audience ?? serverDid, ...rest }, signer);
  };

  const handshake = async (args: unknown, handshakeOptions: HandshakeOptions = {}): Promise<kyaos.HandshakeResponse> => {
    const format = kyaos.validateHandshakeFormat(args);
    if (!format.ok) throw new KyaOsError(format.problem, format.message);
    const request = format.request;
    if (!sessionsEnabled) throw new KyaOsError('sessions_disabled', 'this server does not open KYA-OS sessions');
    if (!audiences.has(request.audience)) {
      throw new KyaOsError('audience_mismatch', `audience ${request.audience} is not this server (${[...audiences].join(' or ')})`);
    }
    const nowMs = now();
    const nowSeconds = Math.floor(nowMs / 1000);
    if (!kyaos.withinSkew(request.timestamp, nowSeconds, skew)) {
      throw new KyaOsError('timestamp_skew', `timestamp ${request.timestamp} is more than ${skew} s from the server time ${nowSeconds}`);
    }
    const verified = handshakeOptions.authenticatedAgentDid;
    if (verified !== undefined && request.agentDid !== undefined && verified !== request.agentDid) {
      throw new KyaOsError('agent_did_mismatch', `agentDid ${request.agentDid} is not the authenticated agent ${verified}`);
    }
    const agentDid = verified ?? request.agentDid;
    if (!(await nonceStore.insert(request.nonce, agentDid, retainUntil(request.timestamp)))) {
      throw new KyaOsError('nonce_replayed', 'nonce was already used');
    }
    const session = await sessionStore.create({
      agentDid,
      identityState: verified !== undefined ? 'authenticated' : 'anonymous',
      audience: request.audience,
      nonce: request.nonce,
      now: nowMs,
    });
    return {
      sessionId: session.id,
      serverDid,
      protocolVersion: kyaos.PROTOCOL_VERSION,
      serverCapabilities: { proofs: true, delegation: false, statusList: false },
      sessionTtl: Math.round(sessionStore.ttlMinutes * 60),
      nonce: request.nonce,
    };
  };

  const handshakeToolResult = async (args: unknown, handshakeOptions?: HandshakeOptions): Promise<Record<string, unknown>> => {
    try {
      const response = await handshake(args, handshakeOptions);
      return { content: [{ type: 'text', text: JSON.stringify(response) }], structuredContent: response };
    } catch (error) {
      if (!(error instanceof KyaOsError)) throw error;
      return { isError: true, content: [{ type: 'text', text: `${error.reason}: ${error.message}` }], structuredContent: { error: error.reason, message: error.message } };
    }
  };

  /** The session a call names, or a `KyaOsError` when it names one that is not live. */
  const sessionOf = async (args: Record<string, unknown>, nowMs: number): Promise<KyaOsSession | undefined> => {
    const id = args[kyaos.SESSION_CONTROL_ARGUMENT];
    if (id === undefined) return undefined;
    if (!sessionsEnabled) throw new KyaOsError('sessions_disabled', 'this server does not open KYA-OS sessions');
    if (!kyaos.isSessionId(id)) throw new KyaOsError('session_id_malformed', `${kyaos.SESSION_CONTROL_ARGUMENT} must be kyaos_<uuid-v4>`);
    const session = await sessionStore.get(id, nowMs);
    if (session === undefined) throw new KyaOsError('session_unknown', `session ${id} is unknown or has expired`);
    return session;
  };

  const start = async (call: KyaOsCallInput, startOptions: KyaOsStartOptions = {}): Promise<KyaOsStarted> => {
    const args = isRecord(call.arguments) ? call.arguments : {};
    const requestHash = kyaos.hashRequest({ method: 'tools/call', params: { name: call.name, arguments: args } });
    const stripped = kyaos.stripControlArguments(args);
    let session: KyaOsSession | undefined;
    let clientDid = startOptions.clientDid;
    try {
      session = await sessionOf(args, now());
      const caller = startOptions.authorize === undefined ? undefined : await startOptions.authorize();
      clientDid ??= caller?.agentDid ?? session?.agentDid;
      if (session?.agentDid !== undefined && clientDid !== undefined && session.agentDid !== clientDid) {
        throw new KyaOsError('session_agent_mismatch', `session ${session.id} belongs to ${session.agentDid}, not ${clientDid}`);
      }
    } catch (error) {
      const reason = reasonOf(error);
      if (isNeedsAuthorizationError(error)) {
        // L3-E: the challenge is a response body, so its proof carries responseHash over all of it (authorizationUrl included).
        const body = challengeToolResult(error.challenge);
        const proof = await sign({
          sessionId: session?.id ?? NO_SESSION_ID,
          audience: session?.audience,
          requestHash,
          responseHash: kyaos.hashResponse(body, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE),
          outcome: 'needs_authorization',
          reason: `requires delegation with scope: ${error.challenge.scopes.join(' ')}`,
          ...(clientDid !== undefined ? { clientDid } : {}),
          prf: kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE,
        });
        return { outcome: 'needs_authorization', challenge: error.challenge, error, proof, requestHash, session, result: attachResponseProof(body, proof) };
      }
      const proof = await sign({
        sessionId: session?.id ?? NO_SESSION_ID,
        audience: session?.audience,
        requestHash,
        outcome: 'denied',
        reason,
        ...(clientDid !== undefined ? { clientDid } : {}),
      });
      return { outcome: 'denied', reason, error, proof, requestHash, session };
    }
    if (session !== undefined) session = await sessionStore.touch(session.id, now());
    const sessionId = session?.id ?? NO_SESSION_ID;
    const audience = session?.audience;
    return {
      outcome: 'allowed',
      arguments: stripped,
      requestHash,
      session,
      clientDid,
      finish: async <T extends Record<string, unknown>>(result: T): Promise<T & { _meta: Record<string, unknown> }> => {
        const proof = await sign({
          sessionId,
          audience,
          requestHash,
          responseHash: kyaos.hashResponse(result, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE),
          outcome: 'allowed',
          ...(clientDid !== undefined ? { clientDid } : {}),
          prf: kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE,
        });
        return attachResponseProof(result, proof);
      },
    };
  };

  return {
    serverDid,
    clockSkewSeconds: skew,
    sessionsEnabled,
    nonceStore,
    sessionStore,
    handshakeToolName: kyaos.HANDSHAKE_TOOL_NAME,
    describe: (): KyaOsDescription =>
      describeKyaOs({ clockSkewSeconds: skew, session: { enabled: sessionsEnabled }, toolsEndpoint: options.toolsEndpoint }),
    isHandshake: (name): boolean => name === kyaos.HANDSHAKE_TOOL_NAME,
    handshake,
    handshakeToolResult,
    start,
    call: async <T extends Record<string, unknown>>(
      call: KyaOsCallInput,
      run: (args: Record<string, unknown>, context: { session?: KyaOsSession | undefined; clientDid?: string | undefined }) => Promise<T> | T,
      startOptions?: KyaOsStartOptions,
    ): Promise<KyaOsDenied | KyaOsNeedsAuthorization | (KyaOsAllowed & { result: T & { _meta: Record<string, unknown> } })> => {
      const started = await start(call, startOptions);
      if (started.outcome !== 'allowed') return started;
      const result = await run(started.arguments, { session: started.session, clientDid: started.clientDid });
      return { ...started, result: await started.finish(result) };
    },
  };
}
