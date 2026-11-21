// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { AuditSink, ToolAuditEvent } from './audit.js';
import { MemoryResumeTokenStore, isResumeToken, type ResumeTokenRecord, type ResumeTokenStore } from './resume-token-store.js';

/**
 * The signed `needs_authorization` challenge and the resume flow (KYA-OS
 * story L3-E; SPEC §9.2, §9.3; conformance L3.25, L3.26).
 *
 * When a call's delegation is missing or does not cover the tool's scopes
 * the guard throws a {@link NeedsAuthorizationError} built here instead of
 * the plain 403: `{error: "needs_authorization", message, authorizationUrl,
 * resumeToken, expiresAt, scopes, display?}`. The KYA-OS runtime (L2-A)
 * turns it into a tool result signed with `outcome: needs_authorization`
 * and a `responseHash` over the whole result, so `authorizationUrl` is
 * covered by the service signature and a proxy cannot redirect the user to
 * a consent page of its own.
 *
 * `resumeToken` is opaque, bound to the agent DID, the tool and the scopes
 * asked for, single-use and expiring at `expiresAt` ({@link ResumeTokenStore}).
 * A retry carries it as the `_kyaos_resume` control argument and the new
 * DelegationCredential as `_kyaos_delegation` (SPEC §7.3's `_kyaos*`
 * channel; both are stripped before the handler and never hashed).
 * `authorizeRetry` consumes the token, checks the binding, then hands the
 * credential to the injected {@link RetryAuthorizer}: the seam story F-2
 * (chain verification) and L3-H (the user-signed root hop) implement. The
 * default authorizer refuses, so until they land a retry never succeeds
 * on a token alone: completing consent never authorises the call by itself.
 *
 * Every challenge issued is audited through the existing `AuditSink` as an
 * `AUTHZ_DENIED` event with `reason: "needs_authorization"` (L3.26); the
 * signed proof on the challenge is the tamper-evident record of it.
 *
 * Cross-border rule: the only state is the resume-token store, local like
 * the nonce store; nothing here asks a Helix database anything.
 */

export const NEEDS_AUTHORIZATION = 'needs_authorization';
/** Control argument carrying the resume token on a retry. */
export const RESUME_CONTROL_ARGUMENT = '_kyaos_resume';
/** Control argument carrying the new DelegationCredential on a retry. */
export const DELEGATION_CONTROL_ARGUMENT = '_kyaos_delegation';
/** Default lifetime of a resume token, in seconds. */
export const DEFAULT_RESUME_TTL_SECONDS = 600;

export type DisplayHint = 'link' | 'qr' | 'code';

/** SPEC §9.2 `display`: how a client may present the authorization step. */
export interface NeedsAuthorizationDisplay {
  title?: string;
  hint?: DisplayHint[];
  authorizationCode?: string;
  qrUrl?: string;
}

/** SPEC §9.2 `NeedsAuthorizationError`: the challenge body. */
export interface NeedsAuthorizationChallenge {
  error: typeof NEEDS_AUTHORIZATION;
  message: string;
  /** Where the user can grant the authorization. Covered by the proof's `responseHash`. */
  authorizationUrl: string;
  /** Opaque, single-use, bound to the agent, tool and scopes. */
  resumeToken: string;
  /** Unix seconds at which `resumeToken` expires. */
  expiresAt: number;
  /** The scopes being requested. */
  scopes: string[];
  display?: NeedsAuthorizationDisplay;
}

/**
 * The guard's refusal when authority is missing: carries the challenge. The
 * KYA-OS runtime answers it as a signed tool result; a host without the
 * runtime answers it through `toHttpErrorResponse` as a 403 whose body is
 * the challenge (unsigned, since there is no signer).
 */
export class NeedsAuthorizationError extends Error {
  public readonly code = 'NEEDS_AUTHORIZATION';
  public readonly httpStatus = 403;

  constructor(public readonly challenge: NeedsAuthorizationChallenge) {
    super(challenge.message);
    this.name = 'NeedsAuthorizationError';
  }
}

export function isNeedsAuthorizationError(error: unknown): error is NeedsAuthorizationError {
  return error instanceof NeedsAuthorizationError || (error as { code?: unknown } | null)?.code === 'NEEDS_AUTHORIZATION';
}

/** Why a retry was refused; the `reason` of the denied proof. */
export type ResumeRefusalReason =
  | 'resume_token_malformed'
  | 'resume_token_unknown'
  | 'resume_token_agent_mismatch'
  | 'resume_token_tool_mismatch'
  | 'resume_token_scope_mismatch'
  | 'delegation_missing'
  | 'delegation_refused'
  | 'retry_authorizer_missing';

/** A retry refused: the token was replayed, expired, bound to another agent or tool, or the credential did not verify. */
export class ResumeRefusedError extends Error {
  public readonly code = 'RESUME_REFUSED';
  public readonly httpStatus = 403;

  constructor(
    public readonly reason: ResumeRefusalReason,
    message: string,
  ) {
    super(message);
    this.name = 'ResumeRefusedError';
  }
}

export interface RetryAuthorizerInput {
  /** The DelegationCredential the retry carried, as received. */
  credential: unknown;
  /** The consumed token's binding. */
  token: ResumeTokenRecord;
  /** The agent retrying, as the guard identified it. */
  agentDid: string;
  tool: string;
  /** The scopes the tool requires. */
  scopes: string[];
}

export interface RetryAuthorization {
  /** The scopes the credential grants this agent at this service. */
  scopes: string[];
}

/**
 * Verifies the credential a retry carries and says what it grants; throws
 * to refuse (any throw becomes `delegation_refused`). Story F-2 supplies
 * the chain verifier and L3-H the user-signed root hop; until then the
 * default refuses every retry.
 */
export type RetryAuthorizer = (input: RetryAuthorizerInput) => Promise<RetryAuthorization> | RetryAuthorization;

export interface ChallengeContext {
  agentDid: string;
  tool: string;
  /** The scopes the tool requires. */
  scopes: string[];
}

export interface ChallengeInput extends ChallengeContext {
  /** The scopes the caller lacked; default every required scope. */
  missing?: string[] | undefined;
  message?: string | undefined;
  display?: NeedsAuthorizationDisplay | undefined;
  /** For the audit event: how the caller authenticated and what it had. */
  authMethod?: ToolAuditEvent['authMethod'] | undefined;
  effectiveScopes?: string[] | undefined;
  oauthSubject?: string | undefined;
  vpId?: string | undefined;
}

export interface NeedsAuthorizationOptions {
  /** The consent page: a URL, or a function of the challenge's binding. Always covered by the proof. */
  authorizationUrl: string | ((context: ChallengeContext) => string);
  /** Default `MemoryResumeTokenStore` (one instance); share a `RedisResumeTokenStore` across instances. */
  store?: ResumeTokenStore | undefined;
  /** Resume-token lifetime; default 600. */
  ttlSeconds?: number | undefined;
  /** Verifies the credential a retry carries (F-2, L3-H). Default: refuses. */
  authorizer?: RetryAuthorizer | undefined;
  /** Receives one `AUTHZ_DENIED` event with `reason: "needs_authorization"` per challenge issued. */
  auditSink?: AuditSink | undefined;
  onAuditError?: ((error: unknown) => void) | undefined;
  /** This server's DID, for the audit event. */
  serviceDid?: string | undefined;
  /** Default message; the challenge input may override it. */
  message?: ((context: ChallengeContext) => string) | undefined;
  display?: NeedsAuthorizationDisplay | undefined;
  /** Milliseconds since the epoch; default `Date.now`. Injectable for tests. */
  now?: (() => number) | undefined;
}

export interface ResumeRetry {
  resumeToken: unknown;
  credential: unknown;
}

export interface NeedsAuthorization {
  readonly store: ResumeTokenStore;
  readonly ttlSeconds: number;
  /** Issues a resume token bound to the context and builds the challenge; audits it. */
  challenge(input: ChallengeInput): Promise<NeedsAuthorizationError>;
  /**
   * Consumes `resumeToken` (single use: a second call with the same token is
   * refused), checks it is bound to `context`, then hands `credential` to
   * the authorizer. Resolves what the credential grants; throws
   * `ResumeRefusedError`.
   */
  authorizeRetry(resumeToken: unknown, credential: unknown, context: ChallengeContext): Promise<RetryAuthorization>;
  /** The retry a call carries (`_kyaos_resume` present in its arguments), or undefined for an ordinary call. */
  readRetry(call: { input?: Record<string, unknown> | undefined }): ResumeRetry | undefined;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The challenge as an MCP tool result: `isError`, the challenge as text and as `structuredContent`. */
export function challengeToolResult(challenge: NeedsAuthorizationChallenge): Record<string, unknown> {
  return { isError: true, content: [{ type: 'text', text: JSON.stringify(challenge) }], structuredContent: challenge };
}

/** The retry a call carries, read from its arguments; undefined when there is no `_kyaos_resume`. */
export function readResumeRetry(call: { input?: Record<string, unknown> | undefined }): ResumeRetry | undefined {
  const args = call.input;
  if (!isRecord(args) || !Object.hasOwn(args, RESUME_CONTROL_ARGUMENT)) return undefined;
  return { resumeToken: args[RESUME_CONTROL_ARGUMENT], credential: args[DELEGATION_CONTROL_ARGUMENT] };
}

const defaultMessage = (context: ChallengeContext): string =>
  `${context.tool} requires delegation with scope: ${context.scopes.join(' ')}`;

const refusingAuthorizer: RetryAuthorizer = () => {
  throw new ResumeRefusedError('retry_authorizer_missing', 'no retry authorizer is configured: the delegation credential cannot be verified here');
};

export function createNeedsAuthorization(options: NeedsAuthorizationOptions): NeedsAuthorization {
  const now = options.now ?? Date.now;
  const store = options.store ?? new MemoryResumeTokenStore({ now });
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_RESUME_TTL_SECONDS;
  if (!(ttlSeconds > 0) || !Number.isFinite(ttlSeconds)) throw new RangeError('createNeedsAuthorization: ttlSeconds must be a positive number');
  const authorizer = options.authorizer ?? refusingAuthorizer;
  const urlOf = (context: ChallengeContext): string => {
    const url = typeof options.authorizationUrl === 'function' ? options.authorizationUrl(context) : options.authorizationUrl;
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error(`createNeedsAuthorization: authorizationUrl must be http(s), got ${url}`);
    return parsed.toString();
  };

  const audit = async (input: ChallengeInput, requiredScope: string): Promise<void> => {
    if (!options.auditSink) return;
    const event: ToolAuditEvent = {
      event: 'AUTHZ_DENIED',
      result: 'denied',
      timestamp: new Date(now()).toISOString(),
      authMethod: input.authMethod ?? 'helixvp',
      agentDid: input.agentDid,
      ...(input.oauthSubject !== undefined ? { oauthSubject: input.oauthSubject } : {}),
      ...(input.vpId !== undefined ? { vpId: input.vpId } : {}),
      toolName: input.tool,
      requiredScope,
      effectiveScopes: input.effectiveScopes ?? [],
      reason: NEEDS_AUTHORIZATION,
      ...(options.serviceDid !== undefined ? { serviceDid: options.serviceDid } : {}),
    };
    try {
      await options.auditSink(event);
    } catch (error) {
      options.onAuditError?.(error);
    }
  };

  const challenge = async (input: ChallengeInput): Promise<NeedsAuthorizationError> => {
    const context: ChallengeContext = { agentDid: input.agentDid, tool: input.tool, scopes: [...input.scopes] };
    if (context.scopes.length === 0) throw new Error('createNeedsAuthorization: a challenge needs at least one scope');
    const missing = input.missing !== undefined && input.missing.length > 0 ? input.missing : context.scopes;
    const authorizationUrl = urlOf(context);
    const expiresAtMs = now() + ttlSeconds * 1000;
    const resumeToken = await store.issue(context, expiresAtMs);
    const display = input.display ?? options.display;
    const body: NeedsAuthorizationChallenge = {
      error: NEEDS_AUTHORIZATION,
      message: input.message ?? (options.message ?? defaultMessage)(context),
      authorizationUrl,
      resumeToken,
      expiresAt: Math.floor(expiresAtMs / 1000),
      scopes: context.scopes,
      ...(display !== undefined ? { display } : {}),
    };
    await audit(input, missing[0] as string);
    return new NeedsAuthorizationError(body);
  };

  const authorizeRetry = async (resumeToken: unknown, credential: unknown, context: ChallengeContext): Promise<RetryAuthorization> => {
    if (!isResumeToken(resumeToken)) throw new ResumeRefusedError('resume_token_malformed', `${RESUME_CONTROL_ARGUMENT} must be the token of a needs_authorization challenge`);
    // Consumed before anything else is checked: a token is spent by its first use, whatever that use looked like.
    const record = await store.consume(resumeToken);
    if (record === undefined) throw new ResumeRefusedError('resume_token_unknown', 'the resume token is unknown, already used or expired');
    if (record.agentDid !== context.agentDid) throw new ResumeRefusedError('resume_token_agent_mismatch', 'the resume token was issued to another agent');
    if (record.tool !== context.tool) throw new ResumeRefusedError('resume_token_tool_mismatch', `the resume token was issued for ${record.tool}, not ${context.tool}`);
    if (context.scopes.some((scope) => !record.scopes.includes(scope))) {
      throw new ResumeRefusedError('resume_token_scope_mismatch', 'the retry asks for scopes the challenge did not');
    }
    if (credential === undefined || credential === null) {
      throw new ResumeRefusedError('delegation_missing', `the retry carries no ${DELEGATION_CONTROL_ARGUMENT}: consent alone does not authorise the call`);
    }
    let granted: RetryAuthorization;
    try {
      granted = await authorizer({ credential, token: record, agentDid: context.agentDid, tool: context.tool, scopes: [...context.scopes] });
    } catch (error) {
      if (error instanceof ResumeRefusedError) throw error;
      throw new ResumeRefusedError('delegation_refused', `the delegation credential was refused: ${error instanceof Error ? error.message : String(error)}`);
    }
    const scopes = Array.isArray(granted?.scopes) ? granted.scopes.filter((s): s is string => typeof s === 'string') : [];
    return { scopes };
  };

  return { store, ttlSeconds, challenge, authorizeRetry, readRetry: readResumeRetry };
}
