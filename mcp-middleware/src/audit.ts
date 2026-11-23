// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS auditability for an MCP server (AUDITABILITY.md, AAP-1 Recorded).
 *
 * The middleware hands `auditSink` one `ToolAuditEvent` per authorization
 * decision; `McpAuditTrail.toolAuditSink()` turns each into the typed events
 * of the protocol (`proof.verified` / `proof.rejected`,
 * `authorization.approved` / `authorization.denied`), and
 * `beginToolCall()` records the call's own lifecycle (`session.established`,
 * `tool.call.started` / `completed` / `failed` / `denied`) under one
 * correlation id. Every event goes through the SDK's `AuditTrail`: strictly
 * validated, references bounded, sequenced per source, digested, and handed
 * to a reporter (`createHelixAuditReporter`: `POST /v1/audit-log/events`).
 *
 * No event ever holds tool arguments, a response, a bearer token or a credential. An
 * OAuth subject enters only as a keyed commitment under a key the trail
 * holds; a tool name is withheld unless `includeToolNames` is set.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import type { OutboundAttachment, OutboundAudit } from './delegation/outbound.js';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  AUDIT_BINDING_MCP,
  AuditTrail,
  UNKNOWN_DELEGATION_REF,
  credentialDigest,
  delegationChainDigests,
  delegationRef,
  didWebFor,
  keyedCommitmentValue,
  pairwiseDid,
  publicDid,
  type AuditEventInput,
  type AuditOutcome,
  type AuditSink as AuditEntrySink,
  type AuditTrailEntry,
  type AuthorizationEvidence,
  type AuthorizationPhase,
  type DelegationPhase,
  type Digest,
  type PartyRef,
  type ProofPhase,
  type SessionPhase,
  type ToolPhase,
} from '@helixid/sdk-js';

/** One authorization decision for one tool call, as the middleware reports it. */
export interface ToolAuditEvent {
  /** `AUTHZ_GRANTED` when the call was allowed to run, `AUTHZ_DENIED` otherwise. */
  event: 'AUTHZ_GRANTED' | 'AUTHZ_DENIED';
  result: 'allowed' | 'denied';
  timestamp: string;
  authMethod: 'kyaos' | 'oauth';
  /** KYA-OS callers: the agent DID the request proof verified as. */
  agentDid?: string;
  /** KYA-OS callers: the level the local verifier derived (story F-2) and whether every status was read live. */
  level?: 'L1' | 'L2' | 'L3';
  fresh?: boolean;
  /** KYA-OS callers (story C-C): `L3` on a full `cnf` fusion, `L3-minus` without a token `cnf`; absent for a call with no proof. */
  proofAssurance?: 'L3' | 'L3-minus';
  /** KYA-OS callers: true when the call's L3 rests on an unfused proof (L3-minus). */
  l3Minus?: boolean;
  /** KYA-OS callers: the `cnf` diagnostics (`cnf_present_but_token_unfused`), when there are any. */
  cnfDiagnostics?: string[];
  /** KYA-OS callers refused on level: the tool's minimum. */
  requiredLevel?: 'L1' | 'L2' | 'L3';
  /** OAuth callers: the token's `sub`. Never recorded as such; see `McpAuditTrail`. */
  oauthSubject?: string;
  toolName?: string;
  /** The scope that was required (on denial, the one that was missing). */
  requiredScope?: string;
  effectiveScopes: string[];
  reason?: string;
  /** This server's DID (`serviceDid` option, else `expectedTargetService`). */
  serviceDid?: string;
  /** The tool call this decision belongs to; defaults to the current `beginToolCall()` context. */
  correlationId?: string;
}

/** Receives every decision for an identified caller. Await-ed before the tool runs. */
export type AuditSink = (event: ToolAuditEvent) => void | Promise<void>;

export interface HelixAuditReporterOptions {
  /** HelixID API base URL (pass your own; there is no default). */
  baseUrl: string;
  /** Admin or enterprise account API key, sent as the bearer token. */
  apiKey: string;
  timeoutMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

export interface HelixAuditSinkOptions extends HelixAuditReporterOptions {
  /** This server's DID: the producer of every event and the resource of every call. Required unless the middleware reports one per event. */
  serviceDid?: string;
  /** Names this producer source; default `mcp-middleware:<serviceDid>`. */
  sourceId?: string;
  /** Record tool names (`action.name`). Default false: a tool name is often sensitive in itself. */
  includeToolNames?: boolean;
}

/**
 * The reporter behind every Helix-backed trail: posts each recorded event,
 * exactly as the trail built it, to `POST /v1/audit-log/events`. Built on
 * plain `fetch`, not `HelixClient`, so the middleware needs no SDK client
 * for audit alone. A non-2xx answer is an error (the trail's record fails;
 * the middleware reports it through `onAuditError` and the tool call goes on).
 */
export function createHelixAuditReporter(options: HelixAuditReporterOptions): AuditEntrySink {
  const base = options.baseUrl.replace(/\/+$/, '');
  const doFetch = options.fetch ?? fetch;
  return {
    async append(entry: AuditTrailEntry): Promise<void> {
      const res = await doFetch(`${base}/v1/audit-log/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${options.apiKey}` },
        // The canonical text is the event's JSON; the API re-derives the same digest from it.
        body: entry.canonical,
        signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
      });
      if (!res.ok) throw new Error(`audit-log/events responded ${res.status}`);
    },
  };
}

/** What every event of a tool call shares; each member overrides the current `beginToolCall()` context. */
export interface McpAuditContext {
  actor?: PartyRef;
  responsibleParty?: PartyRef;
  authorization?: AuthorizationEvidence;
  correlationId?: string;
  causationId?: string;
}

export interface McpAuditTrailOptions {
  /** Where recorded entries go: `createHelixAuditReporter`, a `MemoryAuditSink`, ... */
  reporter: AuditEntrySink;
  /** This server's DID: the default producer (as a pairwise DID) and the resource of every event. */
  serviceDid?: string;
  /** Names this producer source; default `mcp-middleware:<serviceDid>`. */
  sourceId?: string;
  /** Overrides the producer; required when there is no `serviceDid`. */
  producer?: PartyRef;
  /** Default: the producer. */
  tenantRef?: PartyRef;
  /** Record tool names (`action.name`). Default false. */
  includeToolNames?: boolean;
  /** The key OAuth subjects are committed under; default 32 random bytes per trail. */
  oauthSubjectKey?: Uint8Array;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: () => number;
  /** Default `audit_<uuid>`. */
  newEventId?: () => string;
}

export interface ToolCallAuditOptions {
  toolName?: string;
  /** Default `audit_<uuid>`. */
  correlationId?: string;
  /** The caller, when already known; the authorization sink fills it in otherwise. */
  actor?: PartyRef;
}

/** The members a tool call's events share, kept in `AsyncLocalStorage` for the call's duration. */
interface ToolCallState {
  correlationId: string;
  toolName: string | undefined;
  actor: PartyRef | undefined;
}

const OAUTH_SUBJECT_KEY_ID = 'oauth-subject-v1';

/** The guard's own denials of an identified caller; any other reason a KYA-OS caller is denied with is the local verifier's. */
const GUARD_REASONS: ReadonlySet<string> = new Set(['tool is not in toolScopes', 'insufficient scope', 'needs_authorization']);

/**
 * `KYAOS_PROOF_<level>`, with `_CACHED` when the verifier did not read every
 * status live (story F-2). Story C-C: an L3 that rests on an unfused proof is
 * `L3_MINUS`, and the `cnf` diagnostic `cnf_present_but_token_unfused` adds
 * `_CNF_UNFUSED`; the code is the only place A-1's events carry them.
 */
export function kyaosVerificationCode(event: ToolAuditEvent): string {
  const l3Minus = event.l3Minus ?? (event.level === 'L3' && event.proofAssurance === 'L3-minus');
  const level = event.level === undefined ? '' : `_${l3Minus ? 'L3_MINUS' : event.level}`;
  const cnfUnfused = event.cnfDiagnostics?.includes('cnf_present_but_token_unfused') === true;
  return `KYAOS_PROOF${level}${event.fresh === false ? '_CACHED' : ''}${cnfUnfused ? '_CNF_UNFUSED' : ''}`;
}

/** Story C-C: the reason code of a call refused because its derived level is below the tool's minimum. */
export const LEVEL_INSUFFICIENT_REASON = 'proof_level_insufficient';

/** The lifecycle events of one tool call; see `McpAuditTrail.beginToolCall`. */
export class ToolCallAudit {
  constructor(
    private readonly trail: McpAuditTrail,
    private readonly calls: AsyncLocalStorage<ToolCallState>,
    private readonly state: ToolCallState,
  ) {}

  /** The id every event of this call carries. */
  get correlationId(): string {
    return this.state.correlationId;
  }

  /** The caller, once known (given at `beginToolCall`, or learned from the authorization decision). */
  get actor(): PartyRef | undefined {
    return this.state.actor;
  }

  /**
   * Records `session.established`, then runs `fn` with this call as the
   * current context: an `auditSink` the middleware calls inside it attributes
   * its events to this call (same correlation id, same actor).
   */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.trail.session('established', { succeeded: true, context: this.context() });
    return this.calls.run(this.state, fn);
  }

  /** The tool is about to run. */
  started(): Promise<AuditTrailEntry> {
    return this.toolEvent('started', 'unknown');
  }

  /** The tool answered. */
  completed(): Promise<AuditTrailEntry> {
    return this.toolEvent('completed', 'succeeded');
  }

  /** The tool threw; `reasonCode` is a code, never the exception text. */
  failed(reasonCode: string): Promise<AuditTrailEntry> {
    return this.toolEvent('failed', 'failed', reasonCode);
  }

  /** The guard refused the call before the tool ran; `reasonCode` is the error code. */
  denied(reasonCode: string): Promise<AuditTrailEntry> {
    return this.toolEvent('denied', 'denied', reasonCode);
  }

  private toolEvent(phase: ToolPhase, outcome: AuditOutcome, reasonCode?: string): Promise<AuditTrailEntry> {
    return this.trail.tool(phase, {
      ...(this.state.toolName !== undefined ? { toolName: this.state.toolName } : {}),
      outcome,
      attempt: '1',
      ...(reasonCode !== undefined ? { reasonCode } : {}),
      context: this.context(),
    });
  }

  private context(): McpAuditContext {
    return { correlationId: this.state.correlationId, ...(this.state.actor !== undefined ? { actor: this.state.actor } : {}) };
  }
}

/**
 * One MCP server's audit source. Every method records one typed event (the
 * returned entry holds the event, its canonical text and digest) under the
 * MCP binding, with this server as the resource and the current tool call's
 * correlation id and actor unless the context says otherwise.
 */
export class McpAuditTrail {
  readonly trail: AuditTrail;
  readonly serviceDid: string | undefined;
  readonly includeToolNames: boolean;
  private readonly oauthSubjectKey: Uint8Array;
  private readonly calls = new AsyncLocalStorage<ToolCallState>();

  constructor(options: McpAuditTrailOptions) {
    const producer = options.producer ?? (options.serviceDid !== undefined ? pairwiseDid(options.serviceDid) : undefined);
    if (producer === undefined) {
      throw new TypeError('createMcpAuditTrail needs serviceDid (this server\'s DID) or an explicit producer');
    }
    this.serviceDid = options.serviceDid;
    this.includeToolNames = options.includeToolNames ?? false;
    this.oauthSubjectKey = options.oauthSubjectKey ?? randomBytes(32);
    this.trail = new AuditTrail({
      sink: options.reporter,
      sourceId: options.sourceId ?? `mcp-middleware:${options.serviceDid ?? 'server'}`,
      producer,
      tenantRef: options.tenantRef ?? producer,
      binding: AUDIT_BINDING_MCP,
      includeToolNames: this.includeToolNames,
      ...(options.clock !== undefined ? { clock: options.clock } : {}),
      ...(options.newEventId !== undefined ? { newEventId: options.newEventId } : {}),
    });
  }

  /** The actor an OAuth subject is recorded as: a keyed commitment, never the subject itself. */
  oauthActor(subject: string): PartyRef {
    return { kind: 'keyed_commitment', value: keyedCommitmentValue(this.oauthSubjectKey, subject), keyId: OAUTH_SUBJECT_KEY_ID };
  }

  session(phase: SessionPhase, options: { succeeded: boolean; reasonCode?: string; context?: McpAuditContext }): Promise<AuditTrailEntry> {
    const outcome: AuditOutcome = options.succeeded ? 'succeeded' : phase === 'expired' ? 'failed' : 'denied';
    return this.record(
      {
        eventType: `session.${phase}`,
        action: { category: 'session' },
        outcome,
        ...(options.reasonCode !== undefined ? { reason: { code: options.reasonCode } } : {}),
        details: { family: 'session', phase, ...(options.reasonCode !== undefined ? { reasonCode: options.reasonCode } : {}) },
      },
      options.context,
    );
  }

  proof(
    phase: ProofPhase,
    options: { outcome: AuditOutcome; proofDigest?: Digest; verificationCode?: string; reasonCode?: string; context?: McpAuditContext },
  ): Promise<AuditTrailEntry> {
    return this.record(
      {
        eventType: `proof.${phase}`,
        action: { category: 'proof' },
        outcome: options.outcome,
        ...(options.reasonCode !== undefined ? { reason: { code: options.reasonCode } } : {}),
        details: {
          family: 'proof',
          phase,
          ...(options.proofDigest !== undefined ? { proofDigest: options.proofDigest } : {}),
          ...(options.verificationCode !== undefined ? { verificationCode: options.verificationCode } : {}),
        },
      },
      options.context,
    );
  }

  delegation(
    phase: DelegationPhase,
    options: { delegationRef: string; outcome: AuditOutcome; reasonCode?: string; parentRef?: string; context?: McpAuditContext },
  ): Promise<AuditTrailEntry> {
    return this.record(
      {
        eventType: `delegation.${phase}`,
        action: { category: 'delegation' },
        outcome: options.outcome,
        ...(options.reasonCode !== undefined ? { reason: { code: options.reasonCode } } : {}),
        details: {
          family: 'delegation',
          phase,
          delegationRef: options.delegationRef,
          ...(options.parentRef !== undefined ? { parentRef: options.parentRef } : {}),
        },
      },
      options.context,
    );
  }

  authorization(
    phase: AuthorizationPhase,
    options: { outcome: AuditOutcome; reasonCode?: string; grantRef?: string; toolName?: string; context?: McpAuditContext },
  ): Promise<AuditTrailEntry> {
    return this.record(
      {
        eventType: phase === 'grant_used' ? 'grant.used' : `authorization.${phase}`,
        action: { category: 'authorization' },
        outcome: options.outcome,
        ...(options.reasonCode !== undefined ? { reason: { code: options.reasonCode } } : {}),
        details: { family: 'authorization', phase, ...(options.grantRef !== undefined ? { grantRef: options.grantRef } : {}) },
      },
      options.context,
      options.toolName,
    );
  }

  /**
   * Story L3-D (L3.26): one outbound delegation attachment, as
   * `delegation.outbound_attached`: the chain string as the action name
   * (verbatim up to 256 characters, else its digest), the target as the
   * resource (its DID when given, else the did:web of the audience host),
   * the forwarded credential's reference, digest and the chain's digests
   * root first, the agent as actor and the Responsible Party.
   */
  outboundAttached(attachment: OutboundAttachment, options: { targetDid?: string; context?: McpAuditContext } = {}): Promise<AuditTrailEntry> {
    const leaf = attachment.chain[attachment.chain.length - 1];
    const parent = attachment.chain.length > 1 ? attachment.chain[attachment.chain.length - 2] : undefined;
    const leafRef = delegationRef(leaf) ?? UNKNOWN_DELEGATION_REF;
    const parentRef = parent === undefined ? undefined : delegationRef(parent);
    const leafDigest = credentialDigest(leaf);
    const chainDigests = delegationChainDigests(attachment.chain);
    let target: string | undefined = options.targetDid;
    if (target === undefined) {
      try {
        target = didWebFor(attachment.audience);
      } catch {
        target = undefined;
      }
    }
    const authorization: AuthorizationEvidence = {
      source: 'delegation',
      decision: 'allowed',
      delegationRef: leafRef,
      ...(leafDigest === undefined ? {} : { delegationCredentialDigest: leafDigest }),
      ...(chainDigests === undefined ? {} : { delegationChainDigests: chainDigests }),
    };
    return this.record(
      {
        eventType: 'delegation.outbound_attached',
        action: { category: 'delegation.outbound', name: attachment.chainString },
        outcome: 'succeeded',
        details: { family: 'delegation', phase: 'outbound_attached', delegationRef: leafRef, ...(parentRef === undefined ? {} : { parentRef }) },
      },
      {
        actor: pairwiseDid(attachment.agentDid),
        responsibleParty: pairwiseDid(attachment.responsibleParty),
        authorization,
        ...(attachment.correlationId === undefined ? {} : { correlationId: attachment.correlationId }),
        causationId: attachment.jti,
        ...options.context,
      },
      undefined,
      // An audience that names no host has no DID: the event then names no resource, never this server instead.
      target === undefined ? null : publicDid(target),
    );
  }

  /** `withDelegation`'s `audit` option: every outbound attachment recorded by `outboundAttached`. */
  outboundAudit(options: { targetDid?: (attachment: OutboundAttachment) => string | undefined } = {}): OutboundAudit {
    return async (attachment) => {
      const targetDid = options.targetDid?.(attachment);
      await this.outboundAttached(attachment, targetDid === undefined ? {} : { targetDid });
    };
  }

  tool(
    phase: ToolPhase,
    options: { toolName?: string; outcome: AuditOutcome; attempt?: string; reasonCode?: string; context?: McpAuditContext },
  ): Promise<AuditTrailEntry> {
    return this.record(
      {
        eventType: `tool.call.${phase}`,
        action: { category: 'tool.call' },
        outcome: options.outcome,
        ...(options.reasonCode !== undefined ? { reason: { code: options.reasonCode } } : {}),
        details: { family: 'tool', phase, attempt: options.attempt ?? '1' },
      },
      options.context,
      options.toolName,
    );
  }

  /**
   * Starts one tool call's audit. Run the guard and the tool inside
   * `run()`; call `started()` / `completed()` / `failed()` / `denied()` as
   * the call goes.
   */
  beginToolCall(options: ToolCallAuditOptions = {}): ToolCallAudit {
    const state: ToolCallState = {
      correlationId: options.correlationId ?? `audit_${randomUUID()}`,
      toolName: options.toolName,
      actor: options.actor,
    };
    return new ToolCallAudit(this, this.calls, state);
  }

  /**
   * The middleware's `auditSink`: translates each authorization decision into
   * the typed events. A KYA-OS caller (story F-2): `proof.verified`, its
   * verification code naming the level the local verifier derived (and
   * `_CACHED` when a status was not read live), then `authorization.approved` or
   * `authorization.denied` (reason `needs_authorization` for an L3-E
   * challenge); a request proof the verifier refused is `proof.rejected` by
   * its first reason code, and nothing else. Story C-C: the verification
   * code also names L3-minus and an unfused `cnf`, and a call below the tool's
   * minimum level is `proof.verified` then `authorization.denied` with reason
   * `proof_level_insufficient`. An OAuth caller: only the
   * authorization event, with the subject as a keyed commitment.
   */
  toolAuditSink(): AuditSink {
    return async (event: ToolAuditEvent): Promise<void> => {
      const call = this.calls.getStore();
      const actor = this.actorOf(event) ?? call?.actor;
      if (call !== undefined && call.actor === undefined && actor !== undefined) call.actor = actor;
      const base: McpAuditContext = {
        ...(actor !== undefined ? { actor } : {}),
        ...(event.correlationId !== undefined ? { correlationId: event.correlationId } : {}),
      };
      const toolName = event.toolName;
      const scopeId = event.requiredScope;
      const allowed = event.result === 'allowed';
      const kyaos = event.authMethod === 'kyaos';
      const levelRefused = kyaos && !allowed && event.requiredLevel !== undefined;
      if (kyaos && !allowed && !levelRefused && scopeId === undefined && event.reason !== undefined && !GUARD_REASONS.has(event.reason)) {
        // The local verifier refused the request proof: its reasons are codes, the first one names the refusal.
        await this.proof('rejected', { outcome: 'denied', reasonCode: event.reason.split(',')[0]!.trim() || 'proof_invalid', context: base });
        return;
      }
      if (kyaos) {
        await this.proof('verified', {
          outcome: 'succeeded',
          verificationCode: kyaosVerificationCode(event),
          context: base,
        });
      }
      const decision: AuthorizationEvidence['decision'] = allowed ? 'allowed' : 'denied';
      const authorization: AuthorizationEvidence = { source: kyaos ? 'delegation' : 'policy', decision, ...(scopeId !== undefined ? { scopeId } : {}) };
      const context: McpAuditContext = { ...base, authorization };
      if (allowed) {
        await this.authorization('approved', { outcome: 'succeeded', context, ...(toolName !== undefined ? { toolName } : {}) });
      } else {
        await this.authorization('denied', {
          outcome: 'denied',
          // KYA-OS story L3-E: a signed needs_authorization challenge keeps its reason; story C-C: a level refusal is its own code.
          reasonCode: levelRefused
            ? LEVEL_INSUFFICIENT_REASON
            : event.reason === 'needs_authorization'
              ? 'needs_authorization'
              : scopeId !== undefined
                ? 'insufficient_scope'
                : 'tool_not_permitted',
          context,
          ...(toolName !== undefined ? { toolName } : {}),
        });
      }
    };
  }

  private actorOf(event: ToolAuditEvent): PartyRef | undefined {
    if (event.authMethod === 'oauth') return event.oauthSubject !== undefined ? this.oauthActor(event.oauthSubject) : undefined;
    return event.agentDid !== undefined ? pairwiseDid(event.agentDid) : undefined;
  }

  /** Fills the context (explicit members over the current call's) and the resource, applies the tool-name policy, records. */
  private record(input: AuditEventInput, context: McpAuditContext | undefined, toolName?: string, resource?: PartyRef | null): Promise<AuditTrailEntry> {
    const call = this.calls.getStore();
    const correlationId = context?.correlationId ?? call?.correlationId;
    const actor = context?.actor ?? call?.actor;
    const event: AuditEventInput = {
      ...input,
      ...(correlationId !== undefined ? { correlationId } : {}),
      ...(context?.causationId !== undefined ? { causationId: context.causationId } : {}),
      ...(actor !== undefined ? { actor } : {}),
      ...(context?.responsibleParty !== undefined ? { responsibleParty: context.responsibleParty } : {}),
      ...(resource === null ? {} : resource !== undefined ? { resource } : this.serviceDid !== undefined ? { resource: publicDid(this.serviceDid) } : {}),
      ...(context?.authorization !== undefined ? { authorization: context.authorization } : {}),
      action: { ...input.action, ...(toolName !== undefined && this.includeToolNames ? { name: toolName } : {}) },
    };
    return this.trail.record(event);
  }
}

export function createMcpAuditTrail(options: McpAuditTrailOptions): McpAuditTrail {
  return new McpAuditTrail(options);
}

/**
 * The middleware's `auditSink` backed by the HelixID API: a trail whose
 * reporter posts every typed event to `POST /v1/audit-log/events`, with the
 * legacy decision translated by `McpAuditTrail.toolAuditSink()`. For the
 * call lifecycle events too, build the trail yourself with
 * `createMcpAuditTrail({ reporter: createHelixAuditReporter(...) })`.
 */
export function createHelixAuditSink(options: HelixAuditSinkOptions): AuditSink {
  const { serviceDid, sourceId, includeToolNames, ...reporter } = options;
  return createMcpAuditTrail({
    reporter: createHelixAuditReporter(reporter),
    ...(serviceDid !== undefined ? { serviceDid } : {}),
    ...(sourceId !== undefined ? { sourceId } : {}),
    ...(includeToolNames !== undefined ? { includeToolNames } : {}),
  }).toolAuditSink();
}
