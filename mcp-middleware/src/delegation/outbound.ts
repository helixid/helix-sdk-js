// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Forwarding an agent's authority on a downstream call (KYA-OS story L3-D,
 * SPEC.md §8): `withDelegation(fetch, options)` wraps the `fetch` a tool
 * handler uses for downstream HTTP and MCP (Streamable HTTP) calls. Every
 * request it sends carries:
 *
 * - `KYA-OS-Delegation-Credential`: the chain the agent presented, root to
 *   leaf, or that chain with the service's own hop appended when it
 *   re-delegates (the hop must attenuate: it is checked here before
 *   anything is sent, and again by the receiver);
 * - `KYA-OS-Delegation-Proof`: the §8.2 JWT this service signs for the
 *   target host, 60 s, fresh `jti`;
 * - `KYA-OS-Agent-DID`: the agent DID this service recovered from the
 *   inbound request proof's signature;
 * - `KYA-OS-Session-Id` when the call had a session;
 * - optionally the advisory `KYA-OS-Delegation-Chain` and
 *   `KYA-OS-Granted-Scopes`, copies of what the credential and the proof
 *   say, which a receiver never decides on.
 *
 * Every attachment is audited (L3.26): the chain string and the target
 * audience, as A-1's `delegation.outbound_attached`.
 *
 * The context comes from the guard: `delegationContextOf(caller)` after
 * `authorize()`, then `runWithDelegation(context, handler)` makes it current
 * for the handler; or it is given to `withDelegation` directly. A call with
 * no context is refused, never sent without authority.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { kyaos } from '@helixid/sdk-js';
import { DELEGATION_HEADERS, encodeDelegationCredential } from './headers.js';
import { buildChainString, delegationIdOf, mintDelegationProofJwt } from './proof-jwt.js';

/** The authority a tool call carries, as the guard established it. */
export interface DelegationContext {
  /** The agent DID recovered from the inbound request proof's signature. */
  agentDid: string;
  /** The chain the agent presented, root first. */
  chain: readonly unknown[];
  /** The caller's effective scopes at this service. */
  scopes: readonly string[];
  /** The KYA-OS session id, when the call had one. */
  sessionId?: string | undefined;
  /** The tool call's audit correlation id, when known. */
  correlationId?: string | undefined;
}

/** One outbound attachment, as it is audited. */
export interface OutboundAttachment {
  /** ISO 8601 time the headers were attached. */
  timestamp: string;
  /** The proof's `aud`: the target host. */
  audience: string;
  /** The §8.3 chain string of the chain sent. */
  chainString: string;
  /** The chain sent, root first. */
  chain: readonly unknown[];
  delegationId: string;
  agentDid: string;
  /** The Responsible Party: the root hop's issuer, the proof's `sub`. */
  responsibleParty: string;
  /** This service's DID, the proof's `iss`. */
  forwarder: string;
  jti: string;
  scopes: string[];
  /** True when the service appended hops of its own. */
  redelegated: boolean;
  correlationId?: string | undefined;
}

export type OutboundAudit = (attachment: OutboundAttachment) => void | Promise<void>;

export class DelegationContextMissingError extends Error {
  readonly code = 'DELEGATION_CONTEXT_MISSING';
  constructor(message = 'withDelegation: no delegation context; run the handler with runWithDelegation(delegationContextOf(caller), ...)') {
    super(message);
    this.name = 'DelegationContextMissingError';
  }
}

export class RedelegationError extends Error {
  readonly code = 'REDELEGATION_INVALID';
  constructor(readonly reasons: string[]) {
    super(`withDelegation: the service's own hop does not attenuate the chain: ${reasons.join('; ')}`);
    this.name = 'RedelegationError';
  }
}

const contexts = new AsyncLocalStorage<DelegationContext>();

/** Runs `fn` with `context` as the current delegation, which `withDelegation` reads. */
export function runWithDelegation<T>(context: DelegationContext, fn: () => T): T {
  return contexts.run(context, fn);
}

/** The current delegation context, inside `runWithDelegation`. */
export function currentDelegation(): DelegationContext | undefined {
  return contexts.getStore();
}

/**
 * The delegation context of a caller the guard authorized, or undefined
 * when it carried no chain (an OAuth caller, an agent without delegation).
 */
export function delegationContextOf(
  caller: { authMethod: string; agentDid?: string | undefined; scopes: readonly string[]; chain?: readonly unknown[] | undefined },
  extra: { sessionId?: string | undefined; correlationId?: string | undefined } = {},
): DelegationContext | undefined {
  if (caller.authMethod !== 'kyaos' || caller.agentDid === undefined || caller.chain === undefined || caller.chain.length === 0) return undefined;
  return {
    agentDid: caller.agentDid,
    chain: caller.chain,
    scopes: caller.scopes,
    ...(extra.sessionId === undefined ? {} : { sessionId: extra.sessionId }),
    ...(extra.correlationId === undefined ? {} : { correlationId: extra.correlationId }),
  };
}

export interface WithDelegationOptions {
  /** This service's Signer: the proof's `iss` and key. */
  signer: kyaos.Signer;
  /** The delegation to forward; default the current one (`runWithDelegation`). */
  context?: DelegationContext | (() => DelegationContext | undefined) | undefined;
  /** Narrows the scopes forwarded (never widens: they are intersected with the context's and the leaf's). */
  scopes?: readonly string[] | ((context: DelegationContext, target: URL) => readonly string[]) | undefined;
  /**
   * Re-delegation: the service's own hop (or hops), signed by it, appended
   * to the chain for this target. It must attenuate the chain; a broadening
   * hop throws `RedelegationError` and nothing is sent.
   */
  redelegate?: ((context: DelegationContext, target: URL) => unknown | Promise<unknown>) | undefined;
  /** Also send the advisory `KYA-OS-Delegation-Chain` and `KYA-OS-Granted-Scopes`; default false. */
  advisoryHeaders?: boolean | undefined;
  /** Where each attachment is audited: an `OutboundAudit` (`McpAuditTrail.outboundAudit()`, say). */
  audit?: OutboundAudit | undefined;
  /** Called when `audit` throws; auditing never blocks the call. */
  onAuditError?: ((error: unknown) => void) | undefined;
  /** The longest chain sent; default 10. */
  maxChainLength?: number | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function leafActions(chain: readonly unknown[]): string[] {
  const leaf = chain[chain.length - 1];
  if (!isRecord(leaf) || !isRecord(leaf['credentialSubject'])) return [];
  const actions = leaf['credentialSubject']['allowedAction'];
  return Array.isArray(actions) ? actions.filter((action): action is string => typeof action === 'string') : [];
}

function rootIssuer(chain: readonly unknown[]): string | undefined {
  const root = chain[0];
  return isRecord(root) && typeof root['issuer'] === 'string' ? root['issuer'] : undefined;
}

function urlOf(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof URL) return input;
  if (typeof input === 'string') return new URL(input);
  return new URL((input as Request).url);
}

/** The headers one downstream request carries, and what is audited about them. */
export interface OutboundDelegation {
  headers: Record<string, string>;
  attachment: OutboundAttachment;
}

/**
 * Builds the §8.1 headers for a request to `target` on behalf of `context`
 * (what `withDelegation` attaches). Throws `RedelegationError` when the
 * service's own hop does not attenuate the chain.
 */
export async function buildOutboundDelegation(target: URL, context: DelegationContext, options: Omit<WithDelegationOptions, 'context' | 'audit' | 'onAuditError'>): Promise<OutboundDelegation> {
  const now = (options.clock ?? Date.now)();
  let chain: readonly unknown[] = context.chain;
  let redelegated = false;
  if (options.redelegate !== undefined) {
    const own = await options.redelegate(context, target);
    const hops = own === undefined || own === null ? [] : Array.isArray(own) ? own : [own];
    if (hops.length > 0) {
      chain = [...context.chain, ...hops];
      redelegated = true;
      const rules = kyaos.verifier.evaluateDelegationChainRules(chain, { now, maxChainLength: options.maxChainLength ?? kyaos.verifier.MAX_DELEGATION_DEPTH });
      if (!rules.ok) throw new RedelegationError(rules.reasons);
      const issuers = hops.map((hop) => (isRecord(hop) ? hop['issuer'] : undefined));
      if (issuers.some((issuer) => issuer !== options.signer.did)) throw new RedelegationError(['a re-delegated hop must be issued by this service']);
    }
  }
  const responsibleParty = rootIssuer(chain);
  const delegationId = delegationIdOf(chain);
  if (responsibleParty === undefined || delegationId === undefined) throw new DelegationContextMissingError('withDelegation: the delegation context holds no chain to forward');
  const chainString = buildChainString(chain);
  const allowed = new Set(leafActions(chain));
  let scopes = context.scopes.filter((scope) => allowed.has(scope));
  if (options.scopes !== undefined) {
    const narrowed = new Set(typeof options.scopes === 'function' ? options.scopes(context, target) : options.scopes);
    scopes = scopes.filter((scope) => narrowed.has(scope));
  }
  const audience = target.host;
  const jti = `urn:uuid:${randomUUID()}`;
  const proof = await mintDelegationProofJwt(
    { sub: responsibleParty, aud: audience, delegation_id: delegationId, delegation_chain: chainString, scope: scopes, jti, now },
    options.signer,
  );
  const headers: Record<string, string> = {
    [DELEGATION_HEADERS.credential]: encodeDelegationCredential(chain),
    [DELEGATION_HEADERS.proof]: proof,
    [DELEGATION_HEADERS.agentDid]: context.agentDid,
    ...(context.sessionId === undefined ? {} : { [DELEGATION_HEADERS.sessionId]: context.sessionId }),
    ...(options.advisoryHeaders === true ? { [DELEGATION_HEADERS.chain]: chainString, [DELEGATION_HEADERS.grantedScopes]: scopes.join(',') } : {}),
  };
  return {
    headers,
    attachment: {
      timestamp: new Date(now).toISOString(),
      audience,
      chainString,
      chain,
      delegationId,
      agentDid: context.agentDid,
      responsibleParty,
      forwarder: options.signer.did,
      jti,
      scopes,
      redelegated,
      ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
    },
  };
}

/**
 * A `fetch` that forwards the current delegation on every request (story
 * L3-D point 1). Headers the caller set are kept, except the KYA-OS ones,
 * which are this helper's alone.
 */
export function withDelegation(fetchImpl: typeof fetch, options: WithDelegationOptions): typeof fetch {
  const contextOf = (): DelegationContext | undefined =>
    options.context === undefined ? currentDelegation() : typeof options.context === 'function' ? options.context() : options.context;
  return async (input, init) => {
    const context = contextOf();
    if (context === undefined) throw new DelegationContextMissingError();
    const target = urlOf(input);
    const { headers: delegation, attachment } = await buildOutboundDelegation(target, context, options);
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    for (const name of Object.values(DELEGATION_HEADERS)) headers.delete(name);
    for (const [name, value] of Object.entries(delegation)) headers.set(name, value);
    if (options.audit !== undefined) {
      try {
        await options.audit(attachment);
      } catch (error) {
        options.onAuditError?.(error);
      }
    }
    return fetchImpl(input, { ...init, headers });
  };
}
