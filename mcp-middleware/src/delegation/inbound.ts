// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Verifying a downstream call (KYA-OS story L3-D point 5, SPEC.md §8.1,
 * L3.27): the receiving service derives everything from the two signed
 * artifacts, the chain in `KYA-OS-Delegation-Credential` and the forwarding
 * service's `KYA-OS-Delegation-Proof`, through its own local verifier (story
 * F-2), with no secret shared with the forwarder:
 *
 * 1. the three authoritative headers, once each; the chain decoded and
 *    bounded (`maxChainLength`) before any hop is read;
 * 2. the proof JWT: EdDSA under the forwarder's (`iss`) assertion key,
 *    `aud` this service's host, `iat`/`exp` held (60 s at most);
 * 3. the proof against the chain: `sub` is the root hop's issuer (the
 *    Responsible Party), `delegation_id` the leaf capability,
 *    `delegation_chain` the chain's own string;
 * 4. who may forward what: the chain's `invocationTarget` is this service's
 *    resource, or the forwarder itself when this service accepts forwards
 *    from it (`forwarders`, default any); the forwarder is bound to the chain (it is the
 *    target the agent was granted, or the leaf delegate holding it); and
 *    `KYA-OS-Agent-DID` is the agent the chain names (the leaf delegate, or
 *    who delegated to the forwarder), the DID whose signature the forwarder
 *    verified;
 * 5. the `jti`, once, in the replay store (under the forwarder);
 * 6. the chain root to leaf with the local verifier (every hop's proof, the
 *    attenuation and continuity rules, every status), on the chain alone:
 *    a forwarded call carries no request proof of the agent's, so its level
 *    is at most L2. The verdict is cached by credential id
 *    (`VerificationCache`), except for a tool whose minimum level is L3,
 *    whose lists are read live (story L3-C, P1);
 * 7. scopes: the verifier's (attestations ∩ leaf `allowedAction` ∩ catalog)
 *    narrowed by the proof's `scope`, never widened by it.
 *
 * `KYA-OS-Delegation-Chain` and `KYA-OS-Granted-Scopes` never enter the
 * decision: each is returned when it agrees with the signed artifacts and
 * dropped (named in `advisory.dropped`) when it does not.
 */

import type { HeadersLike, kyaos } from '@helixid/sdk-js';
import type { LocalVerifier } from '../verify-locally.js';
import { DELEGATION_HEADERS, decodeDelegationCredential, headerValues } from './headers.js';
import { buildChainString, delegationIdOf, scopeList, verifyDelegationProofJwt, type DelegationProofClaims } from './proof-jwt.js';
import type { VerificationCache } from './verification-cache.js';

export const InboundDelegationReasons = {
  HEADERS_MISSING: 'delegation_headers_missing',
  HEADER_DUPLICATED: 'delegation_header_duplicated',
  CREDENTIAL_MALFORMED: 'delegation_credential_malformed',
  CHAIN_TOO_LONG: 'chain_too_long',
  PROOF_REPLAYED: 'delegation_proof_replayed',
  SUBJECT_MISMATCH: 'delegation_subject_mismatch',
  ID_MISMATCH: 'delegation_id_mismatch',
  CHAIN_MISMATCH: 'delegation_chain_mismatch',
  TARGET_NOT_ACCEPTED: 'delegation_target_not_accepted',
  FORWARDER_UNBOUND: 'delegation_forwarder_unbound',
  AGENT_DID_MISMATCH: 'agent_did_mismatch',
} as const;

export interface InboundDelegationOptions {
  /** This service's local verifier: its seams resolve DIDs, read status lists and hold the replay store. */
  verifier: LocalVerifier;
  /** This service's host or hosts, as forwarders name them in `aud`; default the host of a did:web `serviceDid`. */
  audience?: string | readonly string[] | undefined;
  /** The resource chains must target when not forwarded; default the verifier's `serviceDid`. */
  resource?: string | undefined;
  /**
   * The forwarding services whose own resource this service honours as a
   * chain's target (authority the agent granted at the forwarder, carried
   * by it): `'*'` any (the default), or a list of DIDs; `[]` accepts only
   * chains that target this service. The forwarder is always bound to the
   * chain: it must be the chain's target or its leaf delegate.
   */
  forwarders?: '*' | readonly string[] | undefined;
  /** Cached chain verdicts; default none (every chain verified). */
  cache?: VerificationCache | undefined;
  /** Read every status live, past both caches: set for a tool whose minimum level is L3. */
  liveStatus?: boolean | undefined;
  /** Clock skew on the proof's window, seconds; default 5. */
  skewSeconds?: number | undefined;
  /** The longest chain read; default 10. */
  maxChainLength?: number | undefined;
}

export interface AdvisoryHeaders {
  /** `KYA-OS-Delegation-Chain`, when it agrees with the credential. */
  chain?: string | undefined;
  /** `KYA-OS-Granted-Scopes`, when it agrees with the proof's `scope`. */
  grantedScopes?: string[] | undefined;
  /** The advisory headers that disagreed with the signed artifacts and were dropped. */
  dropped: Array<'chain' | 'grantedScopes'>;
}

export interface InboundDelegationResult {
  ok: boolean;
  reasons: string[];
  messages: string[];
  /** The agent the chain names, as `KYA-OS-Agent-DID` gave it; set once that check held. */
  agentDid?: string | undefined;
  /** The forwarding service: the proof's `iss`, once its signature held. */
  forwarder?: string | undefined;
  /** The root hop's issuer. */
  responsibleParty?: string | undefined;
  delegationId?: string | undefined;
  chainString?: string | undefined;
  /** The chain, root first, once decoded. */
  chain?: unknown[] | undefined;
  /** The chain's `invocationTarget`. */
  invocationTarget?: string | undefined;
  /** What the caller may do here; empty when refused. */
  effectiveScopes: string[];
  /** At most L2: a forwarded call carries no request proof of the agent's. `L1` when refused. */
  level: kyaos.verifier.ConformanceLevel;
  /** True when every status was read live for this call (false on a cached verdict). */
  fresh: boolean;
  /** True when the chain's verdict came from the verification cache. */
  cached: boolean;
  /** `KYA-OS-Session-Id`, an anchor only. */
  sessionId?: string | undefined;
  advisory: AdvisoryHeaders;
  /** The proof's claims, once verified. */
  claims?: DelegationProofClaims | undefined;
  /** The local verifier's result on the chain, when it ran or was cached. */
  verification?: kyaos.verifier.VerifierResult | undefined;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The host a did:web DID names (`did:web:127.0.0.1%3A3000:services:ab` → `127.0.0.1:3000`), or undefined. */
export function hostOfDidWeb(did: string): string | undefined {
  if (!did.startsWith('did:web:')) return undefined;
  const segment = did.slice('did:web:'.length).split(':')[0];
  if (!segment) return undefined;
  try {
    return decodeURIComponent(segment).toLowerCase();
  } catch {
    return undefined;
  }
}

function subjectOf(hop: unknown): Record<string, unknown> {
  return isRecord(hop) && isRecord(hop['credentialSubject']) ? hop['credentialSubject'] : {};
}

function invokerOfHop(hop: unknown): string | undefined {
  const subject = subjectOf(hop);
  const invoker = subject['invoker'] ?? subject['controller'];
  return typeof invoker === 'string' ? invoker : undefined;
}

/**
 * The agent a chain names for `forwarder`: its leaf delegate, unless the
 * forwarder holds the leaf itself (it re-delegated, or was delegated to),
 * in which case the agent is whoever first delegated to the forwarder (the
 * forwarder itself when the root hop names it).
 */
export function agentOfChain(chain: readonly unknown[], forwarder: string): string | undefined {
  const leafInvoker = invokerOfHop(chain[chain.length - 1]);
  if (leafInvoker !== forwarder) return leafInvoker;
  const first = chain.findIndex((hop) => invokerOfHop(hop) === forwarder);
  if (first <= 0) return forwarder;
  const hop = chain[first];
  return isRecord(hop) && typeof hop['issuer'] === 'string' ? hop['issuer'] : undefined;
}

class Refusal {
  readonly reasons: string[] = [];
  readonly messages: string[] = [];
}

/** Verifies the delegation headers of one downstream call. Never throws for a bad request: every refusal is a reason. */
export async function verifyInboundDelegationHeaders(headers: HeadersLike | undefined, options: InboundDelegationOptions): Promise<InboundDelegationResult> {
  const verifier = options.verifier;
  const advisory: AdvisoryHeaders = { dropped: [] };
  let partial: Partial<InboundDelegationResult> = {};
  const refuse = (reason: string, message: string): InboundDelegationResult => {
    const refusal = new Refusal();
    refusal.reasons.push(reason);
    refusal.messages.push(message);
    return { ok: false, reasons: refusal.reasons, messages: refusal.messages, effectiveScopes: [], level: 'L1', fresh: false, cached: false, advisory, ...partial };
  };

  // 1. The authoritative headers, once each.
  const read = (name: string): string[] => headerValues(headers, name);
  const credentialValues = read(DELEGATION_HEADERS.credential);
  const proofValues = read(DELEGATION_HEADERS.proof);
  const agentValues = read(DELEGATION_HEADERS.agentDid);
  for (const [name, values] of [
    [DELEGATION_HEADERS.credential, credentialValues],
    [DELEGATION_HEADERS.proof, proofValues],
    [DELEGATION_HEADERS.agentDid, agentValues],
  ] as const) {
    if (values.length === 0) return refuse(InboundDelegationReasons.HEADERS_MISSING, `${name} is missing`);
    if (values.length > 1) return refuse(InboundDelegationReasons.HEADER_DUPLICATED, `${name} is sent more than once`);
  }
  const sessionId = read(DELEGATION_HEADERS.sessionId)[0];
  if (sessionId !== undefined) partial = { ...partial, sessionId };
  const chain = decodeDelegationCredential(credentialValues[0]!);
  if (chain === undefined) return refuse(InboundDelegationReasons.CREDENTIAL_MALFORMED, `${DELEGATION_HEADERS.credential} is not base64url JSON of a chain`);
  const maxChainLength = options.maxChainLength ?? 10;
  if (chain.length > maxChainLength) return refuse(InboundDelegationReasons.CHAIN_TOO_LONG, `the chain has ${chain.length} hops; at most ${maxChainLength} are read`);
  const chainString = buildChainString(chain);
  const delegationId = delegationIdOf(chain);
  const root = chain[0];
  const responsibleParty = isRecord(root) && typeof root['issuer'] === 'string' ? root['issuer'] : undefined;
  const target = subjectOf(chain[chain.length - 1])['invocationTarget'];
  const invocationTarget = typeof target === 'string' ? target : undefined;
  partial = { ...partial, chain, chainString, ...(delegationId === undefined ? {} : { delegationId }), ...(responsibleParty === undefined ? {} : { responsibleParty }), ...(invocationTarget === undefined ? {} : { invocationTarget }) };

  // 2. The proof JWT: signature by the forwarder, audience, window.
  const now = verifier.seams.clock!();
  const audience = options.audience ?? hostOfDidWeb(verifier.serviceDid);
  if (audience === undefined || (typeof audience !== 'string' && audience.length === 0)) {
    return refuse('configuration_error', 'verifyInboundDelegationHeaders: no audience (this service\'s host) is configured');
  }
  const proof = await verifyDelegationProofJwt(proofValues[0]!, { resolveDid: verifier.seams.resolveDid!, audience, now, skewSeconds: options.skewSeconds });
  if (!proof.ok) {
    if (proof.iss !== undefined) partial = { ...partial, forwarder: proof.iss };
    return refuse(proof.reason, proof.message);
  }
  const claims = proof.claims;
  const forwarder = claims.iss;
  partial = { ...partial, forwarder, claims };

  // 3. The proof against the chain.
  if (responsibleParty === undefined || claims.sub !== responsibleParty) {
    return refuse(InboundDelegationReasons.SUBJECT_MISMATCH, `sub ${claims.sub} is not the chain's root issuer ${String(responsibleParty)}`);
  }
  if (delegationId === undefined || claims.delegation_id !== delegationId) {
    return refuse(InboundDelegationReasons.ID_MISMATCH, `delegation_id ${claims.delegation_id} is not the leaf capability ${String(delegationId)}`);
  }
  if (claims.delegation_chain !== chainString) {
    return refuse(InboundDelegationReasons.CHAIN_MISMATCH, 'delegation_chain is not the credential\'s chain string');
  }

  // 4. Who may forward what, and for which agent.
  const resource = options.resource ?? verifier.serviceDid;
  // Default '*' (Harish, 2026-11-23): any forwarder, for the authority granted at that forwarder; [] accepts none.
  const forwarders = options.forwarders ?? '*';
  const forwardAccepted = forwarders === '*' || forwarders.includes(forwarder);
  if (invocationTarget === undefined || (invocationTarget !== resource && !(invocationTarget === forwarder && forwardAccepted))) {
    return refuse(InboundDelegationReasons.TARGET_NOT_ACCEPTED, `the chain targets ${String(invocationTarget)}, which this service does not accept from ${forwarder}`);
  }
  const leafInvoker = invokerOfHop(chain[chain.length - 1]);
  if (forwarder !== invocationTarget && forwarder !== leafInvoker) {
    return refuse(InboundDelegationReasons.FORWARDER_UNBOUND, `${forwarder} is neither the chain's target nor its leaf delegate`);
  }
  const agentDid = agentOfChain(chain, forwarder);
  if (agentDid === undefined || agentValues[0] !== agentDid) {
    return refuse(InboundDelegationReasons.AGENT_DID_MISMATCH, `${DELEGATION_HEADERS.agentDid} ${agentValues[0]!} is not the agent the chain names, ${String(agentDid)}`);
  }
  partial = { ...partial, agentDid };

  // 5. The jti, once (the replay store, under the forwarder), until the proof could no longer be accepted.
  const skew = options.skewSeconds ?? 5;
  const fresh = await verifier.nonceStore.insert(claims.jti, forwarder, (claims.exp + skew + 1) * 1000);
  if (!fresh) return refuse(InboundDelegationReasons.PROOF_REPLAYED, `jti ${claims.jti} was already presented by ${forwarder}`);

  // 6. The chain, root to leaf, by this service's own verifier (cached unless status must be read live).
  const live = options.liveStatus === true;
  let verification = live ? undefined : options.cache?.get(chain);
  const cached = verification !== undefined;
  if (verification === undefined) {
    verification = await verifier.verify({ proof: undefined, chain }, { requireProof: false, resource: invocationTarget, ...(live ? { liveStatus: true } : {}) });
    if (verification.ok && !live) options.cache?.set(chain, verification);
  }
  partial = { ...partial, verification };
  if (!verification.ok) {
    // A refused verification always names its reasons: they are the refusal.
    return { ...refuse('chain_invalid', 'the chain was refused'), reasons: [...verification.reasons], messages: [...verification.messages] };
  }

  // 7. Scopes from the signed artifacts only; the proof's scope can narrow them, never widen them.
  const forwarded = new Set(scopeList(claims.scope));
  const effectiveScopes = verification.effectiveScopes.filter((scope) => forwarded.has(scope));

  // Advisory headers: kept when they agree, dropped when they do not; never read for the decision above.
  const advisoryChain = read(DELEGATION_HEADERS.chain);
  if (advisoryChain.length > 0) {
    if (advisoryChain.length === 1 && advisoryChain[0] === chainString) advisory.chain = chainString;
    else advisory.dropped.push('chain');
  }
  const advisoryScopes = read(DELEGATION_HEADERS.grantedScopes);
  if (advisoryScopes.length > 0) {
    const stated = advisoryScopes.length === 1 ? scopeList(advisoryScopes[0]!) : undefined;
    const signed = scopeList(claims.scope);
    if (stated !== undefined && stated.length === signed.length && stated.every((scope) => forwarded.has(scope))) advisory.grantedScopes = stated;
    else advisory.dropped.push('grantedScopes');
  }

  return {
    ok: true,
    reasons: [],
    messages: [],
    ...partial,
    agentDid,
    forwarder,
    effectiveScopes,
    level: verification.level,
    fresh: cached ? false : verification.fresh,
    cached,
    advisory,
    claims,
    verification,
  };
}
