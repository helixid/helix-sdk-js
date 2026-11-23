// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The local verifier (KYA-OS story F-2): one pure module that verifies one
 * shape, a per-request holder-of-key proof (`org.kya-os/proof.v1`,
 * SPEC-ENTITY-CARD.md §8) plus the delegation chain the request carries
 * (§10.5, SPEC.md §6.10), from the presented artifacts and what its seams
 * answer, and nothing else:
 *
 * - `resolveDid` and `resolveDidKeys`: public DID documents;
 * - `fetchStatusList`: public status lists, already decoded (each list's
 *   proof verified first, story L3-C);
 * - `checkRevocation`: one credential's `{revoked, fresh}`, cached and
 *   keeper-aware (story L3-C); default one over `fetchStatusList`;
 * - `resolveCard`: the agent's Entity Card, for its attestations;
 * - `nonceStore`: the local replay store;
 * - `clock`: the time, injected, so the module holds no global clock;
 * - `trustedIssuers`: local config, `'*'` unless a list is set.
 *
 * No network, no database, no global state inside. A missing seam fails
 * closed with its own reason code; it never skips the check. Cross-border
 * rule (stories rule 4): a credential issued by any Helix deployment
 * verifies here from these inputs alone, and the module never asks a Helix
 * database whether it has seen one.
 *
 * Order: seams and options; the carried chain's length, bounded before any
 * entry is parsed; the request proof in the exact §11.2 order
 * (`verifyRequestProof`, story C-C: schema, `kid`⇄`did`, the signing key,
 * its DID membership (RFC 7638), audience, `requestHash`, window, nonce,
 * detached JWS, `cnf` fusion); the chain's schema, attenuation, continuity
 * and windows; the leaf join `leafInvoker === proof.did`; trusted roots; the
 * invoked action; each hop's `eddsa-jcs-2022` proof by its own issuer; each
 * credential's status, root to leaf, stopping at the first revoked hop
 * (story L3-C); the card, its `responsibleParty === issuer(rootVC)`
 * gate and its attestations; the level per §9.4 and the demotion matrix. A
 * carried chain that fails is refused; nothing is ever looked up in its
 * place.
 *
 * A call may carry a chain and no proof (story C-C) when the caller allows
 * it (`requireProof: false`): the chain is verified the same way, the agent
 * is the leaf delegate, unproven, and the proof floor does not hold, so the
 * level is at most L2. The middleware's minimum-level check decides whether
 * that is enough for the tool.
 *
 * Ported to helix-sdk-py as `helix_sdk.verifier`, same seams, same codes,
 * same results, proven by the fixtures helix-core generates with this module.
 */

import type { DidResolver, Ed25519PublicJwk } from '../jws.js';
import { checkCapabilities, deriveConformanceLevel, type CapabilityCheck, type CardCapability, type ConformanceLevel } from './attestation.js';
import { validateEntityCard, type EntityCard } from './card.js';
import { ReasonCodes, type ReasonCode } from './codes.js';
import {
  MAX_DELEGATION_DEPTH,
  deriveEffectiveScopes,
  evaluateDelegationChainRules,
  isTrustedIssuer,
  type SignedDelegationHop,
  type TrustedIssuers,
} from './credentials.js';
import { verifyDataIntegrity } from './data-integrity.js';
import type { ProofRequest } from './request-proof.js';
import { checkChainRevocation, revocationCheckerOf, type RevocationChecker, type RevocationSubject, type RevocationVerdict } from './revocation.js';
import type { FetchStatusList, StatusListRead } from './status.js';
import { verifyRequestProof, type NonceStoreSeam, type ProofAssurance } from './verify-request-proof.js';

/** What the verifier is given: the proof, the chain the request carried, the request, and the card when the caller already holds it. */
export interface VerifierInput {
  /** The `org.kya-os/proof.v1` object, as `_meta["org.kya-os/request-proof"]` (or the legacy key) carried it. */
  proof: unknown;
  /** The carried chain, `_meta["org.kya-os/delegation-chain"]`: root to leaf. Absent when the request carried none. */
  chain?: unknown;
  /** The JSON-RPC request the proof binds (`{method, params}`), as received. */
  request?: ProofRequest | undefined;
  /** The agent's Entity Card, when the caller already holds it; else the `resolveCard` seam is asked. */
  card?: unknown;
}

export interface VerifierSeams {
  /** The DID document of a DID, over HTTPS or offline; `null` when there is none. */
  resolveDid?: DidResolver | undefined;
  /** Every Ed25519 key a DID publishes: the RFC 7638 membership proof of the signing key. */
  resolveDidKeys?: ((did: string) => Promise<Ed25519PublicJwk[]> | Ed25519PublicJwk[]) | undefined;
  /** A status list, decoded, by its URL. */
  fetchStatusList?: FetchStatusList | undefined;
  /**
   * The revocation check of one credential (story L3-C): `{revoked, fresh}`,
   * fail-closed, cached, keeper-aware. Default: one built over
   * `fetchStatusList` with no cache, every read live.
   */
  checkRevocation?: RevocationChecker | undefined;
  /** The Entity Card of an agent DID, or `undefined` when it publishes none. */
  resolveCard?: ((did: string) => Promise<unknown>) | undefined;
  nonceStore?: NonceStoreSeam | undefined;
  /** Milliseconds since the epoch. */
  clock?: (() => number) | undefined;
  /** `'*'` (default) trusts every attestation issuer; a list trusts those DIDs (stories rule 9). */
  trustedIssuers?: TrustedIssuers | undefined;
}

export interface VerifierOptions {
  /** This verifier's own DID: the proof's `audience` must equal it. */
  expectedAudience: string;
  /** The longest carried chain parsed; default 10. */
  maxChainLength?: number | undefined;
  /** Clock skew, in seconds, on the proof's window; default 5. */
  skewSeconds?: number | undefined;
  /** The longest proof lifetime accepted, in seconds; default 60. */
  maxTtlSeconds?: number | undefined;
  /** Clock tolerance on credential and status-list windows, in ms; default 120,000. */
  maxClockSkewMs?: number | undefined;
  /** The resource this verifier gates: the chain's root `invocationTarget` must equal it. */
  resource?: string | undefined;
  /** When set, the root hop's issuer must be this DID. */
  resourceOwner?: string | undefined;
  /** When set, the root hop's issuer must be one of these DIDs (§11.4 step 4). */
  trustedRootIssuers?: readonly string[] | undefined;
  /** The scopes this service offers; `effectiveScopes` is intersected with it. Default: the leaf's own `allowedAction`. */
  catalog?: readonly string[] | undefined;
  /** The invoked action, which the leaf must allow (§11.4 step 6). */
  action?: string | undefined;
  /** The access token's RFC 9449 `cnf.jkt`, for the L3 fusion; absent means L3-minus. */
  tokenCnfJkt?: string | undefined;
  /**
   * Default true: a call without a request proof is refused `proof_missing`.
   * False (story C-C): a call carrying a chain and no proof is verified on
   * the chain alone, with the proof floor unmet, so its level is at most L2.
   */
  requireProof?: boolean | undefined;
  /**
   * Read every status list live, past the status cache (story L3-C with
   * C-C's levels): a call to a tool whose minimum Card level is L3 needs
   * fresh revocation status, which a cached read is not. Default false: the
   * cache serves, and a cached read is not fresh, so at most L2.
   */
  liveStatus?: boolean | undefined;
}

export interface ChainSummary {
  depth: number;
  responsibleParty?: string | undefined;
  leafInvoker?: string | undefined;
  invocationTarget?: string | undefined;
  /** The leaf's `allowedAction` when the chain verified; empty otherwise. */
  allowedAction: string[];
  /** True when every hop's status was read live. */
  fresh: boolean;
}

export interface VerifierResult {
  ok: boolean;
  /** Recomputed per §9.4; `L1` whenever the call is refused. */
  level: ConformanceLevel;
  /** Attestations ∩ leaf `allowedAction` ∩ catalog (story F-1 point 4); empty when refused. */
  effectiveScopes: string[];
  /** Reason codes, in the order the checks ran; empty iff `ok`. */
  reasons: ReasonCode[];
  /** One message per reason, for logs; never compared across languages. */
  messages: string[];
  chainSummary: ChainSummary;
  /** The accountable principal, once its proof verified. */
  proofDid?: string | undefined;
  /**
   * Who the call is for: the proof's DID, or, on a call verified without a
   * proof, the chain's leaf delegate (unproven). Set on success.
   */
  agentDid?: string | undefined;
  /** True when a request proof verified: the §9.4 proof floor. */
  proofFloor: boolean;
  /** `L3` on a full `cnf` fusion, `L3-minus` without a token `cnf`; present once the proof verified. */
  proofAssurance?: ProofAssurance | undefined;
  /** The card's capabilities sorted; both empty when no card was presented. */
  capabilities: CapabilityCheck;
  /** True when every status the level relies on was read live. */
  fresh: boolean;
  /** Non-fatal diagnostics (`cnf_present_but_token_unfused`). */
  warnings: string[];
}

/** The revocation seam in force: the one given, else one over `fetchStatusList`, else none. */
function revocationSeam(seams: VerifierSeams, options: VerifierOptions): RevocationChecker | undefined {
  if (typeof seams.checkRevocation === 'function') return seams.checkRevocation;
  return typeof seams.fetchStatusList === 'function' ? revocationCheckerOf(seams.fetchStatusList, options.maxClockSkewMs) : undefined;
}

/** The scopes a request touches, which pick the status cache TTL: the invoked action, else what the leaf allows. */
function requestScopes(options: VerifierOptions, allowedAction: readonly string[]): readonly string[] {
  return options.action === undefined ? allowedAction : [options.action];
}

const NO_CHAIN: ChainSummary = { depth: 0, allowedAction: [], fresh: true };

class Refusals {
  readonly reasons: ReasonCode[] = [];
  readonly messages: string[] = [];
  add(code: ReasonCode, message: string): void {
    this.reasons.push(code);
    this.messages.push(message);
  }
  get any(): boolean {
    return this.reasons.length > 0;
  }
}

function refused(refusals: Refusals, chainSummary: ChainSummary, extra: Partial<VerifierResult> = {}): VerifierResult {
  return {
    ok: false,
    level: 'L1',
    effectiveScopes: [],
    reasons: [...refusals.reasons],
    messages: [...refusals.messages],
    chainSummary: { ...chainSummary, allowedAction: [], fresh: false },
    capabilities: { verified: [], unverified: [] },
    fresh: false,
    warnings: [],
    proofFloor: false,
    ...extra,
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The seams a verification cannot run without, each reported when absent, so a misconfiguration never passes as a check skipped. */
function missingSeams(seams: VerifierSeams, refusals: Refusals): void {
  if (typeof seams.clock !== 'function') refusals.add(ReasonCodes.CLOCK_SEAM_MISSING, 'no clock seam: the verifier holds no clock of its own');
  if (typeof seams.resolveDid !== 'function') refusals.add(ReasonCodes.DID_RESOLVER_MISSING, 'no resolveDid seam: the signing key cannot be read');
  if (typeof seams.resolveDidKeys !== 'function') {
    refusals.add(ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE, 'no resolveDidKeys seam: the key cannot be shown to belong to the DID');
  }
  if (seams.nonceStore === undefined || typeof seams.nonceStore.insert !== 'function') {
    refusals.add(ReasonCodes.NONCE_SEAM_MISSING, 'no nonceStore seam: there is no replay defense to run');
  }
}

/**
 * Verifies `input` with `seams` under `options`. Never throws for a bad
 * input: every refusal is a reason code in the result. Throws only for a
 * seam that is not a function where one is given, which is a programming
 * error, not a presentation.
 */
export async function verify(input: VerifierInput, seams: VerifierSeams, options: VerifierOptions): Promise<VerifierResult> {
  const refusals = new Refusals();

  // 1. Seams and options, before anything is read.
  missingSeams(seams, refusals);
  const maxChainLength = options.maxChainLength ?? MAX_DELEGATION_DEPTH;
  if (!Number.isInteger(maxChainLength) || maxChainLength < 1) {
    refusals.add(ReasonCodes.CONFIGURATION_ERROR, 'maxChainLength must be a positive integer');
  }
  if (typeof options.expectedAudience !== 'string' || !options.expectedAudience.startsWith('did:')) {
    refusals.add(ReasonCodes.CONFIGURATION_ERROR, 'expectedAudience must be this verifier\'s DID');
  }
  if (refusals.any) return refused(refusals, NO_CHAIN);
  const now = seams.clock!();

  // 2. The carried chain's length, bounded before any entry is parsed (§10.5 rule 2).
  let hops: unknown[] | undefined;
  if (input.chain !== undefined) {
    if (!Array.isArray(input.chain) || input.chain.length === 0) {
      refusals.add(ReasonCodes.CHAIN_INVALID, 'the carried chain is not a non-empty array');
      return refused(refusals, NO_CHAIN);
    }
    if (input.chain.length > maxChainLength) {
      refusals.add(ReasonCodes.CHAIN_TOO_LONG, `the carried chain has ${input.chain.length} hops; at most ${maxChainLength} are read`);
      return refused(refusals, { depth: input.chain.length, allowedAction: [], fresh: false });
    }
    hops = input.chain;
  }
  const depth = hops?.length ?? 0;
  const noChain: ChainSummary = { depth, allowedAction: [], fresh: false };

  // 3. The request proof, in the exact §11.2 order (story C-C). A call that may go without one
  //    (`requireProof: false`) and carries a chain is verified on the chain alone, without the proof floor.
  const requireProof = options.requireProof ?? true;
  const proofAbsent = input.proof === undefined || input.proof === null;
  let proved: Partial<VerifierResult> = {};
  let proofDid: string | undefined;
  if (!proofAbsent || requireProof || hops === undefined) {
    const verdict = await verifyRequestProof(input.proof, input.request, seams, {
      expectedAudience: options.expectedAudience,
      skewSeconds: options.skewSeconds,
      maxTtlSeconds: options.maxTtlSeconds,
      tokenCnfJkt: options.tokenCnfJkt,
    });
    if (!verdict.ok) {
      verdict.reasons.forEach((code, index) => refusals.add(code, verdict.messages[index]!));
      return refused(refusals, noChain);
    }
    proofDid = verdict.did!;
    // Every binding held: from here a refusal names the principal it refused.
    proved = { proofDid, proofAssurance: verdict.assurance, warnings: verdict.warnings, proofFloor: true };
  }

  // Lists read live for this verification: a second credential on the same list stays a live read.
  const reads = new Map<string, StatusListRead>();

  // 6. The chain: local rules first (§11.4 steps 1 to 4, 6), then each hop's proof (step 5), then status (step 7).
  let chainSummary: ChainSummary = { ...NO_CHAIN };
  let leafAllowedAction: string[] = [];
  let chainFresh = true;
  if (hops !== undefined) {
    const evaluation = evaluateDelegationChainRules(hops, {
      now,
      maxChainLength,
      ...(options.resource === undefined ? {} : { resource: options.resource }),
      ...(options.resourceOwner === undefined ? {} : { resourceOwner: options.resourceOwner }),
      ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
    });
    chainSummary = {
      depth: evaluation.depth,
      responsibleParty: evaluation.responsibleParty,
      leafInvoker: evaluation.leafInvoker,
      invocationTarget: evaluation.invocationTarget,
      allowedAction: evaluation.allowedAction,
      fresh: false,
    };
    if (!evaluation.ok) {
      for (const rule of evaluation.broken) refusals.add(rule.code as ReasonCode, rule.reason);
      return refused(refusals, chainSummary, proved);
    }
    if (proofDid !== undefined && evaluation.leafInvoker !== proofDid) {
      refusals.add(ReasonCodes.LEAF_INVOKER_MISMATCH, `the leaf delegate ${String(evaluation.leafInvoker)} is not the proof's did ${proofDid}`);
      return refused(refusals, chainSummary, proved);
    }
    const chain = hops as SignedDelegationHop[];
    const root = chain[0]!;
    if (options.trustedRootIssuers !== undefined && !options.trustedRootIssuers.includes(root.issuer)) {
      refusals.add(ReasonCodes.ISSUER_UNTRUSTED, `root issuer ${root.issuer} is not a trusted root issuer`);
      return refused(refusals, chainSummary, proved);
    }
    if (options.action !== undefined && !evaluation.allowedAction.includes(options.action)) {
      refusals.add(ReasonCodes.ACTION_NOT_DELEGATED, `the leaf does not allow ${options.action}`);
      return refused(refusals, chainSummary, proved);
    }
    for (let index = 0; index < chain.length; index += 1) {
      const verdict = await verifyDataIntegrity(chain[index] as unknown as Record<string, unknown>, seams.resolveDid!);
      if (!verdict.ok) {
        refusals.add(ReasonCodes.HOP_PROOF_INVALID, `hop ${index}: ${verdict.reason}: ${verdict.message}`);
        return refused(refusals, chainSummary, proved);
      }
    }
    const checker = revocationSeam(seams, options);
    if (checker === undefined) {
      refusals.add(ReasonCodes.STATUS_SEAM_MISSING, 'no fetchStatusList seam: the hops\' status cannot be read');
      return refused(refusals, chainSummary, proved);
    }
    // Root to leaf, stopping at the first revoked or unresolvable hop (§6.5 cascade, story L3-C point 4).
    const revocation = await checkChainRevocation(chain, checker, {
      now,
      scopes: requestScopes(options, evaluation.allowedAction),
      reads,
      ...(options.liveStatus === true ? { live: true } : {}),
    });
    if (revocation.revoked) {
      refusals.add(revocation.code ?? ReasonCodes.STATUS_REVOKED, `hop ${String(revocation.index)}: ${revocation.message ?? 'revoked'}`);
      return refused(refusals, chainSummary, proved);
    }
    chainFresh = revocation.fresh;
    chainSummary = { ...chainSummary, fresh: chainFresh };
    leafAllowedAction = evaluation.allowedAction;
  }

  // 7. The card: its shape, the responsibleParty gate (§10.2) and its attestations (§9.2).
  //    Without a proof the card is the leaf delegate's, which the chain names but nothing proves.
  const agentDid = proofDid ?? chainSummary.leafInvoker!;
  let card: EntityCard | undefined;
  let cardValue: unknown = input.card;
  if (cardValue === undefined && typeof seams.resolveCard === 'function') {
    try {
      cardValue = await seams.resolveCard(agentDid);
    } catch (error) {
      refusals.add(ReasonCodes.CARD_UNRESOLVABLE, `the card of ${agentDid} could not be read: ${(error as Error).message}`);
      return refused(refusals, chainSummary, proved);
    }
  }
  if (cardValue !== undefined && cardValue !== null) {
    const problems = validateEntityCard(cardValue);
    if (problems.length > 0) {
      refusals.add(ReasonCodes.CARD_MALFORMED, problems.join('; '));
      return refused(refusals, chainSummary, proved);
    }
    card = cardValue as EntityCard;
    if (card.id !== agentDid) {
      refusals.add(ReasonCodes.CARD_SUBJECT_MISMATCH, `the card is ${card.id}'s, not ${agentDid}'s`);
      return refused(refusals, chainSummary, proved);
    }
    if (hops !== undefined && card.responsibleParty !== undefined && card.responsibleParty !== chainSummary.responsibleParty) {
      refusals.add(ReasonCodes.ROOT_NOT_RESPONSIBLE_PARTY, `the root issuer ${String(chainSummary.responsibleParty)} is not the card's responsibleParty ${card.responsibleParty}`);
      return refused(refusals, chainSummary, proved);
    }
  }
  // The card's own revocation entry (SPEC-ENTITY-CARD §10.3; Cleanup, Harish's pick A): a revoked
  // agent is refused. The list's keeper is the card's DID unless the configuration binds the URL
  // (statusListIssuers) to another issuer, as a Helix card's list is bound to Helix.
  let cardFresh = true;
  if (card?.revocation !== undefined) {
    const checker = revocationSeam(seams, options);
    if (checker === undefined) {
      refusals.add(ReasonCodes.STATUS_SEAM_MISSING, "no fetchStatusList seam: the card's revocation entry cannot be read");
      return refused(refusals, chainSummary, proved);
    }
    const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', ...card.revocation } as RevocationSubject['credentialStatus'];
    let verdict: RevocationVerdict;
    try {
      verdict = await checker({ issuer: card.id, credentialStatus: entry }, {
        now,
        scopes: requestScopes(options, leafAllowedAction),
        reads,
        ...(options.liveStatus === true ? { live: true } : {}),
      });
    } catch (error) {
      verdict = { revoked: true, fresh: false, code: ReasonCodes.STATUS_UNAVAILABLE, message: `the revocation check failed: ${(error as Error).message}` };
    }
    if (verdict.revoked) {
      refusals.add(verdict.code ?? ReasonCodes.STATUS_REVOKED, `the card's revocation entry: ${verdict.message ?? 'revoked'}`);
      return refused(refusals, chainSummary, proved);
    }
    cardFresh = verdict.fresh;
  }
  let capabilities: CapabilityCheck = { verified: [], unverified: [] };
  let capabilitiesFresh = true;
  if (card !== undefined && Array.isArray(card.capabilities) && card.capabilities.length > 0) {
    const check = await checkCapabilities(card.capabilities as CardCapability[], seams.resolveDid!, {
      subjectDid: agentDid,
      trustedIssuers: seams.trustedIssuers ?? '*',
      now,
      maxClockSkewMs: options.maxClockSkewMs,
      fetchStatusList: seams.fetchStatusList,
      checkRevocation: revocationSeam(seams, options),
      scopes: requestScopes(options, leafAllowedAction),
      reads,
      ...(options.liveStatus === true ? { liveStatus: true } : {}),
    });
    capabilities = { verified: check.verified, unverified: check.unverified };
    capabilitiesFresh = check.fresh;
  }

  // 8. Authority and level (story F-1 point 4; §9.4): the proof floor holds only when a proof verified.
  const effectiveScopes = deriveEffectiveScopes(capabilities.verified, leafAllowedAction, options.catalog ?? leafAllowedAction);
  const fresh = chainFresh && capabilitiesFresh && cardFresh;
  const proofFloor = proofDid !== undefined;
  const level = deriveConformanceLevel(capabilities, proofFloor, fresh);
  return {
    ok: true,
    level,
    effectiveScopes,
    reasons: [],
    messages: [],
    chainSummary,
    ...(proofDid === undefined ? {} : { proofDid, proofAssurance: proved.proofAssurance }),
    agentDid,
    proofFloor,
    capabilities,
    fresh,
    warnings: proved.warnings ?? [],
  };
}

/** Whether an issuer is trusted under the seam's setting; exported for hosts that list issuers. */
export { isTrustedIssuer };
/** Whether `value` is a plain object, for hosts reading `_meta`. */
export { isRecord as isPlainObject };
