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
 * - `fetchStatusList`: public status lists, already decoded;
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
 * Order (§11.2, §11.4, with every local check before the first network
 * read): seams and options; the carried chain's length, bounded before any
 * entry is parsed; the proof's shape, `kid`⇄`did`, audience, `requestHash`
 * and window; the signing key, its DID membership (RFC 7638) and the
 * detached JWS; the `cnf` fusion; the nonce; the chain's schema,
 * attenuation, continuity and windows; the leaf join `leafInvoker ===
 * proof.did`; trusted roots; the invoked action; each hop's
 * `eddsa-jcs-2022` proof by its own issuer; each credential's status; the
 * card, its `responsibleParty === issuer(rootVC)` gate and its attestations;
 * the level per §9.4 and the demotion matrix. A carried chain that fails is
 * refused; nothing is ever looked up in its place.
 *
 * Ported to helix-sdk-py as `helix_sdk.verifier`, same seams, same codes,
 * same results, proven by the fixtures helix-core generates with this module.
 */

import { InvalidJWSError } from '../../HelixError.js';
import { base64UrlDecodeStrict, selectAssertionMethod, verificationMethodToJwk, type DidResolver, type Ed25519PublicJwk } from '../jws.js';
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
import {
  DEFAULT_PROOF_SKEW_SECONDS,
  MAX_PROOF_TTL_SECONDS,
  didOfKid,
  jwkThumbprint,
  parseRequestProof,
  requestHashContentDigest,
  verifyDetachedJws,
  windowProblems,
  type ProofRequest,
  type RequestProof,
} from './request-proof.js';
import { checkStatusEntry, type FetchStatusList } from './status.js';

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

/** The local replay store: one atomic conditional insert, the middleware's `NonceStore` shape. */
export interface NonceStoreSeam {
  insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean>;
}

export interface VerifierSeams {
  /** The DID document of a DID, over HTTPS or offline; `null` when there is none. */
  resolveDid?: DidResolver | undefined;
  /** Every Ed25519 key a DID publishes: the RFC 7638 membership proof of the signing key. */
  resolveDidKeys?: ((did: string) => Promise<Ed25519PublicJwk[]> | Ed25519PublicJwk[]) | undefined;
  /** A status list, decoded, by its URL. */
  fetchStatusList?: FetchStatusList | undefined;
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

export type ProofAssurance = 'L3' | 'L3-minus';

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
  /** `L3` on a full `cnf` fusion, `L3-minus` without a token `cnf`; present once the proof verified. */
  proofAssurance?: ProofAssurance | undefined;
  /** The card's capabilities sorted; both empty when no card was presented. */
  capabilities: CapabilityCheck;
  /** True when every status the level relies on was read live. */
  fresh: boolean;
  /** Non-fatal diagnostics (`cnf_present_but_token_unfused`). */
  warnings: string[];
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

interface ResolvedKey {
  jwk: Ed25519PublicJwk;
  publicKey: Uint8Array;
}

/** The signing key `proof.kid` names in `proof.did`'s document, under the CID §3.3 assertion rule. */
async function resolveSigningKey(proof: RequestProof, seams: VerifierSeams, refusals: Refusals): Promise<ResolvedKey | undefined> {
  let document;
  try {
    document = await seams.resolveDid!(proof.did);
  } catch (error) {
    refusals.add(ReasonCodes.DID_UNRESOLVED, `could not resolve ${proof.did}: ${(error as Error).message}`);
    return undefined;
  }
  if (document === null || document === undefined) {
    refusals.add(ReasonCodes.DID_UNRESOLVED, `${proof.did} did not resolve`);
    return undefined;
  }
  try {
    const jwk = verificationMethodToJwk(selectAssertionMethod(document, proof.did, proof.kid));
    const publicKey = base64UrlDecodeStrict(jwk.x)!;
    return { jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: proof.kid }, publicKey };
  } catch (error) {
    const reason = error instanceof InvalidJWSError ? `${error.reason}: ` : '';
    refusals.add(ReasonCodes.KEY_UNRESOLVABLE, `${reason}${(error as Error).message}`);
    return undefined;
  }
}

/** The RFC 7638 membership proof: the signing key's thumbprint is among those the DID publishes. */
async function assertDidMembership(proof: RequestProof, key: ResolvedKey, seams: VerifierSeams, refusals: Refusals): Promise<void> {
  let published: Ed25519PublicJwk[];
  try {
    published = await seams.resolveDidKeys!(proof.did);
  } catch (error) {
    refusals.add(ReasonCodes.DID_KEYS_UNRESOLVABLE, `could not list the keys of ${proof.did}: ${(error as Error).message}`);
    return;
  }
  const wanted = jwkThumbprint(key.jwk);
  const thumbprints = published.map((jwk) => {
    try {
      return jwkThumbprint(jwk);
    } catch {
      return undefined;
    }
  });
  if (!thumbprints.includes(wanted)) {
    refusals.add(ReasonCodes.KID_NOT_IN_DID_DOCUMENT, `${proof.kid} is not a key ${proof.did} publishes`);
  }
}

/** §8.6: `token.cnf.jkt === proof.cnf.jkt === thumbprint(key)` for L3; no token cnf is L3-minus. */
function cnfFusion(proof: RequestProof, key: ResolvedKey, options: VerifierOptions, refusals: Refusals, warnings: string[]): ProofAssurance {
  const keyJkt = jwkThumbprint(key.jwk);
  if (proof.cnf !== undefined && proof.cnf.jkt !== keyJkt) {
    refusals.add(ReasonCodes.CNF_KEY_MISMATCH, 'cnf.jkt is not the thumbprint of the signing key');
  }
  if (options.tokenCnfJkt === undefined) {
    if (proof.cnf !== undefined) warnings.push('cnf_present_but_token_unfused');
    return 'L3-minus';
  }
  if (proof.cnf === undefined) {
    refusals.add(ReasonCodes.CNF_REQUIRED_BY_TOKEN, 'the token is sender-constrained but the proof carries no cnf');
    return 'L3-minus';
  }
  if (proof.cnf.jkt !== options.tokenCnfJkt) {
    refusals.add(ReasonCodes.CNF_TOKEN_MISMATCH, 'cnf.jkt is not the token cnf.jkt');
    return 'L3-minus';
  }
  return proof.cnf.jkt === keyJkt ? 'L3' : 'L3-minus';
}

/**
 * Verifies `input` with `seams` under `options`. Never throws for a bad
 * input: every refusal is a reason code in the result. Throws only for a
 * seam that is not a function where one is given, which is a programming
 * error, not a presentation.
 */
export async function verify(input: VerifierInput, seams: VerifierSeams, options: VerifierOptions): Promise<VerifierResult> {
  const refusals = new Refusals();
  const warnings: string[] = [];

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
  const nowSeconds = Math.floor(now / 1000);
  const skewSeconds = options.skewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;

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

  // 3. The proof's shape and its local bindings (§11.2 steps 1, 2, 5, 6, 7).
  if (input.proof === undefined || input.proof === null) {
    refusals.add(ReasonCodes.PROOF_MISSING, 'the request carries no org.kya-os/request-proof');
    return refused(refusals, noChain);
  }
  const proof = parseRequestProof(input.proof);
  if (proof === undefined) {
    refusals.add(ReasonCodes.MALFORMED_PROOF, 'the request proof is not an org.kya-os/proof.v1 object');
    return refused(refusals, noChain);
  }
  if (didOfKid(proof.kid) !== proof.did) refusals.add(ReasonCodes.KID_DID_MISMATCH, 'kid does not belong to did');
  if (proof.alg !== 'EdDSA') refusals.add(ReasonCodes.ALG_UNSUPPORTED, `proof alg ${proof.alg} is not EdDSA`);
  if (proof.audience !== options.expectedAudience) {
    refusals.add(ReasonCodes.AUDIENCE_MISMATCH, `audience ${proof.audience} is not this verifier (${options.expectedAudience})`);
  }
  if (input.request === undefined) {
    refusals.add(ReasonCodes.REQUEST_MISSING, 'no request to recompute requestHash from');
  } else {
    let computed: string | undefined;
    try {
      computed = requestHashContentDigest(input.request);
    } catch {
      computed = undefined;
    }
    if (computed !== proof.requestHash) refusals.add(ReasonCodes.REQUEST_HASH_MISMATCH, 'requestHash does not recompute from the request');
  }
  for (const problem of windowProblems(proof, nowSeconds, skewSeconds, options.maxTtlSeconds ?? MAX_PROOF_TTL_SECONDS)) {
    refusals.add(ReasonCodes[problem.toUpperCase() as 'INVALID_WINDOW' | 'TTL_TOO_LONG' | 'CREATED_IN_FUTURE' | 'EXPIRED'], `proof window: ${problem}`);
  }
  if (refusals.any) return refused(refusals, noChain);

  // 4. The signing key, its DID membership and the signature (§11.2 steps 3, 4, 9, 10).
  const key = await resolveSigningKey(proof, seams, refusals);
  if (key === undefined) return refused(refusals, noChain);
  await assertDidMembership(proof, key, seams, refusals);
  if (!verifyDetachedJws(proof, key.publicKey)) refusals.add(ReasonCodes.INVALID_SIGNATURE, 'the detached JWS does not verify over the covered claims');
  const proofAssurance = cnfFusion(proof, key, options, refusals, warnings);
  if (refusals.any) return refused(refusals, noChain, { warnings });
  // The signature held: from here the refusal names the principal it refused.
  const proved: Partial<VerifierResult> = { proofDid: proof.did, proofAssurance, warnings };

  // 5. The nonce, consumed only once every binding held (§11.2 step 8).
  try {
    const expiresAt = (proof.expires + skewSeconds + 1) * 1000;
    if (!(await seams.nonceStore!.insert(proof.nonce, proof.did, expiresAt))) {
      refusals.add(ReasonCodes.NONCE_REPLAYED, `nonce ${proof.nonce} was already used by ${proof.did}`);
    }
  } catch (error) {
    refusals.add(ReasonCodes.NONCE_STORE_UNAVAILABLE, `the nonce store could not answer: ${(error as Error).message}`);
  }
  if (refusals.any) return refused(refusals, noChain, proved);

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
    if (evaluation.leafInvoker !== proof.did) {
      refusals.add(ReasonCodes.LEAF_INVOKER_MISMATCH, `the leaf delegate ${String(evaluation.leafInvoker)} is not the proof's did ${proof.did}`);
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
    if (typeof seams.fetchStatusList !== 'function') {
      refusals.add(ReasonCodes.STATUS_SEAM_MISSING, 'no fetchStatusList seam: the hops\' status cannot be read');
      return refused(refusals, chainSummary, proved);
    }
    for (let index = 0; index < chain.length; index += 1) {
      const hop = chain[index]!;
      let read;
      try {
        read = await seams.fetchStatusList(hop.credentialStatus.statusListCredential);
      } catch (error) {
        refusals.add(ReasonCodes.STATUS_UNAVAILABLE, `hop ${index}: status list could not be read: ${(error as Error).message}`);
        return refused(refusals, chainSummary, proved);
      }
      const status = checkStatusEntry(hop.credentialStatus, hop.issuer, read, { now, maxClockSkewMs: options.maxClockSkewMs });
      if (!status.ok) {
        refusals.add(status.code, `hop ${index}: ${status.message}`);
        return refused(refusals, chainSummary, proved);
      }
      chainFresh &&= status.fresh;
    }
    chainSummary = { ...chainSummary, fresh: chainFresh };
    leafAllowedAction = evaluation.allowedAction;
  }

  // 7. The card: its shape, the responsibleParty gate (§10.2) and its attestations (§9.2).
  let card: EntityCard | undefined;
  let cardValue: unknown = input.card;
  if (cardValue === undefined && typeof seams.resolveCard === 'function') {
    try {
      cardValue = await seams.resolveCard(proof.did);
    } catch (error) {
      refusals.add(ReasonCodes.CARD_UNRESOLVABLE, `the card of ${proof.did} could not be read: ${(error as Error).message}`);
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
    if (card.id !== proof.did) {
      refusals.add(ReasonCodes.CARD_SUBJECT_MISMATCH, `the card is ${card.id}'s, not ${proof.did}'s`);
      return refused(refusals, chainSummary, proved);
    }
    if (hops !== undefined && card.responsibleParty !== undefined && card.responsibleParty !== chainSummary.responsibleParty) {
      refusals.add(ReasonCodes.ROOT_NOT_RESPONSIBLE_PARTY, `the root issuer ${String(chainSummary.responsibleParty)} is not the card's responsibleParty ${card.responsibleParty}`);
      return refused(refusals, chainSummary, proved);
    }
  }
  let capabilities: CapabilityCheck = { verified: [], unverified: [] };
  let capabilitiesFresh = true;
  if (card !== undefined && Array.isArray(card.capabilities) && card.capabilities.length > 0) {
    const check = await checkCapabilities(card.capabilities as CardCapability[], seams.resolveDid!, {
      subjectDid: proof.did,
      trustedIssuers: seams.trustedIssuers ?? '*',
      now,
      maxClockSkewMs: options.maxClockSkewMs,
      fetchStatusList: seams.fetchStatusList,
    });
    capabilities = { verified: check.verified, unverified: check.unverified };
    capabilitiesFresh = check.fresh;
  }

  // 8. Authority and level (story F-1 point 4; §9.4).
  const effectiveScopes = deriveEffectiveScopes(capabilities.verified, leafAllowedAction, options.catalog ?? leafAllowedAction);
  const fresh = chainFresh && capabilitiesFresh;
  const level = deriveConformanceLevel(capabilities, true, fresh);
  return {
    ok: true,
    level,
    effectiveScopes,
    reasons: [],
    messages: [],
    chainSummary,
    proofDid: proof.did,
    proofAssurance,
    capabilities,
    fresh,
    warnings,
  };
}

/** Whether an issuer is trusted under the seam's setting; exported for hosts that list issuers. */
export { isTrustedIssuer };
/** Whether `value` is a plain object, for hosts reading `_meta`. */
export { isRecord as isPlainObject };
