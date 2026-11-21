// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The three credentials of KYA-OS story F-1 as the verifier reads them, and
 * the delegation chain (SPEC.md §6.10): a list of hops root to leaf, valid
 * only if EVERY hop attenuates its parent. Pure functions: no database, no
 * network, no lookup fallback.
 *
 * Ported from helix-core `src/core/credentials/{types,validation,chain}.ts`
 * (story F-1) for story F-2 (stories rule 24: the middleware runs this
 * in-process and cannot import helix-core). `evaluateDelegationChain` and
 * `deriveEffectiveScopes` behave byte for byte as the helix-core originals
 * do, which `fixtures/kya-os-helix/credentials.json` proves.
 *
 * Attenuation invariants (fail-closed, every reason reported):
 * - action subset: child `allowedAction` ⊆ parent;
 * - monotone caveats: no parent caveat dropped; `MaxAmount` ≤ parent (same
 *   currency, exact decimals), `ValidUntil` ≤ parent, unknown types verbatim;
 * - `validUntil` narrowing: child ≤ parent, both read as RFC 3339 with offset;
 * - continuity: parent `invoker` = child `issuer`; child `parentCapability`
 *   = parent capability `id`;
 * - constant `invocationTarget`;
 * - root: `parentCapability` = `invocationTarget`; when the caller asserts
 *   `resource` / `resourceOwner`, the root's target / issuer must match.
 *
 * Chain length is bounded (10 hops, `maxChainLength`) before any entry is
 * parsed, so an oversized chain costs nothing to refuse.
 */

import { deepEqual, parseDateTime, validateJsonSchema, type SchemaViolation } from './json-schema.js';
import { CAPABILITY_ATTESTATION_SCHEMA, DELEGATION_HOP_SCHEMA, IDENTITY_CREDENTIAL_SCHEMA } from './schemas.js';

export { describeViolations } from './json-schema.js';

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const ZCAP_CONTEXT = 'https://w3id.org/security/zcap/v1';
export const KYA_OS_DELEGATION_CONTEXT = 'https://kya-os.org/ns/delegation/v1';
export const HELIX_CONTEXT = 'https://helixid.io/contexts/v1';

export const IDENTITY_CREDENTIAL_TYPE = 'AgentIdentityCredential';
export const CAPABILITY_ATTESTATION_TYPE = 'CapabilityAttestationCredential';
export const DELEGATION_CREDENTIAL_TYPE = 'DelegationCredential';

export const MAX_DELEGATION_DEPTH = 10;
/** Default clock tolerance for validity windows, the reference verifier's 120 seconds. */
export const DEFAULT_CLOCK_SKEW_MS = 120_000;
export const MAX_CLOCK_SKEW_MS = 600_000;

/** `'*'` trusts every issuer (the shipped default, stories rule 9); a list trusts those DIDs only. */
export type TrustedIssuers = '*' | readonly string[];
export const TRUST_ALL_ISSUERS: TrustedIssuers = '*';

/** W3C Bitstring Status List v1.0 entry (the StatusList2021Entry successor). */
export interface BitstringStatusEntry {
  id?: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
  statusSize?: number;
}

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export type Signed<T> = T & { proof: DataIntegrityProof };

export interface IdentityCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: { id: string; name: string; responsibleParty: string };
  credentialStatus: BitstringStatusEntry;
}

export interface CapabilityAttestationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: { id: string; capability: string };
  credentialStatus: BitstringStatusEntry;
}

/** A monotone-narrowing constraint on a hop; unknown types are replicated verbatim down the chain. */
export interface Caveat {
  type: string;
  date?: string;
  limit?: string;
  currency?: string;
  [member: string]: unknown;
}

/** The attenuated ZCAP-LD capability a hop carries as its `credentialSubject`. */
export interface ZcapCapability {
  id: string;
  invoker?: string;
  controller?: string;
  parentCapability: string;
  invocationTarget: string;
  allowedAction: string[];
  caveats?: Caveat[];
}

/** One delegation hop: SPEC.md §6.10 (VC 2.0 + ZCAP-LD, Bitstring status, eddsa-jcs-2022). */
export interface DelegationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom?: string;
  validUntil: string;
  credentialSubject: ZcapCapability;
  credentialStatus: BitstringStatusEntry;
}

export type SignedIdentityCredential = Signed<IdentityCredential>;
export type SignedCapabilityAttestation = Signed<CapabilityAttestationCredential>;
export type SignedDelegationHop = Signed<DelegationCredential>;

// ── schema and window checks ──────────────────────────────────────────────────

export type CredentialKind = 'identity' | 'attestation' | 'hop';

const SCHEMAS = {
  identity: IDENTITY_CREDENTIAL_SCHEMA,
  attestation: CAPABILITY_ATTESTATION_SCHEMA,
  hop: DELEGATION_HOP_SCHEMA,
} as const;

/** Every way `value` fails the schema of `kind`; empty when it conforms. */
export function credentialSchemaViolations(kind: CredentialKind, value: unknown): SchemaViolation[] {
  return validateJsonSchema(SCHEMAS[kind], value);
}

export function isDelegationHop(value: unknown): value is SignedDelegationHop {
  return credentialSchemaViolations('hop', value).length === 0;
}

export type WindowVerdict = 'inside' | 'expired' | 'not_yet_valid' | 'malformed' | 'skew_invalid';

/** The clock tolerance in use, or undefined when `maxClockSkewMs` is not a number of ms from 0 to 600,000. */
export function clockSkewMs(maxClockSkewMs: unknown): number | undefined {
  if (maxClockSkewMs === undefined) return DEFAULT_CLOCK_SKEW_MS;
  if (typeof maxClockSkewMs !== 'number' || !Number.isFinite(maxClockSkewMs)) return undefined;
  if (maxClockSkewMs < 0 || maxClockSkewMs > MAX_CLOCK_SKEW_MS) return undefined;
  return maxClockSkewMs;
}

/**
 * Where `nowMs` stands against a window `validFrom` .. `validUntil`, either
 * bound optional, each held with `maxClockSkewMs`. A bound that is not an
 * RFC 3339 date-time with offset is `malformed` (fail-closed).
 */
export function windowVerdict(validFrom: unknown, validUntil: unknown, nowMs: number, maxClockSkewMs?: unknown): WindowVerdict {
  const skew = clockSkewMs(maxClockSkewMs);
  if (skew === undefined) return 'skew_invalid';
  let from: number | undefined;
  let until: number | undefined;
  if (validFrom !== undefined) {
    from = parseDateTime(validFrom);
    if (from === undefined) return 'malformed';
  }
  if (validUntil !== undefined) {
    until = parseDateTime(validUntil);
    if (until === undefined) return 'malformed';
  }
  if (until !== undefined && nowMs > until + skew) return 'expired';
  if (from !== undefined && nowMs < from - skew) return 'not_yet_valid';
  return 'inside';
}

/** `'*'` trusts every issuer; a list trusts exactly those DIDs (stories rule 9, story C-B point 4). */
export function isTrustedIssuer(issuerDid: string, trustedIssuers: TrustedIssuers): boolean {
  if (trustedIssuers === '*') return true;
  return Array.isArray(trustedIssuers) && trustedIssuers.includes(issuerDid);
}

// ── the chain ─────────────────────────────────────────────────────────────────

export type ChainRefusalCode =
  | 'chain_invalid'
  | 'delegation_malformed'
  | 'delegation_expired'
  | 'delegation_not_yet_valid'
  | 'untrusted_root'
  | 'configuration_error'
  | 'proof_invalid';

export interface EvaluateDelegationChainOptions {
  /** The resource the verifier is: the root's `invocationTarget` must equal it. */
  resource?: string;
  /** When asserted, the root's `issuer` must be this DID (the accountable resource owner). */
  resourceOwner?: string;
  /** Epoch ms; default `Date.now()`. */
  now?: number;
  /** Default {@link MAX_DELEGATION_DEPTH}; must be a positive integer. */
  maxChainLength?: number;
  /** 0 to 600,000 ms; default 120,000. */
  maxClockSkewMs?: number;
}

/**
 * The chain rules with the hop's `proof` shape left unread (`'any'`), for a
 * caller that checks no hop proof (the Entity Card vectors carry placeholder
 * proofs). Default `'data-integrity'`: the full hop schema.
 */
export interface EvaluateDelegationChainRulesOptions extends EvaluateDelegationChainOptions {
  proofShape?: 'data-integrity' | 'any';
}

/** The hop schema with `proof` any object and not required. */
const HOP_SCHEMA_ANY_PROOF = (() => {
  const schema = JSON.parse(JSON.stringify(DELEGATION_HOP_SCHEMA)) as { required: string[]; properties: Record<string, unknown> };
  schema.required = schema.required.filter((member) => member !== 'proof');
  schema.properties['proof'] = { type: 'object' };
  return schema;
})();

export interface DelegationChainEvaluation {
  ok: boolean;
  /** The code of the first rule broken; absent when `ok`. */
  code?: ChainRefusalCode;
  reasons: string[];
  /** `issuer(root)`: the accountable party. */
  responsibleParty?: string;
  /** The leaf delegate, which a verifier joins to the request proof's DID. */
  leafInvoker?: string;
  invocationTarget?: string;
  /** The leaf's `allowedAction`: the authority the chain grants. Empty when refused. */
  allowedAction: string[];
  depth: number;
}

/**
 * The finer code of each broken rule: an attenuation or continuity failure
 * between two hops is `attenuation_violation`, which the local verifier
 * reports as such; `evaluateDelegationChain` folds it into `chain_invalid`,
 * the helix-core code.
 */
export type ChainRuleCode = ChainRefusalCode | 'attenuation_violation';

export interface BrokenRule {
  code: ChainRuleCode;
  reason: string;
}

/** A non-negative decimal split into digit strings, or undefined when it is not one. */
function decimalParts(value: string): { whole: string; fraction: string } | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
  return match?.[1] ? { whole: match[1], fraction: match[2] ?? '' } : undefined;
}

/** `child <= parent` as exact decimals, never rounded; any unparseable value is false. */
export function decimalLte(child: string, parent: string): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = (part: { whole: string; fraction: string }): bigint => BigInt(part.whole + part.fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}

function dateLte(child: unknown, parent: unknown): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

/** True iff `child` is at least as narrow as `parent` for the same caveat type. */
export function caveatNarrows(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    // A currency-less parent may be narrowed by a child that pins one; a
    // parent that pins a currency requires the same one.
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return (
      currencyNarrows &&
      typeof parent.limit === 'string' &&
      typeof child.limit === 'string' &&
      decimalLte(child.limit, parent.limit)
    );
  }
  return deepEqual(parent, child);
}

/** The delegate a hop names: `invoker`, falling back to `controller`. */
export function invokerOf(hop: Pick<DelegationCredential, 'credentialSubject'>): string | undefined {
  return hop.credentialSubject.invoker ?? hop.credentialSubject.controller;
}

/** Every way `child` fails to attenuate `parent`; empty when the hop is a valid narrowing. */
export function attenuationReasons(parent: DelegationCredential, child: DelegationCredential): string[] {
  const p = parent.credentialSubject;
  const c = child.credentialSubject;
  const reasons: string[] = [];
  const parentActions = new Set(p.allowedAction);
  const escalated = c.allowedAction.filter((action) => !parentActions.has(action));
  if (escalated.length > 0) {
    reasons.push(`allowedAction escalation: [${escalated.join(', ')}] not in parent`);
  }
  for (const parentCaveat of p.caveats ?? []) {
    if (!(c.caveats ?? []).some((childCaveat) => caveatNarrows(parentCaveat, childCaveat))) {
      reasons.push(`caveat "${parentCaveat.type}" broadened or dropped by child`);
    }
  }
  if (!dateLte(child.validUntil, parent.validUntil)) {
    reasons.push('validUntil broadened: child must expire no later than its parent');
  }
  const delegate = invokerOf(parent);
  if (delegate === undefined || delegate !== child.issuer) {
    reasons.push('broken continuity: parent invoker is not the child issuer');
  }
  if (c.parentCapability !== p.id) {
    reasons.push('broken continuity: child parentCapability is not the parent capability id');
  }
  if (c.invocationTarget !== p.invocationTarget) {
    reasons.push('invocationTarget drift: the resource must be constant along the chain');
  }
  return reasons;
}

function rootRules(root: DelegationCredential, options: EvaluateDelegationChainOptions): BrokenRule[] {
  const subject = root.credentialSubject;
  const broken: BrokenRule[] = [];
  if (subject.parentCapability !== subject.invocationTarget) {
    broken.push({ code: 'chain_invalid', reason: 'root delegation: parentCapability must equal invocationTarget' });
  }
  if (options.resource !== undefined && subject.invocationTarget !== options.resource) {
    broken.push({ code: 'chain_invalid', reason: 'root invocationTarget is not the expected resource' });
  }
  if (options.resourceOwner !== undefined && root.issuer !== options.resourceOwner) {
    broken.push({ code: 'untrusted_root', reason: 'root issuer is not the resource owner' });
  }
  return broken;
}

function windowRules(chain: readonly DelegationCredential[], nowMs: number, maxClockSkewMs: number | undefined): BrokenRule[] {
  const broken: BrokenRule[] = [];
  chain.forEach((hop, index) => {
    const verdict = windowVerdict(hop.validFrom, hop.validUntil, nowMs, maxClockSkewMs);
    if (verdict === 'malformed') {
      broken.push({ code: 'delegation_malformed', reason: `hop ${index}: validFrom/validUntil is not an RFC 3339 date-time with offset` });
    } else if (verdict === 'expired') {
      broken.push({ code: 'delegation_expired', reason: `hop ${index}: expired (validUntil ${hop.validUntil} is in the past)` });
    } else if (verdict === 'not_yet_valid') {
      broken.push({ code: 'delegation_not_yet_valid', reason: `hop ${index}: not yet valid (validFrom ${hop.validFrom} is in the future)` });
    }
    for (const caveat of hop.credentialSubject.caveats ?? []) {
      if (caveat.type !== 'ValidUntil') continue;
      const caveatVerdict = windowVerdict(undefined, caveat.date, nowMs, maxClockSkewMs);
      if (caveatVerdict === 'malformed') {
        broken.push({ code: 'delegation_malformed', reason: `hop ${index}: ValidUntil caveat date is not an RFC 3339 date-time with offset` });
      } else if (caveatVerdict === 'expired') {
        broken.push({ code: 'delegation_expired', reason: `hop ${index}: expired caveat (ValidUntil ${String(caveat.date)} is in the past)` });
      }
    }
  });
  return broken;
}

/** The chain evaluation with every broken rule and its finer code; what `verify()` reads. */
export interface DelegationChainRules extends DelegationChainEvaluation {
  broken: BrokenRule[];
}

const REFUSED: Pick<DelegationChainEvaluation, 'ok' | 'allowedAction'> = { ok: false, allowedAction: [] };

function refusedRules(code: ChainRuleCode, reasons: string[], depth: number): DelegationChainRules {
  const broken = reasons.map((reason) => ({ code, reason }));
  return { ...REFUSED, code: code === 'attenuation_violation' ? 'chain_invalid' : code, reasons, depth, broken };
}

/**
 * {@link evaluateDelegationChain} with each broken rule and its finer code
 * (`attenuation_violation` for a hop that broadens or breaks continuity).
 */
export function evaluateDelegationChainRules(hops: unknown, options: EvaluateDelegationChainRulesOptions = {}): DelegationChainRules {
  const maxChainLength = options.maxChainLength ?? MAX_DELEGATION_DEPTH;
  if (!Number.isInteger(maxChainLength) || maxChainLength < 1) {
    return refusedRules('configuration_error', ['maxChainLength must be a positive integer'], 0);
  }
  if (clockSkewMs(options.maxClockSkewMs) === undefined) {
    return refusedRules('configuration_error', ['maxClockSkewMs must be a number of milliseconds from 0 to 600000'], 0);
  }
  if (!Array.isArray(hops) || hops.length === 0) {
    return refusedRules('chain_invalid', ['empty delegation chain'], 0);
  }
  // Bounded before any entry is parsed: an oversized chain is refused for its length alone.
  if (hops.length > maxChainLength) {
    return refusedRules('chain_invalid', [`delegation chain depth ${hops.length} exceeds the maximum of ${maxChainLength}`], hops.length);
  }
  const malformed: string[] = [];
  hops.forEach((hop, index) => {
    const violations = options.proofShape === 'any' ? validateJsonSchema(HOP_SCHEMA_ANY_PROOF, hop) : credentialSchemaViolations('hop', hop);
    if (violations.length > 0) {
      malformed.push(`hop ${index}: ${violations.map((violation) => `${violation.path}: ${violation.message}`).join('; ')}`);
    }
  });
  if (malformed.length > 0) {
    return refusedRules('delegation_malformed', malformed, hops.length);
  }
  const chain = hops as SignedDelegationHop[];
  const root = chain[0]!;
  const leaf = chain[chain.length - 1]!;
  const broken: BrokenRule[] = [...rootRules(root, options)];
  for (let index = 1; index < chain.length; index += 1) {
    for (const reason of attenuationReasons(chain[index - 1]!, chain[index]!)) {
      broken.push({ code: 'attenuation_violation', reason: `hop ${index}: ${reason}` });
    }
  }
  broken.push(...windowRules(chain, options.now ?? Date.now(), options.maxClockSkewMs));
  const first = broken[0];
  const firstCode = first === undefined ? undefined : first.code === 'attenuation_violation' ? 'chain_invalid' : first.code;
  return {
    ok: first === undefined,
    ...(firstCode === undefined ? {} : { code: firstCode }),
    reasons: broken.map((rule) => rule.reason),
    responsibleParty: root.issuer,
    ...(invokerOf(leaf) === undefined ? {} : { leafInvoker: invokerOf(leaf)! }),
    invocationTarget: leaf.credentialSubject.invocationTarget,
    allowedAction: first === undefined ? [...leaf.credentialSubject.allowedAction] : [],
    depth: chain.length,
    broken,
  };
}

/**
 * Evaluates a chain of hops (root to leaf) against the attenuation, root,
 * continuity and window invariants. Pure: it reads the hops it is given and
 * nothing else. A refused chain reports every rule it breaks and the code
 * of the first; `allowedAction` is then empty, so nothing downstream can
 * read authority out of a refusal. Same result as helix-core's.
 */
export function evaluateDelegationChain(hops: unknown, options: EvaluateDelegationChainOptions = {}): DelegationChainEvaluation {
  const { broken: _broken, ...evaluation } = evaluateDelegationChainRules(hops, options);
  return evaluation;
}

/** An attestation as the scope it attests, whether given as a name or as a credential. */
export type AttestedCapability = string | { credentialSubject: { capability: string } };

export function attestedCapabilities(attestations: readonly AttestedCapability[]): string[] {
  const names: string[] = [];
  for (const attestation of attestations) {
    const name = typeof attestation === 'string' ? attestation : attestation.credentialSubject.capability;
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/**
 * Enforcement scopes (story F-1 point 4): the three-way intersection of what
 * the agent is attested for, what the leaf hop allows and what the service
 * offers. Order follows the attestations; duplicates collapse. With no hops
 * (no delegation presented) `leafAllowedAction` is the caller's choice; an
 * empty array grants nothing.
 */
export function deriveEffectiveScopes(
  attestations: readonly AttestedCapability[],
  leafAllowedAction: readonly string[],
  catalog: readonly string[],
): string[] {
  const allowed = new Set(leafAllowedAction);
  const offered = new Set(catalog);
  return attestedCapabilities(attestations).filter((scope) => allowed.has(scope) && offered.has(scope));
}
