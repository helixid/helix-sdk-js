// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The contract below is the KYA-OS conformance harness's `ConformanceAdapter`
// (decentralized-identity/kya-os-mcp, conformance/types.ts at a4d7f61, MIT
// licensed, Copyright (c) 2026 KYA-OS), restated so Helix runs the vendored
// vectors (helix-core fixtures/kya-os/) against its own implementation. The
// harness code itself is not vendored (fixtures/kya-os/PIN.md).

/** Categories a vector can target. One adapter method per category. */
export type VectorCategory =
  | 'signed-proof'
  | 'delegation-chain'
  | 'status-list'
  | 'did-key-resolution'
  | 'did-web-resolution'
  | 'card-proof'
  | 'entity-card'
  | 'audit-integrity'
  | 'negotiation';

/** The seven categories story F-2 pins. */
export const F2_CATEGORIES: readonly VectorCategory[] = [
  'signed-proof',
  'delegation-chain',
  'status-list',
  'did-key-resolution',
  'did-web-resolution',
  'card-proof',
  'entity-card',
];

export type ExpectedOutcome = 'pass' | 'fail';

export interface ConformanceVector {
  id: string;
  category: VectorCategory;
  description: string;
  expected: ExpectedOutcome;
  reason: string;
  input: unknown;
}

export interface VectorFile {
  version: string;
  category: VectorCategory;
  vectors: ConformanceVector[];
}

/** `pass` = the implementation ACCEPTED the artifact; `fail` = it REJECTED it. */
export interface AdapterResult {
  outcome: ExpectedOutcome;
  detail?: string;
}

export interface SignedProofInput {
  proof: unknown;
  publicKeyJwk?: { kty: string; crv: string; x: string; kid?: string };
  didDocuments?: Record<string, unknown>;
  keyId?: string;
  now: number;
  skewSeconds: number;
  expected?: {
    request: { method: string; params?: unknown };
    response?: { data: unknown };
    delegationChain?: unknown[] | null;
    outcome?: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization' | null;
  };
}

export interface DelegationChainInput {
  leaf: unknown;
  ancestors?: unknown[];
  serverDid: string;
  didDocuments: Record<string, unknown>;
}

export interface StatusListInput {
  credential: unknown;
  statusLists: Record<string, unknown>;
  didDocuments: Record<string, unknown>;
  serverDid: string;
  trustedRootIssuer?: string;
  trustedRootStatusList?: string;
  statusListIssuers?: Record<string, string[]>;
}

export interface DidResolutionInput {
  did: string;
  didDocument?: unknown;
}

export interface Ed25519PublicJwkLike {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
  use?: string;
}

export interface CardProofInput {
  proof: unknown;
  request: { method: string; params?: unknown };
  jwks: { keys: Ed25519PublicJwkLike[] };
  expectedAudience: string;
  nowMs: number;
  skewSeconds: number;
  tokenCnfJkt?: string;
  omitNonceSeam?: boolean;
}

export interface EntityCardAccountabilityInput {
  resourceOwner: string;
  resource?: string;
  chain: unknown[];
  proofDid?: string;
  now?: number;
}

export interface EntityCardInput {
  card: unknown;
  trustedIssuers?: string[];
  accountability?: EntityCardAccountabilityInput;
  cimdKeyProven?: boolean;
}

/**
 * The contract a third party implements to run the KYA-OS vectors against
 * its own implementation. Fail-closed: any error, malformed input, or unmet
 * security property maps to `{ outcome: 'fail' }`; methods never throw.
 */
export interface ConformanceAdapter {
  readonly name: string;
  verifySignedProof(input: SignedProofInput): Promise<AdapterResult>;
  verifyDelegationChain(input: DelegationChainInput): Promise<AdapterResult>;
  verifyStatusList(input: StatusListInput): Promise<AdapterResult>;
  resolveDidKey(input: DidResolutionInput): Promise<AdapterResult>;
  resolveDidWeb(input: DidResolutionInput): Promise<AdapterResult>;
  verifyCardProof(input: CardProofInput): Promise<AdapterResult>;
  verifyEntityCard(input: EntityCardInput): Promise<AdapterResult>;
  verifyAuditIntegrity(input: unknown): Promise<AdapterResult>;
  evaluateNegotiation(input: unknown): Promise<AdapterResult>;
}
