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
 * The custody endpoints of the Helix API (KYA-OS story F-3), as one small
 * client. Every request body passes `assertNoPrivateMaterial` before it is
 * sent: the SDK never sends private key material, whatever the caller hands
 * it (self-custody invariant, stories rule 7).
 */

import { assertNoPrivateMaterial, type AgentPublicKeyJwk } from '../agent-key.js';
import { ownDidWebProblem } from '../entity-card.js';

export type KeyCustodyMode = 'self' | 'helix';
export type DidHostingMode = 'own' | 'helix';
export type CustodySubjectKind = 'agent' | 'service' | 'owner';
export type CustodyLabel = 'custody: self' | 'custody: helix';

export interface CustodyKeyView {
  kid: string;
  location: KeyCustodyMode;
  status: 'active' | 'retiring' | 'revoked';
  createdAt: string;
  retiresAt: string | null;
  revokedAt: string | null;
}

export interface CustodyView {
  did: string;
  subjectType: CustodySubjectKind;
  name: string | null;
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
  label: CustodyLabel;
  conformant: boolean;
  status: 'pending_key' | 'pending_resolution' | 'active';
  kid: string | null;
  credentialVcId: string | null;
  keys: CustodyKeyView[];
}

export interface PublishedDocuments {
  didDocument: Record<string, unknown>;
  card: Record<string, unknown>;
  didDocumentUrl: string;
  cardUrl: string;
}

export interface OnboardingResult extends CustodyView {
  enrollmentToken?: string;
  enrollmentExpiresAt?: string;
  documents?: PublishedDocuments;
  publishRequired?: boolean;
  vcId?: string;
}

export interface EnrollmentChallenge {
  did: string;
  kid: string;
  nonce: string;
  keyCustody: 'self';
  didHosting: DidHostingMode;
  name: string | null;
  didDocumentUrl: string;
  cardUrl: string;
}

export interface SignResponse {
  did: string;
  kid: string;
  alg: 'EdDSA';
  signature: string;
}

export interface ChangeCustodyResult extends CustodyView {
  previousKid: string;
  previousKeyShredded: boolean;
  retiresAt: string;
  hopReissue: { reissued: number; pending: boolean; note?: string };
  documents: PublishedDocuments;
  publishRequired: boolean;
  vcId?: string;
}

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

export interface HelixCustodyClientOptions {
  apiUrl: string;
  /** Core's admin key (`x-admin-api-key`). */
  adminApiKey?: string | undefined;
  /** The enterprise account API key (bearer). */
  apiKey?: string | undefined;
  fetch?: FetchLike | undefined;
}

/** A refusal from the custody API, with its error code and HTTP status. */
export class CustodyApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown> | undefined,
  ) {
    super(message);
    this.name = 'CustodyApiError';
  }
}

/**
 * Own hosting: the DID on the owner's domain may have any path, but no
 * unencoded port (`did:web:localhost:3000:x` names another URL); refused
 * here before any request, as the API refuses it (one did:web shape,
 * 2026-11-23).
 */
function assertOwnDid(input: { didHosting?: DidHostingMode | undefined; did?: string | undefined }): void {
  if (input.didHosting !== 'own' || input.did === undefined) return;
  const problem = ownDidWebProblem(input.did);
  if (problem !== undefined) throw new CustodyApiError(400, 'VALIDATION_ERROR', problem);
}

function pathOf(kind: CustodySubjectKind): string {
  return `${kind}s`;
}

export class HelixCustodyClient {
  readonly #apiUrl: string;
  readonly #headers: Record<string, string>;
  readonly #fetch: FetchLike;

  constructor(options: HelixCustodyClientOptions) {
    if (typeof options?.apiUrl !== 'string' || options.apiUrl.length === 0) throw new Error('HelixCustodyClient: apiUrl is required');
    this.#apiUrl = options.apiUrl.replace(/\/+$/, '');
    this.#headers = options.apiKey
      ? { authorization: `Bearer ${options.apiKey}` }
      : options.adminApiKey
        ? { 'x-admin-api-key': options.adminApiKey }
        : {};
    this.#fetch = options.fetch ?? ((url, init): ReturnType<FetchLike> => fetch(url, init));
  }

  async request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    if (body !== undefined) assertNoPrivateMaterial(body);
    const response = await this.#fetch(`${this.#apiUrl}${path}`, {
      method,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...this.#headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }
    if (!response.ok) {
      const error = (payload as { error?: { code?: string; message?: string; details?: Record<string, unknown> } } | undefined)?.error;
      throw new CustodyApiError(response.status, error?.code ?? 'HTTP_ERROR', error?.message ?? `HTTP ${response.status}`, error?.details);
    }
    return payload as T;
  }

  /**
   * Custodial agents are created in one call; self-custody returns the enrollment token for `helix init`.
   * `requestedDomains` (bare hosts or http(s) URLs) become `#domain-N` LinkedDomains entries in the agent's
   * DID document; `maxDelegationDepth` (0 to 5, default 0) is written on its identity credential.
   */
  async createAgent(input: {
    name: string;
    scopes?: string[];
    keyCustody?: KeyCustodyMode;
    didHosting?: DidHostingMode;
    did?: string;
    ownerDid?: string;
    expiry?: number;
    requestedDomains?: string[];
    maxDelegationDepth?: number;
  }): Promise<OnboardingResult> {
    assertOwnDid(input);
    return this.request('POST', '/v1/agents', input);
  }

  async createService(input: {
    name: string;
    domain: string;
    requiredScopes: string[];
    keyCustody?: KeyCustodyMode;
    didHosting?: DidHostingMode;
    did?: string;
    publicKeyJwk?: AgentPublicKeyJwk;
    description?: string;
    framework?: string;
  }): Promise<OnboardingResult & { id: string; domain: string; requiredScopes: string[] }> {
    assertOwnDid(input);
    return this.request('POST', '/v1/services', input);
  }

  async createOwner(input: { name: string; keyCustody?: KeyCustodyMode; didHosting?: DidHostingMode; did?: string; publicKeyJwk?: AgentPublicKeyJwk; entityType?: string }): Promise<OnboardingResult> {
    assertOwnDid(input);
    return this.request('POST', '/v1/owners', input);
  }

  enrollmentChallenge(enrollmentToken: string): Promise<EnrollmentChallenge> {
    return this.request('POST', '/v1/agents/enroll/challenge', { enrollmentToken });
  }

  enroll(input: { enrollmentToken: string; publicKeyJwk: AgentPublicKeyJwk; kid?: string; signature: string }): Promise<OnboardingResult> {
    return this.request('POST', '/v1/agents/enroll', input);
  }

  activate(did: string, input: { enrollmentToken?: string } = {}, kind: CustodySubjectKind = 'agent'): Promise<OnboardingResult> {
    return this.request('POST', `/v1/${pathOf(kind)}/${encodeURIComponent(did)}/activate`, input);
  }

  sign(did: string, input: { payload: string; kid?: string }, kind: CustodySubjectKind = 'agent'): Promise<SignResponse> {
    return this.request('POST', `/v1/${pathOf(kind)}/${encodeURIComponent(did)}/sign`, input);
  }

  getCustody(did: string, kind: CustodySubjectKind = 'agent'): Promise<CustodyView> {
    return this.request('GET', `/v1/${pathOf(kind)}/${encodeURIComponent(did)}/custody`);
  }

  changeCustody(
    did: string,
    input: { keyCustody: KeyCustodyMode; publicKeyJwk?: AgentPublicKeyJwk; kid?: string; proof?: { issuedAt: string; signature: string }; overlapSeconds?: number },
    kind: CustodySubjectKind = 'agent',
  ): Promise<ChangeCustodyResult> {
    return this.request('POST', `/v1/${pathOf(kind)}/${encodeURIComponent(did)}/custody`, input);
  }

  finalizeRotation(did: string, input: { force?: boolean } = {}, kind: CustodySubjectKind = 'agent'): Promise<CustodyView & { revoked: string[] }> {
    return this.request('POST', `/v1/${pathOf(kind)}/${encodeURIComponent(did)}/custody/finalize`, input);
  }

  defaults(): Promise<{ custody: { defaultKeyCustody: KeyCustodyMode; defaultDidHosting: DidHostingMode }; source: 'account' | 'built-in' }> {
    return this.request('GET', '/v1/custody/defaults');
  }

  conformanceReport(): Promise<{
    claimSet: (CustodyView & { claims: { profile: string; level: string }[] })[];
    excluded: (CustodyView & { reason: string })[];
    pending: CustodyView[];
    summary: Record<string, number>;
  }> {
    return this.request('GET', '/v1/conformance/report');
  }
}
