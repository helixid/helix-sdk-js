import { AuditEvents } from '../core/audit-events.js';
import { generateKeyPair, type KeyPair } from '../core/keys.js';
import { SDKOnlyModeNoAPIError } from '../errors/index.js';
import { verifyJWT } from '../core/jwt.js';
import type { HelixJWTPayload } from '../core/schemas/jwt.js';
import type { DIDDocument, ServiceEndpoint } from '../core/did.js';
import type { StatusListCredential } from '../core/status-list-schema.js';
import type { SignedVC } from '../core/schemas/vc.js';
import type { SignedVP } from '../core/schemas/vp.js';
import type { VerifyVPOptions, VerifyVPResult } from '../core/verification-types.js';
import { HttpAdapter } from '../http/HttpAdapter.js';

/**
 * Full response from `POST /v1/vp/verify` — see docs/proposal-sdk-api-only.md.
 * Superset of core's `VerifyVPResult` (same verification fields — parity is
 * enforced server-side, see helix-api's IVPService) plus the fields only the
 * API call itself can produce (targetService, verifiedAt, an optional
 * session). The server logs VP_VERIFIED/VP_REJECTED on every call, so unlike
 * the old local-verification path, the SDK does not need its own audit call
 * here.
 */
export interface VerifyVPApiResult extends VerifyVPResult {
  targetService: string;
  verifiedAt: string;
  userDid?: string;
  session?: {
    token: string;
    expiresAt: string;
    publicKeyEndpoint: string;
  };
}

/**
 * Agent-side record of a consent grant landing in the wallet (spec §2a) — the
 * agent-side analogue of `VC_ISSUED`.
 */
export interface ConsentGrantedAuditEntry {
  vcId: string;
  agentDid: string;
  issuer?: string;
  userDid?: string;
  scopes?: string[];
  durability?: string;
  grantedAt: string;
  source: 'sdk';
}

interface HttpAdapterLike {
  post<T>(path: string, body?: unknown): Promise<T>;
  get?<T>(path: string): Promise<T>;
  delete?<T>(path: string): Promise<T>;
}

function toQueryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

export interface CreateDIDOptions {
  subjectType: 'agent' | 'user';
  domains?: string[];
}

export interface CreateDIDResult {
  did: string;
  keyPair: KeyPair;
  didDocument: DIDDocument;
  hederaTransactionId: string;
}

export interface IssueVCOptions {
  subjectDid: string;
  subjectType: 'agent' | 'user';
  privilegeScopes?: string[];
  agentName?: string;
  userId?: string;
  expiresInSeconds?: number;
}

export interface VCResponse {
  vcId: string;
  vc?: Record<string, unknown>;
  status?: string;
  statusListIndex?: number;
  expiresAt?: string;
  [key: string]: unknown;
}

export interface ListVCFilters {
  subjectDid?: string;
  status?: 'active' | 'revoked' | 'expired';
  limit?: number;
}

export interface VCSummary {
  vcId: string;
  subjectDid: string;
  agentName?: string;
  scopes: string[];
  status: 'active' | 'revoked' | 'expired';
  issuedAt: string;
  expiresAt: string;
  parentVcId?: string;
}

export interface AuditLogFilters {
  eventType?: string;
  since?: string;
  limit?: number;
}

export interface AuditLogEvent {
  id: string;
  eventType: string;
  timestamp: string;
  subjectDid?: string;
  vcId?: string;
  targetService?: string;
  result?: string;
  delegatedFrom?: string;
  delegatedTo?: string;
  parentVcId?: string;
  delegationDepth?: number;
}

export interface StatusListCredentialResponse {
  credentialSubject: {
    encodedList: string;
  };
  [key: string]: unknown;
}

export interface SessionPublicKeyResponse {
  publicKeyHex: string;
  publicKeyMultibase: string;
  alg: 'EdDSA';
  crv: 'Ed25519';
}

export interface HelixClientOptions {
  /** OSS/core mode: the single shared secret the server was started with (x-admin-api-key). */
  adminApiKey?: string;
  /**
   * Enterprise (server-custody, account-scoped) mode: presence of this
   * option is what selects it -- signVP() then talks to
   * /v1/custodial-agents/:did/vp (not core's /v1/agents/:did/vp) and sends
   * this directly as the bearer token. See helix-server-enterprise's
   * POST /v1/account/api-keys. No email/password, no login call -- an
   * agent process holds only this, the same way an OSS agent holds only
   * `adminApiKey`.
   */
  apiKey?: string;
}

// -- prepare/finalize (see docs/proposal-sdk-api-only.md) -----------------
// Mirrors helix-api's IPreparedPayloadService types. Duplicated here rather
// than imported, since helix-api is a server-only package the SDK doesn't
// (and shouldn't) depend on — only the wire shape needs to match.

export interface PrepareDelegationInput {
  /** DID of the delegator — becomes `issuer` and `credentialSubject.delegatedFrom`. */
  delegatorDid: string;
  /** The delegator's own currently-held agent-authority VC. */
  fromVC: SignedVC;
  to: string;
  scopes: string[];
  expiresIn: number;
}

export interface PrepareResult {
  token: string;
  unsignedPayload: Record<string, unknown>;
  canonicalHash: string;
  expiresAt: string;
}

export interface PrepareGrantInput {
  /** SP's own issuer DID — becomes `issuer` of the grant VC. */
  issuerDid: string;
  agentDid: string;
  userDid: string;
  scopes: string[];
  durability: 'standing' | 'session';
  serviceDid?: string;
  /** Current status list credential, unmodified — caller (SP) owns storage. */
  statusList: { credentialSubject: { encodedList: string } };
  statusListCredentialUrl: string;
}

export interface PrepareAgentRenewalInput {
  /**
   * The agent's current (soon-to-expire or already-expired-within-grace) VC.
   * Must carry a `credentialStatus` entry — renewal can't check revocation
   * without one. Renewal is signed by whoever signed this VC (`issuer`).
   */
  currentVC: SignedVC;
  /**
   * Status list the currentVC's credentialStatus entry lives on, unmodified.
   * Caller owns storage, same as PrepareGrantInput.statusList.
   */
  statusList: { credentialSubject: { encodedList: string } };
  statusListCredentialUrl: string;
  expiresIn: number;
  /**
   * Optional narrower scope set for the renewed VC. Must be a subset of
   * currentVC's scopes — renewal can only narrow, never widen. Omit to keep
   * the same scopes.
   */
  scopes?: string[];
}

export interface FinalizeInput {
  token: string;
  verificationMethod: string;
  /** Hex-encoded raw Ed25519 signature over the hash returned by prepare(). */
  signatureHex: string;
  /** Optional; defaults to now if omitted. */
  proofCreatedAt?: string;
}

export interface CreateStatusListOptions {
  listId?: string;
  length?: number;
}

type DIDResolveResponse = {
  didDocument?: DIDDocument;
  document?: DIDDocument;
} & DIDDocument;

const SDK_ONLY_HTTP_ADAPTER: HttpAdapterLike = {
  post: async <T>(): Promise<T> => {
    throw new SDKOnlyModeNoAPIError();
  },
};

/** Used only when apiKey is given with no explicit URL — see the constructor. Not a claim that any fixed URL is "the" enterprise instance; just the default port any local helix-api listens on. */
const DEFAULT_ENTERPRISE_URL = 'http://localhost:3000';

export class HelixClient {
  private http: HttpAdapterLike;
  private readonly sdkOnlyMode: boolean;
  private readonly apiAuditEnabled: boolean;
  private readonly baseUrl: string | undefined;
  private readonly apiKey: string | undefined;

  constructor(apiUrl?: string);
  constructor(baseUrl?: string, options?: HelixClientOptions);
  constructor(http: HttpAdapter, baseUrl: string);
  constructor(first?: string | HttpAdapter, second?: string | HelixClientOptions) {
    const isHttpAdapterOverload = first !== undefined && typeof first !== 'string';
    // Only the (baseUrl?, options?) overload can carry a HelixClientOptions —
    // the (http, baseUrl) overload's `second` is a baseUrl string, not options.
    const options = !isHttpAdapterOverload && typeof second === 'object' && second !== null ? second : undefined;

    // No explicit URL, but an apiKey was given: don't fall back to offline
    // SDK-only mode, default the URL instead -- process.env.HELIX_API_URL
    // (Node) if set, else DEFAULT_ENTERPRISE_URL. Explicit URL argument
    // always wins when given.
    let resolvedUrl = typeof first === 'string' ? first : undefined;
    if (resolvedUrl === undefined && !isHttpAdapterOverload && options?.apiKey) {
      resolvedUrl =
        (typeof process !== 'undefined' && typeof process.env !== 'undefined' && process.env.HELIX_API_URL) ||
        DEFAULT_ENTERPRISE_URL;
    }

    this.sdkOnlyMode = first === undefined && resolvedUrl === undefined;
    this.apiAuditEnabled =
      !this.sdkOnlyMode &&
      (isHttpAdapterOverload
        ? 'hasAdminApiKey' in first && typeof first.hasAdminApiKey === 'function' && first.hasAdminApiKey()
        : Boolean(options?.adminApiKey));
    this.http = isHttpAdapterOverload
      ? first
      : this.sdkOnlyMode
        ? SDK_ONLY_HTTP_ADAPTER
        : new HttpAdapter(resolvedUrl as string, options ?? {});
    this.baseUrl = !isHttpAdapterOverload && resolvedUrl ? resolvedUrl.replace(/\/$/, '') : undefined;
    this.apiKey = options?.apiKey;
  }

  async createDID(options: CreateDIDOptions): Promise<CreateDIDResult> {
    const keyPair = generateKeyPair();
    const response = await this.http.post<{
      id?: string;
      did?: string;
      didDocument: DIDDocument;
      hederaTransactionId: string;
    }>('/v1/dids', {
      publicKeyHex: keyPair.publicKey,
      subjectType: options.subjectType,
      domains: options.domains ?? [],
    });
    return {
      did: response.did ?? response.id ?? response.didDocument.id,
      didDocument: response.didDocument,
      hederaTransactionId: response.hederaTransactionId,
      keyPair,
    };
  }

  async resolveDID(
    did: string,
    options?: { live?: boolean },
  ): Promise<{ did: string; didDocument: DIDDocument; source: 'cache' | 'hedera' }> {
    const query = options?.live ? '?live=true' : '';
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    const response = await this.http.get<DIDResolveResponse>(
      `/v1/dids/${encodeURIComponent(did)}${query}`,
    );
    const didDocument = response.didDocument ?? response.document ?? response;
    return {
      did,
      didDocument,
      source: options?.live ? 'hedera' : 'cache',
    };
  }

  async addServiceEndpoint(
    did: string,
    endpoint: ServiceEndpoint,
  ): Promise<{ did: string; didDocument: DIDDocument }> {
    const didDocument = await this.http.post<DIDDocument>(
      `/v1/dids/${encodeURIComponent(did)}/services`,
      endpoint,
    );
    return { did, didDocument };
  }

  async removeServiceEndpoint(
    did: string,
    endpointId: string,
  ): Promise<{ did: string; didDocument: DIDDocument }> {
    if (!this.http.delete) throw new Error('DELETE not implemented by adapter');
    const didDocument = await this.http.delete<DIDDocument>(
      `/v1/dids/${encodeURIComponent(did)}/services/${encodeURIComponent(endpointId)}`,
    );
    return { did, didDocument };
  }

  async deactivateDID(did: string, reason: string): Promise<{ did: string; deactivated: true }> {
    await this.http.post(`/v1/dids/${encodeURIComponent(did)}/deactivate`, { reason });
    return { did, deactivated: true };
  }

  async issueVC(options: IssueVCOptions): Promise<{
    vcId: string;
    vc: Record<string, unknown>;
    statusListIndex: number;
    expiresAt: string;
  }> {
    return this.http.post('/v1/vcs', {
      expiresInSeconds: 7_776_000,
      ...options,
    });
  }

  async getVC(vcId: string): Promise<VCResponse> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    return this.http.get(`/v1/vcs/${encodeURIComponent(vcId)}`);
  }

  async listVCs(filters: ListVCFilters = {}): Promise<VCSummary[]> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    return this.http.get(
      `/v1/vcs${toQueryString({
        subjectDid: filters.subjectDid,
        status: filters.status,
        limit: filters.limit,
      })}`,
    );
  }

  async revokeVC(vcId: string): Promise<VCResponse> {
    return this.http.post(`/v1/vcs/${encodeURIComponent(vcId)}/revoke`);
  }

  async renewVC(
    vcId: string,
    overrides: { privilegeScopes?: string[]; expiresInSeconds?: number } = {},
  ): Promise<VCResponse> {
    return this.http.post(`/v1/vcs/${encodeURIComponent(vcId)}/renew`, overrides);
  }

  // -- prepare/finalize: see docs/proposal-sdk-api-only.md. prepare() returns
  // an unsigned payload + hash; the caller signs the hash locally (private
  // key never leaves the client) and finalize() attaches the signature.

  async prepareDelegation(input: PrepareDelegationInput): Promise<PrepareResult> {
    return this.http.post('/v1/vcs/delegation/prepare', input);
  }

  async finalizeDelegation(input: FinalizeInput): Promise<SignedVC> {
    return this.http.post('/v1/vcs/delegation/finalize', input);
  }

  async prepareGrant(input: PrepareGrantInput): Promise<PrepareResult> {
    return this.http.post('/v1/vcs/grant/prepare', input);
  }

  async finalizeGrant(input: FinalizeInput): Promise<SignedVC> {
    return this.http.post('/v1/vcs/grant/finalize', input);
  }

  async prepareAgentRenewal(input: PrepareAgentRenewalInput): Promise<PrepareResult> {
    return this.http.post('/v1/vcs/agent-renewal/prepare', input);
  }

  async finalizeAgentRenewal(input: FinalizeInput): Promise<SignedVC> {
    return this.http.post('/v1/vcs/agent-renewal/finalize', input);
  }

  async getStatusList(listId: string): Promise<StatusListCredentialResponse> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    return this.http.get(`/v1/status-list/${encodeURIComponent(listId)}`);
  }

  async createStatusList(
    options: CreateStatusListOptions = {},
  ): Promise<StatusListCredential> {
    this.assertAPIConfigured();
    return this.http.post<StatusListCredential>('/v1/status-list', options);
  }

  async getAuditLog(filters: AuditLogFilters = {}): Promise<AuditLogEvent[]> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    return this.http.get(
      `/v1/audit-log${toQueryString({
        eventType: filters.eventType,
        since: filters.since,
        limit: filters.limit,
      })}`,
    );
  }

  async verifyVP(vp: SignedVP, options: VerifyVPOptions = {}): Promise<VerifyVPApiResult> {
    // Verification, audit logging (VP_VERIFIED/VP_REJECTED), and session
    // issuance all happen server-side (see docs/proposal-sdk-api-only.md) —
    // no local verifyVP() call, no separate SDK-side audit write. Note
    // `statusListResolver` isn't forwarded: it's a function (not
    // serializable) and only ever used as helix-api's own internal
    // same-origin-list fast path, never by an external caller.
    return this.http.post<VerifyVPApiResult>('/v1/vp/verify', {
      signedVP: vp,
      ...(options.expectedTargetService !== undefined
        ? { expectedTargetService: options.expectedTargetService }
        : {}),
      ...(options.allowSelfSigned !== undefined ? { allowSelfSigned: options.allowSelfSigned } : {}),
    });
  }

  async checkVCStatus(vc: SignedVC): Promise<'active' | 'revoked' | 'expired'> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    const response = await this.http.get<{ vcId: string; status: 'active' | 'revoked' | 'expired' }>(
      `/v1/vcs/${encodeURIComponent(vc.id)}/status`,
    );
    return response.status;
  }

  async fetchSessionPublicKey(): Promise<string> {
    if (!this.http.get) throw new Error('GET not implemented by adapter');
    const response = await this.http.get<SessionPublicKeyResponse>('/v1/sessions/public-key');
    return response.publicKeyHex;
  }

  verifySessionToken(token: string, publicKeyHex: string): HelixJWTPayload {
    return verifyJWT(token, publicKeyHex);
  }

  /**
   * Onboards an agent in one call — agent self-custody has been retired.
   * The server generates and holds the private key itself; no local
   * keypair, no wallet file, no passphrase. `enrollmentToken` must already
   * exist (see `POST /v1/enrollment-tokens`, not exposed as an SDK method —
   * it's an agent-owner action, typically taken via Console or a direct API
   * call, not something the onboarding agent itself does).
   */
  async onboardAgent(
    enrollmentToken: string,
    domains: string[] = [],
  ): Promise<{ agentDid: string; vcId: string }> {
    this.assertAPIConfigured();
    return this.http.post('/v1/onboard', { enrollmentToken, domains });
  }

  /**
   * Signs a VP on behalf of a server-custody agent — the caller never has,
   * and never can have, the private key, so this is an API call instead of
   * local VPBuilder.sign(). The server looks up the agent's active
   * HelixAgentCredential itself; pass `vcId` to pin a specific one instead
   * (e.g. right after a renewal, when more than one is active). `grantVC`
   * is an SP-issued DelegationGrantCredential the caller already holds —
   * not secret material, just data to include — for the consent-grant flow.
   */
  async signVP(
    did: string,
    targetService: string,
    options: { userDid?: string; grantVC?: SignedVC; vcId?: string } = {},
  ): Promise<SignedVP> {
    this.assertAPIConfigured();
    const body = {
      targetService,
      ...(options.userDid !== undefined ? { userDid: options.userDid } : {}),
      ...(options.grantVC !== undefined ? { grantVC: options.grantVC } : {}),
      ...(options.vcId !== undefined ? { vcId: options.vcId } : {}),
    };

    // Enterprise mode (this.apiKey set): custodial signing is
    // account-scoped, a different route + auth than core's admin-key-gated
    // /v1/agents/:did/vp -- see HelixClientOptions.apiKey's doc comment.
    if (this.apiKey) {
      if (!this.baseUrl) throw new Error('HelixClient: enterprise mode requires a baseUrl');
      const res = await fetch(`${this.baseUrl}/v1/custodial-agents/${encodeURIComponent(did)}/vp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
        body: JSON.stringify(body),
      });
      const result = (await res.json()) as { signedVP?: SignedVP; error?: { message?: string } };
      if (!res.ok || !result.signedVP) {
        throw new Error(result.error?.message ?? `signVP failed: HTTP ${res.status}`);
      }
      return result.signedVP;
    }

    const result = await this.http.post<{ signedVP: SignedVP }>(`/v1/agents/${encodeURIComponent(did)}/vp`, body);
    return result.signedVP;
  }

  async requestUserChallenge(
    userDid: string,
  ): Promise<{ challengeId: string; nonce: string; expiresAt: string }> {
    return this.http.post('/v1/challenges', { did: userDid, purpose: 'user_verification' });
  }

  async verifyUserChallenge(
    challengeId: string,
    signature: string,
  ): Promise<{ did: string; verified: true; vc?: Record<string, unknown> }> {
    return this.http.post(`/v1/challenges/${challengeId}/verify`, { signature });
  }

  __setTestHttpAdapter(adapter: HttpAdapterLike): void {
    this.http = adapter;
  }

  /**
   * Best-effort consent-grant audit. Called by {@link AgentWallet} once a grant
   * VC is safely stored; a failure here must never surface to the caller, since
   * the credential is already in the wallet either way.
   */
  async recordConsentGrantedAudit(entry: ConsentGrantedAuditEntry): Promise<void> {
    if (!this.apiAuditEnabled) {
      return;
    }

    try {
      await this.http.post('/v1/audit-log/consent-granted', {
        ...entry,
        subjectDid: entry.agentDid,
        eventType: AuditEvents.CONSENT_GRANTED,
      });
    } catch {
      // Audit writes are best-effort. The stored credential remains authoritative.
    }
  }

  private assertAPIConfigured(): void {
    if (this.sdkOnlyMode) {
      throw new SDKOnlyModeNoAPIError();
    }
  }
}
