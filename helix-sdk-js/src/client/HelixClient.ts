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
   * option is what selects it. Every call then sends it as the bearer
   * token (enterprise has no admin key), and signVP()/delegateAuthority()
   * talk to /v1/custodial-agents/:did/... instead of core's
   * /v1/agents/:did/.... See helix-server-enterprise's
   * POST /v1/account/api-keys. No email/password, no login call -- an
   * agent process holds only this, the same way an OSS agent holds only
   * `adminApiKey`.
   */
  apiKey?: string;
}

// -- Service Providers (custodial, like agents) ----------------------------

export interface CreateServiceInput {
  /** Short handle, also the `targetService` a VP names. Unique per server. */
  serviceName: string;
  displayName: string;
  /** Origin the service is reachable at, e.g. https://sp.example. */
  verifiedDomain: string;
  apiEndpoint?: string;
}

export interface IssueServiceDelegationGrantInput {
  /** The service granting on the user's behalf -- the grant's `issuer`. */
  serviceDid: string;
  /** The agent the user is delegating to -- the grant's subject. */
  agentDid: string;
  /** The consenting user, recorded as given (never resolved). */
  userDid: string;
  scopes: string[];
  /** `standing` (default, ~10 years) or `session` (24 hours). */
  durability?: 'standing' | 'session';
  /**
   * Also revoke every other grant this service holds for the same user and
   * agent, so the new one is the only consent that stands. Off by default:
   * a consent with a different scope set is added beside the existing ones,
   * and consenting again to exactly the same scopes refreshes that grant.
   */
  revokeExisting?: boolean;
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

/** Used only when apiKey is given with no explicit URL — see the constructor. The hosted HelixID enterprise API. */
const DEFAULT_ENTERPRISE_URL = 'https://api.helixid.dev';

export class HelixClient {
  private http: HttpAdapterLike;
  private readonly sdkOnlyMode: boolean;
  private readonly apiAuditEnabled: boolean;
  private readonly apiKey: string | undefined;

  constructor(apiUrl?: string);
  constructor(baseUrl?: string, options?: HelixClientOptions);
  constructor(options?: HelixClientOptions);
  constructor(first?: string | HelixClientOptions, second?: HelixClientOptions) {
    const options =
      typeof first === 'object' && first !== null
        ? first
        : typeof second === 'object' && second !== null
          ? second
          : undefined;

    // No explicit URL, but an apiKey was given: don't fall back to offline
    // SDK-only mode, default the URL instead -- DEFAULT_ENTERPRISE_URL.
    // Explicit URL argument always wins when given; ambient env vars are not
    // consulted here (pass the URL explicitly to override the default).
    let resolvedUrl = typeof first === 'string' ? first : undefined;
    if (resolvedUrl === undefined && options?.apiKey) {
      resolvedUrl = DEFAULT_ENTERPRISE_URL;
    }

    this.sdkOnlyMode = resolvedUrl === undefined;
    // Enterprise's /v1/audit-log/consent-granted takes an account, so an
    // API key enables the consent audit write just as the admin key does.
    this.apiAuditEnabled = !this.sdkOnlyMode && Boolean(options?.adminApiKey || options?.apiKey);
    // The adapter sends whichever credential was given on every call, so
    // enterprise (apiKey) and core (adminApiKey) differ only in which routes
    // a method targets, never in how it authenticates.
    this.http = this.sdkOnlyMode ? SDK_ONLY_HTTP_ADAPTER : new HttpAdapter(resolvedUrl as string, options ?? {});
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

  /**
   * Registers a VC that was signed outside the platform (an SP-signed
   * DelegationGrantCredential, typically) so the server holds it and can
   * list/revoke/renew it. The server verifies the proof. Distinct from
   * {@link issueVC}, which has the platform sign a new VC. Idempotent by
   * vc id.
   */
  async registerVC(vc: SignedVC): Promise<{ vcId: string; alreadyRegistered: boolean }> {
    this.assertAPIConfigured();
    return this.http.post('/v1/vcs/register', { vc });
  }

  // -- Service Providers ---------------------------------------------------
  // Services hold no keys: the server mints the service DID, keeps its key,
  // and signs consent grants on the service's behalf. Same custody model as
  // agents (onboardAgent/signVP/delegateAuthority), so both are API calls.

  /** Enroll a service (self-hosted servers; hosted accounts enroll through the console/account API). */
  async createService(input: CreateServiceInput): Promise<{ serviceDid: string; serviceName: string }> {
    this.assertAPIConfigured();
    return this.http.post('/v1/services', input);
  }

  /**
   * Issues a DelegationGrantCredential from `serviceDid` to `agentDid` on
   * `userDid`'s behalf: built, signed with the service's server-held key
   * and stored with a revocable status-list entry, in one call. Revoke it
   * with {@link revokeVC}.
   */
  async issueServiceDelegationGrant(input: IssueServiceDelegationGrantInput): Promise<SignedVC> {
    this.assertAPIConfigured();
    const result = await this.http.post<{ grantVC: SignedVC }>('/v1/service-delegation-grants', input);
    return result.grantVC;
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
   * (e.g. right after a renewal, when more than one is active).
   *
   * `targetService` is the DID of the service the VP is for. With a
   * `userDid` the agent is acting on that user's behalf, and the server
   * attaches every active DelegationGrantCredential that service issued to
   * this agent for that user; none at all fails with
   * CONSENT_GRANT_NOT_FOUND, meaning the user has not consented yet. A
   * caller that already holds a grant may pass it as `grantVC` instead of
   * having it looked up.
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
    // account-scoped, so it targets /v1/custodial-agents/:did/vp instead of
    // core's admin-key-gated /v1/agents/:did/vp. The bearer token itself is
    // sent by HttpAdapter, like every other call -- so errors map to typed
    // HelixErrors here too, not a bare Error.
    const result = await this.http.post<{ signedVP: SignedVP }>(
      `/v1/${this.agentRoutePrefix()}/${encodeURIComponent(did)}/vp`,
      body,
    );
    return result.signedVP;
  }

  /**
   * Delegates a slice of a server-custody agent's authority to another DID —
   * the custodial counterpart to the (now-defunct, see delegation.ts)
   * wallet-based delegate(), which needed the delegator's own private key
   * and so has had nothing legitimate to call since agent self-custody was
   * retired. Same trust boundary as signVP(): the caller never has, and
   * never can have, the delegator's private key, so this is an API call
   * that authorizes HelixID to sign on the delegator's behalf, not a local
   * signature.
   *
   * Mirrors signVP()'s two modes exactly: enterprise (this.apiKey set) hits
   * the account-scoped custodial route; core/OSS hits the admin-key-gated
   * route. Pass `vcId` to pin which of the delegator's active credentials to
   * delegate from (e.g. it already holds more than one, ambiguous to the
   * default subject-only lookup).
   */
  async delegateAuthority(
    did: string,
    to: string,
    scopes: string[],
    expiresIn: number,
    options: { vcId?: string; revokeExisting?: boolean } = {},
  ): Promise<SignedVC> {
    this.assertAPIConfigured();
    const body = {
      to,
      scopes,
      expiresIn,
      ...(options.vcId !== undefined ? { vcId: options.vcId } : {}),
      // Same rule as every stored credential: the same scopes delegated
      // again refresh the earlier delegation, other scopes stand beside it,
      // revokeExisting clears the others.
      ...(options.revokeExisting !== undefined ? { revokeExisting: options.revokeExisting } : {}),
    };

    const result = await this.http.post<{ delegatedVC: SignedVC }>(
      `/v1/${this.agentRoutePrefix()}/${encodeURIComponent(did)}/delegate`,
      body,
    );
    return result.delegatedVC;
  }

  /** Where custodial agent actions live: enterprise's account-scoped routes, or core's admin-key-gated ones. */
  private agentRoutePrefix(): 'custodial-agents' | 'agents' {
    return this.apiKey ? 'custodial-agents' : 'agents';
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
