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
 * The consent flow of KYA-OS story L3-H, both sides, over Helix's consent
 * API. The root of an agent's chain is signed by the user's own did:key on
 * the Helix-hosted consent page; neither the service nor the SDK ever holds
 * a key able to sign as the user.
 *
 * Service side (the middleware uses these):
 * - {@link createConsentRequest}: submits the unsigned root
 *   DelegationCredential for one of the service's users in a request the
 *   service signs (`helix-consent-request+jwt`); answers the consent page
 *   URL, the `authorizationUrl` of the signed `needs_authorization`
 *   challenge (story L3-E).
 * - {@link withdrawConsent}: the user withdrew in the service's settings;
 *   Helix revokes the hops under the user's key.
 *
 * Agent side:
 * - {@link awaitConsentHop}: once the user approved, the signed root hop, read
 *   from the consent request the (verified) `authorizationUrl` names, and
 *   checked by {@link verifyConsentHop}: its issuer is a did:key whose
 *   signature verifies from the DID alone, it delegates to this agent at this
 *   service, it is a root.
 * - {@link ConsentHopKeeper}: stores the hop as the root of the agent's chain
 *   (CredentialStore, story F-1) and renews it before it expires
 *   ({@link renewBefore}), inside the consented window, without a click
 *   (`helix-consent-renewal+jwt`, signed by the agent's own key). A renewal
 *   asking for more than was consented is `step_up_required`.
 *
 * Self-custody invariant (rule 7): every request carries a JWS, never key
 * material; signing goes through the Signer.
 */

import { ConsentFlowError } from '../HelixError.js';
import type { CredentialStore, StoredCredential } from '../credential-store.js';
import { signJws, type DidResolver } from './jws.js';
import type { Signer } from './signer.js';
import { evaluateDelegationChain, invokerOf, isDelegationHop } from './verifier/credentials.js';
import { verifyDataIntegrity } from './verifier/data-integrity.js';
import { didKeyDocument } from './verifier/resolve.js';

export const CONSENT_REQUEST_TYP = 'helix-consent-request+jwt';
export const CONSENT_RENEWAL_TYP = 'helix-consent-renewal+jwt';
export const CONSENT_WITHDRAWAL_TYP = 'helix-consent-withdrawal+jwt';

/** Renew a hop this long before its `validUntil` by default. */
export const DEFAULT_RENEW_MARGIN_SECONDS = 60;

export const ConsentReasons = {
  REQUEST_REFUSED: 'consent_request_refused',
  HOP_INVALID: 'consent_hop_invalid',
  NOT_APPROVED: 'consent_not_approved',
  TIMEOUT: 'consent_timeout',
  STEP_UP_REQUIRED: 'step_up_required',
  WINDOW_ENDED: 'consent_window_ended',
  WITHDRAWN: 'consent_withdrawn',
  RENEWAL_REFUSED: 'consent_renewal_refused',
  WITHDRAWAL_REFUSED: 'consent_withdrawal_refused',
  URL_INVALID: 'consent_url_invalid',
  /** Helix could not be reached (the request never got an answer). */
  UNREACHABLE: 'consent_unreachable',
} as const;
export type ConsentReason = (typeof ConsentReasons)[keyof typeof ConsentReasons];

export type ConsentFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/** A root DelegationCredential with its proof, as the consent page signs it. */
export type ConsentHop = StoredCredential & {
  issuer: string;
  validUntil: string;
  credentialSubject: { id: string; invoker: string; invocationTarget: string; parentCapability: string; allowedAction: string[]; [member: string]: unknown };
};

export interface UnsignedRootGrantInput {
  agentDid: string;
  serviceDid: string;
  scopes: readonly string[];
  /** The end of the consented window. */
  validUntil: Date | string;
  caveats?: ReadonlyArray<Record<string, unknown>> | undefined;
}

/** The unsigned root DelegationCredential a service fills from its catalog (SPEC.md §6.10; L3-H point 2). */
export function unsignedRootGrant(input: UnsignedRootGrantInput): Record<string, unknown> {
  return {
    validUntil: typeof input.validUntil === 'string' ? input.validUntil : input.validUntil.toISOString(),
    credentialSubject: {
      invoker: input.agentDid,
      invocationTarget: input.serviceDid,
      parentCapability: input.serviceDid,
      allowedAction: [...input.scopes],
      ...(input.caveats === undefined ? {} : { caveats: input.caveats.map((caveat) => ({ ...caveat })) }),
    },
  };
}

const defaultFetch: ConsentFetch = (url, init) => globalThis.fetch(url, init as RequestInit) as unknown as ReturnType<ConsentFetch>;

const trimSlash = (url: string): string => url.replace(/\/+$/, '');

async function signedRequest(body: Record<string, unknown>, signer: Signer, typ: string, audience: string, now: number): Promise<string> {
  const claims = { ...body, iss: signer.did, aud: audience, iat: Math.floor(now / 1000), jti: `urn:uuid:${globalThis.crypto.randomUUID()}` };
  return signJws(claims, signer, { header: { typ } });
}

interface HelixErrorBody {
  error?: { code?: string; message?: string; details?: Record<string, unknown> };
}

async function post(fetch: ConsentFetch, url: string, request: string): Promise<{ ok: boolean; status: number; body: unknown }> {
  let response: Awaited<ReturnType<ConsentFetch>>;
  try {
    response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request }) });
  } catch (error) {
    // No answer at all: an outage, never a refusal.
    throw new ConsentFlowError(ConsentReasons.UNREACHABLE, `Helix could not be reached: ${error instanceof Error ? error.message : String(error)}`, 503);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return { ok: response.ok, status: response.status, body };
}

function refusal(reason: ConsentReason, what: string, status: number, body: unknown): ConsentFlowError {
  const error = (body as HelixErrorBody | undefined)?.error;
  return new ConsentFlowError(reason, `${what}: ${error?.code ?? status} ${error?.message ?? ''}`.trim(), status, typeof error?.code === 'string' ? error.code : undefined);
}

export interface CreateConsentRequestOptions {
  /** Helix's API base URL. */
  helixUrl: string;
  /** The service's Signer: the request is signed by the service DID, which must be the grant's target. */
  signer: Signer;
  /** The service's own id for its user (Helix keeps only a digest of it with the service DID). */
  serviceUserId: string;
  grant: Record<string, unknown>;
  /** Each hop's lifetime inside the window; omitted, one hop covers the window. */
  hopLifetimeSeconds?: number | undefined;
  display?: { serviceName?: string; agentName?: string; logoUrl?: string } | undefined;
  /** Where the page sends the user back, with `consent=approved|denied&request=<id>`. */
  returnUrl?: string | undefined;
  fetch?: ConsentFetch | undefined;
  now?: number | undefined;
}

export interface CreatedConsentRequest {
  id: string;
  authorizationUrl: string;
  resultUrl: string;
  expiresAt: number;
  status: 'pending';
}

/** Service side: `POST /v1/consent/requests`. */
export async function createConsentRequest(options: CreateConsentRequestOptions): Promise<CreatedConsentRequest> {
  const base = trimSlash(options.helixUrl);
  const audience = `${base}/v1/consent/requests`;
  const body: Record<string, unknown> = {
    serviceUserId: options.serviceUserId,
    grant: options.grant,
    ...(options.hopLifetimeSeconds === undefined ? {} : { hopLifetimeSeconds: options.hopLifetimeSeconds }),
    ...(options.display === undefined ? {} : { display: options.display }),
    ...(options.returnUrl === undefined ? {} : { returnUrl: options.returnUrl }),
  };
  const request = await signedRequest(body, options.signer, CONSENT_REQUEST_TYP, audience, options.now ?? Date.now());
  const response = await post(options.fetch ?? defaultFetch, audience, request);
  if (!response.ok) throw refusal(ConsentReasons.REQUEST_REFUSED, 'Helix refused the consent request', response.status, response.body);
  const created = response.body as Partial<CreatedConsentRequest> | undefined;
  if (typeof created?.id !== 'string' || typeof created.authorizationUrl !== 'string') {
    throw new ConsentFlowError(ConsentReasons.REQUEST_REFUSED, 'Helix answered the consent request without an authorizationUrl', 502);
  }
  return created as CreatedConsentRequest;
}

export interface WithdrawConsentOptions {
  helixUrl: string;
  signer: Signer;
  consentId: string;
  fetch?: ConsentFetch | undefined;
  now?: number | undefined;
}

export interface WithdrawnConsent {
  consentId: string;
  withdrawn: string[];
  userDid: string;
  revoked: string[];
}

/** Service side: `POST /v1/consent/withdrawals`. Helix revokes every live hop of the consent under the user's key. */
export async function withdrawConsent(options: WithdrawConsentOptions): Promise<WithdrawnConsent> {
  const audience = `${trimSlash(options.helixUrl)}/v1/consent/withdrawals`;
  const request = await signedRequest({ consentId: options.consentId }, options.signer, CONSENT_WITHDRAWAL_TYP, audience, options.now ?? Date.now());
  const response = await post(options.fetch ?? defaultFetch, audience, request);
  if (!response.ok) throw refusal(ConsentReasons.WITHDRAWAL_REFUSED, 'Helix refused the withdrawal', response.status, response.body);
  return response.body as WithdrawnConsent;
}

/**
 * Where Helix answers for the consent request an `authorizationUrl` names:
 * the page `<API>/consent/<id>` → `<API>/v1/consent/requests/<id>`.
 */
export function consentResultUrl(authorizationUrl: string): string {
  let url: URL;
  try {
    url = new URL(authorizationUrl);
  } catch {
    throw new ConsentFlowError(ConsentReasons.URL_INVALID, `not a URL: ${authorizationUrl}`);
  }
  const match = /^(.*)\/consent\/([^/]+)$/.exec(url.pathname);
  if (match === null || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
    throw new ConsentFlowError(ConsentReasons.URL_INVALID, `not a Helix consent page URL: ${authorizationUrl}`);
  }
  return `${url.origin}${match[1]}/v1/consent/requests/${match[2]}`;
}

/** The API base URL of the Helix deployment whose consent page `authorizationUrl` is. */
export function helixUrlOf(authorizationUrl: string): string {
  const result = consentResultUrl(authorizationUrl);
  return result.slice(0, result.indexOf('/v1/consent/requests/'));
}

export interface ConsentResult {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  expiresAt: number;
  consentId?: string;
  hop?: unknown;
  windowUntil?: number;
}

/** `GET /v1/consent/requests/:id` for the request `authorizationUrl` names. */
export async function fetchConsentResult(authorizationUrl: string, fetch: ConsentFetch = defaultFetch): Promise<ConsentResult> {
  const response = await fetch(consentResultUrl(authorizationUrl), { method: 'GET' });
  const body = await response.json().catch(() => undefined);
  if (!response.ok) throw refusal(ConsentReasons.NOT_APPROVED, 'Helix has no such consent request', response.status, body);
  return body as ConsentResult;
}

export interface VerifyConsentHopOptions {
  agentDid: string;
  serviceDid: string;
  /** Milliseconds since the epoch; default `Date.now()`. */
  now?: number | undefined;
}

/** A did:key resolves from the DID alone; nothing else is looked up. */
const didKeyOnly: DidResolver = async (did) => (did.startsWith('did:key:') ? didKeyDocument(did) : undefined);

/**
 * The root hop the consent page signed, checked before the agent stores or
 * carries it: a §6.10 hop whose issuer is a did:key and whose proof verifies
 * from that DID alone (no lookup, no hosting), delegating to `agentDid` at
 * `serviceDid` as a root, not yet expired. Throws ConsentFlowError.
 */
export async function verifyConsentHop(value: unknown, options: VerifyConsentHopOptions): Promise<ConsentHop> {
  const invalid = (message: string): never => {
    throw new ConsentFlowError(ConsentReasons.HOP_INVALID, message);
  };
  if (!isDelegationHop(value)) return invalid('not a DelegationCredential');
  const hop = value as unknown as ConsentHop;
  if (typeof hop.issuer !== 'string' || !hop.issuer.startsWith('did:key:')) invalid('the root issuer must be the user did:key');
  if (invokerOf(hop as never) !== options.agentDid) invalid(`the hop delegates to ${String(invokerOf(hop as never))}, not ${options.agentDid}`);
  if (hop.credentialSubject.invocationTarget !== options.serviceDid) invalid(`the hop targets ${hop.credentialSubject.invocationTarget}, not ${options.serviceDid}`);
  const evaluation = evaluateDelegationChain([hop], { now: options.now ?? Date.now(), resource: options.serviceDid });
  if (!evaluation.ok) invalid(`the hop is not a valid root: ${evaluation.reasons.join(', ')}`);
  const proof = await verifyDataIntegrity(hop as unknown as Record<string, unknown>, didKeyOnly);
  if (!proof.ok) invalid(`the user's signature does not verify: ${proof.reason}`);
  if (Date.parse(hop.validUntil) <= (options.now ?? Date.now())) invalid('the hop has expired');
  return hop;
}

export interface AwaitConsentHopOptions extends VerifyConsentHopOptions {
  fetch?: ConsentFetch | undefined;
  /** Between polls; default 1000 ms. */
  intervalMs?: number | undefined;
  /** Give up after; default 300,000 ms. */
  timeoutMs?: number | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
}

export interface ApprovedConsent {
  consentId: string;
  hop: ConsentHop;
  /** The end of the consented window, Unix seconds. */
  windowUntil: number;
  /** Helix's API base URL, for renewals. */
  helixUrl: string;
}

/**
 * Agent side: polls the consent request the challenge's (verified)
 * `authorizationUrl` names until the user decided, and returns the signed
 * root hop once checked. Throws when the user declined, the request expired,
 * or the time ran out.
 */
export async function awaitConsentHop(authorizationUrl: string, options: AwaitConsentHopOptions): Promise<ApprovedConsent> {
  const fetch = options.fetch ?? defaultFetch;
  const interval = options.intervalMs ?? 1000;
  const sleep = options.sleep ?? ((ms: number): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = Date.now() + (options.timeoutMs ?? 300_000);
  for (;;) {
    const result = await fetchConsentResult(authorizationUrl, fetch);
    if (result.status === 'approved' && result.hop !== undefined && result.consentId !== undefined) {
      const hop = await verifyConsentHop(result.hop, options);
      return { consentId: result.consentId, hop, windowUntil: result.windowUntil ?? Math.floor(Date.parse(hop.validUntil) / 1000), helixUrl: helixUrlOf(authorizationUrl) };
    }
    if (result.status === 'denied' || result.status === 'expired') {
      throw new ConsentFlowError(ConsentReasons.NOT_APPROVED, `the consent request is ${result.status}`, 403);
    }
    if (Date.now() >= deadline) throw new ConsentFlowError(ConsentReasons.TIMEOUT, 'the user did not decide in time', 408);
    await sleep(interval);
  }
}

export interface RenewConsentHopOptions {
  helixUrl: string;
  consentId: string;
  /** The agent's Signer: only the agent the consent names may renew. */
  signer: Signer;
  /** A narrower set of scopes; wider is `step_up_required`. */
  allowedAction?: readonly string[] | undefined;
  serviceDid: string;
  fetch?: ConsentFetch | undefined;
  now?: number | undefined;
}

/** Agent side: `POST /v1/consent/renewals`. The fresh hop is checked like the first. */
export async function renewConsentHop(options: RenewConsentHopOptions): Promise<{ hop: ConsentHop; windowUntil: number }> {
  const audience = `${trimSlash(options.helixUrl)}/v1/consent/renewals`;
  const body = { consentId: options.consentId, ...(options.allowedAction === undefined ? {} : { allowedAction: [...options.allowedAction] }) };
  const request = await signedRequest(body, options.signer, CONSENT_RENEWAL_TYP, audience, options.now ?? Date.now());
  const response = await post(options.fetch ?? defaultFetch, audience, request);
  if (!response.ok) {
    const code = (response.body as HelixErrorBody | undefined)?.error?.code;
    const reason =
      code === 'CONSENT_STEP_UP_REQUIRED'
        ? ConsentReasons.STEP_UP_REQUIRED
        : code === 'CONSENT_WINDOW_ENDED'
          ? ConsentReasons.WINDOW_ENDED
          : code === 'CONSENT_WITHDRAWN'
            ? ConsentReasons.WITHDRAWN
            : ConsentReasons.RENEWAL_REFUSED;
    throw refusal(reason, 'Helix refused the renewal', response.status, response.body);
  }
  const renewed = response.body as { hop?: unknown; windowUntil?: number };
  const hop = await verifyConsentHop(renewed.hop, { agentDid: options.signer.did, serviceDid: options.serviceDid, ...(options.now === undefined ? {} : { now: options.now }) });
  return { hop, windowUntil: renewed.windowUntil ?? Math.floor(Date.parse(hop.validUntil) / 1000) };
}

/**
 * When to renew a hop that is valid until `validUntil`: `marginSeconds`
 * before it ends (never before now). Milliseconds since the epoch.
 */
export function renewBefore(validUntil: string | Date, marginSeconds: number = DEFAULT_RENEW_MARGIN_SECONDS, now: number = Date.now()): number {
  const until = typeof validUntil === 'string' ? Date.parse(validUntil) : validUntil.getTime();
  if (Number.isNaN(until)) throw new ConsentFlowError(ConsentReasons.HOP_INVALID, 'validUntil is not a date-time');
  return Math.max(now, until - marginSeconds * 1000);
}

export interface ConsentHopKeeperOptions {
  store: CredentialStore;
  signer: Signer;
  serviceDid: string;
  consent: ApprovedConsent;
  marginSeconds?: number | undefined;
  fetch?: ConsentFetch | undefined;
  clock?: (() => number) | undefined;
}

/**
 * Keeps an agent's consent hop for one service: stores the root hop in the
 * CredentialStore (where `presentChain({invocationTarget})` finds it), and
 * renews it when {@link renewBefore} says so, as long as the consented window
 * allows. `chain()` is what a request carries.
 */
export class ConsentHopKeeper {
  readonly #options: ConsentHopKeeperOptions;
  readonly #clock: () => number;
  #hop: ConsentHop;

  constructor(options: ConsentHopKeeperOptions) {
    this.#options = options;
    this.#clock = options.clock ?? Date.now;
    this.#hop = options.consent.hop;
    options.store.addHop(this.#hop);
  }

  get hop(): ConsentHop {
    return this.#hop;
  }

  get consentId(): string {
    return this.#options.consent.consentId;
  }

  /** The current hop, renewed first when it is due and the window still allows it. */
  async current(): Promise<ConsentHop> {
    const now = this.#clock();
    const windowEnd = this.#options.consent.windowUntil * 1000;
    if (now >= renewBefore(this.#hop.validUntil, this.#options.marginSeconds, now) && now < windowEnd && Date.parse(this.#hop.validUntil) < windowEnd) {
      await this.renew();
    }
    return this.#hop;
  }

  /** Renews now: the new hop replaces the old one in the store. */
  async renew(allowedAction?: readonly string[]): Promise<ConsentHop> {
    const renewed = await renewConsentHop({
      helixUrl: this.#options.consent.helixUrl,
      consentId: this.#options.consent.consentId,
      signer: this.#options.signer,
      serviceDid: this.#options.serviceDid,
      ...(allowedAction === undefined ? {} : { allowedAction }),
      ...(this.#options.fetch === undefined ? {} : { fetch: this.#options.fetch }),
      now: this.#clock(),
    });
    this.#options.store.removeHop(this.#hop.id);
    this.#options.store.addHop(renewed.hop);
    this.#hop = renewed.hop;
    return renewed.hop;
  }

  /** The chain to carry at this service, root first: here, the one root hop. */
  async chain(): Promise<ConsentHop[]> {
    return [await this.current()];
  }
}
