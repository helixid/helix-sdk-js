// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * The service's half of KYA-OS story L3-H in the middleware: the consent page
 * a `needs_authorization` challenge (story L3-E) points at is Helix's, and the
 * root of the agent's new chain is signed there by the user's own did:key.
 *
 * - {@link createHelixConsent}`.authorizationUrl` is the challenge's
 *   `authorizationUrl` function: per challenge it builds the unsigned root
 *   DelegationCredential (`invoker` the agent, `invocationTarget` and
 *   `parentCapability` this service, `allowedAction` the tool's scopes,
 *   `validUntil` the end of the consented window), submits it to Helix in a
 *   request this service signs, and answers the consent page URL, which the
 *   challenge proof then covers.
 * - {@link consentRetryAuthorizer} is the L3-E retry authorizer: the
 *   credential a retry carries (the signed root hop, or a chain) is verified
 *   in full by this service's local verifier (story F-2: signatures from the
 *   DIDs, status lists live, the card, attenuation), must delegate to the
 *   agent the resume token was issued to, and grants what the verifier
 *   derives. Completing consent alone never authorises a call.
 * - `withdraw(consentId)`: the user withdrew in this service's settings;
 *   Helix revokes the hops under the user's key.
 *
 * The service never holds a key able to sign as a user.
 */

import { kyaos } from '@helixid/sdk-js';
import type { ChallengeContext, ChallengeInput, RetryAuthorization, RetryAuthorizer, RetryAuthorizerInput } from './needs-authorization.js';
import type { LocalVerifier } from './verify-locally.js';

export interface HelixConsentOptions {
  /** Helix's API base URL, where the consent page lives. */
  helixUrl: string;
  /** This service's DID: the grant's target and the consent request's signer. */
  serviceDid: string;
  /** This service's Signer (the one that signs its response proofs). */
  signer: kyaos.Signer;
  /** How long the user consents for: the window each hop sits inside. */
  windowSeconds: number;
  /** Each hop's lifetime inside the window, renewed by the agent without a click; omitted, one hop covers the window. */
  hopLifetimeSeconds?: number | undefined;
  /**
   * This service's id for the user the agent acts for. Default: the caller's
   * OAuth subject. The service must know its user: an id taken from the agent's
   * word would let an agent ask consent under someone else's key.
   */
  serviceUserOf?: ((input: ChallengeInput) => string | undefined | Promise<string | undefined>) | undefined;
  display?: { serviceName?: string; agentName?: string; logoUrl?: string } | undefined;
  returnUrl?: string | undefined;
  fetch?: kyaos.consent.ConsentFetch | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  now?: (() => number) | undefined;
}

export interface HelixConsent {
  /** The challenge's `authorizationUrl`: creates a consent request at Helix for this challenge. */
  authorizationUrl(context: ChallengeContext, input: ChallengeInput): Promise<string>;
  /** Withdraws a user's consent (Helix revokes the hops under the user's key). */
  withdraw(consentId: string): Promise<kyaos.consent.WithdrawnConsent>;
}

/** Thrown by `authorizationUrl` when the service cannot say which of its users the agent acts for. */
export class ConsentUserUnknownError extends Error {
  constructor() {
    super('createHelixConsent: no service user for this call (serviceUserOf returned nothing); consent needs to know whose it is');
    this.name = 'ConsentUserUnknownError';
  }
}

export function createHelixConsent(options: HelixConsentOptions): HelixConsent {
  if (!(options.windowSeconds > 0) || !Number.isFinite(options.windowSeconds)) throw new RangeError('createHelixConsent: windowSeconds must be a positive number');
  if (options.signer.did !== options.serviceDid) throw new Error('createHelixConsent: the signer must be the service DID');
  const now = options.now ?? Date.now;
  const userOf = options.serviceUserOf ?? ((input: ChallengeInput) => input.oauthSubject);
  return {
    async authorizationUrl(context, input) {
      const serviceUserId = await userOf(input);
      if (serviceUserId === undefined || serviceUserId === '') throw new ConsentUserUnknownError();
      const created = await kyaos.consent.createConsentRequest({
        helixUrl: options.helixUrl,
        signer: options.signer,
        serviceUserId,
        grant: kyaos.consent.unsignedRootGrant({
          agentDid: context.agentDid,
          serviceDid: options.serviceDid,
          scopes: context.scopes,
          validUntil: new Date(now() + options.windowSeconds * 1000),
        }),
        ...(options.hopLifetimeSeconds === undefined ? {} : { hopLifetimeSeconds: options.hopLifetimeSeconds }),
        ...(options.display === undefined ? {} : { display: options.display }),
        ...(options.returnUrl === undefined ? {} : { returnUrl: options.returnUrl }),
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
        now: now(),
      });
      return created.authorizationUrl;
    },
    withdraw(consentId) {
      return kyaos.consent.withdrawConsent({
        helixUrl: options.helixUrl,
        signer: options.signer,
        consentId,
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
        now: now(),
      });
    },
  };
}

/**
 * The L3-E retry authorizer over the local verifier: the retry's credential
 * (one hop or a chain, root first) is verified in full, without a request
 * proof of its own (the retried call's proof authenticated the agent), with
 * every status read live; it must delegate to the agent the token was issued
 * to. Grants the verifier's effective scopes.
 */
export function consentRetryAuthorizer(verifier: Pick<LocalVerifier, 'verify'>): RetryAuthorizer {
  return async (input: RetryAuthorizerInput): Promise<RetryAuthorization> => {
    const chain = Array.isArray(input.credential) ? input.credential : [input.credential];
    const result = await verifier.verify({ proof: undefined, chain }, { requireProof: false, liveStatus: true });
    if (!result.ok) throw new Error(`the delegation did not verify: ${result.reasons.join(', ')}`);
    if (result.agentDid !== input.agentDid) throw new Error(`the delegation is for ${String(result.agentDid)}, not ${input.agentDid}`);
    return { scopes: result.effectiveScopes };
  };
}
