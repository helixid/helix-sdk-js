// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { consentRetryAuthorizer, createHelixConsent, type ChallengeInput, type LocalVerifier, type RetryAuthorization, type RetryAuthorizer } from '@helixid/mcp-middleware';
import type { kyaos } from '@helixid/sdk-js';

/** The variables `readConsentSettings` reads (story L3-H). */
export const CONSENT_VARIABLES = ['KYAOS_HELIX_CONSENT_URL', 'KYAOS_CONSENT_WINDOW_SECONDS', 'KYAOS_CONSENT_HOP_LIFETIME_SECONDS', 'KYAOS_CONSENT_USER', 'KYAOS_CONSENT_SERVICE_NAME'] as const;

export interface ConsentSettings {
  /** Helix's API base URL: the consent page and the consent API. */
  helixUrl: string;
  windowSeconds: number;
  hopLifetimeSeconds?: number;
  /** The service user for callers without an OAuth subject: a one-user demo only. */
  demoUser?: string;
  serviceName?: string;
}

function seconds(env: Readonly<Record<string, string | undefined>>, name: string): number | undefined {
  const raw = env[name]?.trim();
  if (!raw) return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name}: ${raw} is not a positive whole number of seconds`);
  return value;
}

/**
 * Story L3-H from the environment: `KYAOS_HELIX_CONSENT_URL` (Helix's API
 * base) turns the challenge's consent page into Helix's, where the user's own
 * did:key signs the root hop; `KYAOS_CONSENT_WINDOW_SECONDS` (default one
 * day), `KYAOS_CONSENT_HOP_LIFETIME_SECONDS` (each hop's life, renewed by the
 * agent without a click), `KYAOS_CONSENT_USER` (the service user when the
 * caller carries no OAuth subject: a one-user demo) and
 * `KYAOS_CONSENT_SERVICE_NAME` (the page's branding). Undefined when the URL
 * is unset; throws on anything malformed, or on another variable set without it.
 */
export function readConsentSettings(env: Readonly<Record<string, string | undefined>>): ConsentSettings | undefined {
  const helixUrl = env['KYAOS_HELIX_CONSENT_URL']?.trim();
  if (!helixUrl) {
    const stray = CONSENT_VARIABLES.slice(1).find((name) => env[name]?.trim());
    if (stray !== undefined) throw new Error(`${stray} needs KYAOS_HELIX_CONSENT_URL`);
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(helixUrl);
  } catch {
    throw new Error(`KYAOS_HELIX_CONSENT_URL: ${helixUrl} is not a URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('KYAOS_HELIX_CONSENT_URL must be http(s)');
  const windowSeconds = seconds(env, 'KYAOS_CONSENT_WINDOW_SECONDS') ?? 86_400;
  const hopLifetimeSeconds = seconds(env, 'KYAOS_CONSENT_HOP_LIFETIME_SECONDS');
  const demoUser = env['KYAOS_CONSENT_USER']?.trim();
  const serviceName = env['KYAOS_CONSENT_SERVICE_NAME']?.trim();
  return {
    helixUrl: helixUrl.replace(/\/+$/, ''),
    windowSeconds,
    ...(hopLifetimeSeconds === undefined ? {} : { hopLifetimeSeconds }),
    ...(demoUser ? { demoUser } : {}),
    ...(serviceName ? { serviceName } : {}),
  };
}

/** The challenge's consent page and retry authorizer over Helix (story L3-H); the verifier is read when a retry arrives. */
export function consentFromSettings(
  settings: ConsentSettings,
  serviceDid: string,
  signer: kyaos.Signer,
  verifierOf: () => Pick<LocalVerifier, 'verify'> | undefined,
): { authorizationUrl: ReturnType<typeof createHelixConsent>['authorizationUrl']; authorizer: RetryAuthorizer } {
  const consent = createHelixConsent({
    helixUrl: settings.helixUrl,
    serviceDid,
    signer,
    windowSeconds: settings.windowSeconds,
    ...(settings.hopLifetimeSeconds === undefined ? {} : { hopLifetimeSeconds: settings.hopLifetimeSeconds }),
    ...(settings.serviceName === undefined ? {} : { display: { serviceName: settings.serviceName } }),
    serviceUserOf: (input: ChallengeInput) => input.oauthSubject ?? settings.demoUser,
  });
  return {
    authorizationUrl: consent.authorizationUrl,
    authorizer: async (input): Promise<RetryAuthorization> => {
      const verifier = verifierOf();
      if (verifier === undefined) throw new Error('no local verifier: the retry cannot be verified here');
      return consentRetryAuthorizer(verifier)(input);
    },
  };
}

export function describeConsent(settings: ConsentSettings | undefined): string {
  if (settings === undefined) return 'off (set KYAOS_HELIX_CONSENT_URL)';
  return `Helix ${settings.helixUrl}, window ${settings.windowSeconds} s${settings.hopLifetimeSeconds === undefined ? '' : `, hops ${settings.hopLifetimeSeconds} s`}${settings.demoUser === undefined ? '' : `, demo user ${settings.demoUser}`}`;
}
