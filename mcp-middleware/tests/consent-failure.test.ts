// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

// A consent request Helix refuses or cannot take never becomes a 500: the caller's refusal is a 403
// insufficient_scope (audited as a denial), Helix's outage a 503-style AuthorizationServerUnavailableError.
import { describe, expect, it, vi } from 'vitest';
import { kyaos, generateKeyPair } from '@helixid/sdk-js';
import { helixidMCPMiddleware } from '../src/middleware.js';
import { createHelixConsent } from '../src/helix-consent.js';
import { createNeedsAuthorization } from '../src/needs-authorization.js';
import { MemoryResumeTokenStore } from '../src/resume-token-store.js';
import { consentFailureOf } from '../src/needs-authorization-guard.js';
import { AuthorizationServerUnavailableError, ToolScopeError } from '../src/errors.js';
import { toHttpErrorResponse } from '../src/metadata.js';
import type { ToolAuditEvent } from '../src/audit.js';

const HELIX = 'https://helix.example';
const SERVICE = 'did:web:shop.example:services:aa';
const signer = new kyaos.EnvSigner({ did: SERVICE, envVar: 'K', env: { K: generateKeyPair().privateKey } });
const CALL = { name: 'refund_order', input: { orderId: 'ORD-1' }, headers: { authorization: 'Bearer t' } };

/** A guard whose consent requests go to `fetch`; the caller is an OAuth subject holding orders:read only. */
function guardWith(fetch: kyaos.consent.ConsentFetch) {
  const events: ToolAuditEvent[] = [];
  const consent = createHelixConsent({ helixUrl: HELIX, serviceDid: SERVICE, signer, windowSeconds: 60, fetch });
  const guard = helixidMCPMiddleware({
    validateOAuthToken: async () => ({ sub: 'user-1', scopes: ['orders:read'] }),
    toolScopes: { refund_order: ['orders:admin'] },
    needsAuthorization: createNeedsAuthorization({ authorizationUrl: consent.authorizationUrl, store: new MemoryResumeTokenStore() }),
    auditSink: (event) => {
      events.push(event);
    },
  });
  return { guard, events };
}

const answering = (status: number, body: unknown): kyaos.consent.ConsentFetch => vi.fn(async () => ({ ok: status < 300, status, json: async () => body }));

describe('a refused or failed consent request', () => {
  it('Helix refuses because of the caller (agent not attested): 403 insufficient_scope with the reason, audited as a denial', async () => {
    const { guard, events } = guardWith(answering(403, { error: { code: 'CONSENT_GRANT_SCOPE_NOT_ALLOWED', message: 'the agent is not attested for: orders:admin' } }));
    const error = await guard(CALL).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ToolScopeError);
    expect((error as ToolScopeError).message).toBe('Required scope: orders:admin. Helix refused the consent request: CONSENT_GRANT_SCOPE_NOT_ALLOWED the agent is not attested for: orders:admin');
    const http = toHttpErrorResponse(error, { resourceMetadataUrl: 'https://shop.example/.well-known/oauth-protected-resource' })!;
    expect(http.status).toBe(403);
    expect(http.body.error).toBe('insufficient_scope');
    expect(http.headers['WWW-Authenticate']).toContain('scope="orders:admin"');
    expect(events).toEqual([expect.objectContaining({ event: 'AUTHZ_DENIED', requiredScope: 'orders:admin', reason: 'consent_refused: CONSENT_GRANT_SCOPE_NOT_ALLOWED', oauthSubject: 'user-1' })]);
  });

  it('Helix does not know the agent (DID_NOT_FOUND) is the caller too', async () => {
    const { guard } = guardWith(answering(404, { error: { code: 'DID_NOT_FOUND', message: 'Delegatee is not a known agent' } }));
    await expect(guard(CALL)).rejects.toBeInstanceOf(ToolScopeError);
  });

  it('Helix failing (5xx) or unreachable is an outage, never a 401/403, and is not audited as a denial', async () => {
    for (const fetch of [
      answering(503, { error: { code: 'SERVICE_UNAVAILABLE' } }),
      vi.fn(async () => {
        throw new TypeError('fetch failed');
      }) as unknown as kyaos.consent.ConsentFetch,
    ]) {
      const { guard, events } = guardWith(fetch);
      const error = await guard(CALL).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(AuthorizationServerUnavailableError);
      expect((error as Error).message).toMatch(/^Helix's consent service is unavailable: /);
      expect(toHttpErrorResponse(error, { resourceMetadataUrl: 'https://x' })).toBeUndefined();
      expect(events).toEqual([]);
    }
  });

  it('a refusal that is the service’s own doing (unknown service) stays a server error', async () => {
    const { guard } = guardWith(answering(403, { error: { code: 'CONSENT_SERVICE_UNKNOWN', message: 'not a service of a hosted account' } }));
    const error = await guard(CALL).catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'CONSENT_FLOW_FAILED', helixCode: 'CONSENT_SERVICE_UNKNOWN' });
    expect(toHttpErrorResponse(error, { resourceMetadataUrl: 'https://x' })).toBeUndefined();
  });
});

describe('consentFailureOf', () => {
  const flow = (reason: string, httpStatus: number, helixCode?: string) => ({ code: 'CONSENT_FLOW_FAILED', reason, httpStatus, helixCode, message: 'm' });
  it('sorts consent errors into refused, unavailable or neither', () => {
    expect(consentFailureOf(flow('consent_request_refused', 403, 'CONSENT_NO_GRANTABLE_SCOPES'))).toEqual({ kind: 'refused', helixCode: 'CONSENT_NO_GRANTABLE_SCOPES', message: 'm' });
    expect(consentFailureOf(flow('consent_unreachable', 503))).toEqual({ kind: 'unavailable', message: 'm' });
    expect(consentFailureOf(flow('consent_request_refused', 502))).toMatchObject({ kind: 'unavailable' });
    expect(consentFailureOf(flow('consent_request_refused', 408))).toMatchObject({ kind: 'unavailable' });
    expect(consentFailureOf(flow('consent_request_refused', 429))).toMatchObject({ kind: 'unavailable' });
    expect(consentFailureOf({ code: 'CONSENT_FLOW_FAILED', reason: 'consent_unreachable' })).toEqual({ kind: 'unavailable', message: 'consent flow failed' });
    expect(consentFailureOf({ code: 'CONSENT_FLOW_FAILED' })).toBeUndefined();
    expect(consentFailureOf(flow('consent_request_refused', 403))).toBeUndefined();
    expect(consentFailureOf(flow('consent_hop_invalid', 400, 'CONSENT_GRANT_SCOPE_NOT_ALLOWED'))).toBeUndefined();
    expect(consentFailureOf(new Error('x'))).toBeUndefined();
    expect(consentFailureOf(null)).toBeUndefined();
  });
});
