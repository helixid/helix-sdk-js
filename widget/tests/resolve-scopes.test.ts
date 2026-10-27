// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// resolveConsentScopes: the consent screen offers the service's scopes that
// the agent holds as itself, plus accept-terms; it fails closed when the
// agent's scopes cannot be read or the two sets share nothing.

import { describe, expect, it, vi } from 'vitest';
import {
  ACCEPT_TERMS_SCOPE,
  AgentScopesLookupError,
  ConsentNoGrantableScopesError,
  humanizeScope,
  resolveConsentScopes,
  type CuratedScopeEntry,
} from '../src/server/resolve-scopes.js';

const SERVICE_DID = 'did:web:air.example';
const AGENT_DID = 'did:key:zAgent';

const AIRLINE_SCOPES: CuratedScopeEntry[] = [
  { scope: 'book:flights', label: 'Book flights', description: 'Buy tickets on your behalf' },
  { scope: 'modify:booking', label: 'Modify bookings', required: true },
  { scope: 'cancel:booking', label: '' },
];

function clientHolding(scopes: string[]) {
  return { getAgentScopes: vi.fn(async () => ({ agentDid: AGENT_DID, scopes })) };
}

function resolve(client: ReturnType<typeof clientHolding>, serviceScopes = AIRLINE_SCOPES) {
  return resolveConsentScopes({ serviceDid: SERVICE_DID, agentDid: AGENT_DID, serviceScopes, client });
}

describe('resolveConsentScopes', () => {
  it('offers the service scopes the agent holds, in the service order, plus accept-terms', async () => {
    const client = clientHolding(['modify:booking', 'book:flights', 'book:hotel']);

    const options = await resolve(client);

    expect(options.map((option) => option.scope)).toEqual(['book:flights', 'modify:booking', ACCEPT_TERMS_SCOPE]);
    expect(options[0]).toEqual({
      scope: 'book:flights',
      label: 'Book flights',
      description: 'Buy tickets on your behalf',
    });
    expect(options[1]).toMatchObject({ required: true });
    expect(client.getAgentScopes).toHaveBeenCalledWith({ serviceDid: SERVICE_DID, agentDid: AGENT_DID });
  });

  it('never offers an agent scope the service does not list (book:hotel above)', async () => {
    const options = await resolve(clientHolding(['book:flights', 'book:hotel']));
    expect(options.map((option) => option.scope)).not.toContain('book:hotel');
  });

  it('falls back to humanizeScope() for a scope with an empty label', async () => {
    const options = await resolve(clientHolding(['cancel:booking']));
    expect(options[0]).toMatchObject({ scope: 'cancel:booking', label: 'cancel booking' });
  });

  it('always appends accept-terms required and pre-checked, even if the service lists it', async () => {
    const options = await resolve(clientHolding(['book:flights', ACCEPT_TERMS_SCOPE]), [
      ...AIRLINE_SCOPES,
      { scope: ACCEPT_TERMS_SCOPE, label: 'Terms' },
    ]);
    expect(options.filter((option) => option.scope === ACCEPT_TERMS_SCOPE)).toEqual([
      { scope: ACCEPT_TERMS_SCOPE, label: 'Accept the terms and conditions', required: true, defaultChecked: true },
    ]);
  });

  it('throws ConsentNoGrantableScopesError when the agent holds none of the service scopes', async () => {
    const attempt = resolve(clientHolding(['book:hotel', ACCEPT_TERMS_SCOPE]));
    await expect(attempt).rejects.toBeInstanceOf(ConsentNoGrantableScopesError);
    await expect(attempt).rejects.toMatchObject({ code: 'CONSENT_NO_GRANTABLE_SCOPES' });
  });

  it('throws AgentScopesLookupError, never the full catalog, when the lookup fails', async () => {
    const failure = new Error('agent not found');
    const client = { getAgentScopes: vi.fn(async () => Promise.reject(failure)) };

    const attempt = resolve(client as unknown as ReturnType<typeof clientHolding>);
    await expect(attempt).rejects.toBeInstanceOf(AgentScopesLookupError);
    await expect(attempt).rejects.toMatchObject({ code: 'AGENT_SCOPES_LOOKUP_FAILED', cause: failure });
  });
});

describe('humanizeScope', () => {
  it('turns scope strings into readable labels', () => {
    expect(humanizeScope('book:flights')).toBe('book flights');
    expect(humanizeScope('modify:booking')).toBe('modify booking');
    expect(humanizeScope('accept-terms')).toBe('accept terms');
    expect(humanizeScope('read_orders')).toBe('read orders');
  });
});
