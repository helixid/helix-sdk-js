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

import type { CuratedScopeEntry, ScopeOption } from '../types.js';

export type { CuratedScopeEntry, ScopeOption } from '../types.js';

/**
 * The T&C scope. Folded into grant scopes rather than carried as a separate
 * field (consolidated log §4.4), and appended by this resolver rather than
 * listed in any SP's curated catalog (register D8).
 */
export const ACCEPT_TERMS_SCOPE = 'accept-terms';

/**
 * Where the agent's own scopes come from. `HelixClient` from
 * `@helixid/sdk-js` satisfies this as is.
 */
export interface AgentScopesSource {
  getAgentScopes(input: { serviceDid: string; agentDid: string }): Promise<{ scopes: string[] }>;
}

export interface ResolveConsentScopesOptions {
  /** The service whose consent screen this is; the grant's issuer. */
  serviceDid: string;
  /** The agent asking for consent. */
  agentDid: string;
  /**
   * Every scope this service can grant. How the SP builds it (a curated
   * list, its MCP server's tool metadata, anything else) is up to the SP.
   */
  serviceScopes: CuratedScopeEntry[];
  client: AgentScopesSource;
}

/**
 * The agent and the service share no scope, so a consent here would grant
 * nothing. Distinct from {@link AgentScopesLookupError}: the lookup worked.
 */
export class ConsentNoGrantableScopesError extends Error {
  readonly code = 'CONSENT_NO_GRANTABLE_SCOPES';
  constructor(agentDid: string, serviceDid: string) {
    super(`Agent ${agentDid} holds none of the scopes ${serviceDid} can grant`);
    this.name = 'ConsentNoGrantableScopesError';
  }
}

/**
 * The agent's scopes could not be read (unknown agent, no active credential,
 * API unreachable). The consent screen fails closed rather than falling back
 * to the service's full catalog, which would offer scopes grant issuance
 * then refuses.
 */
export class AgentScopesLookupError extends Error {
  readonly code = 'AGENT_SCOPES_LOOKUP_FAILED';
  constructor(agentDid: string, readonly cause: unknown) {
    super(
      `Could not read the scopes of agent ${agentDid}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
    this.name = 'AgentScopesLookupError';
  }
}

/**
 * `book:flights` -> `book flights`. Last-resort label so no scope is ever
 * rendered without one.
 */
export function humanizeScope(scope: string): string {
  return scope
    .replace(/[:_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Resolves what the consent screen may offer: the service's scopes that the
 * agent also holds as itself, plus `accept-terms`. Grant issuance enforces
 * the same bound, so nothing offered here is refused at submit.
 *
 * Throws {@link AgentScopesLookupError} when the agent's scopes cannot be
 * read and {@link ConsentNoGrantableScopesError} when the two sets share
 * nothing; the SP's scopes route turns either into a non-200, which the
 * widget shows as its error state.
 *
 * No persistence, no auth, no grant signing.
 */
export async function resolveConsentScopes(
  opts: ResolveConsentScopesOptions,
): Promise<ScopeOption[]> {
  let agentScopes: Set<string>;
  try {
    const { scopes } = await opts.client.getAgentScopes({
      serviceDid: opts.serviceDid,
      agentDid: opts.agentDid,
    });
    agentScopes = new Set(scopes);
  } catch (error) {
    throw new AgentScopesLookupError(opts.agentDid, error);
  }

  // The service's scopes, in its order, narrowed to what the agent holds.
  const resolved = new Map<string, ScopeOption>();
  for (const entry of opts.serviceScopes) {
    if (entry.scope === ACCEPT_TERMS_SCOPE || !agentScopes.has(entry.scope)) continue;
    resolved.set(entry.scope, {
      scope: entry.scope,
      // Never leave a resolved scope without a label.
      label: entry.label !== '' ? entry.label : humanizeScope(entry.scope),
      ...(entry.description !== undefined ? { description: entry.description } : {}),
      ...(entry.required !== undefined ? { required: entry.required } : {}),
    });
  }

  if (resolved.size === 0) {
    throw new ConsentNoGrantableScopesError(opts.agentDid, opts.serviceDid);
  }

  // Always append the T&C entry, required and pre-checked.
  return [
    ...resolved.values(),
    {
      scope: ACCEPT_TERMS_SCOPE,
      label: 'Accept the terms and conditions',
      required: true,
      defaultChecked: true,
    },
  ];
}
