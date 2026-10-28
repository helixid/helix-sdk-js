# @helixid/widget

## 0.3.1

### Patch Changes

- 5c2fcda: Publish from CI via npm trusted publishing (OIDC) with provenance. No code
  changes: the previous versions of these three packages were published by hand
  because they had no trusted publisher configured on npm.

## 0.3.0

### Minor Changes

- cc1d8b9: Consent scopes come from the agent's own credential.

  - `HelixClient.getAgentScopes({ serviceDid, agentDid })` returns the scopes the agent holds as itself (its active onboarding credentials, never delegated ones).
  - `issueServiceDelegationGrant` accepts `allowDelegation`; the grant schema carries it.
  - Widget (breaking): `resolveConsentScopes` now takes `{ serviceDid, agentDid, serviceScopes, client }` and returns the service's scopes the agent holds, plus `accept-terms`. `mcpServerUrl` and `curatedFallback` are gone: building the service's scope list is the SP's job. It throws `ConsentNoGrantableScopesError` when nothing is shared and `AgentScopesLookupError` when the lookup fails, instead of falling back to the full catalog.
  - Widget: `offerDelegationChoice` prop, `setAllowDelegation()`, and `allowDelegation` on the selection.
