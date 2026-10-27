# @helixid/sdk-js

## 0.6.0

### Minor Changes

- cc1d8b9: Consent scopes come from the agent's own credential.

  - `HelixClient.getAgentScopes({ serviceDid, agentDid })` returns the scopes the agent holds as itself (its active onboarding credentials, never delegated ones).
  - `issueServiceDelegationGrant` accepts `allowDelegation`; the grant schema carries it.
  - Widget (breaking): `resolveConsentScopes` now takes `{ serviceDid, agentDid, serviceScopes, client }` and returns the service's scopes the agent holds, plus `accept-terms`. `mcpServerUrl` and `curatedFallback` are gone: building the service's scope list is the SP's job. It throws `ConsentNoGrantableScopesError` when nothing is shared and `AgentScopesLookupError` when the lookup fails, instead of falling back to the full catalog.
  - Widget: `offerDelegationChoice` prop, `setAllowDelegation()`, and `allowDelegation` on the selection.

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.

## 0.4.0

### Minor Changes

- e8fcb27: `HelixClient`'s constructor now also accepts a single `HelixClientOptions` object with no leading URL argument (`new HelixClient({ apiKey })`), in addition to the existing `(apiUrl?)` and `(baseUrl?, options?)` forms.

## 0.3.0

### Minor Changes

- ee2b9e9: `HelixClient`'s enterprise-mode default `baseUrl` (used when `apiKey` is given with no explicit URL) now points at the hosted HelixID API (`https://api.helixid.dev`) instead of `http://localhost:3000`, and no longer falls back to a `HELIX_API_URL` environment variable — pass the URL explicitly to override the default.

  Also removes the `(http: HttpAdapter, baseUrl: string)` constructor overload entirely (a breaking change, hence the minor bump under 0.x).

- 8066fcc: Fix credential verification for delegated presentations.

## 0.2.0

### Minor Changes

- 8dc8a4d: Release the changes accumulated on `main` since the last manual npm publish (0.1.7 / 0.1.1 / 0.1.1, 2026-07-11) that were never pushed to npm:

  - `HelixClient`: enterprise account-scoped mode for `signVP()`, API-key auth with a default `baseUrl`, and `delegateAuthority()`
  - Removed the account (email/password) login fallback from `HelixClient`
  - Agent self-custody retired across the SDK/CLI/MCP/LangChain surface
  - Pluggable `WalletStorage` threaded through `HelixClientOptions`; new `helix agent onboard` CLI command
