# @helixid/cli

## 0.3.1

### Patch Changes

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.

- Updated dependencies [cc1d8b9]
- Updated dependencies [e495dea]
  - @helixid/sdk-js@0.6.0

## 0.2.2

### Patch Changes

- Updated dependencies [e8fcb27]
  - @helixid/sdk-js@0.4.0

## 0.2.1

### Patch Changes

- Updated dependencies [ee2b9e9]
- Updated dependencies [8066fcc]
  - @helixid/sdk-js@0.3.0

## 0.2.0

### Minor Changes

- 8dc8a4d: Release the changes accumulated on `main` since the last manual npm publish (0.1.7 / 0.1.1 / 0.1.1, 2026-07-11) that were never pushed to npm:

  - `HelixClient`: enterprise account-scoped mode for `signVP()`, API-key auth with a default `baseUrl`, and `delegateAuthority()`
  - Removed the account (email/password) login fallback from `HelixClient`
  - Agent self-custody retired across the SDK/CLI/MCP/LangChain surface
  - Pluggable `WalletStorage` threaded through `HelixClientOptions`; new `helix agent onboard` CLI command

### Patch Changes

- Updated dependencies [8dc8a4d]
  - @helixid/sdk-js@0.2.0
