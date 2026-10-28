# @helixid/mcp-middleware

## 0.3.1

### Patch Changes

- 5c2fcda: Publish from CI via npm trusted publishing (OIDC) with provenance. No code
  changes: the previous versions of these three packages were published by hand
  because they had no trusted publisher configured on npm.

## 0.3.0

### Minor Changes

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.

### Patch Changes

- Updated dependencies [cc1d8b9]
- Updated dependencies [e495dea]
  - @helixid/sdk-js@0.6.0

## 0.1.6

### Patch Changes

- Updated dependencies [e8fcb27]
  - @helixid/sdk-js@0.4.0

## 0.1.5

### Patch Changes

- Updated dependencies [ee2b9e9]
- Updated dependencies [8066fcc]
  - @helixid/sdk-js@0.3.0

## 0.1.3

### Patch Changes

- Updated dependencies [8dc8a4d]
  - @helixid/sdk-js@0.2.0
