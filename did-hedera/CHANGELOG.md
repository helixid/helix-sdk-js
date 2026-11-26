# @helixid/did-hedera

## 0.2.2

### Patch Changes

- f69bb66: KYA-OS story C-C: the Helix VP format is removed with no backward compatibility. Gone from `@helixid/sdk-js`: `HelixClient.signVP()` and `HelixClient.verifyVP()`, `VPBuilder` and `VPBuilderOptions`, the local `verifyVP()`, `checkScope()` / `requireScope()` (they read a VP verification result), the types `SignedVP`, `VerifyVPOptions`, `VerifyVPResult` and `VerifyVPApiResult`, `VPMissingError` and the `VP_MISSING` code, and the `vp-builder.json` golden vector. An agent signs each request with `kyaos.withRequestProof(call, signer, {audience})`; a service verifies it in-process with `kyaos.verifier.verify()` or `@helixid/mcp-middleware`. `@helixid/langchain`: `encodeBase64UrlJson` (the VP header encoder) is removed. `@helixid/cli` and `@helixid/did-hedera`: their copies of the error catalog drop `VPMissingError` / `VP_MISSING`, and the CLI no longer points to `signVP()`.

## 0.2.1

### Patch Changes

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.
