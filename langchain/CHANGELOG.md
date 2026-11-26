# @helixid/langchain

## 1.0.0

### Major Changes

- f69bb66: KYA-OS story C-C: the Helix VP format is removed with no backward compatibility. Gone from `@helixid/sdk-js`: `HelixClient.signVP()` and `HelixClient.verifyVP()`, `VPBuilder` and `VPBuilderOptions`, the local `verifyVP()`, `checkScope()` / `requireScope()` (they read a VP verification result), the types `SignedVP`, `VerifyVPOptions`, `VerifyVPResult` and `VerifyVPApiResult`, `VPMissingError` and the `VP_MISSING` code, and the `vp-builder.json` golden vector. An agent signs each request with `kyaos.withRequestProof(call, signer, {audience})`; a service verifies it in-process with `kyaos.verifier.verify()` or `@helixid/mcp-middleware`. `@helixid/langchain`: `encodeBase64UrlJson` (the VP header encoder) is removed. `@helixid/cli` and `@helixid/did-hedera`: their copies of the error catalog drop `VPMissingError` / `VP_MISSING`, and the CLI no longer points to `signVP()`.
- 8d0823d: KYA-OS story C-C: the per-request holder-of-key proof. `kyaos.mintRequestProof(call, signer, {audience, cnfJkt?})`, `kyaos.requestHashContentDigest(call)` (`sha-256=:<base64>:`), `kyaos.attachChain(hops)` and `kyaos.withRequestProof()` put an `org.kya-os/proof.v1` signed by the agent's own Signer at `_meta["org.kya-os/request-proof"]` and its delegation chain at `_meta["org.kya-os/delegation-chain"]`. The verifier checks the proof in the exact SPEC-ENTITY-CARD §11.2 order (`kyaos.verifier.verifyRequestProof`, used by `verify()`), can verify a chain without a proof (`requireProof: false`, at most L2) and reports `agentDid` and `proofFloor`; `deriveConformanceLevel` also takes a `{ok}` proof floor. The X-Helix-VP carrier is removed with no backward compatibility (`HELIX_VP_HEADER`, `HELIX_VP_META_KEY`, `encodeHelixVP`, `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`); `HeadersLike` stays. `@helixid/langchain`: `HelixIDToolWrapper(tool, {signer, audience, chain?, cnfJkt?})` and `signCurrentRequest(call)` replace the per-call VP and `currentHelixVPHeaders()`.

### Patch Changes

- Updated dependencies [f69bb66]
- Updated dependencies [8d0823d]
- Updated dependencies [973ae0f]
- Updated dependencies [b921272]
- Updated dependencies [086670b]
- Updated dependencies [7049359]
- Updated dependencies [7a0f7b0]
- Updated dependencies [0040d7b]
- Updated dependencies [3728b59]
- Updated dependencies [1068d5d]
- Updated dependencies [1b596b1]
- Updated dependencies [f22cd08]
- Updated dependencies [dac99e5]
- Updated dependencies [f38dca2]
  - @helixid/sdk-js@1.0.0

## 0.4.0

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
