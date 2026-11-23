---
'@helixid/sdk-js': major
'@helixid/langchain': major
'@helixid/cli': patch
'@helixid/did-hedera': patch
---

KYA-OS story C-C: the Helix VP format is removed with no backward compatibility. Gone from `@helixid/sdk-js`: `HelixClient.signVP()` and `HelixClient.verifyVP()`, `VPBuilder` and `VPBuilderOptions`, the local `verifyVP()`, `checkScope()` / `requireScope()` (they read a VP verification result), the types `SignedVP`, `VerifyVPOptions`, `VerifyVPResult` and `VerifyVPApiResult`, `VPMissingError` and the `VP_MISSING` code, and the `vp-builder.json` golden vector. An agent signs each request with `kyaos.withRequestProof(call, signer, {audience})`; a service verifies it in-process with `kyaos.verifier.verify()` or `@helixid/mcp-middleware`. `@helixid/langchain`: `encodeBase64UrlJson` (the VP header encoder) is removed. `@helixid/cli` and `@helixid/did-hedera`: their copies of the error catalog drop `VPMissingError` / `VP_MISSING`, and the CLI no longer points to `signVP()`.
