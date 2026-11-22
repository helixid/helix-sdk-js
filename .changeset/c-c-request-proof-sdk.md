---
'@helixid/sdk-js': major
'@helixid/langchain': major
---

KYA-OS story C-C: the per-request holder-of-key proof. `kyaos.mintRequestProof(call, signer, {audience, cnfJkt?})`, `kyaos.requestHashContentDigest(call)` (`sha-256=:<base64>:`), `kyaos.attachChain(hops)` and `kyaos.withRequestProof()` put an `org.kya-os/proof.v1` signed by the agent's own Signer at `_meta["org.kya-os/request-proof"]` and its delegation chain at `_meta["org.kya-os/delegation-chain"]`. The verifier checks the proof in the exact SPEC-ENTITY-CARD §11.2 order (`kyaos.verifier.verifyRequestProof`, used by `verify()`), can verify a chain without a proof (`requireProof: false`, at most L2) and reports `agentDid` and `proofFloor`; `deriveConformanceLevel` also takes a `{ok}` proof floor. The X-Helix-VP carrier is removed with no backward compatibility (`HELIX_VP_HEADER`, `HELIX_VP_META_KEY`, `encodeHelixVP`, `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`); `HeadersLike` stays. `@helixid/langchain`: `HelixIDToolWrapper(tool, {signer, audience, chain?, cnfJkt?})` and `signCurrentRequest(call)` replace the per-call VP and `currentHelixVPHeaders()`.
