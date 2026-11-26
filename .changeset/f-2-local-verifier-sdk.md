---
'@helixid/sdk-js': minor
---

KYA-OS story F-2: `kyaos.verifier.verify(input, seams, options)` verifies a KYA-OS request proof (`org.kya-os/proof.v1`, or the legacy `org.kya-os/proof@1`) and the delegation chain the request carries, in-process: SPEC-ENTITY-CARD §11.2 order, chain length bounded before parsing, per-hop `eddsa-jcs-2022` proofs, attenuation, status through the `fetchStatusList` seam, `responsibleParty === issuer(rootVC)` and `leafInvoker === proof.did`, level per §9.4. Seams (`resolveDid`, `resolveDidKeys`, `fetchStatusList`, `resolveCard`, `nonceStore`, `clock`, `trustedIssuers`) are injected; a missing one fails closed with its reason code (`kyaos.verifier.ReasonCodes`). `kyaos.verifier.signRequestProof` mints a proof. `kyaos.conformance.HelixConformanceAdapter` runs the KYA-OS vectors.
