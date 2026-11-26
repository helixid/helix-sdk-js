---
'@helixid/mcp-middleware': minor
---

KYA-OS story L3-D: forward delegation context on downstream calls (SPEC.md §8). `withDelegation(fetch, { signer })` attaches `KYA-OS-Delegation-Credential` (the chain), `KYA-OS-Delegation-Proof` (`mintDelegationProofJwt`, 60 s, `sub` the root hop's issuer), `KYA-OS-Agent-DID`, `KYA-OS-Session-Id` and, optionally, the advisory chain and scope headers, with re-delegation checked for attenuation and every attachment audited (`McpAuditTrail.outboundAttached` / `outboundAudit()`, `delegation.outbound_attached`). The guard verifies inbound delegation headers with the local verifier (`inboundDelegation`, `verifyInboundDelegationHeaders`; advisory headers never decide), caches chain verdicts by credential id (`VerificationCache`, dropped at once by a revocation signal), and keeps a `DelegationGraph` (L3.14 to L3.19). `AuthorizedCaller` gains `chain` and `forwardedBy`.
