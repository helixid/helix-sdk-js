---
'@helixid/sdk-js': minor
---

KYA-OS story L3-C: `kyaos.verifier` reads status lists the SPEC.md §6.6 way. `readBitstringStatusList` and `readStatusList2021` verify the list's own proof (`eddsa-jcs-2022` or `Ed25519Signature2020`) before decoding any bit; `createStatusListFetcher` fetches through an injected (Safe)fetch; the keeper rules (`keeper`, `statusConfiguration`) decide whose list counts. `createRevocationChecker` (the new `checkRevocation` seam, `{revoked, fresh}`, fail-closed) caches lists and verdicts in a `StatusCache` (`statusCacheTtl`, `highPrivilegeScopes` ≤ 60 s, `invalidate(credentialId)`); `checkChainRevocation` walks a chain root to leaf. `signRevocationSignal` / `verifyRevocationSignal` are the RFC 8417 SET of one revoked credential. New reason codes `status_list_malformed`, `status_list_proof_invalid`. The conformance `status-list` category now runs through these production readers.
