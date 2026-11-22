---
'@helixid/mcp-middleware': major
---

KYA-OS story F-2: every tool call is verified in-process by `createLocalVerifier()` (option `verifier`), from the request proof at `_meta["org.kya-os/request-proof"]` and the chain at `_meta["org.kya-os/delegation-chain"]`, with the Helix API never asked. The Helix VP is retired with no backward compatibility: `Authorization: HelixVP`, `X-Helix-VP`, `_meta["x-helix-vp"]`, the `client` option and `attachHelixVP()` are gone; refusals are `ProofError` (`PROOF_MISSING`, `PROOF_INVALID` with the verifier's `reasons`). `reportVerification` is the hook story A-1 connects; until then each verification is logged once as unrecorded.
