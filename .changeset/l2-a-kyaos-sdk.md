---
'@helixid/sdk-js': minor
---

KYA-OS story L2-A: the SDK carries its own `kyaos` namespace (RFC 8785 canonical JSON hashing, EdDSA JWS and the `Signer`, ported from helix-core), the session handshake helpers, the SPEC §7.3 request and response hashes, and `verifyResponseProof()`, which checks a server's detached response proof against its DID by recomputing both hashes. New errors `InvalidJWSError` and `ResponseProofError`.
