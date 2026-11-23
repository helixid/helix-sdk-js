---
"@helixid/sdk-js": minor
---

KYA-OS story C-E: key rotation. `rotateKey()` generates the new key client side and registers only its public half, the current key signing the rotation (`HelixCustodyClient.rotateKey`, `revokeKey`). The verifier picks the key by `kid` and checks the proof's `created` (or `iat`) against that key's `validUntil`; a key marked `revoked` verifies nothing (`key_revoked`, `key_superseded`, `jws_key_revoked`, `jws_key_superseded`). `createDidResolver` refuses a DID document whose `rotationSequence` is lower than one already seen (`did_document_stale`, `RotationSequenceGuard`); `projectJwks` / `readJwks` do the same for `jwks.json`. `finalizeRotation` now returns `retired`. `reissueHop` lets an issuer that holds its own key reissue its hop for a delegate's new key (the rotate result's `pendingIssuers`), with `signDataIntegrity` from the custody module.
