---
"@helixid/mcp-middleware": minor
---

KYA-OS story C-E: `RedisRotationSequenceStore` keeps the last-seen DID document `rotationSequence` per DID in the shared Redis (an atomic raise-to-max), and `createLocalVerifier({ rotationSequenceStore })` uses it, so every instance refuses the same stale document. The order-management sample shares it whenever `KYAOS_REDIS_URL` is set.
