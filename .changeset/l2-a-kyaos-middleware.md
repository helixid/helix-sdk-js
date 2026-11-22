---
'@helixid/mcp-middleware': minor
---

KYA-OS story L2-A: `createKyaOs()` adds the `_kyaos_handshake` tool, sessions (`kyaos_<uuid-v4>`, idle TTL), a replay store (`MemoryNonceStore`, `RedisNonceStore`, `DynamoNonceStore`) and a server-signed detached proof on every tool call outcome at `_meta["org.kya-os/response-proof"]`. `helixidMCPMiddleware()` gains `authorize()`, `toHttpErrorResponse()` can carry a denied proof, and `describeKyaOs()` exposes what `/.well-known/mcp` advertises.

The replay store is chosen by environment variables when no `nonceStore` is passed (`nonceStoreFromEnv()`): `KYAOS_NONCE_STORE` = `memory` (default), `redis` (`KYAOS_REDIS_URL`, `KYAOS_NONCE_KEY_PREFIX`) or `dynamo` (`KYAOS_DYNAMO_TABLE`, `KYAOS_DYNAMO_KEY_ATTRIBUTE`, `KYAOS_DYNAMO_TTL_ATTRIBUTE`, `KYAOS_DYNAMO_REGION`, `KYAOS_DYNAMO_ENDPOINT`). `ioredis`, `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb` are optional peer dependencies, loaded only when chosen. A bad setting or a missing package fails at startup (`kya.ready()`), never falling back to memory.
