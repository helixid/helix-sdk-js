---
'@helixid/mcp-middleware': minor
---

KYA-OS story L2-A: `createKyaOs()` adds the `_kyaos_handshake` tool, sessions (`kyaos_<uuid-v4>`, idle TTL), a replay store (`MemoryNonceStore`, `RedisNonceStore`, `DynamoNonceStore`) and a server-signed detached proof on every tool call outcome at `_meta["org.kya-os/response-proof"]`. `helixidMCPMiddleware()` gains `authorize()`, `toHttpErrorResponse()` can carry a denied proof, and `describeKyaOs()` exposes what `/.well-known/mcp` advertises.
