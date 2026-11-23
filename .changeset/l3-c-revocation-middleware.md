---
'@helixid/mcp-middleware': minor
---

KYA-OS story L3-C: `createLocalVerifier` verifies every status list's proof before reading a bit (unreachable, malformed, unsigned, badly signed, wrong-purpose and out-of-range lists read as revoked), caches lists and verdicts in a `StatusCache` (`statusCache` option; `RedisStatusCacheStore` shares it between instances) and exposes it as `verifier.statusCache`. `RevocationSignalClient` / `createRevocationSignalClient` receive Helix's revocation SETs over SSE (reconnecting) or RFC 8935 push (`webhookHandler()`), verify them and invalidate the cache. The default resolution fetch (`createResolutionFetch`) refuses non-https URLs, non-public IP literals, cross-origin redirects, slow and oversized bodies.
