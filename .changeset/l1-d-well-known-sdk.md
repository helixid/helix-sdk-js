---
"@helixid/sdk-js": minor
---

KYA-OS discovery, client side (story L1-D): `kyaos.fetchWellKnownMcp(origin)` and `kyaos.readWellKnownMcp(document)` read a server's `/.well-known/mcp`, check it the way the schema does, resolve relative endpoints and fill `clockSkewSeconds` with the default when absent, so a client can apply the advertised skew to its handshake timing and to `verifyResponseProof`.
