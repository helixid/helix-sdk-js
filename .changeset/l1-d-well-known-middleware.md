---
"@helixid/mcp-middleware": minor
---

KYA-OS discovery (story L1-D): `createWellKnownMcp()` builds the `/.well-known/mcp` document from config (serverDid, publicOrigin, the L2-A description for proofs, handshake and skew, capability flags, statusListCredential, advisory DID methods and proof algorithms), validates it against the vendored `well-known-mcpi.json` schema at startup and serves it (`handle()` for node:http, `respond()` elsewhere); `enabled: false` answers 404. `docs/well-known.md` covers routing the origin-root path to the middleware behind nginx, an ALB or API Gateway and the `publicOrigin` rule.
