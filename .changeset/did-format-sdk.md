---
"@helixid/sdk-js": minor
"@helixid/mcp-middleware": patch
---

DID format: `didWebFor` takes the raw `host[:port]` and percent-encodes it once (a port's `:` becomes `%3A`); an encoded host or a segment holding `:` is refused. New `ownDidWebProblem` and `isRawDidWebHost`: an own-hosted did:web may have any path but no unencoded port; the custody client and `serveIdentity` refuse one.
