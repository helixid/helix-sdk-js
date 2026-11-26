---
"@helixid/cli": patch
"@helixid/mcp-server": patch
---

DID format: `helix did create --method web` and `did_create` build the issuer DID through `didWebFor`, so a `--domain` with a port gives `did:web:host%3Aport`.
