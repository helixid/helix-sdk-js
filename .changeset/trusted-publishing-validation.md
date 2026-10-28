---
'@helixid/widget': patch
'@helixid/mcp-middleware': patch
'@helixid/mcp-server': patch
---

Publish from CI via npm trusted publishing (OIDC) with provenance. No code
changes: the previous versions of these three packages were published by hand
because they had no trusted publisher configured on npm.
