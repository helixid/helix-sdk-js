---
"@helixid/sdk-js": minor
"@helixid/mcp-middleware": minor
---

Registry v3: `kyaos.registry.createRegistryClient` for the Helix agent registry ("Make discoverable", signed registration and withdrawal); discoverable never gates access. Own authority: an agent with no delegation chain may act on the capabilities Helix attested on its card, within the scopes the service offers. `createLocalVerifier` now allows it by default (`allowOwnAuthority: false` opts out); a tool that needs the user's consent sets `requireDelegation`. The verifier's new `ownAuthorityCatalog` keeps calls with a chain unchanged. MCP gate: every method is gated (except `initialize`, `notifications/initialized`, `tools/list`), resource and prompt scopes, unidentified refusals audited; `helixMcpGate` wraps a server in one line.
