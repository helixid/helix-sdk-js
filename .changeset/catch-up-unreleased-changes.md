---
"@helixid/sdk-js": minor
"@helixid/cli": minor
"@helixid/langchain": minor
---

Release the changes accumulated on `main` since the last manual npm publish (0.1.7 / 0.1.1 / 0.1.1, 2026-07-11) that were never pushed to npm:

- `HelixClient`: enterprise account-scoped mode for `signVP()`, API-key auth with a default `baseUrl`, and `delegateAuthority()`
- Removed the account (email/password) login fallback from `HelixClient`
- Agent self-custody retired across the SDK/CLI/MCP/LangChain surface
- Pluggable `WalletStorage` threaded through `HelixClientOptions`; new `helix agent onboard` CLI command
