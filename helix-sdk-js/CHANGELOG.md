# @helixid/sdk-js

## 0.3.0

### Minor Changes

- ee2b9e9: `HelixClient`'s enterprise-mode default `baseUrl` (used when `apiKey` is given with no explicit URL) now points at the hosted HelixID API (`https://api.helixid.dev`) instead of `http://localhost:3000`, and no longer falls back to a `HELIX_API_URL` environment variable — pass the URL explicitly to override the default.

  Also removes the `(http: HttpAdapter, baseUrl: string)` constructor overload entirely (a breaking change, hence the minor bump under 0.x).

- 8066fcc: Fix credential verification for delegated presentations.

## 0.2.0

### Minor Changes

- 8dc8a4d: Release the changes accumulated on `main` since the last manual npm publish (0.1.7 / 0.1.1 / 0.1.1, 2026-07-11) that were never pushed to npm:

  - `HelixClient`: enterprise account-scoped mode for `signVP()`, API-key auth with a default `baseUrl`, and `delegateAuthority()`
  - Removed the account (email/password) login fallback from `HelixClient`
  - Agent self-custody retired across the SDK/CLI/MCP/LangChain surface
  - Pluggable `WalletStorage` threaded through `HelixClientOptions`; new `helix agent onboard` CLI command
