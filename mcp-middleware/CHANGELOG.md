# @helixid/mcp-middleware

## 0.4.0

### Minor Changes

- bda0a3c: Phase 1: the middleware is now a complete auth gate for an MCP server. Existing callers keep working (`X-Helix-VP`, `_meta["x-helix-vp"]` and `requiredScopes` are unchanged).

  **Credentials.** `Authorization: HelixVP <vp>` (alongside legacy `X-Helix-VP` and stdio `_meta["x-helix-vp"]`) and OAuth 2.1 `Authorization: Bearer` tokens. Conflicting credentials are rejected with `CREDENTIAL_CONFLICT`, never resolved by picking one. `client` is now optional (only needed to verify HelixID VPs).

  **OAuth.** `oauth` takes one trusted issuer or a list; a JWT is routed to its issuer by `iss`, and an issuer not in the list is refused without a network call.

  - JWT access tokens are verified against the issuer's JWKS (cached, refetched on key rotation). `requireAccessTokenType` enforces `typ: at+jwt`; `scopeClaims` names the claims that carry scopes.
  - Opaque tokens are checked by RFC 7662 introspection (`introspection: { clientId, clientSecret }`) at the one issuer configured for it. `introspectJwts` also introspects JWTs, so a revoked one is refused before it expires.
  - An entry may be just `{ issuer, audience }`: `jwks_uri` and `introspection_endpoint` are read from the issuer's metadata.
  - Presets for common providers: `entra()`, `auth0()`, `okta()`, `keycloak()`.
  - `validateOAuthToken` remains for credentials no standard describes (your own API keys as bearers).

  **Authorization.** Per-tool `toolScopes`, deny by default; `requiredScopes` remains the fallback.

  **HTTP.** `buildProtectedResourceMetadata` and `protectedResourceMetadataUrl` (RFC 9728), and `toHttpErrorResponse`: 401 / 400 / 403 with `Bearer` and `HelixVP` challenges, the 403 listing the scopes the tool requires. An authorization server that cannot be reached throws `AuthorizationServerUnavailableError`, which maps to no auth response: answer 5xx, never 401.

  **Audit.** `auditSink` receives `AUTHZ_GRANTED` / `AUTHZ_DENIED` for every identified caller; `createHelixAuditSink` writes them to `POST /v1/audit-log/events`.

  **Behaviour changes.**

  - A bearer token sent to a server with no OAuth configured is rejected (`OAUTH_TOKEN_INVALID`) instead of ignored.
  - A credential error raised by the HelixID API during verification (a revoked or expired credential, a VP for another service) is reported as `VP_VERIFICATION_FAILED` rather than passed through.
  - Token segments must be canonical, unpadded base64url.

## 0.3.1

### Patch Changes

- 5c2fcda: Publish from CI via npm trusted publishing (OIDC) with provenance. No code
  changes: the previous versions of these three packages were published by hand
  because they had no trusted publisher configured on npm.

## 0.3.0

### Minor Changes

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.

### Patch Changes

- Updated dependencies [cc1d8b9]
- Updated dependencies [e495dea]
  - @helixid/sdk-js@0.6.0

## 0.1.6

### Patch Changes

- Updated dependencies [e8fcb27]
  - @helixid/sdk-js@0.4.0

## 0.1.5

### Patch Changes

- Updated dependencies [ee2b9e9]
- Updated dependencies [8066fcc]
  - @helixid/sdk-js@0.3.0

## 0.1.3

### Patch Changes

- Updated dependencies [8dc8a4d]
  - @helixid/sdk-js@0.2.0
