---
'@helixid/mcp-middleware': minor
---

Phase 1: the middleware is now a complete auth gate for an MCP server. Existing callers keep working (`X-Helix-VP`, `_meta["x-helix-vp"]` and `requiredScopes` are unchanged).

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
