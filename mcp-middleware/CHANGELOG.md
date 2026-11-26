# @helixid/mcp-middleware

## 1.0.0

### Major Changes

- 8d0823d: KYA-OS story C-C: every request proof is verified in the SPEC-ENTITY-CARD §11.2 order (`verifyRequestProof`), the legacy `org.kya-os/proof@1` key and `prf` accepted, the canonical key winning. A bearer token sent with a proof is its sender constraint: its `cnf.jkt` (`AuthResult.cnfJkt`, read from JWT and introspection claims) fuses with the proof's for L3; without it the proof is L3-minus. A chain without a proof is verified in full at most at L2. New `minimumLevel` (default `L3`), `tools[name].minimumLevel` and `l3MinusSatisfiesL3` (default `true`): a call below a tool's minimum, checked after the scopes, is a `LevelError` (`PROOF_LEVEL_INSUFFICIENT`, 401 `insufficient_user_authentication`) with `derivedLevel` and `requiredLevel`. Audit events and verification reports record the level, `fresh`, `proofAssurance`, L3-minus and `cnf` diagnostics; in A-1's typed events they are the `proof.verified` verification code (`KYAOS_PROOF_L3_MINUS`, `_CACHED`, `_CNF_UNFUSED`), and a level refusal is `authorization.denied` with reason `proof_level_insufficient`.
- 7a0f7b0: KYA-OS story F-2: every tool call is verified in-process by `createLocalVerifier()` (option `verifier`), from the request proof at `_meta["org.kya-os/request-proof"]` and the chain at `_meta["org.kya-os/delegation-chain"]`, with the Helix API never asked. The Helix VP is retired with no backward compatibility: `Authorization: HelixVP`, `X-Helix-VP`, `_meta["x-helix-vp"]`, the `client` option and `attachHelixVP()` are gone; refusals are `ProofError` (`PROOF_MISSING`, `PROOF_INVALID` with the verifier's `reasons`). `reportVerification` is the hook story A-1 connects; until then each verification is logged once as unrecorded.

### Minor Changes

- 65727f7: KYA-OS story C-E: `RedisRotationSequenceStore` keeps the last-seen DID document `rotationSequence` per DID in the shared Redis (an atomic raise-to-max), and `createLocalVerifier({ rotationSequenceStore })` uses it, so every instance refuses the same stale document. The order-management sample shares it whenever `KYAOS_REDIS_URL` is set.
- 1068d5d: Registry v3: `kyaos.registry.createRegistryClient` for the Helix agent registry ("Make discoverable", signed registration and withdrawal); discoverable never gates access. Own authority: an agent with no delegation chain may act on the capabilities Helix attested on its card, within the scopes the service offers. `createLocalVerifier` now allows it by default (`allowOwnAuthority: false` opts out); a tool that needs the user's consent sets `requireDelegation`. The verifier's new `ownAuthorityCatalog` keeps calls with a chain unchanged. MCP gate: every method is gated (except `initialize`, `notifications/initialized`, `tools/list`), resource and prompt scopes, unidentified refusals audited; `helixMcpGate` wraps a server in one line.
- 1b596b1: KYA-OS discovery (story L1-D): `createWellKnownMcp()` builds the `/.well-known/mcp` document from config (serverDid, publicOrigin, the L2-A description for proofs, handshake and skew, capability flags, statusListCredential, advisory DID methods and proof algorithms), validates it against the vendored `well-known-mcpi.json` schema at startup and serves it (`handle()` for node:http, `respond()` elsewhere); `enabled: false` answers 404. `docs/well-known.md` covers routing the origin-root path to the middleware behind nginx, an ALB or API Gateway and the `publicOrigin` rule.
- f22cd08: KYA-OS story L2-A: `createKyaOs()` adds the `_kyaos_handshake` tool, sessions (`kyaos_<uuid-v4>`, idle TTL), a replay store (`MemoryNonceStore`, `RedisNonceStore`, `DynamoNonceStore`) and a server-signed detached proof on every tool call outcome at `_meta["org.kya-os/response-proof"]`. `helixidMCPMiddleware()` gains `authorize()`, `toHttpErrorResponse()` can carry a denied proof, and `describeKyaOs()` exposes what `/.well-known/mcp` advertises.

  The replay store is chosen by environment variables when no `nonceStore` is passed (`nonceStoreFromEnv()`): `KYAOS_NONCE_STORE` = `memory` (default), `redis` (`KYAOS_REDIS_URL`, `KYAOS_NONCE_KEY_PREFIX`) or `dynamo` (`KYAOS_DYNAMO_TABLE`, `KYAOS_DYNAMO_KEY_ATTRIBUTE`, `KYAOS_DYNAMO_TTL_ATTRIBUTE`, `KYAOS_DYNAMO_REGION`, `KYAOS_DYNAMO_ENDPOINT`). `ioredis`, `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb` are optional peer dependencies, loaded only when chosen. A bad setting or a missing package fails at startup (`kya.ready()`), never falling back to memory.

- dac99e5: KYA-OS story L3-C: `createLocalVerifier` verifies every status list's proof before reading a bit (unreachable, malformed, unsigned, badly signed, wrong-purpose and out-of-range lists read as revoked), caches lists and verdicts in a `StatusCache` (`statusCache` option; `RedisStatusCacheStore` shares it between instances) and exposes it as `verifier.statusCache`. `RevocationSignalClient` / `createRevocationSignalClient` receive Helix's revocation SETs over SSE (reconnecting) or RFC 8935 push (`webhookHandler()`), verify them and invalidate the cache. The default resolution fetch (`createResolutionFetch`) refuses non-https URLs, non-public IP literals, cross-origin redirects, slow and oversized bodies.
- 6d18999: KYA-OS story L3-D: forward delegation context on downstream calls (SPEC.md §8). `withDelegation(fetch, { signer })` attaches `KYA-OS-Delegation-Credential` (the chain), `KYA-OS-Delegation-Proof` (`mintDelegationProofJwt`, 60 s, `sub` the root hop's issuer), `KYA-OS-Agent-DID`, `KYA-OS-Session-Id` and, optionally, the advisory chain and scope headers, with re-delegation checked for attenuation and every attachment audited (`McpAuditTrail.outboundAttached` / `outboundAudit()`, `delegation.outbound_attached`). The guard verifies inbound delegation headers with the local verifier (`inboundDelegation`, `verifyInboundDelegationHeaders`; advisory headers never decide), caches chain verdicts by credential id (`VerificationCache`, dropped at once by a revocation signal), and keeps a `DelegationGraph` (L3.14 to L3.19). `AuthorizedCaller` gains `chain` and `forwardedBy`.
- c5e3cca: KYA-OS story L3-D follow-up: `inboundDelegation.forwarders` / `verifyInboundDelegationHeaders({ forwarders })` default to `'*'`, so a service accepts a chain forwarded by the service it was granted at, from any such service; the forwarder stays bound to the chain (its target or its leaf delegate). `[]` accepts only chains that target this service. The order-management sample reads `KYAOS_FORWARDERS=none` for that.
- f38dca2: KYA-OS story L3-H: the root of an agent's delegation chain is signed by the user's own pairwise did:key on Helix's consent page. `kyaos.consent` (service side: `createConsentRequest`, `withdrawConsent`; agent side: `awaitConsentHop`, `verifyConsentHop`, `renewConsentHop`, `renewBefore`, `ConsentHopKeeper`), `ConsentFlowError`. The middleware's `authorizationUrl` may be asynchronous; `createHelixConsent` makes it a consent request at Helix and `consentRetryAuthorizer` verifies a retry's credential with the local verifier. `HelixClient.issueServiceDelegationGrant` and `getAgentScopes` are removed with their routes.

### Patch Changes

- b921272: DID format: `didWebFor` takes the raw `host[:port]` and percent-encodes it once (a port's `:` becomes `%3A`); an encoded host or a segment holding `:` is refused. New `ownDidWebProblem` and `isRawDidWebHost`: an own-hosted did:web may have any path but no unencoded port; the custody client and `serveIdentity` refuse one.
- Updated dependencies [f69bb66]
- Updated dependencies [8d0823d]
- Updated dependencies [973ae0f]
- Updated dependencies [b921272]
- Updated dependencies [086670b]
- Updated dependencies [7049359]
- Updated dependencies [7a0f7b0]
- Updated dependencies [0040d7b]
- Updated dependencies [3728b59]
- Updated dependencies [1068d5d]
- Updated dependencies [1b596b1]
- Updated dependencies [f22cd08]
- Updated dependencies [dac99e5]
- Updated dependencies [f38dca2]
  - @helixid/sdk-js@1.0.0

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
