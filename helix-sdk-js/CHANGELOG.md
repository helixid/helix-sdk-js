# @helixid/sdk-js

## 1.0.1

### Patch Changes

- 5f72456: `helix init` / `helix activate`, own hosting: `card.json` is rewritten on activation only when Helix returns a different card (an older Helix that issues the credentials at activation). With a current Helix the card written by `helix init` is final, and the CLI says Helix activates the agent once both documents resolve, with `helix activate` to check now.

## 1.0.0

### Major Changes

- f69bb66: KYA-OS story C-C: the Helix VP format is removed with no backward compatibility. Gone from `@helixid/sdk-js`: `HelixClient.signVP()` and `HelixClient.verifyVP()`, `VPBuilder` and `VPBuilderOptions`, the local `verifyVP()`, `checkScope()` / `requireScope()` (they read a VP verification result), the types `SignedVP`, `VerifyVPOptions`, `VerifyVPResult` and `VerifyVPApiResult`, `VPMissingError` and the `VP_MISSING` code, and the `vp-builder.json` golden vector. An agent signs each request with `kyaos.withRequestProof(call, signer, {audience})`; a service verifies it in-process with `kyaos.verifier.verify()` or `@helixid/mcp-middleware`. `@helixid/langchain`: `encodeBase64UrlJson` (the VP header encoder) is removed. `@helixid/cli` and `@helixid/did-hedera`: their copies of the error catalog drop `VPMissingError` / `VP_MISSING`, and the CLI no longer points to `signVP()`.
- 8d0823d: KYA-OS story C-C: the per-request holder-of-key proof. `kyaos.mintRequestProof(call, signer, {audience, cnfJkt?})`, `kyaos.requestHashContentDigest(call)` (`sha-256=:<base64>:`), `kyaos.attachChain(hops)` and `kyaos.withRequestProof()` put an `org.kya-os/proof.v1` signed by the agent's own Signer at `_meta["org.kya-os/request-proof"]` and its delegation chain at `_meta["org.kya-os/delegation-chain"]`. The verifier checks the proof in the exact SPEC-ENTITY-CARD §11.2 order (`kyaos.verifier.verifyRequestProof`, used by `verify()`), can verify a chain without a proof (`requireProof: false`, at most L2) and reports `agentDid` and `proofFloor`; `deriveConformanceLevel` also takes a `{ok}` proof floor. The X-Helix-VP carrier is removed with no backward compatibility (`HELIX_VP_HEADER`, `HELIX_VP_META_KEY`, `encodeHelixVP`, `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`); `HeadersLike` stays. `@helixid/langchain`: `HelixIDToolWrapper(tool, {signer, audience, chain?, cnfJkt?})` and `signCurrentRequest(call)` replace the per-call VP and `currentHelixVPHeaders()`.
- f38dca2: KYA-OS story L3-H: the root of an agent's delegation chain is signed by the user's own pairwise did:key on Helix's consent page. `kyaos.consent` (service side: `createConsentRequest`, `withdrawConsent`; agent side: `awaitConsentHop`, `verifyConsentHop`, `renewConsentHop`, `renewBefore`, `ConsentHopKeeper`), `ConsentFlowError`. The middleware's `authorizationUrl` may be asynchronous; `createHelixConsent` makes it a consent request at Helix and `consentRetryAuthorizer` verifies a retry's credential with the local verifier. `HelixClient.issueServiceDelegationGrant` and `getAgentScopes` are removed with their routes.

### Minor Changes

- 973ae0f: KYA-OS story C-E: key rotation. `rotateKey()` generates the new key client side and registers only its public half, the current key signing the rotation (`HelixCustodyClient.rotateKey`, `revokeKey`). The verifier picks the key by `kid` and checks the proof's `created` (or `iat`) against that key's `validUntil`; a key marked `revoked` verifies nothing (`key_revoked`, `key_superseded`, `jws_key_revoked`, `jws_key_superseded`). `createDidResolver` refuses a DID document whose `rotationSequence` is lower than one already seen (`did_document_stale`, `RotationSequenceGuard`); `projectJwks` / `readJwks` do the same for `jwks.json`. `finalizeRotation` now returns `retired`. `reissueHop` lets an issuer that holds its own key reissue its hop for a delegate's new key (the rotate result's `pendingIssuers`), with `signDataIntegrity` from the custody module.
- b921272: DID format: `didWebFor` takes the raw `host[:port]` and percent-encodes it once (a port's `:` becomes `%3A`); an encoded host or a segment holding `:` is refused. New `ownDidWebProblem` and `isRawDidWebHost`: an own-hosted did:web may have any path but no unencoded port; the custody client and `serveIdentity` refuse one.
- 086670b: KYA-OS story F-1 follow-up: `HelixClient.delegateAuthority()` is removed. It called `POST /v1/agents/:did/delegate` (or `/v1/custodial-agents/:did/delegate`), which F-1 removed from core and enterprise retires. Delegation is now a hop chain: `POST /v1/grants` and `POST /v1/grants/:id/hops`.
- 7a0f7b0: KYA-OS story F-2: `kyaos.verifier.verify(input, seams, options)` verifies a KYA-OS request proof (`org.kya-os/proof.v1`, or the legacy `org.kya-os/proof@1`) and the delegation chain the request carries, in-process: SPEC-ENTITY-CARD §11.2 order, chain length bounded before parsing, per-hop `eddsa-jcs-2022` proofs, attenuation, status through the `fetchStatusList` seam, `responsibleParty === issuer(rootVC)` and `leafInvoker === proof.did`, level per §9.4. Seams (`resolveDid`, `resolveDidKeys`, `fetchStatusList`, `resolveCard`, `nonceStore`, `clock`, `trustedIssuers`) are injected; a missing one fails closed with its reason code (`kyaos.verifier.ReasonCodes`). `kyaos.verifier.signRequestProof` mints a proof. `kyaos.conformance.HelixConformanceAdapter` runs the KYA-OS vectors.
- 0040d7b: KYA-OS story F-3: custody preference. `helixInit` (self-custody onboarding: the key is generated client side, only the public JWK and a proof of possession are sent, `did.json` and `card.json` written to an output directory, own-domain resolution checked before activation), `activateAgent`, `changeToSelfCustody`, `HelixCustodialSigner` (custodial agents sign through the API), `EnvSigner`, the `Signer` the agent runtime takes (`VPBuilder.signWith`), and `HelixCustodyClient` for the custody endpoints.
- 3728b59: KYA-OS story F-3 follow-up: an own-hosted agent's card carries what its credentials say. On activation Helix returns the card with the agent's capability attestations, responsible party and revocation entry; `activateAgent()` (and `helixInit()` when it activates) rewrites `card.json` in the output directory and reports `cardUpdated: true`. `helix init` and `helix activate` tell the owner to republish it at the card URL.
- 1068d5d: Registry v3: `kyaos.registry.createRegistryClient` for the Helix agent registry ("Make discoverable", signed registration and withdrawal); discoverable never gates access. Own authority: an agent with no delegation chain may act on the capabilities Helix attested on its card, within the scopes the service offers. `createLocalVerifier` now allows it by default (`allowOwnAuthority: false` opts out); a tool that needs the user's consent sets `requireDelegation`. The verifier's new `ownAuthorityCatalog` keeps calls with a chain unchanged. MCP gate: every method is gated (except `initialize`, `notifications/initialized`, `tools/list`), resource and prompt scopes, unidentified refusals audited; `helixMcpGate` wraps a server in one line.
- 1b596b1: KYA-OS discovery, client side (story L1-D): `kyaos.fetchWellKnownMcp(origin)` and `kyaos.readWellKnownMcp(document)` read a server's `/.well-known/mcp`, check it the way the schema does, resolve relative endpoints and fill `clockSkewSeconds` with the default when absent, so a client can apply the advertised skew to its handshake timing and to `verifyResponseProof`.
- f22cd08: KYA-OS story L2-A: the SDK carries its own `kyaos` namespace (RFC 8785 canonical JSON hashing, EdDSA JWS and the `Signer`, ported from helix-core), the session handshake helpers, the SPEC §7.3 request and response hashes, and `verifyResponseProof()`, which checks a server's detached response proof against its DID by recomputing both hashes. New errors `InvalidJWSError` and `ResponseProofError`.
- dac99e5: KYA-OS story L3-C: `kyaos.verifier` reads status lists the SPEC.md §6.6 way. `readBitstringStatusList` and `readStatusList2021` verify the list's own proof (`eddsa-jcs-2022` or `Ed25519Signature2020`) before decoding any bit; `createStatusListFetcher` fetches through an injected (Safe)fetch; the keeper rules (`keeper`, `statusConfiguration`) decide whose list counts. `createRevocationChecker` (the new `checkRevocation` seam, `{revoked, fresh}`, fail-closed) caches lists and verdicts in a `StatusCache` (`statusCacheTtl`, `highPrivilegeScopes` ≤ 60 s, `invalidate(credentialId)`); `checkChainRevocation` walks a chain root to leaf. `signRevocationSignal` / `verifyRevocationSignal` are the RFC 8417 SET of one revoked credential. New reason codes `status_list_malformed`, `status_list_proof_invalid`. The conformance `status-list` category now runs through these production readers.

### Patch Changes

- 7049359: KYA-OS story F-1 fix: a signer for a did:key DID now defaults its kid to the did:key multibase value (`did:key:z…#z…`), the one verification method a did:key document defines, instead of `key-1`. `kyaos.defaultKidFragment(did)` gives the rule; `kyaos.EnvSigner` and the custody `EnvSigner` / `kidFragment` use it. An explicit kid is unchanged; other DIDs keep `key-1`.

## 0.6.0

### Minor Changes

- cc1d8b9: Consent scopes come from the agent's own credential.

  - `HelixClient.getAgentScopes({ serviceDid, agentDid })` returns the scopes the agent holds as itself (its active onboarding credentials, never delegated ones).
  - `issueServiceDelegationGrant` accepts `allowDelegation`; the grant schema carries it.
  - Widget (breaking): `resolveConsentScopes` now takes `{ serviceDid, agentDid, serviceScopes, client }` and returns the service's scopes the agent holds, plus `accept-terms`. `mcpServerUrl` and `curatedFallback` are gone: building the service's scope list is the SP's job. It throws `ConsentNoGrantableScopesError` when nothing is shared and `AgentScopesLookupError` when the lookup fails, instead of falling back to the full catalog.
  - Widget: `offerDelegationChoice` prop, `setAllowDelegation()`, and `allowDelegation` on the selection.

- e495dea: VP transport and SDK-API-only revamp.

  `@helixid/sdk-js` (breaking):

  - `issueGrant` / `revokeGrant` and the prepare/finalize client calls (`prepareGrant`, `finalizeGrant`) are removed. Grants are issued by the API: `HelixClient.createService`, `issueServiceDelegationGrant` (with `revokeExisting` and `allowDelegation`) and `registerVC`.
  - `HelixClient` sends the account API key on every call in enterprise mode.
  - New `vp-transport` module: `HELIX_VP_HEADER` / `HELIX_VP_META_KEY`, `encodeHelixVP` / `decodeHelixVP`, `helixVPHeaders`, `readHelixVPHeader`, `readHelixVPMeta`. A VP travels in the `X-Helix-VP` header over HTTP, or in MCP `_meta["x-helix-vp"]`.

  `@helixid/langchain` (breaking): `HelixIDMiddleware` is replaced by `HelixIDToolWrapper` (`HelixIDToolWrapperOptions`); `currentHelixVPHeaders` exposes the headers for the current tool call.

  `@helixid/mcp-middleware`: the VP is read from `_meta["x-helix-vp"]` or the `X-Helix-VP` header instead of `_helixVP` in the tool input; `expectedTargetService` option.

  `@helixid/cli`, `@helixid/did-hedera`: `allowDelegation` on the delegation-grant schema; clearer "no VP" error.

## 0.4.0

### Minor Changes

- e8fcb27: `HelixClient`'s constructor now also accepts a single `HelixClientOptions` object with no leading URL argument (`new HelixClient({ apiKey })`), in addition to the existing `(apiUrl?)` and `(baseUrl?, options?)` forms.

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
