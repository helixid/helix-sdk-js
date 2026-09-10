# helix-sdk-js

TypeScript/JavaScript SDK for HelixID — `HelixClient`, local signing
primitives, and DID/VC/VP construction and verification.

## Architecture

Follows the **SDK-API-only** design (see `docs/proposal-sdk-api-only.md`
and `docs/proposal-retire-core-package.md` in the `helixid/helixid` repo):
every SDK, in every language, depends only on the HelixID API — never on a
shared "core" package — except for private-key operations that must stay
local: keygen, sign, canonical-hash, and `VPBuilder.sign()`, which issuers
and Service Providers still use to sign with their own keys. Verification,
delegation-VC construction, DID resolution, and status checks are all API
calls made through `HelixClient`.

**Agents hold no keys.** Agent self-custody has been retired: the server
generates an agent's keypair during onboarding and holds the private key,
so onboarding, presenting, and delegating are all API calls
(`HelixClient.onboardAgent()`, `signVP()`, `delegateAuthority()`).
`AgentWallet` remains for other actors' key storage (e.g. an issuer's or
Service Provider's own key material), not for agent onboarding.

## Modules

| Module | Purpose |
|---|---|
| `client/` | `HelixClient` — the main public API surface: onboarding, server-side VP signing/delegation, DID/VC lifecycle, verification |
| `core/` | Local-signing primitives (keygen, sign, canonical-hash, Ed25519 proof, JWT) plus the DID/VC/VP schemas and types shared across the package |
| `wallet/` | `AgentWallet` — encrypted local key/DID/VC storage, for issuer/SP key material, not agent onboarding |
| `resolver/` | `HelixDidResolver` — DID resolution via the API |
| `session/` | `SessionManager` — session-token issuance/verification |
| `http/` | `HttpAdapter` — internal HTTP client |
| `audit/` | SDK-side audit log implementation |
| `delegation.ts` | Wallet-based `delegate()` — builds and signs a delegation VC via the API's prepare/finalize endpoints, for callers that still hold their own key |
| `grant.ts` | SP-side `issueGrant()` / `revokeGrant()` — signs and revokes `DelegationGrantCredential`s with the SP's own key |
| `renewal.ts` | `renewAgentVC()` — renews a VC via the prepare/finalize flow |
| `scope.ts` | `checkScope()` / `requireScope()` — local checks against a verification result's `effectiveScopes` |
| `verify.ts` | `verifyVP()` — thin wrapper over `HelixClient.verifyVP()`; there is no local verification fallback by design |
| `vp-builder.ts` | `VPBuilder` — local VP construction and signing (the explicit private-key carveout above) |

`HelixClient` is the primary entry point for the API-backed flows
(onboarding, signing, delegation, verification, DID/VC lifecycle), but the
package also exports `VPBuilder`, `AgentWallet`, `generateKeyPair`, and the
other local-signing primitives directly for callers that need them — see
`src/index.ts` for the full public surface.

## Scripts

```bash
npm run build          # Compile TypeScript
npm run test           # Run tests with coverage
npm run test:security  # Run security tests
npm run lint           # ESLint
npm run typecheck      # Type-check without emitting
```
