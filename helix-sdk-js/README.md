# helix-sdk-js

TypeScript/JavaScript SDK for HelixID — `HelixClient`, local signing
primitives, DID/VC construction, and the KYA-OS request proof and local
verifier (`kyaos`).

## Architecture

Follows the **SDK-API-only** design:
every SDK, in every language, depends only on the HelixID API — never on a
shared "core" package — except for private-key operations that must stay
local: keygen, sign and canonical-hash, which issuers use to sign with their
own keys. Verification, delegation-VC construction,
DID resolution, and status checks are all API calls made through
`HelixClient`.

**Agents and Service Providers hold no keys.** The server generates the
keypair when an agent is onboarded or a service is enrolled and holds the
private key, so onboarding and issuing consent grants are API calls
(`HelixClient.onboardAgent()`, `createService()`, `issueServiceDelegationGrant()`).
`AgentWallet` remains for an issuer's own key material only.

## Modules

| Module | Purpose |
|---|---|
| `client/` | `HelixClient` — the main public API surface: onboarding, delegation, DID/VC lifecycle |
| `core/` | Local-signing primitives (keygen, sign, canonical-hash, Ed25519 proof, JWT) plus the DID/VC schemas and types shared across the package |
| `wallet/` | `AgentWallet` — encrypted local key/DID/VC storage, for issuer/SP key material, not agent onboarding |
| `resolver/` | `HelixDidResolver` — DID resolution via the API |
| `session/` | `SessionManager` — session-token issuance/verification |
| `http/` | `HttpAdapter` — internal HTTP client |
| `audit/` | SDK-side audit log implementation |
| `core/kyaos/verifier/` | `kyaos.verifier.verify(input, seams, options)` — the local verifier (story F-2): a KYA-OS request proof plus its carried delegation chain, verified in-process from public DID documents, status lists and the agent's card through injected seams, never a Helix database. Mirrored by `helix_sdk.verifier` in helix-sdk-py |
| `core/kyaos/request-proof.ts` | `kyaos.mintRequestProof(call, signer, {audience, cnfJkt?})`, `kyaos.requestHashContentDigest(call)` (`sha-256=:<b64>:`), `kyaos.attachChain(hops)` and `kyaos.withRequestProof(call, signer, options)` — the per-request holder-of-key proof (story C-C): every tool call carries an `org.kya-os/proof.v1` signed by the agent's own Signer at `_meta["org.kya-os/request-proof"]`, with its delegation chain at `_meta["org.kya-os/delegation-chain"]`. The Helix VP is gone: no `VPBuilder`, `signVP()`, `verifyVP()` or X-Helix-VP carrier |
| `core/kyaos/conformance/` | `kyaos.conformance.HelixConformanceAdapter` — the KYA-OS `ConformanceAdapter` and a runner for the vendored vector categories |
| `core/custody/` | KYA-OS story F-3: `helixInit` (self-custody onboarding: the key is generated here, only the public JWK is sent), `activateAgent`, `changeToSelfCustody`, `EnvSigner` and `HelixCustodialSigner` (a custodial agent signs through the API; same `Signer` shape, so application code, such as a request proof from `kyaos.verifier.signRequestProof`, does not change), `HelixCustodyClient`. Custodial agents are labelled `custody: helix` and are not counted in KYA-OS conformance claims; their proofs still verify |

`HelixClient` is the primary entry point for the API-backed flows
(onboarding, delegation, DID/VC lifecycle), but the package also exports
`AgentWallet`, `generateKeyPair`, and the
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
