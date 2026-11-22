# @helixid/mcp-middleware

Thin MCP adapter for Helix ID. It verifies every inbound tool call in-process (KYA-OS story F-2): the agent's request proof (`org.kya-os/proof.v1`) rides `params._meta["org.kya-os/request-proof"]` and its delegation chain `params._meta["org.kya-os/delegation-chain"]`, on any transport, stdio included. Verification reads only the presented artifacts, public DID documents, status lists and Entity Cards over HTTPS, the local replay store and local config: the Helix API is never asked, so calls are authorised with it unreachable, and a credential issued by any Helix deployment verifies here. The Helix VP (`X-Helix-VP`, `_meta["x-helix-vp"]`, `attachHelixVP`) is retired with no backward compatibility.

```ts
import { helixidMCPMiddleware, createLocalVerifier, RedisNonceStore } from '@helixid/mcp-middleware';

const verifier = createLocalVerifier({
  serviceDid: 'did:web:mcp.example.com', // the proof audience and the chain's resource
  trustedIssuers: '*',                    // attestation issuers; a list trusts those DIDs only
  maxChainLength: 10,                     // a carried chain is bounded before any entry is parsed
  nonceStore: new RedisNonceStore({ client: ioredis }), // shared by every instance; default in memory
  // fetch: safeFetch,                    // DID documents, status lists and cards; default global fetch, https only
  // reportVerification: (report) => trail.record(...), // story A-1's hook; default logs once "unrecorded"
});
const requireHelix = helixidMCPMiddleware({ verifier, toolScopes: { lookup_order: ['read:orders'] } });

// Pass the request's params._meta (and, over HTTP, the headers for OAuth) and, when you have it, the request itself.
await requireHelix({ name, input: args, _meta: request.params._meta, request, headers: req.headers });
```

A caller's scopes are the three-way intersection of its verified capability attestations (from its Entity Card), the leaf hop's `allowedAction` and the tool scopes this server offers; the caller's level is derived per SPEC-ENTITY-CARD §9.4. A refused proof is a `ProofError` (`PROOF_INVALID`, 401) whose `reasons` are the verifier's codes (`nonce_replayed`, `audience_mismatch`, `request_hash_mismatch`, `attenuation_violation`, `status_revoked`, `chain_too_long`, ...); no proof and no bearer token is `PROOF_MISSING` (401). A carried chain that fails is refused as is: nothing is looked up in its place. The verifier itself is `kyaos.verifier.verify()` in `@helixid/sdk-js`, mirrored by `helix_sdk.verifier` in helix-sdk-py.

## Per-request holder-of-key proof and the minimum Card level (story C-C)

Every proof is checked in the exact SPEC-ENTITY-CARD §11.2 order, stopping at the first broken binding: schema, `kid` names a key of `did`, the key resolved and its RFC 7638 thumbprint among the keys the DID publishes, `audience` equals this service's DID, `requestHash` (`sha-256=:<base64>:` over the JCS of `{method, params}` with `params._meta` removed) recomputed, the window (`expires - created` at most 60 s, ±5 s skew), the nonce unseen in the L2-A replay store, the detached JWS, the `cnf` fusion. A missing DID-keys seam or nonce store fails closed. A proof under the legacy key `org.kya-os/proof@1` or with the legacy `prf` verifies too; when both keys are present the canonical one is read. `verifyRequestProof(verifier, call)` runs the proof check alone.

- **`cnf` fusion**: a bearer token sent with a proof is its sender constraint, not a second caller. Its `cnf.jkt` (`AuthResult.cnfJkt`, or `claims.cnf.jkt`) must equal the proof's `cnf.jkt` and the key's thumbprint for `L3`; without a token `cnf` the proof is `L3-minus`. A token `cnf` with no proof `cnf` is `cnf_required_by_token`. A proof `cnf` with no token is recorded as the `cnf_present_but_token_unfused` diagnostic.
- **Level**: derived per §9.4 (`deriveConformanceLevel(check, proofFloor, revocationFresh)`) from the attested capabilities, the proof floor and whether every status was read live; the card's own `conformanceLevel` is never read.
- **Minimum level**: `minimumLevel` (default `L3`) for every tool, `tools[name].minimumLevel` per tool, and `l3MinusSatisfiesL3` (default `true`). Scopes are checked first, the level after. A call below the tool's minimum is a `LevelError` (`PROOF_LEVEL_INSUFFICIENT`, 401 `insufficient_user_authentication`) carrying `derivedLevel` (`L1`, `L2`, `L3-minus`, `L3`) and `requiredLevel`. OAuth-only callers carry no level and are not checked.
- **A chain without a proof** is verified in full (signatures, attenuation, revocation, card) with the leaf delegate as the unproven agent; the proof floor does not hold, so it comes to `L2` at most and is accepted only where a tool's minimum allows it.
- **Audit**: each event records `level`, `fresh`, `proofAssurance`, `l3Minus`, any `cnfDiagnostics`, and on a level refusal `requiredLevel`; `reportVerification` gets `proofFloor`, `l3Minus` and `cnfDiagnostics` too.

```ts
const requireHelix = helixidMCPMiddleware({
  verifier,
  toolScopes: { lookup_order: ['read:orders'], cancel_order: ['write:orders'] },
  minimumLevel: 'L3',                               // default
  tools: { lookup_order: { minimumLevel: 'L2' } },  // a chain without a proof will do here
  l3MinusSatisfiesL3: true,                         // default
});
```

The agent side is `kyaos.withRequestProof(call, signer, { audience, chain, cnfJkt? })` in `@helixid/sdk-js`: the proof and the chain in `params._meta`, signed by the agent's own Signer.

## HTTP auth, per-tool scopes and audit (Phase 1)

A runnable sample, an order-management MCP server with a 5-minute quickstart, is in
[`examples/order-management`](./examples/order-management) (repository only; not part of the npm package).

Credentials: a KYA-OS request proof in `_meta` (above), or `Authorization: Bearer <token>` for OAuth 2.1 clients. Two `Authorization` headers, or a proof together with a bearer token, are rejected with `CREDENTIAL_CONFLICT` rather than picking one.

```ts
import {
  helixidMCPMiddleware, createHelixAuditSink, buildProtectedResourceMetadata,
  protectedResourceMetadataUrl, toHttpErrorResponse,
} from '@helixid/mcp-middleware';

const resource = 'https://mcp.example.com/mcp';
const requireHelix = helixidMCPMiddleware({
  verifier,                                 // KYA-OS request proofs, verified in-process
  serviceDid: 'did:web:mcp.example.com',
  toolScopes: { execute_query: ['read'], update_record: ['write'] }, // unlisted tools are denied
  // One authorization server. Its issuer URL is enough: keys are read from its metadata.
  oauth: { issuer: 'https://as.example.com', audience: resource },
  // Several, with presets for common providers (import { entra, auth0, okta, keycloak }):
  // oauth: [
  //   entra({ tenantId: '<directory id>', audience: '<API application id>' }),
  //   auth0({ domain: 'tenant.us.auth0.com', audience: resource }),
  //   okta({ domain: 'dev-1.okta.com', audience: resource, introspection: { clientId: '...', clientSecret: '...' } }),
  //   keycloak({ baseUrl: 'https://id.example.com', realm: 'shop', audience: resource }),
  //   { issuer: 'https://as.example.com', audience: resource, introspection: { clientId: '...', clientSecret: '...' } },
  // ],
  // or a callback for credentials no standard describes (your own API keys as bearers):
  // validateOAuthToken: async (token) => ({ sub, scopes }),
  auditSink: createHelixAuditSink({ baseUrl: process.env.HELIX_API_URL!, apiKey: process.env.HELIX_API_KEY! }),
  onAuditError: (e) => console.error(e),
});

// Serve this JSON at protectedResourceMetadataUrl(resource) (RFC 9728):
const metadata = buildProtectedResourceMetadata({ resource, authorizationServers: ['https://as.example.com'] });

try { await requireHelix({ name, input: args, headers: req.headers }); }
catch (err) {
  const res = toHttpErrorResponse(err, { resourceMetadataUrl: protectedResourceMetadataUrl(resource) });
  if (!res) throw err;            // not the caller's fault: handle as a server error
  // send res.status, res.headers['WWW-Authenticate'], res.body
}
```

There is no provider-wide default, and cannot be: Auth0, Okta, Entra and Keycloak give every customer their own authorization server, and trusting "Auth0" would accept tokens minted in anyone's tenant. A preset takes the one or two values that name *your* tenant and fills in the provider's exact issuer string and endpoints. Any other server needs only `{ issuer, audience }`: `jwks_uri` (and, with `introspection: { clientId, clientSecret }`, `introspection_endpoint`) come from `<issuer>/.well-known/openid-configuration` or the RFC 8414 document, fetched on first use and required to name the same issuer.

| Preset | You give | Tokens | Notes |
|---|---|---|---|
| `entra` | `tenantId`, `audience` | JWT | v2.0 tokens (`requestedAccessTokenVersion: 2`); `aud` is the API's application ID; scopes from `scp` and `roles` |
| `auth0` | `domain`, `audience` | JWT | clients must request the API audience, or Auth0 issues an opaque token only its own /userinfo accepts; no introspection endpoint |
| `okta` | `domain`, `authorizationServerId?`, `audience`, `introspection?` | JWT, opaque | custom authorization server only; the org server's tokens are not meant for your resource servers |
| `keycloak` | `baseUrl`, `realm`, `audience`, `introspection?` | JWT, opaque | add an audience mapper so `aud` names this server |

Introspection needs this server's own client credentials at the authorization server, so it fits a tenant you run. Agents bringing tokens from their own organisation's tenant can only be verified by public keys, i.e. as JWTs.

OAuth: a JWT is routed to its issuer by the (unverified) `iss` claim and verified there, so an issuer not in the list is refused with no network call; a token that is not a JWT is opaque and names no issuer, so it goes to the one issuer configured for introspection. Only one issuer may be (construction throws otherwise): with two, every opaque token would have to be shown to both. An issuer with both `jwksUri` and `introspection` verifies JWTs by its keys alone unless `introspectJwts: true`, which also asks the issuer, so a revoked JWT is refused before it expires. `requireAccessTokenType: true` on an issuer refuses JWTs whose header `typ` is not `at+jwt` (RFC 9068). An authorization server that cannot be reached throws `AuthorizationServerUnavailableError`, which `toHttpErrorResponse` leaves unmapped: answer 5xx, never 401, because the caller's token was not shown to be bad. A 403 for a missing scope names it in the challenge (`scope="orders:admin"`, RFC 6750) so a client can request that scope and retry.

Audit: every decision about an identified caller (KYA-OS agent or OAuth subject) is passed to `auditSink` and awaited before the tool runs. Unidentified callers are not logged, and a failing sink never blocks a call. OAuth callers have no agent DID, so set `serviceDid`.

## KYA-OS session, replay store and response proof (story L2-A)

`createKyaOs()` adds the KYA-OS session layer around the gate above: a `_kyaos_handshake` tool, optional sessions, a replay store, and a detached proof signed by the service on every tool call outcome, so an agent or auditor can verify what the server received and returned without trusting anyone in between.

```ts
import { kyaos } from '@helixid/sdk-js';
import { createKyaOs, RedisNonceStore, helixidMCPMiddleware, toHttpErrorResponse } from '@helixid/mcp-middleware';

const guard = helixidMCPMiddleware({ verifier, toolScopes });
const kya = createKyaOs({
  signer: new kyaos.EnvSigner({ did: 'did:web:mcp.example.com', envVar: 'SERVICE_SIGNING_KEY' }), // the key stays in the environment
  publicOrigin: 'https://mcp.example.com',          // accepted as handshake audience next to the DID
  clockSkewSeconds: 120,                            // 30 to 600
  session: { enabled: true, ttlMinutes: 30 },
  nonceStore: new RedisNonceStore({ client: ioredis }), // one store for every instance; default: in memory, this instance only
});

// The handshake is a tool: register it on your MCP server and answer with kya.handshakeToolResult(args).
// Every other tool call: start it before the transport sees it, finish it in the handler.
const started = await kya.start({ name, arguments: args, _meta }, { authorize: () => guard.authorize(toolCall) });
if (started.outcome === 'denied') {
  const denial = toHttpErrorResponse(started.error, { resourceMetadataUrl, proof: started.proof }); // 401/403 with the denied proof in the body
  ...
}
const result = await started.finish(await handler(started.arguments)); // the result with _meta["org.kya-os/response-proof"]
```

- **Handshake** (`_kyaos_handshake`, `{nonce, audience, timestamp, agentDid?}`): the nonce is 22+ characters of base64url, the timestamp is within `clockSkewSeconds` of the server time, the audience is the server DID or `publicOrigin`, and the nonce was never seen before. The answer is `{sessionId: "kyaos_<uuid-v4>", serverDid, protocolVersion, serverCapabilities, sessionTtl, nonce}`. A credential sent with the handshake makes the session `authenticated`; without one it is `anonymous`.
- **Replay store** (`NonceStore`): `(nonce, agentDid, expiry)` with one atomic conditional insert, retained until `ts + skew + 1 s` and never evicted early. `MemoryNonceStore` serves one instance; `RedisNonceStore` (`SET NX PX`, any client with ioredis's `set` signature) and `DynamoNonceStore` (a conditional `PutItem` through `DynamoDBDocument.put`) serve several. The nonces of the proofs the server signs go through the same store.
- **Sessions** (`SessionStore`, `MemorySessionStore`): optional (`session.enabled`). A call names its session in the `_kyaos_session` argument; every valid call moves `lastActivity` and the expiry out by the idle TTL. A call without a session is still authorised from its credentials alone. An unknown, expired or malformed session id is a `denied` call (`KYAOS_REJECTED`, 400).
- **Response proof**: a detached EdDSA JWS over the proof meta `{did, kid, ts, nonce, audience, sessionId, requestHash, responseHash?, outcome, reason?, clientDid?, prf}` at `_meta["org.kya-os/response-proof"]`. `requestHash` covers `{method, params}` minus `params._meta` and every `_kyaos*` argument; `responseHash` covers the result minus its top-level `_meta` (the envelope profile, `prf`), present on `allowed` and `needs_authorization`, absent on `denied` and `step_up_required`. `_kyaos*` arguments are stripped before the tool runs; every non-KYA-OS `_meta` key is ignored.
- **Client side**: `kyaos.verifyResponseProof(result, serverDid, resolveDid, { request })` in `@helixid/sdk-js` (and `helix_sdk.response_proof.verify_response_proof` in helix-sdk-py) verifies the signature against the server's DID document and recomputes both hashes; a swapped body fails.
- **Discovery**: `describeKyaOs()` (or `kya.describe()`) gives `endpoints.handshake`, `clockSkewSeconds` and `capabilities.proofs` for the `/.well-known/mcp` document.
- **Self-custody and cross-border**: the service `Signer` is the only thing that touches the private key (the middleware hands it bytes and takes back a signature); the verify path reads the nonce store and local config only, never a Helix database.

The sample in `examples/order-management` wires all of this (`SERVICE_SIGNING_KEY`, `KYAOS_*` variables); its README has the details.
