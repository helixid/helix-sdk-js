# @helixid/mcp-middleware

Thin MCP adapter for Helix ID. It verifies every inbound tool call in-process (KYA-OS story F-2): the agent's request proof (`org.kya-os/proof.v1`) rides `params._meta["org.kya-os/request-proof"]` and its delegation chain `params._meta["org.kya-os/delegation-chain"]`, on any transport, stdio included. Verification reads only the presented artifacts, public DID documents, status lists and Entity Cards over HTTPS, the local replay store and local config: the Helix API is never asked, so calls are authorised with it unreachable, and a credential issued by any Helix deployment verifies here. The Helix VP (`X-Helix-VP`, `_meta["x-helix-vp"]`, `attachHelixVP`) is retired with no backward compatibility.

```ts
import { helixidMCPMiddleware, createLocalVerifier, RedisNonceStore } from '@helixid/mcp-middleware';

const verifier = createLocalVerifier({
  serviceDid: 'did:web:mcp.example.com', // the proof audience and the chain's resource
  trustedIssuers: '*',                    // attestation issuers; a list trusts those DIDs only
  maxChainLength: 10,                     // a carried chain is bounded before any entry is parsed
  // A HelixID-hosted agent's card names its revocation entry on the Helix issuer's list: bind that exact URL (§10.3).
  statusListIssuers: { 'did:web:api.helixid.dev': ['https://api.helixid.dev/v1/status-list/helix-status-list-1'] },
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
- **Audit**: the in-process `ToolAuditEvent` given to `auditSink` carries `level`, `fresh`, `proofAssurance`, `l3Minus`, any `cnfDiagnostics`, and on a level refusal `requiredLevel`; `reportVerification` gets `proofFloor`, `l3Minus` and `cnfDiagnostics` too. In the typed events (`McpAuditTrail.toolAuditSink()`) they enter only as the `proof.verified` verification code, `KYAOS_PROOF_<L1|L2|L3|L3_MINUS>[_CACHED][_CNF_UNFUSED]`, and a level refusal is `authorization.denied` with reason `proof_level_insufficient`.

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

Since KYA-OS story A-1 the audit log holds typed producer events (AAP-1 Recorded). `createHelixAuditSink` keeps its call shape and now records each decision as typed events: a KYA-OS caller (story F-2) as `proof.verified` (verification code `KYAOS_PROOF_<level>`, with `_CACHED` when a status was not read live) then `authorization.approved` / `authorization.denied`, a request proof the local verifier refused as `proof.rejected` by its first reason code, an OAuth caller as the authorization event alone; each strictly validated (an unknown member is refused), sequenced per source with `previousSourceEventDigest`, digested, and posted to `POST /v1/audit-log/events`. For the full lifecycle of a tool call (`session.established`, then `tool.call.started` / `completed` / `failed` / `denied` under one correlation id) build an `McpAuditTrail` with `createMcpAuditTrail({ reporter: createHelixAuditReporter({ baseUrl, apiKey }), serviceDid })`, pass `audit.toolAuditSink()` as `auditSink`, and wrap each call in `audit.beginToolCall({ toolName }).run(...)`, as `examples/order-management` does. No event ever holds tool arguments, a response, a bearer token or a credential; an OAuth subject is recorded as a keyed commitment; tool names are withheld unless `includeToolNames` is set.

## Audit delivery to the recorder (KYA-OS A-2, AAP-2 Chained)

Audit events go to the HelixID recorder (`POST /v1/audit/submissions`), which
assigns sequence, epoch, predecessor and time and signs a receipt. The server
never chooses any of those.

```ts
const audit = createMcpAuditTrail({
  reporter: createHelixAuditDelivery({ baseUrl, apiKey, delivery: 'required' }),
  serviceDid,
});
const call = audit.beginToolCall({ toolName });
auditToolHandlers(server, call); // before the tools are registered
```

| `delivery` | What it means |
|---|---|
| `required` (default) | The intent's signed receipt is obtained before the handler runs; if it cannot be, the call answers `audit_delivery_failed` and the handler does not run. If the terminal append fails after the handler ran, the result is marked `_meta["org.kya-os/audit"] = { status: "degraded", reason }` with `isError`. |
| `buffered` | Events go to a durable outbox (`outboxDir`) keyed by `(sourceId, eventId)` and are delivered in the background, in order per source; the outbox survives a restart. An ephemeral outbox is refused at startup. |
| `best-effort` | Refused unless `acceptAap1: true`: delivery is attempted and failures are only reported (AAP-1, capture only). |

The order-management sample reads `AUDIT_DELIVERY`, `AUDIT_OUTBOX_DIR` and `AUDIT_ACCEPT_AAP1`.

## Serving the service's KYA-OS identity (Entity Card, story C-A)

A KYA-OS service has a did:web whose DID document anchors its Entity Card (`KyaOsEntityCard`
service entry). `serveIdentity` builds both documents from the middleware's own configuration
and answers them at the paths the did:web derives, from the origin agents connect to:

```ts
import { serveIdentity } from '@helixid/mcp-middleware';

const identity = serveIdentity({
  publicOrigin: 'https://mcp.example.com',   // what the documents name; behind a proxy, not the bind address
  path: '/mcp',                              // did:web:mcp.example.com:mcp → /mcp/did.json and /mcp/card.json
  card: { name: 'Orders', kid: 'key-1', publicKeyJwk, capabilities: ['tools/list', 'tools/call'] },
});
// In the HTTP handler, before the MCP transport:
if (req.method === 'GET' && identity.handle(new URL(req.url, publicOrigin).pathname, res)) return;
// On server.json / catalog.json:
const serverJson = identity.projectServerJson({ name: 'orders', version: '1.0.0' });
// _meta["org.kya-os/card"] = claim-minimal summary + "org.kya-os/cardRef" (the canonical card.json)
```

Hosting follows the `/.well-known/mcp` cases: route `/{path}/did.json` and `/{path}/card.json` at
the origin root to the middleware (a proxy path rule), mount `handle()` in whichever app serves the
root, or write `identity.didDocument` and `identity.card` out as static files. A service whose
`helix init` already wrote the files hands them in as `documents`. The card never carries a
`conformanceLevel` (a verifier recomputes it) nor a proof (it rides per request).

Verifier side, `resolveServerCard(serverJson, { did })` dereferences the projection to the canonical
card through the SDK's SafeFetch (https only, public addresses only, pinned connection, same-origin
redirects, 1 MiB, 5 s); a stripped projection falls back to the two-step resolution of `did`
(`did.json` → `KyaOsEntityCard` → `card.json`). The sample server enables all of this with
`PUBLIC_ORIGIN` (see `examples/order-management/src/main.ts`).

## KYA-OS session, replay store and response proof (story L2-A)

`createKyaOs()` adds the KYA-OS session layer around the gate above: a `_kyaos_handshake` tool, optional sessions, a replay store, and a detached proof signed by the service on every tool call outcome, so an agent or auditor can verify what the server received and returned without trusting anyone in between.

```ts
import { kyaos } from '@helixid/sdk-js';
import { createKyaOs, helixidMCPMiddleware, toHttpErrorResponse } from '@helixid/mcp-middleware';

const guard = helixidMCPMiddleware({ verifier, toolScopes });
const kya = createKyaOs({
  signer: new kyaos.EnvSigner({ did: 'did:web:mcp.example.com', envVar: 'SERVICE_SIGNING_KEY' }), // the key stays in the environment
  publicOrigin: 'https://mcp.example.com',          // accepted as handshake audience next to the DID
  clockSkewSeconds: 120,                            // 30 to 600
  session: { enabled: true, ttlMinutes: 30 },
  // nonceStore: new RedisNonceStore({ client: ioredis }), // an explicit store wins; default: the one KYAOS_NONCE_STORE names
});
await kya.ready(); // redis / dynamo: fails here when the client package is missing

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
- **Replay store from the environment** (`nonceStoreFromEnv()`, the default when no `nonceStore` is passed):

  | Variable | Values | Default |
  |---|---|---|
  | `KYAOS_NONCE_STORE` | `memory`, `redis`, `dynamo` | `memory` |
  | `KYAOS_REDIS_URL` | `redis://` or `rediss://` URL; required for `redis` | |
  | `KYAOS_NONCE_KEY_PREFIX` | Redis key prefix | `kyaos:nonce:` |
  | `KYAOS_DYNAMO_TABLE` | table name; required for `dynamo` | |
  | `KYAOS_DYNAMO_KEY_ATTRIBUTE` | partition key attribute (string) | `pk` |
  | `KYAOS_DYNAMO_TTL_ATTRIBUTE` | the table's TTL attribute (Unix seconds) | `expiresAt` |
  | `KYAOS_DYNAMO_REGION` | AWS region | the AWS SDK's own |
  | `KYAOS_DYNAMO_ENDPOINT` | endpoint URL, for DynamoDB Local | the AWS SDK's own |

  AWS credentials come from the AWS SDK's standard chain, never from these variables. The clients are optional peer dependencies, loaded only when chosen: `npm install ioredis` for `redis`, `npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb` for `dynamo`. It fails closed: an unknown store or a missing required variable throws from `createKyaOs()`, a missing package rejects `kya.ready()` (await it at startup), and nothing falls back to memory. One startup line names the store without secrets (a Redis password is shown as `***`); memory with `NODE_ENV` or `ENV` set to `production` also warns that it covers one process only. JS and Python instances write the same keys, so they can share one Redis or table.
- **Sessions** (`SessionStore`, `MemorySessionStore`): optional (`session.enabled`). A call names its session in the `_kyaos_session` argument; every valid call moves `lastActivity` and the expiry out by the idle TTL. A call without a session is still authorised from its credentials alone. An unknown, expired or malformed session id is a `denied` call (`KYAOS_REJECTED`, 400).
- **Response proof**: a detached EdDSA JWS over the proof meta `{did, kid, ts, nonce, audience, sessionId, requestHash, responseHash?, outcome, reason?, clientDid?, prf}` at `_meta["org.kya-os/response-proof"]`. `requestHash` covers `{method, params}` minus `params._meta` and every `_kyaos*` argument; `responseHash` covers the result minus its top-level `_meta` (the envelope profile, `prf`), present on `allowed` and `needs_authorization`, absent on `denied` and `step_up_required`. `_kyaos*` arguments are stripped before the tool runs; every non-KYA-OS `_meta` key is ignored.
- **Client side**: `kyaos.verifyResponseProof(result, serverDid, resolveDid, { request })` in `@helixid/sdk-js` (and `helix_sdk.response_proof.verify_response_proof` in helix-sdk-py) verifies the signature against the server's DID document and recomputes both hashes; a swapped body fails.
- **Discovery**: `describeKyaOs()` (or `kya.describe()`) gives `endpoints.handshake`, `clockSkewSeconds` and `capabilities.proofs` for the `/.well-known/mcp` document, which `createWellKnownMcp({ publicOrigin, serverDid, kyaos: kya.describe() })` builds, validates against the KYA-OS schema at startup and serves (story L1-D; on by default, `enabled: false` answers 404). Route `/.well-known/mcp` at your origin root to the middleware and set `publicOrigin` to the origin agents connect to: [docs/well-known.md](./docs/well-known.md) has the nginx, ALB and API Gateway snippets.
- **Self-custody and cross-border**: the service `Signer` is the only thing that touches the private key (the middleware hands it bytes and takes back a signature); the verify path reads the nonce store and local config only, never a Helix database.

The sample in `examples/order-management` wires all of this (`SERVICE_SIGNING_KEY`, `KYAOS_*` variables); its README has the details.

## Revocation: signed status lists, the status cache and the revocation signal (story L3-C)

Every status list the local verifier reads is held to SPEC.md §6.6 before a bit is read, and every failure reads as revoked:

- **Proof first.** A list is fetched (`createResolutionFetch` by default: https only, a host written as an IP must be public unicast, same-origin redirects, 5 s, 1 MiB; pass your SafeFetch as `fetch` to pin the connection too), its `DataIntegrityProof` (`eddsa-jcs-2022`, or the §6.2 `Ed25519Signature2020`) is verified against its issuer's `assertionMethod` key, and only then are the bits inflated (multibase `u` + GZIP, MSB first). Unreachable, malformed, unsigned, badly signed, wrong-purpose and out-of-range lists, and lists outside their window, are refused (`status_unavailable`, `status_list_malformed`, `status_list_proof_invalid`, `status_list_mismatch`, `status_entry_malformed`, `status_stale`).
- **Both formats.** W3C Bitstring Status List v1.0 (what Helix issues, one list per issuer DID) and StatusList2021 (read for Core L3.11).
- **The keeper.** A list counts only when its `issuer` keeps the URL: `statusListIssuers` (issuer DID to exact URLs or `https:` origins) first, then the pinned root (`resourceOwner`), then the credential's own issuer.
- **The card's own entry.** A card that declares `revocation` is read the same way (SPEC-ENTITY-CARD §10.3), with the card's DID as the default keeper: a set bit refuses the call (`status_revoked`), and a list the card's DID does not keep, with no `statusListIssuers` binding for its URL, refuses it too (`status_list_mismatch`). A HelixID-hosted agent's card names its identity credential's entry on the Helix issuer's list, so a service bind that list's exact URL to the Helix issuer (not its origin: per-issuer lists share it).
- **Chain walk.** Root to leaf, stopping at the first revoked or unresolvable hop; `fresh` is the AND of every read and is on every `VerificationReport`.
- **Cache.** `statusCache` (a `kyaos.verifier.StatusCache`, or its options): `statusCacheTtl` (default 300 s), `highPrivilegeScopes` held to `highPrivilegeTtl` (≤ 60 s), `maxStaleSeconds` (a list read inside its window may be served past `validUntil` that long). A cached read is `fresh: false`, which demotes a Card L3 request to L2, so the guard reads every list live, past the cache, for a tool whose minimum level is L3 (`verifyCall({ liveStatus: true })`); the cache serves tools at L2 or below. With several instances, give the cache a `RedisStatusCacheStore` (any client with ioredis's `get`/`set PX`/`del`/`incr`), next to the `RedisNonceStore`.

```ts
import { kyaos } from '@helixid/sdk-js';
import { createLocalVerifier, createRevocationSignalClient, RedisStatusCacheStore } from '@helixid/mcp-middleware';

const verifier = createLocalVerifier({
  serviceDid: 'did:web:mcp.example.com',
  statusCache: { store: new RedisStatusCacheStore({ client: ioredis }), statusCacheTtl: 300, highPrivilegeScopes: ['orders:admin'] },
});
// One outbound SSE connection per instance to Helix, reconnecting on drop; each valid SET drops the cached verdict.
const signals = createRevocationSignalClient(verifier, {
  eventsUrl: 'https://api.helixid.example/v1/events/revocations',
  trustedIssuers: ['did:web:api.helixid.example'], // the Helix issuer whose SETs are honoured
  onSignal: (report) => audit(report),              // every signal, honoured or ignored
});
signals.start();
// Or push (RFC 8935): mount signals.webhookHandler() at the URL registered with Helix (202, or 400 {err, description}).
```

- **Revocation signal.** Helix emits one Security Event Token (RFC 8417) per revoked credential, carrying only its id. `RevocationSignalClient` verifies the issuer (checked before anything is resolved) and the signature, then calls `statusCache.invalidate(credentialId)`, which deletes that credential's verdict and the list it was read from (every cached list when it held nothing for the id). In the shared Redis one delete is seen by every instance; a duplicate is harmless. A signal with a bad signature or from an unknown issuer is ignored and reported through `onSignal`; it never revokes anything. Nothing is polled.
## KYA-OS signed `needs_authorization` and resume (story L3-E)

When a caller is identified but its delegation does not cover the tool's scopes, the guard answers with the SPEC §9.2 challenge instead of a plain 403: `{error: "needs_authorization", message, authorizationUrl, resumeToken, expiresAt, scopes, display?}`. Under the KYA-OS runtime the challenge is the call's tool result (`isError`, the challenge as text and as `structuredContent`) signed with `outcome: needs_authorization` and a `responseHash` over the whole result, so `authorizationUrl` is covered by the service signature; the SDK (`kyaos.handleNeedsAuthorization`) recomputes that hash before surfacing the URL and refuses a swapped one with `response_hash_mismatch`.

```ts
import { createNeedsAuthorization, helixidMCPMiddleware } from '@helixid/mcp-middleware';

const needsAuthorization = createNeedsAuthorization({
  authorizationUrl: (c) => `https://consent.example/authorize?agent=${c.agentDid}&tool=${c.tool}`,
  ttlSeconds: 600,                                   // resume-token lifetime
  // store: default follows KYAOS_NONCE_STORE (Redis on KYAOS_REDIS_URL when the replay store is Redis, else memory)
  authorizer: verifyDelegation,                      // the seam stories F-2 and L3-H implement; default refuses every retry
  auditSink,                                         // every challenge is an AUTHZ_DENIED event with reason "needs_authorization"
});
await needsAuthorization.ready();                   // a Redis store loads ioredis in the background, like the replay store
const guard = helixidMCPMiddleware({ ...options, needsAuthorization });
```

`resumeToken` is opaque (32 random bytes), bound to the agent, the tool and the scopes asked for, single-use and gone at `expiresAt` (`ResumeTokenStore`: `MemoryResumeTokenStore`, `RedisResumeTokenStore` with `SET NX PX` / `GETDEL`; `resumeTokenStoreFromEnv` picks one from L2-A's `KYAOS_NONCE_STORE`, key prefix `KYAOS_RESUME_KEY_PREFIX`). A retry carries it as the `_kyaos_resume` control argument and the new DelegationCredential as `_kyaos_delegation` (both stripped before the tool, never hashed); the guard consumes the token, checks the binding (`resume_token_unknown`, `resume_token_agent_mismatch`, `resume_token_tool_mismatch`, `resume_token_scope_mismatch`, `delegation_missing`), hands the credential to the `authorizer`, and only then runs the usual scope check with what the credential grants. Completing consent alone never authorises the call. Without the KYA-OS runtime `toHttpErrorResponse` answers the challenge as an unsigned 403 whose body is the challenge. The store is local state next to the nonce store, never a Helix database (cross-border rule).
