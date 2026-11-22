# @helixid/mcp-middleware

Thin MCP adapter for Helix ID. It verifies the VP on inbound tool calls and attaches a server-signed VP to outbound tool calls. The VP never travels in tool arguments: it is carried as base64url-encoded JSON in the MCP request's `params._meta["x-helix-vp"]` (any transport, including stdio) or, over HTTP, in the `X-Helix-VP` header.

```ts
import { HelixClient } from '@helixid/sdk-js';
import { helixidMCPMiddleware, attachHelixVP } from '@helixid/mcp-middleware';

const client = new HelixClient({ apiKey: process.env.HELIX_API_KEY! });

// Client side: sign a VP and put it in _meta (input is left untouched).
const call = await attachHelixVP(
  { name: 'orders.lookup', input: { orderId: 'ORD-1001' } },
  { client, agentDid: process.env.AGENT_DID!, targetService: 'orders', userDid: 'did:web:user.example.com' },
);
await mcpClient.callTool({ name: call.name!, arguments: call.input, _meta: call._meta });

// Server side: pass the request's params._meta (and, over HTTP, the request headers).
const requireHelix = helixidMCPMiddleware({ client, requiredScopes: ['read:orders'] });
await requireHelix({ name, input: args, _meta: request.params._meta, headers: req.headers });
```

`helixidMCPMiddleware` reads the VP from `_meta["x-helix-vp"]` or the `X-Helix-VP` header, never from `input`, and throws `VPMissingError` when neither is present. Signing (`client.signVP()`) and verification (`verifyVP`, `requireScope`) come from `@helixid/sdk-js`. A VP is not single-use: the same presentation is accepted again until it expires (`VP_TTL_SECONDS` on the API, 300 s by default). Target-service binding, the short TTL, revocation and the audit trail (same `vpId`) bound a replay; single-use enforcement belongs in the verifier and is a Phase 2 item.

## HTTP auth, per-tool scopes and audit (Phase 1)

A runnable sample, an order-management MCP server with a 5-minute quickstart, is in
[`examples/order-management`](./examples/order-management) (repository only; not part of the npm package).

Credentials, in the order they are looked up: `Authorization: HelixVP <base64url_vp>`, the legacy `X-Helix-VP` header, and (stdio / any transport) `_meta["x-helix-vp"]`; or `Authorization: Bearer <token>` for OAuth 2.1 clients. Different VPs in different places, two `Authorization` headers, or a VP together with a bearer token are rejected with `CREDENTIAL_CONFLICT` rather than picking one. The same VP repeated is fine.

```ts
import {
  helixidMCPMiddleware, createHelixAuditSink, buildProtectedResourceMetadata,
  protectedResourceMetadataUrl, toHttpErrorResponse,
} from '@helixid/mcp-middleware';

const resource = 'https://mcp.example.com/mcp';
const requireHelix = helixidMCPMiddleware({
  client,                                   // needed to verify HelixID VPs
  expectedTargetService: 'did:web:mcp.example.com',
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

Audit: every decision about an identified caller (VP agent or OAuth subject) is passed to `auditSink` and awaited before the tool runs. Unidentified callers are not logged, and a failing sink never blocks a call. OAuth callers have no agent DID, so set `serviceDid` (or `expectedTargetService`).

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

const guard = helixidMCPMiddleware({ client, toolScopes });
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
- **Discovery**: `describeKyaOs()` (or `kya.describe()`) gives `endpoints.handshake`, `clockSkewSeconds` and `capabilities.proofs` for the `/.well-known/mcp` document.
- **Self-custody and cross-border**: the service `Signer` is the only thing that touches the private key (the middleware hands it bytes and takes back a signature); the verify path reads the nonce store and local config only, never a Helix database.

The sample in `examples/order-management` wires all of this (`SERVICE_SIGNING_KEY`, `KYAOS_*` variables); its README has the details.
