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

OAuth: a JWT is routed to its issuer by the (unverified) `iss` claim and verified there, so an issuer not in the list is refused with no network call; a token that is not a JWT is opaque and is introspected at each issuer configured for introspection until one reports it active. `requireAccessTokenType: true` on an issuer refuses JWTs whose header `typ` is not `at+jwt` (RFC 9068). An authorization server that cannot be reached throws `AuthorizationServerUnavailableError`, which `toHttpErrorResponse` leaves unmapped: answer 5xx, never 401, because the caller's token was not shown to be bad. A 403 for a missing scope names it in the challenge (`scope="orders:admin"`, RFC 6750) so a client can request that scope and retry.

Audit: every decision about an identified caller (VP agent or OAuth subject) is passed to `auditSink` and awaited before the tool runs. Unidentified callers are not logged, and a failing sink never blocks a call. OAuth callers have no agent DID, so set `serviceDid` (or `expectedTargetService`).
