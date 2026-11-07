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

`helixidMCPMiddleware` reads the VP from `_meta["x-helix-vp"]` or the `X-Helix-VP` header, never from `input`, and throws `VPMissingError` when neither is present. Signing (`client.signVP()`) and verification (`verifyVP`, `requireScope`) come from `@helixid/sdk-js`. Replay protection remains the verifier's responsibility (see `examples/replay-protection/`).

## HTTP auth, per-tool scopes and audit (Phase 1)

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
  oauth: { issuer: 'https://as.example.com', audience: resource, jwksUri: 'https://as.example.com/jwks' },
  // or: validateOAuthToken: async (token) => ({ sub, scopes })  (opaque tokens, introspection)
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

Audit: every decision about an identified caller (VP agent or OAuth subject) is passed to `auditSink` and awaited before the tool runs. Unidentified callers are not logged, and a failing sink never blocks a call. OAuth callers have no agent DID, so set `serviceDid` (or `expectedTargetService`).
