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
