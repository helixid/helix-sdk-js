# Serving `/.well-known/mcp`

KYA-OS servers SHOULD expose a discovery document at `/.well-known/mcp` (Core L1.10). An agent reads it on first contact to learn the server's DID, its clock-skew window, where the MCP endpoint and the session handshake are, and which features the server has on. `@helixid/mcp-middleware` builds and serves that document; this page says how to put it at your origin root.

## What is served

`createWellKnownMcp()` builds the document once from configuration, validates it against the KYA-OS `well-known-mcpi.json` schema (vendored at `schemas/well-known-mcpi.json`, byte for byte the suite's copy at commit `a4d7f61`) and refuses to start on anything that would not validate. It never changes at runtime.

```ts
import { createKyaOs, createWellKnownMcp } from '@helixid/mcp-middleware';

const kya = createKyaOs({ signer, publicOrigin: 'https://mcp.example.com', clockSkewSeconds: 120 });

const wellKnown = createWellKnownMcp({
  publicOrigin: 'https://mcp.example.com',   // the origin agents connect to; required
  serverDid: 'did:web:mcp.example.com',      // did:web or did:key; required
  toolsEndpoint: '/mcp',                     // path at publicOrigin, or an absolute URL there; default /mcp
  kyaos: kya.describe(),                     // proofs, the handshake and the skew, from the L2-A layer
  statusListCredential: 'https://mcp.example.com/credentials/status/1', // optional
  capabilities: { delegation: false, statusList: false, crisp: false }, // each true only while that feature is on
});

// node:http: answers GET and HEAD /.well-known/mcp, returns false for everything else
server.on('request', (req, res) => { if (wellKnown.handle(req, res)) return; /* ... */ });
// any other host: wellKnown.respond() is { status, headers, body }
```

The document:

```json
{
  "version": "1.0",
  "serverDid": "did:web:mcp.example.com",
  "endpoints": {
    "tools": "https://mcp.example.com/mcp",
    "handshake": "https://mcp.example.com/mcp#_kyaos_handshake"
  },
  "clockSkewSeconds": 120,
  "capabilities": { "proofs": true, "delegation": false, "statusList": false, "crisp": false },
  "statusListCredential": "https://mcp.example.com/credentials/status/1",
  "supportedDidMethods": ["did:web", "did:key"],
  "proofAlgorithms": ["EdDSA"]
}
```

| Field | From | Notes |
|---|---|---|
| `version` | `version` | Default `1.0` |
| `serverDid` | `serverDid` | The DID the response proofs are signed under; `did:web` or `did:key` |
| `endpoints.tools` | `publicOrigin` + `toolsEndpoint` | Always an absolute URL at `publicOrigin` |
| `endpoints.handshake` | `kyaos` | `<tools>#_kyaos_handshake`; present only while L2-A sessions are enabled. The handshake is a tool on the MCP endpoint, not a route |
| `clockSkewSeconds` | `kyaos` or `clockSkewSeconds` | Default 120, allowed 30 to 600. With `kyaos` it must equal the runtime's skew: that is the window the handshake enforces |
| `capabilities.proofs` | `kyaos` | True whenever the KYA-OS layer is on (every tool call outcome is answered with a signed proof) |
| `capabilities.delegation`, `statusList`, `crisp` | `capabilities` | False unless you say the feature is on |
| `statusListCredential` | `statusListCredential` | Absolute URL; left out when not given |
| `supportedDidMethods`, `proofAlgorithms` | defaults | Advisory: what the Helix verifier resolves and checks (`did:web`, `did:key`; `EdDSA`). Override only if your verifier differs |

`enabled: false` keeps the route and answers 404 (L1.10 is RECOMMENDED, so the switch exists); nothing is built or validated then.

## The `publicOrigin` rule

Behind a proxy the process sees its own bind address (`http://127.0.0.1:3700`), and an agent that reads `endpoints.tools` from the document connects to exactly that URL. So the document is built from `publicOrigin`, the origin the agent connects to, and `toolsEndpoint` is resolved against it; an absolute `toolsEndpoint` at any other origin is refused at startup. The same origin is what the L2-A handshake accepts as `audience` next to the server DID, so give both the same value.

If MCP lives on `mcp.example.com`, the document belongs on `https://mcp.example.com/.well-known/mcp`, not on `www.example.com`: the agent derives the well-known URL from the origin of the MCP endpoint it was given, and nothing in the spec lets a document on one host speak for another.

## Routing the path to the middleware

`/.well-known/mcp` lives at the origin root while the MCP endpoint usually lives under a path (`/mcp`, `/orders/mcp`). One path rule in front of the server forwards the well-known path to the process that runs the middleware, the same way `/.well-known/oauth-protected-resource` already is. The process must see the path unchanged.

### nginx

```nginx
server {
  listen 443 ssl;
  server_name mcp.example.com;

  # The MCP endpoint
  location = /mcp {
    proxy_pass http://127.0.0.1:3700;
    proxy_set_header Host $host;
  }

  # KYA-OS discovery at the origin root, served by the same process
  location = /.well-known/mcp {
    proxy_pass http://127.0.0.1:3700;
    proxy_set_header Host $host;
  }
}
```

### AWS Application Load Balancer

Two listener rules on the HTTPS listener, both forwarding to the target group that holds the middleware's instances (the MCP rule is already there):

```hcl
resource "aws_lb_listener_rule" "well_known_mcp" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mcp.arn
  }

  condition {
    path_pattern { values = ["/.well-known/mcp"] }
  }
}
```

Console equivalent: Listener → Rules → Add rule → condition *Path* `/.well-known/mcp` → action *Forward to* the MCP target group. Health checks can use the same path: it is an unauthenticated GET that answers 200 while the server is up.

### Amazon API Gateway (HTTP API)

One route for the exact path, integrated with the same backend as the MCP route:

```bash
aws apigatewayv2 create-route \
  --api-id "$API_ID" \
  --route-key 'GET /.well-known/mcp' \
  --target "integrations/$MCP_INTEGRATION_ID"
```

The integration must pass the path through unchanged (an HTTP proxy integration with the request path `/{proxy}` or the literal `/.well-known/mcp`), and the API's custom domain must be the MCP origin (`mcp.example.com`) so the document and the endpoint share one origin. With a REST API, create the resource `/.well-known/mcp` with a GET method and an HTTP proxy integration to the same backend.

## Hosting cases not covered here

The middleware route (above) is the case where you control the proxy. Two more are possible and are added when an operator asks: mounting the handler in another application that owns the origin root, and generating the document as a static file for hosts that cannot run code at the root. The document is static, so a static copy served at the same origin is equivalent; regenerate it on upgrade.

## Checking it

```bash
curl -s https://mcp.example.com/.well-known/mcp | jq .
```

The order-management sample serves the document whenever `SERVICE_DID` is a `did:web` or `did:key` (`WELL_KNOWN_MCP=0` turns it off); its `Discovery:` startup line says where. A client reads it with `kyaos.fetchWellKnownMcp(origin)` from `@helixid/sdk-js`, which checks the document the way the schema does, fills `clockSkewSeconds` with 120 when the server advertised none, and resolves relative endpoints against the origin.
