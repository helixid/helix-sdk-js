# Order Management: a HelixID-protected MCP server

A small MCP server with two tools behind `@helixid/mcp-middleware`:

| Tool | Scope | What it does |
|---|---|---|
| `lookup_order` | `orders:read` | Returns an order by id |
| `refund_order` | `orders:admin` | Refunds an order in full (destructive) |

Any other tool name is denied before it runs. Callers come through either door:

- **HelixID agents**: a signed VP in `Authorization: HelixVP <vp>` (or legacy `X-Helix-VP`, or MCP `params._meta["x-helix-vp"]`).
- **Standard MCP OAuth 2.1 clients**: `Authorization: Bearer <token>`, discovered through the RFC 9728 metadata at
  `/.well-known/oauth-protected-resource/mcp`.

Every decision about an identified caller can be written to the HelixID audit log (`AUTHZ_GRANTED` / `AUTHZ_DENIED`)
and appears in the Operator Console.

## 5-minute quickstart (no accounts, no authorization server)

From the `helix-sdk-js` checkout:

```bash
pnpm install
pnpm --filter @helixid/example-mcp-order-management... build
pnpm --filter @helixid/example-mcp-order-management demo
```

`DEMO_MODE=1` accepts two fixed bearer tokens, `demo-reader` (`orders:read`) and `demo-admin` (`orders:read`,
`orders:admin`), and only on a loopback address. In another terminal:

```bash
MCP=http://localhost:3700/mcp
H=(-H 'content-type: application/json' -H 'accept: application/json, text/event-stream')

# No credentials: 401, with WWW-Authenticate pointing at the metadata
curl -i "${H[@]}" $MCP -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_order","arguments":{"orderId":"ORD-1001"}}}'

# A reader can look up an order...
curl "${H[@]}" -H 'authorization: Bearer demo-reader' $MCP -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup_order","arguments":{"orderId":"ORD-1001"}}}'

# ...but not refund it: 403 insufficient_scope
curl -i "${H[@]}" -H 'authorization: Bearer demo-reader' $MCP -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"refund_order","arguments":{"orderId":"ORD-1001","reason":"damaged"}}}'

# An admin can
curl "${H[@]}" -H 'authorization: Bearer demo-admin' $MCP -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"refund_order","arguments":{"orderId":"ORD-1001","reason":"damaged"}}}'
```

Orders live in memory (`ORD-1001`, `ORD-1002`) and reset on restart.

## With HelixID: verify agent VPs and write the audit log

Point the server at a HelixID API **you run locally** (for example `helix-server-enterprise` on port 3580, the port the
console's dev proxy expects) and give it an account API key (`hak_…`) from that instance:

```bash
HELIX_API_URL=http://localhost:3580 \
HELIX_API_KEY=hak_... \
SERVICE_DID=did:web:orders.example \
DEMO_MODE=1 \
pnpm --filter @helixid/example-mcp-order-management start
```

- VPs are verified by that API (`POST /v1/vp/verify`): signature, delegation chain, expiry, target service and revocation.
  `SERVICE_DID` rejects VPs signed for any other service.
- Each decision is posted to `POST /v1/audit-log/events` and shows up under **Audit** in the console, with the agent DID or
  the OAuth subject, the tool, and the scope that was missing on a denial.
- `HELIX_API_URL` is required whenever `HELIX_API_KEY` is set. The SDK's `HelixClient` given only a key talks to the hosted
  production API, so this sample refuses to start rather than fall back to it.

## With a real authorization server

Drop `DEMO_MODE` and set the authorization server instead. Access tokens must be JWTs whose `aud` is this server's
`MCP_RESOURCE` (default `http://localhost:3700/mcp`):

```bash
OAUTH_ISSUER=https://as.example.com OAUTH_JWKS_URI=https://as.example.com/.well-known/jwks.json \
pnpm --filter @helixid/example-mcp-order-management start
```

For an authorization server that issues opaque tokens, give the sample its introspection endpoint and this server's client
credentials instead of a JWKS URI (RFC 7662):

```bash
OAUTH_ISSUER=https://as.example.com OAUTH_INTROSPECTION_URL=https://as.example.com/oauth2/introspect \
OAUTH_CLIENT_ID=orders-mcp OAUTH_CLIENT_SECRET=... \
pnpm --filter @helixid/example-mcp-order-management start
```

Agents from different providers (one on Auth0, another on Okta) can share the server: list every trusted issuer in
`OAUTH_ISSUERS`, each with `jwksUri`, `introspection`, or both. Tokens are routed to their issuer by `iss`; an issuer not in
the list is refused.

```bash
OAUTH_ISSUERS='[
  {"issuer":"https://tenant.auth0.com/","jwksUri":"https://tenant.auth0.com/.well-known/jwks.json"},
  {"issuer":"https://dev-1.okta.com/oauth2/default",
   "introspection":{"endpoint":"https://dev-1.okta.com/oauth2/default/v1/introspect","clientId":"orders-mcp","clientSecret":"..."}}
]' pnpm --filter @helixid/example-mcp-order-management start
```

For credentials no standard describes (your own API keys presented as bearers), use a `validateOAuthToken` callback
(see `DEMO_MODE` in `src/main.ts`).

## How it is wired (`src/app.ts`)

The gate runs at the HTTP layer, in front of the MCP transport, and only for `tools/call`:

1. Parse the JSON-RPC body. For each `tools/call`, call the middleware with the tool name, arguments, `params._meta` and
   the HTTP headers.
2. On failure, `toHttpErrorResponse()` turns the error into a 401 / 400 / 403 with `WWW-Authenticate`. A real HTTP 401 is
   what makes an MCP OAuth client start discovery; a tool-level error would not.
3. Otherwise hand the request to a stateless `StreamableHTTPServerTransport`.

`initialize` and `tools/list` are not gated, so HelixID clients that carry the VP in `params._meta` keep working and a VP
is verified once per tool call. The tools themselves (`src/orders.ts`) contain no auth code.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `3700`, `127.0.0.1` | Listen address |
| `MCP_RESOURCE` | `http://localhost:$PORT/mcp` | Public URL of the MCP endpoint; the OAuth audience |
| `HELIX_API_URL` | none | HelixID API for VP verification and audit |
| `HELIX_API_KEY` | none | Account API key; enables the audit sink |
| `SERVICE_DID` | none | This server's DID |
| `OAUTH_ISSUER`, `OAUTH_JWKS_URI` | none | One authorization server; its JWT access tokens are verified against this JWKS |
| `OAUTH_ISSUER`, `OAUTH_INTROSPECTION_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | none | One authorization server; tokens are checked by RFC 7662 introspection (opaque tokens) |
| `OAUTH_ISSUERS` | none | JSON array of `{ issuer, jwksUri?, introspection? }`: several trusted authorization servers |
| `DEMO_MODE` | off | `1` accepts `demo-reader` / `demo-admin`; loopback only |
