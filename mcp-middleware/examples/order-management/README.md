# Order Management: a HelixID-protected MCP server

A small MCP server with two tools behind `@helixid/mcp-middleware`:

| Tool | Scope | What it does |
|---|---|---|
| `lookup_order` | `orders:read` | Returns an order by id |
| `refund_order` | `orders:admin` | Refunds an order in full (destructive) |

Any other tool name is denied before it runs. Callers come through either door:

- **KYA-OS agents**: a request proof in MCP `params._meta["org.kya-os/request-proof"]` and its delegation chain in
  `params._meta["org.kya-os/delegation-chain"]`, verified in-process (story F-2): the Helix API is never on the request path.
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

## With HelixID: KYA-OS agents, verified locally

Set `SERVICE_DID` to this server's DID and every tool call that carries a request proof is verified in-process
(`createLocalVerifier` from `@helixid/mcp-middleware`): the proof's signature, audience (`SERVICE_DID`), request hash,
lifetime and nonce; the carried chain's length (bounded before any entry is parsed), each hop's `eddsa-jcs-2022` proof by
its own issuer, attenuation and status; the agent's Entity Card and its capability attestations. Only public DID
documents, status lists and cards are fetched (https only), so calls are authorised with the Helix API unreachable.

```bash
SERVICE_DID=did:web:orders.example pnpm --filter @helixid/example-mcp-order-management start
```

- A caller's scopes are its verified attestations, intersected with the leaf hop's `allowedAction` and the tool scopes
  here (`orders:read`, `orders:admin`). A refused proof answers 401 with the verifier's reason codes.
- `KYAOS_TRUSTED_ISSUERS` (default `*`), `KYAOS_TRUSTED_ROOTS`, `KYAOS_MAX_CHAIN_LENGTH` (default 10) and
  `KYAOS_CARDS_FILE` (agent DID to Entity Card, read before the card is fetched) tune the verifier;
  `KYAOS_ALLOW_LOOPBACK_HTTP=1` reads loopback documents over http in development.
- Status lists (story L3-C): each list's proof is verified before a bit is read, and an unreachable, unsigned, badly
  signed, wrong-purpose or out-of-range list reads as revoked. Lists and verdicts are cached (`KYAOS_STATUS_CACHE_TTL`,
  in Redis with `KYAOS_REDIS_URL`); `KYAOS_REVOCATION_EVENTS_URL` + `KYAOS_SIGNAL_ISSUERS` drop a cached verdict the moment
  Helix signals the revocation.
- `HELIX_API_URL` + `HELIX_API_KEY` turn on the audit sink (`POST /v1/audit-log/events`); nothing else talks to the API.
  `HELIX_API_URL` is required whenever `HELIX_API_KEY` is set, so the sink never falls back to the hosted production API.

## With a real authorization server

Drop `DEMO_MODE` and name the authorization server. Its issuer URL is enough: the keys are read from its metadata.
Access tokens must be JWTs whose `aud` is this server's `MCP_RESOURCE` (default `http://localhost:3700/mcp`):

```bash
OAUTH_ISSUER=https://as.example.com pnpm --filter @helixid/example-mcp-order-management start
```

For an authorization server that issues opaque tokens, add this server's client credentials there; tokens are then
checked by introspection (RFC 7662):

```bash
OAUTH_ISSUER=https://as.example.com OAUTH_CLIENT_ID=orders-mcp OAUTH_CLIENT_SECRET=... \
pnpm --filter @helixid/example-mcp-order-management start
```

Agents from different providers can share the server: list every trusted tenant in `OAUTH_ISSUERS`. Common providers
have presets that need only what names your tenant; anything else is `{ "issuer": ... }`. Tokens are routed to their
issuer by `iss`; an issuer not in the list is refused.

```bash
OAUTH_ISSUERS='[
  {"provider":"entra","tenantId":"<directory id>","audience":"<API application id>"},
  {"provider":"auth0","domain":"tenant.us.auth0.com"},
  {"provider":"okta","domain":"dev-1.okta.com","introspection":{"clientId":"orders-mcp","clientSecret":"..."}},
  {"provider":"keycloak","baseUrl":"https://id.example.com","realm":"shop"},
  {"issuer":"https://as.example.com"}
]' pnpm --filter @helixid/example-mcp-order-management start
```

There is no built-in "trust Auth0" or "trust Okta": every customer of those providers has their own tenant, and the one
you trust has to be yours.

For credentials no standard describes (your own API keys presented as bearers), use a `validateOAuthToken` callback
(see `DEMO_MODE` in `src/main.ts`).

## How it is wired (`src/app.ts`)

The gate runs at the HTTP layer, in front of the MCP transport, and only for `tools/call`:

1. Parse the JSON-RPC body. For each `tools/call`, call the middleware with the tool name, arguments, `params._meta` and
   the HTTP headers.
2. On failure, `toHttpErrorResponse()` turns the error into a 401 / 400 / 403 with `WWW-Authenticate`. A real HTTP 401 is
   what makes an MCP OAuth client start discovery; a tool-level error would not.
3. Otherwise hand the request to a stateless `StreamableHTTPServerTransport`.

`initialize` and `tools/list` are not gated. A KYA-OS proof is verified once per tool call, over the JSON-RPC request as
received. The tools themselves (`src/orders.ts`) contain no auth code.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `3700`, `127.0.0.1` | Listen address |
| `MCP_RESOURCE` | `http://localhost:$PORT/mcp` | Public URL of the MCP endpoint; the OAuth audience |
| `HELIX_API_URL` | none | HelixID API the audit sink writes to |
| `HELIX_API_KEY` | none | Account API key; enables the audit sink |
| `SERVICE_DID` | none | This server's DID: turns on in-process KYA-OS verification (proof audience and chain resource) |
| `KYAOS_TRUSTED_ISSUERS`, `KYAOS_TRUSTED_ROOTS` | `*`, any | Attestation issuers and root-hop issuers the verifier trusts (comma-separated DIDs) |
| `KYAOS_MAX_CHAIN_LENGTH` | `10` | Longest carried chain read |
| `KYAOS_CARDS_FILE` | none | JSON map of agent DID to Entity Card |
| `KYAOS_STATUS_CACHE_TTL` | `300` | Seconds a status list or verdict is cached (story L3-C); a cached read is not fresh (Card L3 → L2) |
| `KYAOS_HIGH_PRIVILEGE_SCOPES`, `KYAOS_HIGH_PRIVILEGE_TTL` | none, `60` | Scopes whose reads are cached at most that long (≤ 60 s) |
| `KYAOS_MAX_STALE_SECONDS` | `60` | How long a list read inside its window may be served past its `validUntil` from the cache |
| `KYAOS_STATUS_LIST_ISSUERS` | none | JSON: issuer DID to the status-list URLs or `https:` origins it keeps |
| `KYAOS_SIGNAL_ISSUERS` | none | DIDs whose revocation SETs are honoured (the Helix issuer) |
| `KYAOS_REVOCATION_EVENTS_URL` | none | Helix's `/v1/events/revocations`: one SSE connection, reconnecting |
| `KYAOS_REVOCATION_WEBHOOK_PATH` | none | A path here that receives pushed SETs (RFC 8935) |
| `KYAOS_REDIS_URL` | none | The status cache's Redis, shared by every instance (and the replay store's when `KYAOS_NONCE_STORE=redis`) |
| `KYAOS_VERIFICATION_LOG` | off | `1`: each verification and signal as one JSON line on stdout; a path: appended there |
| `OAUTH_ISSUER` | none | One authorization server; its keys are read from its metadata |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | none | With `OAUTH_ISSUER`: check tokens by RFC 7662 introspection (opaque tokens) |
| `OAUTH_JWKS_URI`, `OAUTH_INTROSPECTION_URL` | from metadata | Give the endpoints explicitly and skip discovery |
| `OAUTH_ISSUERS` | none | JSON array of trusted tenants: provider presets (`entra`, `auth0`, `okta`, `keycloak`) or `{ issuer, ... }` |
| `DEMO_MODE` | off | `1` accepts `demo-reader` / `demo-admin`; loopback only |
| `WELL_KNOWN_MCP` | on | KYA-OS discovery at `/.well-known/mcp`; `0` answers 404, `1` makes an unusable `SERVICE_DID` a startup error |
| `STATUS_LIST_CREDENTIAL` | none | URL of this server's status list credential, advertised in the discovery document |

## KYA-OS session and response proof (story L2-A)

Set `SERVICE_SIGNING_KEY` (the Ed25519 private key, hex, that `SERVICE_DID`'s document lists as `key-1`) and the server registers the `_kyaos_handshake` tool, opens sessions and signs a detached proof into `_meta["org.kya-os/response-proof"]` on every tool call outcome (a refusal carries its `denied` proof in the 400/401/403 body). Optional: `KYAOS_PUBLIC_ORIGIN` (default: the origin of `MCP_RESOURCE`), `KYAOS_CLOCK_SKEW_SECONDS` (30 to 600, default 120), `KYAOS_SESSIONS=0`, and `KYAOS_SESSION_TTL_MINUTES` (default 30). The replay store is chosen by `KYAOS_NONCE_STORE` (`memory`, the default, covers this instance only; `redis` or `dynamo` is shared by every instance), which `@helixid/mcp-middleware` reads itself: see `.env.example` and the middleware README. `redis` needs the `ioredis` package, `dynamo` needs `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb`; a missing one stops the server at startup.

```bash
SERVICE_DID=did:web:orders.example SERVICE_SIGNING_KEY=<hex> DEMO_MODE=1 pnpm start
# handshake
curl -s localhost:3700/mcp -H 'content-type: application/json' -H 'accept: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"_kyaos_handshake","arguments":{"nonce":"k7Hy9mNpQrStUvWxYz01Aa","audience":"did:web:orders.example","timestamp":'$(date +%s)'}}}'
# a call in that session: the result carries the proof
curl -s localhost:3700/mcp -H 'authorization: Bearer demo-reader' -H 'content-type: application/json' -H 'accept: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup_order","arguments":{"orderId":"ORD-1001","_kyaos_session":"kyaos_<from the handshake>"}}}'
```

## KYA-OS `needs_authorization` and resume (story L3-E)

Set `KYAOS_AUTHORIZATION_URL` (the consent page) and a caller whose scopes do not cover a tool gets the signed `needs_authorization` challenge as the call's result instead of a 403, with a resume token bound to the agent, tool and scopes (`KYAOS_RESUME_TTL_SECONDS`, default 600; the token store follows `KYAOS_NONCE_STORE`: Redis on `KYAOS_REDIS_URL` when the replay store is Redis, memory otherwise). The retry carries `_kyaos_resume` and the DelegationCredential as `_kyaos_delegation`. In `DEMO_MODE` the bearers `demo-agent` and `demo-agent-2` are agents with a DID and `orders:read` only, and the retry's credential is checked structurally by `src/demo-authorizer.ts` (invoker, invocationTarget, allowedAction, validUntil, a `proof` present; no signature verification, which stories F-2 and L3-H bring); outside demo mode every retry is refused until a verifier is wired in. `AUDIT_LOG_FILE` appends every audit event as a JSON line, which is how the e2e suite sees the challenges without a HelixID stack.

## Discovery at `/.well-known/mcp` (story L1-D)

Whenever `SERVICE_DID` is a `did:web` or `did:key`, the server answers `GET /.well-known/mcp` with the KYA-OS discovery document: the DID, `endpoints.tools` at `KYAOS_PUBLIC_ORIGIN` (default: the origin of `MCP_RESOURCE`), `endpoints.handshake` while the KYA-OS layer runs with sessions, `clockSkewSeconds` (the handshake's), `capabilities` (`proofs` true with `SERVICE_SIGNING_KEY`; the rest false, nothing else is on in this sample) and, with `STATUS_LIST_CREDENTIAL`, that URL. The document is validated against the schema at startup; `WELL_KNOWN_MCP=0` turns the route off (404). Behind a proxy, forward `/.well-known/mcp` at the origin root to this process and set `KYAOS_PUBLIC_ORIGIN` (see `mcp-middleware/docs/well-known.md`).

```bash
curl -s localhost:3700/.well-known/mcp | jq .
```

A `SERVICE_DID` of another method (a `did:hedera` from a Helix stack, say) cannot be the document's `serverDid`, so the route stays off and the startup line says why.
