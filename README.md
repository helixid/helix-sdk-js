# helix-sdk-js

JavaScript/TypeScript monorepo for [HelixID](https://www.dgverse.in/products/helix-id)
— decentralized identity and verifiable-credential-based authorization for
AI agents. A pnpm workspace managed with Turborepo.

## Packages

| Package | What it is |
|---|---|
| [`helix-sdk-js`](helix-sdk-js) — `@helixid/sdk-js` | Core SDK: DID/VC/VP primitives, `AgentWallet`, `HelixClient`, delegation, verification. Every other package here builds on this one. |
| [`cli`](cli) — `@helixid/cli` | The `helix` command-line tool for platform operators — DID/wallet/status-list/VC lifecycle. Single canonical implementation (see `docs/decision-cli-mcp-scope.md` in `helixid/helixid`); not duplicated per SDK language. |
| [`mcp-server`](mcp-server) — `@helixid/mcp-server` | Standalone MCP server exposing the same platform-operator workflows as `cli`, as tools for an MCP client/agent instead of shell commands. |
| [`mcp-middleware`](mcp-middleware) — `@helixid/mcp-middleware` | Library for *other* MCP servers/clients — inbound VP verification and outbound VP attachment for agent-to-tool calls. Not a server itself; see that package's README for how it differs from `mcp-server`. |
| [`langchain`](langchain) — `@helixid/langchain` | LangChain/LangGraph integration — VP enforcement at agent execution boundaries, per-tool scope checking. |
| [`widget`](widget) — `@helixid/widget` | Browser-embeddable consent widget — SP-side scope resolution and a headless consent-selection controller for issuing `DelegationGrantCredential`s. |
| [`did-hedera`](did-hedera) — `@helixid/did-hedera` | Optional `did:hedera` method support (HCS anchoring, mirror-node resolution). A real-money-spending dependency; install only where Hedera support is actually needed. |

Each package has its own README with install/usage details, an
`.npmignore`-free `files` allowlist in `package.json` controlling what
actually publishes, and its own test suite.

## Development

```bash
pnpm install
pnpm -r --if-present run build
pnpm test:unit        # every package's unit tests, in dependency order
pnpm -r --if-present run typecheck
pnpm -r --if-present run lint
```

Node version is pinned in `.nvmrc` (`nvm use`) — the resolved `vite`/`vitest`
versions require `^20.19.0 || >=22.12.0`, newer than a plain `>=20.0.0`
would suggest.

Turborepo (`turbo.json`) handles build ordering (`^build` before a
package's own `build`/`test`/`typecheck`) and output caching.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Each package ships its own copy
alongside its own `README.md`, since `npm`'s `files` allowlist only
includes files within that package's own directory.
