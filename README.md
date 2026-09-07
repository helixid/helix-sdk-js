# helix-sdk-js

JavaScript/TypeScript monorepo for [HelixID](https://www.dgverse.in/products/helix-id)
— decentralized identity and verifiable-credential-based authorization for
AI agents. A pnpm workspace managed with Turborepo.

## Documentation

Full documentation is at **[docs.helixid.dev](https://docs.helixid.dev)** — concepts,
guides, and reference. This README covers only what is specific to this repository.

| | |
|---|---|
| **Start here** | [Introduction](https://docs.helixid.dev/) |
| **Concepts** | [The Trust Stack](https://docs.helixid.dev/concepts/trust-stack) · [Two-Issuer Model](https://docs.helixid.dev/concepts/two-issuer-model) · [Delegation](https://docs.helixid.dev/concepts/delegation) · [Revocation](https://docs.helixid.dev/concepts/revocation) |
| **Get started** | [Quick Start](https://docs.helixid.dev/get-started/quick-start) · [Installation & Modes](https://docs.helixid.dev/get-started/installation-and-modes) |
| **Contributing** | [How to Contribute](https://docs.helixid.dev/contributing/how-to-contribute) · [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **Security** | [Reporting a Vulnerability](https://docs.helixid.dev/security/reporting-a-vulnerability) · [`SECURITY.md`](SECURITY.md) |

---

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

## The HelixID ecosystem

| Repository | What it is |
|---|---|
| [helixid](https://github.com/helixid/helixid) | HelixID API — the issuer and verifier service |
| [helix-core](https://github.com/helixid/helix-core) | `@helixid/core` — crypto, schemas, resolver, verification primitives |
| **helix-sdk-js** — you are here | JS/TS SDK, CLI, LangChain + MCP middleware, consent widget |
| [helix-sdk-py](https://github.com/helixid/helix-sdk-py) | `helixid-sdk-py` — the Python SDK |
| [helix-console](https://github.com/helixid/helix-console) | Operator Console SPA |
| [helix-wiki](https://github.com/helixid/helix-wiki) | Source for [docs.helixid.dev](https://docs.helixid.dev) |

---

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Each package ships its own copy
alongside its own `README.md`, since `npm`'s `files` allowlist only
includes files within that package's own directory.
