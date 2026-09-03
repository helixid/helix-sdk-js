# @helixid/mcp-server

Standalone MCP server exposing HelixID platform-operator workflows — DID/wallet/status-list/VC lifecycle — as tools for an MCP client or agent. This is the MCP analogue of [`@helixid/cli`](../cli): same operations, same underlying crypto and wallet logic, different transport (MCP tool calls instead of a shell command tree).

Not to be confused with [`@helixid/mcp-middleware`](../mcp-middleware), which is a library other people's MCP servers import to verify/attach HelixID VPs on tool calls. This package *is* an MCP server; `mcp-middleware` is a library *for* MCP servers.

## Install & run

```bash
npm install -g @helixid/mcp-server
export HELIX_WALLET_PASSPHRASE=your-passphrase
helix-mcp-server
```

Or point an MCP client at it directly, e.g. in a `.mcp.json`/Claude Desktop config:

```json
{
  "mcpServers": {
    "helix": {
      "command": "npx",
      "args": ["-y", "@helixid/mcp-server"],
      "env": { "HELIX_WALLET_PASSPHRASE": "your-passphrase" }
    }
  }
}
```

The server speaks MCP over stdio. All tool operations are local and offline (same as the CLI) except `did_create` with `method: "hedera"`, which requires `@helixid/did-hedera` and Hedera operator credentials (`HEDERA_OPERATOR_ID`, `HEDERA_OPERATOR_KEY`).

## Tools

| Tool | Mirrors CLI command | Description |
|---|---|---|
| `did_create` | `helix did create` | Create a DID (`web`, `hedera`, or `key`) and its encrypted wallet file. `did:web` also creates its initial status list unless `statusList: false`. |
| `issuer_init` | `helix issuer init` | Load an issuer wallet and report its DID and public key. |
| `status_list_create` | `helix status-list create` | Create a signed BitstringStatusList credential file. |
| `vc_issue` | `helix vc issue` | Issue a HelixAgentCredential to an agent DID, updating the issuer status list. |
| `vc_self_issue` | `helix vc self-issue` | Issue a self-signed dev-only credential directly into an agent wallet. |
| `revoke` | `helix revoke` | Revoke a credential by flipping its status list bit. |
| `wallet_inspect` | `helix wallet inspect` | Inspect wallet contents. Never returns the private key. |

Every tool requires `HELIX_WALLET_PASSPHRASE` in the server's environment, exactly like the CLI. Wallet/status-list/VC file paths are read and written on the machine running the server — run it wherever those files should live, same as you would the CLI.

## Design notes

- **Reuses `@helixid/cli`'s internals, not its command layer.** `@helixid/cli`'s `commands/*.ts` functions print human-readable output via `console.log`/`process.exit`, which would corrupt the MCP stdio JSON-RPC stream and crash the server on the first validation error. This package instead imports the safe, non-printing layer underneath (`@helixid/cli/lib/*`, `@helixid/cli/core/*`, exposed via package subpath exports) and re-implements the thin per-command orchestration in `src/operations/*.ts`, returning structured data instead of printing it. The actual crypto and wallet logic is not duplicated — only the "call these functions in this order" glue is, and it's kept small on purpose.
- **`@helixid/cli`'s `lib/output.ts#error()` and `lib/env.ts`'s `require*()` throw instead of exiting** (see the CLI's own changelog/tests) specifically so this reuse is safe: a bad tool call rejects that one call, it doesn't kill the server process. Verified in `tests/server.test.ts`, which drives the server over a real (in-memory) MCP client connection and confirms a failing call comes back as `isError: true` while the server keeps answering subsequent calls.
- See `docs/decision-cli-mcp-scope.md` in the `helixid/helixid` repo for why this exists as its own package, JS-only, rather than duplicated per SDK language.
