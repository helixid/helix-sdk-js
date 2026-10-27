# @helixid/langchain

Thin LangChain/LangGraph adapter for Helix ID. `HelixIDToolWrapper` signs a fresh VP (server-side, via `HelixClient`) on every tool call and passes the tool input through unchanged; the VP never travels in tool arguments. Inside the wrapped tool, `currentHelixVPHeaders()` returns `{ 'X-Helix-VP': <base64url VP> }` to send on the tool's outbound request.

```ts
import { HelixClient } from '@helixid/sdk-js';
import { HelixIDToolWrapper, currentHelixVPHeaders, filterToolsByScope } from '@helixid/langchain';

const client = new HelixClient({ apiKey: process.env.HELIX_API_KEY! });

// Inside the tool's _call:
//   await fetch(url, { headers: { ...currentHelixVPHeaders() } });

const wrappedTool = HelixIDToolWrapper(existingTool, {
  client,
  agentDid: process.env.AGENT_DID!,
  targetService: 'orders',
  userDid: 'did:key:user', // Optional
});
```

## Features

- **Per-call signing**: each wrapped call gets a fresh VP from `client.signVP()`; `currentHelixVPHeaders()` is empty outside a wrapped call.
- **Scope-based Tool Filtering**: `filterToolsByScope(tools, client, agentDid)` keeps only tools whose metadata scope tag (`tool.metadata?.requiredScope`) or name matches the scopes of the agent's active VC.
