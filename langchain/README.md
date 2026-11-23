# @helixid/langchain

Thin LangChain/LangGraph adapter for Helix ID. `HelixIDToolWrapper` gives a wrapped tool a way to sign each MCP request it sends with a KYA-OS request proof (`org.kya-os/proof.v1`, story C-C): signed by the agent's own Signer, bound to that request's body and to the service's DID, with a fresh nonce, and with the agent's delegation chain attached. Both ride in `params._meta`; nothing travels in tool arguments, and no request carries a private key. The Helix VP and its `X-Helix-VP` header are gone.

```ts
import { kyaos } from '@helixid/sdk-js';
import { HelixIDToolWrapper, signCurrentRequest, filterToolsByScope } from '@helixid/langchain';

const signer = new kyaos.EnvSigner({ did: process.env.AGENT_DID! }); // key in HELIX_SIGNING_KEY

// Inside the tool's _call:
//   const request = await signCurrentRequest({ name: 'lookup_order', arguments: { orderId } });
//   await fetch(mcpUrl, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, ...request }) });

const wrappedTool = HelixIDToolWrapper(existingTool, {
  signer,
  audience: 'did:web:orders.example.com', // the service DID, from its card
  chain: () => store.currentChain(),       // optional: root-to-leaf delegation hops
});
```

## Features

- **Per-request proofs**: `signCurrentRequest(call)` returns the call with `_meta["org.kya-os/request-proof"]` (and `_meta["org.kya-os/delegation-chain"]`); each call gets its own proof. It rejects outside a wrapped call.
- **Scope-based Tool Filtering**: `filterToolsByScope(tools, client, agentDid)` keeps only tools whose metadata scope tag (`tool.metadata?.requiredScope`) or name matches the scopes of the agent's active VC.
