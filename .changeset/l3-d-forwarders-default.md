---
'@helixid/mcp-middleware': minor
---

KYA-OS story L3-D follow-up: `inboundDelegation.forwarders` / `verifyInboundDelegationHeaders({ forwarders })` default to `'*'`, so a service accepts a chain forwarded by the service it was granted at, from any such service; the forwarder stays bound to the chain (its target or its leaf delegate). `[]` accepts only chains that target this service. The order-management sample reads `KYAOS_FORWARDERS=none` for that.
