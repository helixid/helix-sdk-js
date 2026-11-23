---
'@helixid/sdk-js': minor
---

KYA-OS story F-1 follow-up: `HelixClient.delegateAuthority()` is removed. It called `POST /v1/agents/:did/delegate` (or `/v1/custodial-agents/:did/delegate`), which F-1 removed from core and enterprise retires. Delegation is now a hop chain: `POST /v1/grants` and `POST /v1/grants/:id/hops`.
