---
'@helixid/sdk-js': minor
'@helixid/cli': minor
---

KYA-OS story F-3 follow-up: an own-hosted agent's card carries what its credentials say. On activation Helix returns the card with the agent's capability attestations, responsible party and revocation entry; `activateAgent()` (and `helixInit()` when it activates) rewrites `card.json` in the output directory and reports `cardUpdated: true`. `helix init` and `helix activate` tell the owner to republish it at the card URL.
