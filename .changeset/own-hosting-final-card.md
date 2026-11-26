---
"@helixid/sdk-js": patch
"@helixid/cli": patch
---

`helix init` / `helix activate`, own hosting: `card.json` is rewritten on activation only when Helix returns a different card (an older Helix that issues the credentials at activation). With a current Helix the card written by `helix init` is final, and the CLI says Helix activates the agent once both documents resolve, with `helix activate` to check now.
