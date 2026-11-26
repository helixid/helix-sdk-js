---
'@helixid/sdk-js': patch
---

KYA-OS story F-1 fix: a signer for a did:key DID now defaults its kid to the did:key multibase value (`did:key:z…#z…`), the one verification method a did:key document defines, instead of `key-1`. `kyaos.defaultKidFragment(did)` gives the rule; `kyaos.EnvSigner` and the custody `EnvSigner` / `kidFragment` use it. An explicit kid is unchanged; other DIDs keep `key-1`.
