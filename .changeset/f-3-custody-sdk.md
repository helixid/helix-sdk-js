---
'@helixid/sdk-js': minor
---

KYA-OS story F-3: custody preference. `helixInit` (self-custody onboarding: the key is generated client side, only the public JWK and a proof of possession are sent, `did.json` and `card.json` written to an output directory, own-domain resolution checked before activation), `activateAgent`, `changeToSelfCustody`, `HelixCustodialSigner` (custodial agents sign through the API), `EnvSigner`, the `Signer` the agent runtime takes (`VPBuilder.signWith`), and `HelixCustodyClient` for the custody endpoints.
