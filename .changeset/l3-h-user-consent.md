---
"@helixid/sdk-js": minor
"@helixid/mcp-middleware": minor
---

KYA-OS story L3-H: the root of an agent's delegation chain is signed by the user's own pairwise did:key on Helix's consent page. `kyaos.consent` (service side: `createConsentRequest`, `withdrawConsent`; agent side: `awaitConsentHop`, `verifyConsentHop`, `renewConsentHop`, `renewBefore`, `ConsentHopKeeper`), `ConsentFlowError`. The middleware's `authorizationUrl` may be asynchronous; `createHelixConsent` makes it a consent request at Helix and `consentRetryAuthorizer` verifies a retry's credential with the local verifier. `HelixClient.issueServiceDelegationGrant` and `getAgentScopes` are removed with their routes.
