---
"@helixid/sdk-js": minor
---

Enterprise mode (`apiKey`) now sends the account API key on every call to the HelixID API, not only `signVP()` and `delegateAuthority()`. `verifyVP()` is attributed to the verifying account, `getAuditLog()` and the other account-scoped calls no longer fail with `ACCOUNT_AUTH_REQUIRED`, and `recordConsentGrantedAudit()` posts instead of silently doing nothing. `getAuditLog()` accepts `before` and `agentDid`, and `AuditLogEvent` gains `vpId`, `reporter` and the `attempted*` fields.
