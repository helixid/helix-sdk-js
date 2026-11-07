---
'@helixid/mcp-middleware': minor
---

Phase 1 auth gate and audit. Accept `Authorization: HelixVP <vp>` (alongside legacy `X-Helix-VP` and stdio `_meta["x-helix-vp"]`) and OAuth 2.1 `Authorization: Bearer` tokens (JWKS validation, or a `validateOAuthToken` callback); conflicting credentials are rejected. Add per-tool `toolScopes` (deny by default; `requiredScopes` remains the fallback), RFC 9728 metadata helpers with `WWW-Authenticate` responses, and an `auditSink` with `createHelixAuditSink` for `POST /v1/audit-log/events`. `client` is now optional (only needed to verify HelixID VPs).
