---
"@helixid/sdk-js": minor
---

`HelixClient`'s enterprise-mode default `baseUrl` (used when `apiKey` is given with no explicit URL) now points at the hosted HelixID API (`https://api.helixid.dev`) instead of `http://localhost:3000`, and no longer falls back to a `HELIX_API_URL` environment variable — pass the URL explicitly to override the default.

Also removes the `(http: HttpAdapter, baseUrl: string)` constructor overload entirely (a breaking change, hence the minor bump under 0.x).
