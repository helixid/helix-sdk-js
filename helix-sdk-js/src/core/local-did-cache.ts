// No-op, kept for pre-retirement test-suite compatibility.
//
// Before the SDK-API-only architecture (docs/proposal-sdk-api-only.md), the
// SDK resolved DIDs directly (including did:web over HTTP) and cached the
// result in a module-level Map, the same way helix-api's own internal
// src/core/did-resolver.ts still does for its own use. Tests called
// clearDIDCache() between runs to avoid cross-test cache pollution.
//
// verifyVP() is now always an API call (see verify.ts) -- resolution and
// caching happen inside helix-api, in a separate process, with its own
// cache lifecycle per run. There is nothing left for the SDK to cache
// locally, so this is an intentional no-op. It's kept as an export so
// call sites written against the old contract (e.g.
// helix-server/examples/e2e-consent-demo/tests/*.ts) don't need to change
// their beforeAll() hooks.
export function clearDIDCache(): void {
  // Intentionally empty.
}
