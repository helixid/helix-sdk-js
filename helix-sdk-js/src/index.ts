// Agent
export { AgentWallet } from './wallet/AgentWallet.js';
export { VPBuilder } from './vp-builder.js';
export { delegate } from './delegation.js';
export type { DelegateOptions } from './delegation.js';
export { renewAgentVC } from './renewal.js';
export type { RenewAgentVCOptions } from './renewal.js';

// Issuer / SP
export { issueGrant } from './grant.js';
export type { IssuerKeyMaterial, IssueGrantOptions, IssueGrantResult } from './grant.js';
// Local (non-API) revocation -- the SP's own status list, no prepare/finalize
// involved (see the comment on revokeGrant() in grant.ts).
export { revokeGrant, type RevokeGrantTarget, type SignedStatusListCredential } from './grant.js';

// Verifier
export { verifyVP } from './verify.js';
// Local Ed25519 linked-data proof create/verify -- signing stays client-side
// (see docs/proposal-sdk-api-only.md); needed by issuers that aren't
// registered with helix-api (e.g. independent did:web Service Providers)
// to sign their own credentials directly.
export { createEd25519Proof, verifyEd25519Proof, type LinkedDataProof } from './core/proof.js';
export { checkScope, requireScope } from './scope.js';
export { SessionManager } from './session/index.js';

// Enrollment only / issuer API operations
export { HelixClient } from './client/HelixClient.js';
export type { CreateStatusListOptions, VerifyVPApiResult } from './client/HelixClient.js';

export * from './errors/index.js';
export * from './resolver/IDidResolver.js';
export * from './resolver/HelixDidResolver.js';
export * from './resolver/types.js';
export type {
  DIDDocument,
  ServiceEndpoint,
  VerificationMethod,
} from './core/did.js';
export { buildDIDDocument } from './core/did.js';
export type { DelegationLink, VerifyVPOptions, VerifyVPResult } from './core/verification-types.js';
export { selfIssueVC } from './core/self-signed.js';
export type { SelfIssueOptions } from './core/self-signed.js';
export type { SignedVC } from './core/schemas/vc.js';
export type { SignedVP } from './core/schemas/vp.js';
export type { VPBuilderOptions } from './core/vp-builder-impl.js';
export {
  generateKeyPair,
  publicKeyToMultibase,
  multibaseToPublicKeyHex,
  signData,
  verifySignature,
  type KeyPair,
} from './core/keys.js';

// Canonical-hash computation is explicitly a client-side operation (see
// docs/proposal-sdk-api-only.md § client-side ops) -- needed by verifiers
// that self-verify VPs/VCs without calling POST /v1/vp/verify.
export { hashCanonicalPayload, base58btcEncode, base58btcDecode, toCanonicalJson } from './core/vp-crypto.js';

// BitstringStatusList bit read is a pure local computation once the status
// list credential itself has been fetched -- also needed for self-verification.
export { getBit, buildStatusListCredential, createStatusList, type StatusListCredential } from './core/status-list-schema.js';

// Activity-trail event-type catalog -- narrow duplicate of helix-api's own
// (see docs/proposal-retire-core-package.md); used by independent issuers
// (e.g. e2e-consent-demo's Service Providers) that emit their own audit
// trail rather than relying on helix-api's.
export { AuditEvents, type AuditEvent, type AuditEventType } from './core/audit-events.js';

// See the file comment in local-did-cache.ts -- an intentional no-op now
// that verification is always an API call, kept for test compatibility.
export { clearDIDCache } from './core/local-did-cache.js';
export type { SessionClaims, SessionIssueInput, SessionManagerOptions } from './session/index.js';

// Dev-only local session-bridge JWT verification (see docs/proposal-sdk-api-only.md § client-side ops).
// issueJWT/decodeJWTUnsafe are intentionally not re-exported: issuance is server-side
// (session-bridge tokens come from POST /v1/vp/verify with session: true), so only
// verification -- given the API's published session public key -- belongs here.
export { verifyJWT } from './core/jwt.js';
