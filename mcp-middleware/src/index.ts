export { helixidMCPMiddleware } from './middleware.js';
export type { MCPMiddleware, AuthorizedCaller as MiddlewareCaller } from './middleware.js';
export { createJwtValidator, createIntrospectionValidator, createOAuthValidator, cnfJktOf } from './oauth.js';
export { createHelixAuditSink, createHelixAuditReporter, createMcpAuditTrail, McpAuditTrail, ToolCallAudit } from './audit.js';
export { serveIdentity, resolveServerCard } from './identity.js';
export type { ServeIdentityOptions, ServedIdentity } from './identity.js';
export { DEFAULT_TRUSTED_ISSUERS } from './credentials.js';
export type { TrustedIssuers } from './credentials.js';
export { isTrustedIssuer, attestationTrust } from './trusted-issuers.js';
export { auth0, entra, keycloak, okta } from './providers.js';
export type { ProviderIntrospection } from './providers.js';
export {
  buildProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  toHttpErrorResponse,
} from './metadata.js';
export { MCPAuthError, ProofError, LevelError, ToolScopeError, AuthorizationServerUnavailableError } from './errors.js';
// KYA-OS signed needs_authorization and resume (story L3-E).
export * from './needs-authorization.js';
export * from './resume-token-store.js';
export * from './resume-token-store-env.js';
export type { MCPMiddlewareOptions, MiddlewareVerifierOptions, MCPToolCall } from './types.js';
export type { AuthResult, OAuthJwtOptions, OAuthIssuerOptions, OAuthIntrospectionOptions, OAuthOptions } from './oauth.js';
export type {
  AuditSink,
  ToolAuditEvent,
  HelixAuditSinkOptions,
  HelixAuditReporterOptions,
  McpAuditTrailOptions,
  McpAuditContext,
  ToolCallAuditOptions,
} from './audit.js';
export type {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataInput,
  HttpErrorOptions,
  HttpErrorResponse,
} from './metadata.js';
export type { MCPAuthErrorCode, ProofErrorCode } from './errors.js';
// Story A-2: delivery to the HelixID recorder and audited tool handlers.
export {
  AUDIT_META_KEY,
  auditToolHandlers,
  auditUnavailableResponse,
  createHelixAuditDelivery,
  markAuditDegraded,
  runAuditedTool,
} from './audit-delivery.js';
export type { AuditedToolResult, HelixAuditDeliveryOptions, RunAuditedToolOptions, ToolRegistrar } from './audit-delivery.js';

// The local verifier the guard runs in-process on every tool call (story F-2).
export { createLocalVerifier, requestOf, unrecordedReporter, cardEndpointOf, resolutionUrl, KYA_OS_CARD_SERVICE_TYPE } from './verify-locally.js';
export { createResolutionFetch, resolutionTarget, isPublicUnicastAddress, ResolutionRefusedError, RESOLUTION_MAX_BYTES, RESOLUTION_TIMEOUT_MS } from './resolution-fetch.js';
export type { ResolutionFetchOptions } from './resolution-fetch.js';
export { RevocationSignalClient, SseParser, createRevocationSignalClient } from './revocation-signals.js';
export type { RevocationSignalClientOptions, SignalReport, SignalOutcome } from './revocation-signals.js';
export type { LocalVerifier, LocalVerifierOptions, LocalVerifierCall, VerificationReport, ReportVerification, ResolverFetch } from './verify-locally.js';

// KYA-OS session, replay store and server response proof (story L2-A).
export * from './kyaos/index.js';

// The minimum Card level per tool (story C-C).
export { deriveConformanceLevel, derivedLevelOf, meetsMinimumLevel, minimumLevelFor, assertLevelPolicy, DEFAULT_MINIMUM_LEVEL, MINIMUM_LEVELS } from './level.js';
export type { MinimumLevel, DerivedLevel, LevelPolicy } from './level.js';
// The §11.2 request-proof check the guard runs through the local verifier (story C-C), for hosts that verify a proof alone.
export { verifyRequestProof } from './verify-request-proof.js';
// The /.well-known/mcp discovery document (story L1-D).
export {
  WELL_KNOWN_MCP_PATH,
  DEFAULT_WELL_KNOWN_VERSION,
  DEFAULT_SUPPORTED_DID_METHODS,
  DEFAULT_PROOF_ALGORITHMS,
  WellKnownMcpError,
  buildWellKnownMcp,
  createWellKnownMcp,
  validateWellKnownMcp,
  assertWellKnownMcp,
} from './well-known.js';
export type { WellKnownMcp, WellKnownMcpConfig, WellKnownMcpDocument, WellKnownMcpResponse, WellKnownMcpValidation, WellKnownCapabilities } from './well-known.js';
