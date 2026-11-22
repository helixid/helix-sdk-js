export { helixidMCPMiddleware } from './middleware.js';
export type { MCPMiddleware, AuthorizedCaller as MiddlewareCaller } from './middleware.js';
export { createJwtValidator, createIntrospectionValidator, createOAuthValidator } from './oauth.js';
export { createHelixAuditSink, createHelixAuditReporter, createMcpAuditTrail, McpAuditTrail, ToolCallAudit } from './audit.js';
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
export { MCPAuthError, ProofError, ToolScopeError, AuthorizationServerUnavailableError } from './errors.js';
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

// The local verifier the guard runs in-process on every tool call (story F-2).
export { createLocalVerifier, unrecordedReporter, cardEndpointOf, resolutionUrl, KYA_OS_CARD_SERVICE_TYPE } from './verify-locally.js';
export type { LocalVerifier, LocalVerifierOptions, LocalVerifierCall, VerificationReport, ReportVerification, ResolverFetch } from './verify-locally.js';

// KYA-OS session, replay store and server response proof (story L2-A).
export * from './kyaos/index.js';

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
