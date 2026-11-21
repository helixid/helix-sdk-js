export { helixidMCPMiddleware } from './middleware.js';
export type { MCPMiddleware, AuthorizedCaller as MiddlewareCaller } from './middleware.js';
export { attachHelixVP } from './attach.js';
export { createJwtValidator, createIntrospectionValidator, createOAuthValidator } from './oauth.js';
export { createHelixAuditSink } from './audit.js';
export { auth0, entra, keycloak, okta } from './providers.js';
export type { ProviderIntrospection } from './providers.js';
export {
  buildProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  toHttpErrorResponse,
} from './metadata.js';
export { MCPAuthError, ToolScopeError, AuthorizationServerUnavailableError } from './errors.js';
export type { MCPMiddlewareOptions, AttachHelixVPOptions, MCPToolCall } from './types.js';
export type { AuthResult, OAuthJwtOptions, OAuthIssuerOptions, OAuthIntrospectionOptions, OAuthOptions } from './oauth.js';
export type { AuditSink, ToolAuditEvent, HelixAuditSinkOptions } from './audit.js';
export type {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataInput,
  HttpErrorOptions,
  HttpErrorResponse,
} from './metadata.js';
export type { MCPAuthErrorCode } from './errors.js';

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
