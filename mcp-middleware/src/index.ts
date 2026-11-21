export { helixidMCPMiddleware } from './middleware.js';
export { attachHelixVP } from './attach.js';
export { createJwtValidator, createIntrospectionValidator, createOAuthValidator } from './oauth.js';
export { createHelixAuditSink, createHelixAuditReporter, createMcpAuditTrail, delegationEvidenceOf, McpAuditTrail, ToolCallAudit } from './audit.js';
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
export type {
  AuditSink,
  ToolAuditEvent,
  HelixAuditSinkOptions,
  HelixAuditReporterOptions,
  McpAuditTrailOptions,
  McpAuditContext,
  DelegationEvidence,
  ToolCallAuditOptions,
} from './audit.js';
export type {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataInput,
  HttpErrorOptions,
  HttpErrorResponse,
} from './metadata.js';
export type { MCPAuthErrorCode } from './errors.js';
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
