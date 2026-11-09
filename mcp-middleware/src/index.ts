export { helixidMCPMiddleware } from './middleware.js';
export { attachHelixVP } from './attach.js';
export { createJwtValidator } from './oauth.js';
export { createHelixAuditSink } from './audit.js';
export {
  buildProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  toHttpErrorResponse,
} from './metadata.js';
export { MCPAuthError, ToolScopeError } from './errors.js';
export type { MCPMiddlewareOptions, AttachHelixVPOptions, MCPToolCall } from './types.js';
export type { AuthResult, OAuthJwtOptions } from './oauth.js';
export type { AuditSink, ToolAuditEvent, HelixAuditSinkOptions } from './audit.js';
export type {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataInput,
  HttpErrorOptions,
  HttpErrorResponse,
} from './metadata.js';
export type { MCPAuthErrorCode } from './errors.js';
