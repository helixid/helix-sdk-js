import type { SignedVP } from '@helixid/sdk-js';
import type { HeadersLike, HelixClient } from '@helixid/sdk-js';
import type { AuditSink } from './audit.js';
import type { AuthResult, OAuthOptions } from './oauth.js';

export interface MCPToolCall {
  name?: string;
  input?: Record<string, unknown>;
  /** The MCP request's `params._meta`; carries the VP as `_meta["x-helix-vp"]` (stdio and any transport). */
  _meta?: Record<string, unknown>;
  /**
   * HTTP request headers, when the MCP server runs over HTTP. Carries the VP as
   * `Authorization: HelixVP <vp>` (or legacy `X-Helix-VP`), or an OAuth token as
   * `Authorization: Bearer <token>`.
   */
  headers?: HeadersLike;
  [key: string]: unknown;
}

export interface MCPMiddlewareOptions {
  /** Required to verify HelixID VPs (verification calls the API). Not needed for an OAuth-only server. */
  client?: HelixClient;
  /**
   * Per-tool required scopes. Deny by default: when this map is set, a tool
   * that is not a key in it is rejected before it runs (an empty array allows
   * any authenticated caller). Takes precedence over `requiredScopes`.
   */
  toolScopes?: Record<string, string[]>;
  /** Fallback applied to every tool when `toolScopes` is not set. */
  requiredScopes?: string[];
  allowSelfSigned?: boolean;
  /**
   * This server's own DID. When set, a VP signed for any other service is
   * rejected, so a VP meant for one service can't be replayed against another.
   */
  expectedTargetService?: string;
  /**
   * Accept `Authorization: Bearer` access tokens from one trusted authorization
   * server, or a list of them. Each issuer is validated by its JWKS (JWTs), by
   * RFC 7662 introspection (opaque tokens), or both; a JWT is routed to its
   * issuer by `iss`. Mutually exclusive with `validateOAuthToken`.
   */
  oauth?: OAuthOptions;
  /**
   * Custom bearer-token validation (opaque tokens, introspection, ...). Resolve
   * with the caller, or throw to reject. Mutually exclusive with `oauth`.
   */
  validateOAuthToken?: (token: string) => Promise<AuthResult>;
  /** Receives an event for every decision about an identified caller. See `createHelixAuditSink`. */
  auditSink?: AuditSink;
  /** Called when `auditSink` throws. Audit failures never block or fail a tool call. */
  onAuditError?: (error: unknown) => void;
  /** Included in audit events; defaults to `expectedTargetService`. */
  serviceDid?: string;
}

export interface AttachHelixVPOptions {
  /** Agent self-custody has been retired — signing happens server-side via this client, not a local wallet. */
  client: HelixClient;
  /** The agent's DID, previously implied by which wallet file was loaded. */
  agentDid: string;
  targetService: string;
  userDid?: string;
}

export type HelixVPInput = SignedVP;
