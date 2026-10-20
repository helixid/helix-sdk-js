import type { SignedVP } from '@helixid/sdk-js';
import type { HeadersLike, HelixClient } from '@helixid/sdk-js';

export interface MCPToolCall {
  name?: string;
  input?: Record<string, unknown>;
  /** The MCP request's `params._meta`; carries the VP as `_meta["x-helix-vp"]`. */
  _meta?: Record<string, unknown>;
  /** HTTP request headers, when the MCP server runs over HTTP; carries the VP as `X-Helix-VP`. */
  headers?: HeadersLike;
  [key: string]: unknown;
}

export interface MCPMiddlewareOptions {
  /**
   * Required now that verification calls the API (see
   * docs/proposal-sdk-api-only.md) rather than verifying locally.
   */
  client: HelixClient;
  requiredScopes?: string[];
  allowSelfSigned?: boolean;
  /**
   * This server's own DID. When set, a VP signed for any other service is
   * rejected, so a VP meant for one service can't be replayed against another.
   */
  expectedTargetService?: string;
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
