import type { SignedVP } from '@helixid/sdk-js';
import type { HelixClient } from '@helixid/sdk-js';

export interface MCPToolCall {
  name?: string;
  input?: Record<string, unknown>;
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
