import type { HeadersLike, kyaos } from '@helixid/sdk-js';
import type { AuditSink } from './audit.js';
import type { AuthResult, OAuthOptions } from './oauth.js';
import type { MinimumLevel } from './level.js';
import type { LocalVerifier, LocalVerifierOptions } from './verify-locally.js';
import type { NeedsAuthorization } from './needs-authorization.js';
import type { VerificationCache } from './delegation/verification-cache.js';

/** How the guard verifies downstream calls carrying KYA-OS delegation headers (story L3-D). */
export interface InboundDelegationSettings {
  /** This service's host(s), as forwarders name it in the proof's `aud`; default the host of a did:web service DID. */
  audience?: string | readonly string[] | undefined;
  /** Forwarding services whose own resource is honoured as a chain's target: `'*'` (default) or DIDs; `[]` for none. */
  forwarders?: '*' | readonly string[] | undefined;
  /** The chain verdict cache; default one as long-lived as the verifier's status cache; `false` for none. */
  cache?: VerificationCache | false | undefined;
}

export interface MCPToolCall {
  /**
   * The JSON-RPC method (`tools/call`, `resources/read`, `prompts/get`, `tools/list`, ...).
   * Default: the received request's method, else `tools/call`. Pass every
   * request through the guard: it decides which methods are open
   * (`openMethods`) and checks the rest.
   */
  method?: string;
  /** What the call acts on: the tool name (`tools/call`), resource URI (`resources/read`) or prompt name (`prompts/get`); default from the request's params. */
  name?: string;
  input?: Record<string, unknown>;
  /**
   * The MCP request's `params._meta`; carries the KYA-OS request proof as
   * `_meta["org.kya-os/request-proof"]` and the delegation chain as
   * `_meta["org.kya-os/delegation-chain"]` (stdio and any transport).
   */
  _meta?: Record<string, unknown>;
  /** HTTP request headers, when the MCP server runs over HTTP: an OAuth token as `Authorization: Bearer <token>`. */
  headers?: HeadersLike;
  /**
   * The JSON-RPC request as received (`{method, params}`), when the host has
   * it: the proof's `requestHash` is recomputed over exactly this. Without
   * it the request is rebuilt from `name`, `input` and `_meta`.
   */
  request?: kyaos.verifier.ProofRequest;
  /** The caller's network address as the host sees it (behind a proxy: the address the host trusts). Recorded in audit events only. */
  clientIp?: string;
  [key: string]: unknown;
}

/** The local verifier's settings, when the middleware builds it; `serviceDid` defaults to the middleware's. */
export type MiddlewareVerifierOptions = Partial<Omit<LocalVerifierOptions, 'serviceDid'>> & { serviceDid?: string | undefined };

export interface MCPMiddlewareOptions {
  /**
   * How KYA-OS request proofs are verified: in-process, from the proof and
   * the carried chain alone (story F-2), with the Helix API never asked. A
   * built `LocalVerifier` (shared with other guards), or its settings. Not
   * needed for an OAuth-only server.
   */
  verifier?: LocalVerifier | MiddlewareVerifierOptions;
  /**
   * Per-tool required scopes. Deny by default: when this map is set, a tool
   * that is not a key in it is rejected before it runs (an empty array allows
   * any authenticated caller). Takes precedence over `requiredScopes`.
   */
  toolScopes?: Record<string, string[]>;
  /** Fallback applied to every tool when `toolScopes` is not set. */
  requiredScopes?: string[];
  /**
   * The JSON-RPC methods let through without a caller; default
   * `DEFAULT_OPEN_METHODS` (`initialize`, `notifications/initialized`,
   * `tools/list`), so clients can see what is available. Every other method
   * needs a verified caller. `[]` opens nothing.
   */
  openMethods?: readonly string[];
  /**
   * Per-resource required scopes, keyed by URI, for `resources/read`,
   * `resources/subscribe` and `resources/unsubscribe`. Deny by default: a URI
   * that is not a key (or any URI when this is not set) is refused.
   * `resources/list` and `resources/templates/list` need a verified caller only.
   */
  resourceScopes?: Record<string, string[]>;
  /** Per-prompt required scopes for `prompts/get`, deny by default like `resourceScopes`. `prompts/list` needs a verified caller only. */
  promptScopes?: Record<string, string[]>;
  /**
   * The Card level every tool demands of a KYA-OS caller (story C-C): `L3`
   * by default, a verified request proof plus a fully attested card read
   * live. Checked after the scopes; a call below it is refused with
   * PROOF_LEVEL_INSUFFICIENT and its derived level. OAuth-only callers
   * carry no level and are not checked.
   */
  minimumLevel?: MinimumLevel;
  /**
   * Per-tool settings: `tools.lookup_order.minimumLevel = 'L2'` accepts a chain without a proof there.
   * `requireDelegation: true` keeps the tool out of an agent's own authority (`allowOwnAuthority`):
   * the call needs a chain, such as the user's consent, and with `needsAuthorization` a call without
   * one is answered with the consent challenge.
   */
  tools?: Record<string, { minimumLevel?: MinimumLevel; requireDelegation?: boolean }>;
  /** Whether L3-minus (a proof with no token `cnf` to fuse with, §8.6) satisfies an `L3` minimum; default true. */
  l3MinusSatisfiesL3?: boolean;
  /** This server's own DID: the proof audience. `serviceDid` is the same setting under its current name. */
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
  /**
   * Receives an event for every decision: allowed and refused, for an
   * identified caller and for one the guard could not identify (no
   * credential, a bad token, a refused proof naming no DID, a replay, ...).
   * Open methods are not audited. See `createHelixAuditSink`.
   */
  auditSink?: AuditSink;
  /** Called when `auditSink` throws. Audit failures never block or fail a tool call. */
  onAuditError?: (error: unknown) => void;
  /** This server's DID: the proof audience, included in audit events; defaults to `expectedTargetService`. */
  serviceDid?: string;
  /**
   * KYA-OS story L3-E: answers a call whose delegation is missing or does not
   * cover the tool's scopes with a signed `needs_authorization` challenge
   * (instead of the plain 403), and verifies the retry that carries the
   * resume token and the new delegation credential. See `createNeedsAuthorization`.
   */
  needsAuthorization?: NeedsAuthorization;
  /**
   * KYA-OS story L3-D: a call carrying `KYA-OS-Delegation-Credential` and
   * `KYA-OS-Delegation-Proof` (another service forwarding an agent's
   * authority) is verified from those signed artifacts by the local
   * verifier. On by default with a verifier; `false` turns it off.
   */
  inboundDelegation?: InboundDelegationSettings | false;
}
