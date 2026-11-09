import { VPMissingError, VPVerificationFailedError, decodeHelixVP } from '@helixid/sdk-js';
import { verifyVP } from '@helixid/sdk-js';
import type { ToolAuditEvent } from './audit.js';
import { extractCredential } from './credentials.js';
import { AuthorizationServerUnavailableError, MCPAuthError, ToolScopeError } from './errors.js';
import { createOAuthValidator } from './oauth.js';
import type { MCPToolCall, MCPMiddlewareOptions } from './types.js';

interface Caller {
  authMethod: 'helixvp' | 'oauth';
  scopes: string[];
  agentDid?: string;
  vpId?: string;
  oauthSubject?: string;
}

/**
 * The HelixID API reports a bad credential the way the local verifier does:
 * as a typed error (VC_REVOKED, VP_EXPIRED, VP_SIGNATURE_INVALID, a target
 * service mismatch, ...), not as `valid: false`. Those are the caller's fault
 * and become a 401. Anything else from the API (our own API key refused, the
 * API down) is a server fault and is passed through unmapped.
 */
const CREDENTIAL_FAULT_PREFIXES = ['VP_', 'VC_', 'DELEGATION_', 'CONSENT_GRANT_'];
const CREDENTIAL_FAULT_CODES = new Set([
  'DID_NOT_FOUND',
  'INVALID_DID_FORMAT',
  'UNSUPPORTED_DID_METHOD',
  'SELF_SIGNED_VC_NOT_ALLOWED',
  'MAX_DELEGATION_DEPTH_EXCEEDED',
  'SCOPE_ESCALATION_DENIED',
  'CREDENTIAL_NOT_FOR_THIS_AGENT',
  'SERVICE_NOT_FOUND',
  'VALIDATION_ERROR',
]);
function isCredentialFault(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code !== 'string') return false;
  return CREDENTIAL_FAULT_PREFIXES.some((prefix) => code.startsWith(prefix)) || CREDENTIAL_FAULT_CODES.has(code);
}

export function helixidMCPMiddleware(options: MCPMiddlewareOptions) {
  if (options.oauth && options.validateOAuthToken) {
    throw new Error('Provide either `oauth` or `validateOAuthToken`, not both');
  }
  const validateOAuth = options.validateOAuthToken ?? (options.oauth ? createOAuthValidator(options.oauth) : undefined);
  const serviceDid = options.serviceDid ?? options.expectedTargetService;

  const audit = async (caller: Caller, toolName: string | undefined, denied: { scope?: string; reason: string } | undefined): Promise<void> => {
    if (!options.auditSink) return;
    const event: ToolAuditEvent = {
      event: denied ? 'AUTHZ_DENIED' : 'AUTHZ_GRANTED',
      result: denied ? 'denied' : 'allowed',
      timestamp: new Date().toISOString(),
      authMethod: caller.authMethod,
      effectiveScopes: caller.scopes,
      ...(caller.agentDid !== undefined ? { agentDid: caller.agentDid } : {}),
      ...(caller.oauthSubject !== undefined ? { oauthSubject: caller.oauthSubject } : {}),
      ...(caller.vpId !== undefined ? { vpId: caller.vpId } : {}),
      ...(toolName !== undefined ? { toolName } : {}),
      ...(denied?.scope !== undefined ? { requiredScope: denied.scope } : {}),
      ...(denied ? { reason: denied.reason } : {}),
      ...(serviceDid !== undefined ? { serviceDid } : {}),
    };
    try {
      await options.auditSink(event);
    } catch (err) {
      options.onAuditError?.(err);
    }
  };

  return async (toolCall: MCPToolCall): Promise<MCPToolCall> => {
    // Credentials come from Authorization / X-Helix-VP / _meta only; tool
    // arguments are never consulted. Ambiguous credentials throw.
    const credential = extractCredential(toolCall);
    if (!credential) {
      throw new VPMissingError(
        'No credentials: send Authorization: HelixVP, X-Helix-VP, MCP _meta["x-helix-vp"]' +
          (validateOAuth ? ', or Authorization: Bearer' : ''),
      );
    }

    let caller: Caller;
    if (credential.kind === 'vp') {
      if (!options.client) {
        throw new Error('helixidMCPMiddleware: `client` is required to verify HelixID VPs');
      }
      const vp = decodeHelixVP(credential.encoded);
      let result;
      try {
        result = await verifyVP(vp, options.client, {
          allowSelfSigned: options.allowSelfSigned ?? false,
          ...(options.expectedTargetService !== undefined
            ? { expectedTargetService: options.expectedTargetService }
            : {}),
        });
      } catch (err) {
        if (isCredentialFault(err)) {
          throw new VPVerificationFailedError(err instanceof Error ? err.message : String(err));
        }
        throw err;
      }
      if (!result.valid) {
        throw new VPVerificationFailedError(result.error);
      }
      caller = {
        authMethod: 'helixvp',
        scopes: result.effectiveScopes,
        agentDid: result.agentDid,
        vpId: result.vpId,
      };
    } else {
      if (!validateOAuth) {
        throw new MCPAuthError('OAUTH_TOKEN_INVALID', 'Bearer tokens are not accepted by this server');
      }
      let auth;
      try {
        auth = await validateOAuth(credential.token);
      } catch (err) {
        // Our own verdicts pass through; the authorization server being down is a
        // server fault, not a bad token. Anything else came from a custom callback
        // and means "rejected".
        if (err instanceof MCPAuthError || err instanceof AuthorizationServerUnavailableError) throw err;
        throw new MCPAuthError('OAUTH_TOKEN_INVALID', 'The access token was rejected');
      }
      if (!auth || typeof auth.sub !== 'string' || auth.sub.length === 0) {
        throw new MCPAuthError('OAUTH_TOKEN_INVALID', 'The access token has no subject');
      }
      caller = { authMethod: 'oauth', scopes: auth.scopes ?? [], oauthSubject: auth.sub };
    }

    // Authorization. With a toolScopes map the default is deny: an unlisted
    // tool (or a call with no tool name) never runs.
    const toolName = typeof toolCall.name === 'string' ? toolCall.name : undefined;
    let required: string[];
    if (options.toolScopes) {
      if (toolName === undefined || !Object.hasOwn(options.toolScopes, toolName)) {
        await audit(caller, toolName, { reason: 'tool is not in toolScopes' });
        throw new MCPAuthError('TOOL_NOT_PERMITTED', 'This tool is not permitted');
      }
      required = options.toolScopes[toolName] ?? [];
    } else {
      required = options.requiredScopes ?? [];
    }

    const missing = required.find((scope) => !caller.scopes.includes(scope));
    if (missing !== undefined) {
      await audit(caller, toolName, { scope: missing, reason: 'insufficient scope' });
      throw new ToolScopeError(missing);
    }

    await audit(caller, toolName, undefined);
    return toolCall;
  };
}
