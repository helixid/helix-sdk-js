import { VPMissingError, VPVerificationFailedError, decodeHelixVP } from '@helixid/sdk-js';
import { verifyVP } from '@helixid/sdk-js';
import type { ToolAuditEvent } from './audit.js';
import { extractCredential } from './credentials.js';
import { MCPAuthError, ToolScopeError } from './errors.js';
import { createJwtValidator } from './oauth.js';
import type { MCPToolCall, MCPMiddlewareOptions } from './types.js';

interface Caller {
  authMethod: 'helixvp' | 'oauth';
  scopes: string[];
  agentDid?: string;
  vpId?: string;
  oauthSubject?: string;
}

export function helixidMCPMiddleware(options: MCPMiddlewareOptions) {
  if (options.oauth && options.validateOAuthToken) {
    throw new Error('Provide either `oauth` or `validateOAuthToken`, not both');
  }
  const validateOAuth = options.validateOAuthToken ?? (options.oauth ? createJwtValidator(options.oauth) : undefined);
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
      const result = await verifyVP(vp, options.client, {
        allowSelfSigned: options.allowSelfSigned ?? false,
        ...(options.expectedTargetService !== undefined
          ? { expectedTargetService: options.expectedTargetService }
          : {}),
      });
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
        if (err instanceof MCPAuthError) throw err;
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
