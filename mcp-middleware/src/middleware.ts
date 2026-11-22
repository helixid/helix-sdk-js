import type { kyaos } from '@helixid/sdk-js';
import type { ToolAuditEvent } from './audit.js';
import { extractCredential } from './credentials.js';
import { AuthorizationServerUnavailableError, LevelError, MCPAuthError, ProofError, ToolScopeError } from './errors.js';
import { assertLevelPolicy, derivedLevelOf, meetsMinimumLevel, minimumLevelFor, type MinimumLevel } from './level.js';
import { cnfJktOf, createOAuthValidator, type AuthResult } from './oauth.js';
import type { MCPToolCall, MCPMiddlewareOptions } from './types.js';
import { createLocalVerifier, type LocalVerifier } from './verify-locally.js';

/** Who a tool call came from, once the guard has identified and authorized them. */
export interface AuthorizedCaller {
  authMethod: 'kyaos' | 'oauth';
  scopes: string[];
  agentDid?: string;
  oauthSubject?: string;
  /** KYA-OS callers: the level the local verifier derived (story F-2), and the proof's assurance. */
  level?: kyaos.verifier.ConformanceLevel;
  proofAssurance?: kyaos.verifier.ProofAssurance;
  /** KYA-OS callers: whether every status the level relies on was read live. */
  fresh?: boolean;
  /** KYA-OS callers (story C-C): true when a request proof verified; false for a chain verified without one. */
  proofFloor?: boolean;
  /** KYA-OS callers: the `cnf` diagnostics (`cnf_present_but_token_unfused`). */
  cnfDiagnostics?: string[];
}

type Caller = AuthorizedCaller;

/**
 * The guard: called with a tool call, resolves it unchanged once the caller
 * is identified and allowed to run the tool, rejects otherwise.
 * `authorize()` does the same and resolves the caller instead, for hosts
 * that need to know who called (the KYA-OS proof's `clientDid`, say).
 */
export type MCPMiddleware = ((toolCall: MCPToolCall) => Promise<MCPToolCall>) & {
  authorize(toolCall: MCPToolCall): Promise<AuthorizedCaller>;
  /** The local verifier the guard runs, when one is configured. */
  readonly verifier: LocalVerifier | undefined;
};

function isLocalVerifier(value: unknown): value is LocalVerifier {
  return typeof value === 'object' && value !== null && typeof (value as { verifyCall?: unknown }).verifyCall === 'function';
}

export function helixidMCPMiddleware(options: MCPMiddlewareOptions): MCPMiddleware {
  if (options.oauth && options.validateOAuthToken) {
    throw new Error('Provide either `oauth` or `validateOAuthToken`, not both');
  }
  const validateOAuth = options.validateOAuthToken ?? (options.oauth ? createOAuthValidator(options.oauth) : undefined);
  // Story C-C: the minimum Card level per tool, checked after the scopes. A typo in a level throws here, never lowers a bar.
  const levelPolicy = { minimumLevel: options.minimumLevel, tools: options.tools, l3MinusSatisfiesL3: options.l3MinusSatisfiesL3 };
  assertLevelPolicy(levelPolicy);
  const serviceDid = options.serviceDid ?? options.expectedTargetService;
  // The verifier runs in-process (story F-2): nothing here ever asks the Helix API about a credential.
  const localVerifier: LocalVerifier | undefined =
    options.verifier === undefined
      ? undefined
      : isLocalVerifier(options.verifier)
        ? options.verifier
        : createLocalVerifier({
            ...(options.toolScopes === undefined ? {} : { catalog: [...new Set(Object.values(options.toolScopes).flat())] }),
            ...options.verifier,
            serviceDid: options.verifier.serviceDid ?? serviceDid ?? '',
          });

  const audit = async (
    caller: Caller,
    toolName: string | undefined,
    denied: { scope?: string; reason: string; requiredLevel?: MinimumLevel } | undefined,
  ): Promise<void> => {
    if (!options.auditSink) return;
    const event: ToolAuditEvent = {
      event: denied ? 'AUTHZ_DENIED' : 'AUTHZ_GRANTED',
      result: denied ? 'denied' : 'allowed',
      timestamp: new Date().toISOString(),
      authMethod: caller.authMethod,
      effectiveScopes: caller.scopes,
      ...(caller.agentDid !== undefined ? { agentDid: caller.agentDid } : {}),
      ...(caller.oauthSubject !== undefined ? { oauthSubject: caller.oauthSubject } : {}),
      ...(caller.level !== undefined ? { level: caller.level } : {}),
      ...(caller.fresh !== undefined ? { fresh: caller.fresh } : {}),
      ...(caller.proofAssurance !== undefined ? { proofAssurance: caller.proofAssurance } : {}),
      ...(caller.authMethod === 'kyaos' && caller.level !== undefined ? { l3Minus: caller.level === 'L3' && caller.proofAssurance === 'L3-minus' } : {}),
      ...(caller.cnfDiagnostics !== undefined && caller.cnfDiagnostics.length > 0 ? { cnfDiagnostics: caller.cnfDiagnostics } : {}),
      ...(denied?.requiredLevel !== undefined ? { requiredLevel: denied.requiredLevel } : {}),
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

  const validateBearer = async (token: string): Promise<AuthResult> => {
    if (!validateOAuth) {
      throw new MCPAuthError('OAUTH_TOKEN_INVALID', 'Bearer tokens are not accepted by this server');
    }
    let auth;
    try {
      auth = await validateOAuth(token);
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
    return auth;
  };

  const authorize = async (toolCall: MCPToolCall): Promise<AuthorizedCaller> => {
    // Credentials come from Authorization or `_meta` only; tool arguments
    // are never consulted. Ambiguous credentials throw.
    const credential = extractCredential(toolCall);
    const toolName = typeof toolCall.name === 'string' ? toolCall.name : undefined;
    if (!credential) {
      throw new ProofError(
        'PROOF_MISSING',
        'No credentials: send a KYA-OS request proof in _meta["org.kya-os/request-proof"]' + (validateOAuth ? ', or Authorization: Bearer' : ''),
      );
    }

    let caller: Caller;
    if (credential.kind === 'proof') {
      if (!localVerifier) {
        throw new Error('helixidMCPMiddleware: `verifier` is required to verify KYA-OS request proofs');
      }
      // A bearer token next to a proof is its sender constraint: its cnf.jkt fuses with the proof's for L3 (§8.6).
      let tokenCnfJkt: string | undefined;
      if (credential.bearer !== undefined) {
        const auth = await validateBearer(credential.bearer);
        tokenCnfJkt = auth.cnfJkt ?? cnfJktOf(auth.claims);
      }
      // A chain may come without a proof (story C-C): it verifies, at most at L2, and the level check below decides.
      const result = await localVerifier.verifyCall({
        ...(toolName === undefined ? {} : { name: toolName }),
        ...(toolCall.input === undefined ? {} : { input: toolCall.input }),
        ...(toolCall._meta === undefined ? {} : { _meta: toolCall._meta }),
        ...(toolCall.request === undefined ? {} : { request: toolCall.request }),
        ...(tokenCnfJkt === undefined ? {} : { tokenCnfJkt }),
        requireProof: false,
      });
      /* c8 ignore next */
      if (result === undefined) throw new ProofError('PROOF_MISSING', 'The request carries no KYA-OS request proof');
      if (!result.ok) {
        const refused = new ProofError('PROOF_INVALID', `The request proof was refused: ${result.reasons.join(', ')}`, result.reasons);
        if (result.proofDid !== undefined) {
          await audit({ authMethod: 'kyaos', scopes: [], agentDid: result.proofDid, level: result.level, fresh: result.fresh }, toolName, { reason: result.reasons.join(',') });
        }
        throw refused;
      }
      const cnfDiagnostics = result.warnings.filter((warning) => warning.startsWith('cnf_'));
      caller = {
        authMethod: 'kyaos',
        scopes: result.effectiveScopes,
        ...(result.agentDid === undefined ? {} : { agentDid: result.agentDid }),
        level: result.level,
        ...(result.proofAssurance === undefined ? {} : { proofAssurance: result.proofAssurance }),
        fresh: result.fresh,
        proofFloor: result.proofFloor,
        ...(cnfDiagnostics.length > 0 ? { cnfDiagnostics } : {}),
      };
    } else {
      const auth = await validateBearer(credential.token);
      caller = { authMethod: 'oauth', scopes: auth.scopes ?? [], oauthSubject: auth.sub };
    }

    // Authorization. With a toolScopes map the default is deny: an unlisted
    // tool (or a call with no tool name) never runs.
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
      throw new ToolScopeError(missing, required);
    }

    // The level, after the scopes (story C-C): how sure we are the caller is that agent right now.
    if (caller.authMethod === 'kyaos') {
      const requiredLevel = minimumLevelFor(levelPolicy, toolName);
      const derived = derivedLevelOf(caller.level ?? 'L1', caller.proofAssurance);
      if (!meetsMinimumLevel(derived, requiredLevel, options.l3MinusSatisfiesL3 ?? true)) {
        await audit(caller, toolName, { reason: `level_insufficient: ${derived} < ${requiredLevel}`, requiredLevel });
        throw new LevelError(derived, requiredLevel);
      }
    }

    await audit(caller, toolName, undefined);
    return caller;
  };

  const guard = async (toolCall: MCPToolCall): Promise<MCPToolCall> => {
    await authorize(toolCall);
    return toolCall;
  };
  return Object.assign(guard, { authorize, verifier: localVerifier });
}
