import { kyaos } from '@helixid/sdk-js';
import type { ToolAuditEvent } from './audit.js';
import { extractCredential } from './credentials.js';
import { AuthorizationServerUnavailableError, LevelError, MCPAuthError, ProofError, ToolScopeError } from './errors.js';
import { assertLevelPolicy, derivedLevelOf, meetsMinimumLevel, minimumLevelFor, type MinimumLevel } from './level.js';
import { cnfJktOf, createOAuthValidator, type AuthResult } from './oauth.js';
import { challengeFor, consentFailureOf, resumeRetry } from './needs-authorization-guard.js';
import type { MCPToolCall, MCPMiddlewareOptions } from './types.js';
import { createLocalVerifier, type LocalVerifier } from './verify-locally.js';
import { hasDelegationHeaders } from './delegation/headers.js';
import { verifyInboundDelegationHeaders } from './delegation/inbound.js';
import { VerificationCache } from './delegation/verification-cache.js';
import { DEFAULT_OPEN_METHODS, PROMPT_METHODS, RESOURCE_METHODS, claimedDidOf, claimedIssuerOf, headerOf, methodOf, refusalCodeOf, targetOf } from './gate.js';

/** Who a tool call came from, once the guard has identified and authorized them. */
export interface AuthorizedCaller {
  /** `none`: an open method (`openMethods`), let through without checking anyone. */
  authMethod: 'kyaos' | 'oauth' | 'none';
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
  /** KYA-OS callers with a delegation (story L3-D): the verified chain, root first, which `delegationContextOf` forwards. */
  chain?: unknown[];
  /** Downstream calls (story L3-D): the service that forwarded the agent's authority (the delegation proof's `iss`). */
  forwardedBy?: string;
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

  // Story L3-D: downstream calls carrying KYA-OS delegation headers, verified by the same local verifier.
  const inbound = options.inboundDelegation === false ? undefined : (options.inboundDelegation ?? {});
  const inboundCache =
    inbound === undefined || localVerifier === undefined || inbound.cache === false
      ? undefined
      : inbound.cache instanceof VerificationCache
        ? inbound.cache
        : localVerifier.statusCache === undefined
          ? new VerificationCache()
          : VerificationCache.forStatusCache(localVerifier.statusCache);

  const openMethods: ReadonlySet<string> = new Set(options.openMethods ?? DEFAULT_OPEN_METHODS);
  // Own authority: the agent's attested capabilities count as far as this service offers them, across its
  // tools, resources and prompts (each gated method checks its own map below).
  const offeredScopes = [options.toolScopes, options.resourceScopes, options.promptScopes].filter((scopes) => scopes !== undefined);
  const ownAuthorityCatalog = offeredScopes.length === 0 ? undefined : [...new Set(offeredScopes.flatMap((scopes) => Object.values(scopes).flat()))];

  /** One request's audit context: what it asked for, from where, and whether its decision was already audited. */
  interface RequestContext {
    method: string;
    toolName: string | undefined;
    resourceUri: string | undefined;
    promptName: string | undefined;
    clientIp: string | undefined;
    userAgent: string | undefined;
    audited: boolean;
  }

  const requestFields = (ctx: RequestContext): Partial<ToolAuditEvent> => ({
    method: ctx.method,
    ...(ctx.resourceUri !== undefined ? { resourceUri: ctx.resourceUri } : {}),
    ...(ctx.promptName !== undefined ? { promptName: ctx.promptName } : {}),
    ...(ctx.clientIp !== undefined ? { clientIp: ctx.clientIp } : {}),
    ...(ctx.userAgent !== undefined ? { userAgent: ctx.userAgent } : {}),
  });

  const deliver = async (event: ToolAuditEvent): Promise<void> => {
    if (!options.auditSink) return;
    try {
      await options.auditSink(event);
    } catch (err) {
      options.onAuditError?.(err);
    }
  };

  const audit = async (
    ctx: RequestContext,
    caller: Caller,
    denied: { scope?: string; reason: string; requiredLevel?: MinimumLevel; reasonCode?: string } | undefined,
  ): Promise<void> => {
    ctx.audited = true;
    const toolName = ctx.toolName;
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
      ...(denied?.reasonCode !== undefined ? { reasonCode: denied.reasonCode } : {}),
      ...requestFields(ctx),
    };
    await deliver(event);
  };

  /** A refusal of a caller the guard could not identify: what is known, the claims marked unverified, no actor. */
  const auditUnidentified = async (ctx: RequestContext, toolCall: MCPToolCall, reasonCode: string): Promise<void> => {
    const claimedDid = claimedDidOf(toolCall._meta, kyaos.verifier.readRequestProof);
    const oauthIssuer = claimedIssuerOf(toolCall.headers);
    await deliver({
      event: 'AUTHZ_DENIED',
      result: 'denied',
      timestamp: new Date().toISOString(),
      authMethod: 'none',
      effectiveScopes: [],
      reason: reasonCode,
      reasonCode,
      ...(ctx.toolName !== undefined ? { toolName: ctx.toolName } : {}),
      ...(serviceDid !== undefined ? { serviceDid } : {}),
      ...requestFields(ctx),
      ...(oauthIssuer !== undefined ? { oauthIssuer } : {}),
      ...(claimedDid !== undefined ? { claimedDid } : {}),
      ...(claimedDid !== undefined || oauthIssuer !== undefined ? { claimedVerified: false as const } : {}),
    });
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

  /**
   * Every request goes through here. An open method (`openMethods`) passes
   * unchecked; any other needs a verified caller, and every refusal is
   * audited, including those of a caller the guard could not identify.
   */
  const authorize = async (toolCall: MCPToolCall): Promise<AuthorizedCaller> => {
    const method = methodOf(toolCall);
    if (openMethods.has(method)) return { authMethod: 'none', scopes: [] };
    const target = targetOf(method, toolCall);
    const ctx: RequestContext = {
      method,
      toolName: method === 'tools/call' ? target : undefined,
      resourceUri: RESOURCE_METHODS.has(method) ? target : undefined,
      promptName: PROMPT_METHODS.has(method) ? target : undefined,
      clientIp: typeof toolCall.clientIp === 'string' ? toolCall.clientIp : undefined,
      userAgent: headerOf(toolCall.headers, 'user-agent'),
      audited: false,
    };
    try {
      return await authorizeRequest(toolCall, ctx);
    } catch (error) {
      const reasonCode = ctx.audited ? undefined : refusalCodeOf(error);
      if (reasonCode !== undefined) await auditUnidentified(ctx, toolCall, reasonCode);
      throw error;
    }
  };

  /** The proof binds the JSON-RPC request: the one received, else rebuilt (`tools/call` by the verifier; another method here). */
  const proofRequestOf = (toolCall: MCPToolCall, method: string): kyaos.verifier.ProofRequest | undefined => {
    if (toolCall.request !== undefined || method === 'tools/call') return toolCall.request;
    return { method, params: { ...(toolCall.input ?? {}), ...(toolCall._meta === undefined ? {} : { _meta: toolCall._meta }) } };
  };

  const authorizeRequest = async (toolCall: MCPToolCall, ctx: RequestContext): Promise<AuthorizedCaller> => {
    // Credentials come from Authorization or `_meta` only; tool arguments
    // are never consulted. Ambiguous credentials throw.
    const toolName = ctx.toolName;
    const proofRequest = proofRequestOf(toolCall, ctx.method);
    const forwarded = inbound !== undefined && hasDelegationHeaders(toolCall.headers);
    const credential = forwarded ? undefined : extractCredential(toolCall);
    if (forwarded && (kyaos.verifier.readRequestProof(toolCall._meta) !== undefined || kyaos.verifier.readCarriedChain(toolCall._meta) !== undefined)) {
      throw new MCPAuthError('CREDENTIAL_CONFLICT', 'Downstream delegation headers and a KYA-OS request proof or chain were both provided; send one');
    }
    if (!credential && !forwarded) {
      throw new ProofError(
        'PROOF_MISSING',
        'No credentials: send a KYA-OS request proof in _meta["org.kya-os/request-proof"]' + (validateOAuth ? ', or Authorization: Bearer' : ''),
      );
    }

    let caller: Caller;
    if (forwarded) {
      if (!localVerifier) {
        throw new Error('helixidMCPMiddleware: `verifier` is required to verify KYA-OS delegation headers');
      }
      const result = await verifyInboundDelegationHeaders(toolCall.headers, {
        verifier: localVerifier,
        ...(inbound?.audience === undefined ? {} : { audience: inbound.audience }),
        ...(inbound?.forwarders === undefined ? {} : { forwarders: inbound.forwarders }),
        ...(inboundCache === undefined ? {} : { cache: inboundCache }),
        ...(minimumLevelFor(levelPolicy, toolName) === 'L3' ? { liveStatus: true } : {}),
      });
      if (!result.ok) {
        if (result.agentDid !== undefined) {
          await audit(ctx, { authMethod: 'kyaos', scopes: [], agentDid: result.agentDid, level: result.level, fresh: result.fresh }, { reason: result.reasons.join(',') });
        }
        throw new ProofError('PROOF_INVALID', `The delegation headers were refused: ${result.reasons.join(', ')}`, result.reasons);
      }
      caller = {
        authMethod: 'kyaos',
        scopes: result.effectiveScopes,
        agentDid: result.agentDid!,
        level: result.level,
        fresh: result.fresh,
        proofFloor: false,
        chain: result.chain!,
        forwardedBy: result.forwarder!,
      };
    } else if (credential!.kind === 'proof') {
      if (!localVerifier) {
        throw new Error('helixidMCPMiddleware: `verifier` is required to verify KYA-OS request proofs');
      }
      // A bearer token next to a proof is its sender constraint: its cnf.jkt fuses with the proof's for L3 (§8.6).
      let tokenCnfJkt: string | undefined;
      if (credential!.bearer !== undefined) {
        const auth = await validateBearer(credential!.bearer);
        tokenCnfJkt = auth.cnfJkt ?? cnfJktOf(auth.claims);
      }
      // A chain may come without a proof (story C-C): it verifies, at most at L2, and the level check below decides.
      // A tool that demands L3 needs fresh revocation status: its lists are read live, past the status cache (story L3-C).
      const liveStatus = minimumLevelFor(levelPolicy, toolName) === 'L3';
      const result = await localVerifier.verifyCall({
        ...(toolName === undefined ? {} : { name: toolName }),
        ...(toolCall.input === undefined ? {} : { input: toolCall.input }),
        ...(toolCall._meta === undefined ? {} : { _meta: toolCall._meta }),
        ...(proofRequest === undefined ? {} : { request: proofRequest }),
        ...(tokenCnfJkt === undefined ? {} : { tokenCnfJkt }),
        requireProof: false,
        ...(liveStatus ? { liveStatus } : {}),
        ...(localVerifier.allowOwnAuthority === true && ownAuthorityCatalog !== undefined ? { ownAuthorityCatalog } : {}),
      });
      /* c8 ignore next */
      if (result === undefined) throw new ProofError('PROOF_MISSING', 'The request carries no KYA-OS request proof');
      if (!result.ok) {
        const refused = new ProofError('PROOF_INVALID', `The request proof was refused: ${result.reasons.join(', ')}`, result.reasons);
        if (result.proofDid !== undefined) {
          await audit(ctx, { authMethod: 'kyaos', scopes: [], agentDid: result.proofDid, level: result.level, fresh: result.fresh }, { reason: result.reasons.join(',') });
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
        ...(Array.isArray(credential!.chain) && credential!.chain.length > 0 ? { chain: credential!.chain as unknown[] } : {}),
      };
    } else {
      const auth = await validateBearer(credential!.token);
      caller = { authMethod: 'oauth', scopes: auth.scopes ?? [], oauthSubject: auth.sub };
    }

    // Authorization, by method. With a toolScopes map the default is deny: an
    // unlisted tool (or a call with no tool name) never runs. Resources and
    // prompts are deny by default: only what resourceScopes / promptScopes list.
    // Any other method (resources/list, prompts/list, ping, ...) needs the verified caller only.
    let required: string[];
    if (ctx.method === 'tools/call') {
      if (options.toolScopes) {
        if (toolName === undefined || !Object.hasOwn(options.toolScopes, toolName)) {
          await audit(ctx, caller, { reason: 'tool is not in toolScopes' });
          throw new MCPAuthError('TOOL_NOT_PERMITTED', 'This tool is not permitted');
        }
        required = options.toolScopes[toolName] ?? [];
      } else {
        required = options.requiredScopes ?? [];
      }
    } else if (RESOURCE_METHODS.has(ctx.method) || PROMPT_METHODS.has(ctx.method)) {
      const resource = RESOURCE_METHODS.has(ctx.method);
      const scopes = resource ? options.resourceScopes : options.promptScopes;
      const name = resource ? ctx.resourceUri : ctx.promptName;
      if (scopes === undefined || name === undefined || !Object.hasOwn(scopes, name)) {
        const kind = resource ? 'resource' : 'prompt';
        await audit(ctx, caller, { reason: `${kind} is not in ${kind}Scopes`, reasonCode: `${kind}_not_permitted` });
        throw new MCPAuthError(resource ? 'RESOURCE_NOT_PERMITTED' : 'PROMPT_NOT_PERMITTED', `This ${kind} is not permitted`);
      }
      required = scopes[name] ?? [];
    } else {
      required = [];
    }

    // A tool marked requireDelegation is not covered by the agent's own authority: only what a chain grants
    // (the user's consent, say) counts, so a call without one is challenged when needsAuthorization is set.
    if (toolName !== undefined && options.tools?.[toolName]?.requireDelegation === true && caller.authMethod === 'kyaos' && caller.chain === undefined) {
      caller = { ...caller, scopes: [] };
    }
    // KYA-OS story L3-E: a retry after consent carries its resume token and credential (needs-authorization-guard.ts).
    const retry = await resumeRetry(options.needsAuthorization, caller, toolCall, toolName, required);
    if (retry !== undefined) caller = retry;
    const missing = required.find((scope) => !caller.scopes.includes(scope));
    if (missing !== undefined) {
      // KYA-OS story L3-E: an identified caller without the authority gets a signed challenge instead of the plain 403.
      let challenge: Awaited<ReturnType<typeof challengeFor>>;
      try {
        challenge = retry === undefined ? await challengeFor(options.needsAuthorization, caller, toolName, required) : undefined;
      } catch (error) {
        // The consent request behind the challenge failed at Helix: the caller's refusal is a 403, Helix's outage a 503.
        const failure = consentFailureOf(error);
        if (failure === undefined) throw error;
        if (failure.kind === 'unavailable') throw new AuthorizationServerUnavailableError(`Helix's consent service is unavailable: ${failure.message}`);
        await audit(ctx, caller, { scope: missing, reason: `consent_refused: ${failure.helixCode}` });
        throw new ToolScopeError(missing, required, `Required scope: ${required.join(' ')}. ${failure.message}`);
      }
      if (challenge !== undefined) throw challenge;
      await audit(ctx, caller, { scope: missing, reason: 'insufficient scope' });
      throw new ToolScopeError(missing, required);
    }

    // The level, after the scopes (story C-C): how sure we are the caller is that agent right now.
    if (caller.authMethod === 'kyaos') {
      const requiredLevel = minimumLevelFor(levelPolicy, toolName);
      const derived = derivedLevelOf(caller.level ?? 'L1', caller.proofAssurance);
      if (!meetsMinimumLevel(derived, requiredLevel, options.l3MinusSatisfiesL3 ?? true)) {
        await audit(ctx, caller, { reason: `level_insufficient: ${derived} < ${requiredLevel}`, requiredLevel });
        throw new LevelError(derived, requiredLevel);
      }
    }

    await audit(ctx, caller, undefined);
    return caller;
  };

  const guard = async (toolCall: MCPToolCall): Promise<MCPToolCall> => {
    await authorize(toolCall);
    return toolCall;
  };
  return Object.assign(guard, { authorize, verifier: localVerifier });
}
