// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/** One authorization decision for one tool call. */
export interface ToolAuditEvent {
  /** `AUTHZ_GRANTED` when the call was allowed to run, `AUTHZ_DENIED` otherwise. */
  event: 'AUTHZ_GRANTED' | 'AUTHZ_DENIED';
  result: 'allowed' | 'denied';
  timestamp: string;
  authMethod: 'kyaos' | 'oauth';
  /** KYA-OS callers: the agent DID the request proof verified as. */
  agentDid?: string;
  /** KYA-OS callers: the level the local verifier derived (story F-2) and whether every status was read live. */
  level?: 'L1' | 'L2' | 'L3';
  fresh?: boolean;
  /** KYA-OS callers (story C-C): `L3` on a full `cnf` fusion, `L3-minus` without a token `cnf`; absent for a call with no proof. */
  proofAssurance?: 'L3' | 'L3-minus';
  /** KYA-OS callers: true when the call's L3 rests on an unfused proof (L3-minus). */
  l3Minus?: boolean;
  /** KYA-OS callers: the `cnf` diagnostics (`cnf_present_but_token_unfused`), when there are any. */
  cnfDiagnostics?: string[];
  /** KYA-OS callers refused on level: the tool's minimum. */
  requiredLevel?: 'L1' | 'L2' | 'L3';
  /** OAuth callers: the token's `sub`. */
  oauthSubject?: string;
  toolName?: string;
  /** The scope that was required (on denial, the one that was missing). */
  requiredScope?: string;
  effectiveScopes: string[];
  reason?: string;
  /** This server's DID (`serviceDid` option, else `expectedTargetService`). */
  serviceDid?: string;
}

/** Receives every decision for an identified caller. Await-ed before the tool runs. */
export type AuditSink = (event: ToolAuditEvent) => void | Promise<void>;

export interface HelixAuditSinkOptions {
  /** HelixID API base URL (pass your own; there is no default). */
  baseUrl: string;
  /** Enterprise account API key, sent as the bearer token. */
  apiKey: string;
  /** Used for OAuth callers, who have no agent DID; the API needs agentDid or serviceDid. */
  serviceDid?: string;
  timeoutMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

/**
 * An `AuditSink` that posts to `POST /v1/audit-log/events`. It is built on
 * plain `fetch`, not `HelixClient`, so no new public SDK method is needed.
 *
 * OAuth callers are identified by `oauthSubject`, which the API shows only to
 * accounts with full access to the row (the service side). It is deliberately
 * not copied into any field other viewers can see, such as `resultSummary`.
 */
export function createHelixAuditSink(options: HelixAuditSinkOptions): AuditSink {
  const base = options.baseUrl.replace(/\/+$/, '');
  const doFetch = options.fetch ?? fetch;
  return async (e) => {
    const serviceDid = e.serviceDid ?? options.serviceDid;
    if (!e.agentDid && !serviceDid) {
      throw new Error('audit event has no agentDid and no serviceDid; set serviceDid for OAuth callers');
    }
    const res = await doFetch(`${base}/v1/audit-log/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${options.apiKey}` },
      body: JSON.stringify({
        event: e.event,
        timestamp: e.timestamp,
        ...(e.agentDid ? { agentDid: e.agentDid } : {}),
        ...(serviceDid ? { serviceDid } : {}),
        ...(e.level ? { level: e.level } : {}),
        ...(e.fresh !== undefined ? { fresh: e.fresh } : {}),
        ...(e.proofAssurance ? { proofAssurance: e.proofAssurance } : {}),
        ...(e.l3Minus !== undefined ? { l3Minus: e.l3Minus } : {}),
        ...(e.cnfDiagnostics && e.cnfDiagnostics.length > 0 ? { cnfDiagnostics: e.cnfDiagnostics } : {}),
        ...(e.requiredLevel ? { requiredLevel: e.requiredLevel } : {}),
        ...(e.toolName ? { toolName: e.toolName } : {}),
        ...(e.requiredScope ? { requiredScope: e.requiredScope } : {}),
        effectiveScopes: e.effectiveScopes,
        result: e.result,
        ...(e.reason ? { reason: e.reason } : {}),
        ...(e.oauthSubject ? { oauthSubject: e.oauthSubject } : {}),
        source: 'mcp-middleware',
      }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
    });
    if (!res.ok) throw new Error(`audit-log/events responded ${res.status}`);
  };
}
