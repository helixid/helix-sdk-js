// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/** One authorization decision for one tool call. */
export interface ToolAuditEvent {
  /** `AUTHZ_GRANTED` when the call was allowed to run, `AUTHZ_DENIED` otherwise. */
  event: 'AUTHZ_GRANTED' | 'AUTHZ_DENIED';
  result: 'allowed' | 'denied';
  timestamp: string;
  authMethod: 'helixvp' | 'oauth';
  /** HelixID callers: the agent DID. */
  agentDid?: string;
  /** OAuth callers: the token's `sub`. */
  oauthSubject?: string;
  vpId?: string;
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
 * The events route has no field for an OAuth subject yet, so for OAuth callers
 * the subject is also written into `resultSummary`; `oauthSubject` is sent
 * as-is for when the API starts storing it.
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
        ...(e.vpId ? { vpId: e.vpId } : {}),
        ...(e.toolName ? { toolName: e.toolName } : {}),
        ...(e.requiredScope ? { requiredScope: e.requiredScope } : {}),
        effectiveScopes: e.effectiveScopes,
        result: e.result,
        ...(e.reason ? { reason: e.reason } : {}),
        ...(e.oauthSubject
          ? { oauthSubject: e.oauthSubject, resultSummary: `oauth subject: ${e.oauthSubject}` }
          : {}),
        source: 'mcp-middleware',
      }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
    });
    if (!res.ok) throw new Error(`audit-log/events responded ${res.status}`);
  };
}
