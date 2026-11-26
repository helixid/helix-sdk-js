// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { IncomingMessage, ServerResponse } from 'node:http';
import { kyaos as sdk } from '@helixid/sdk-js';
import { type McpAuditTrail, type ToolCallAudit } from './audit.js';
import { runAuditedTool, type AuditedToolResult } from './audit-delivery.js';
import { delegationContextOf, runWithDelegation, type DelegationContext } from './delegation/outbound.js';
import { AuthorizationServerUnavailableError } from './errors.js';
import { deferredNonceStoreFromEnv } from './kyaos/nonce-store-env.js';
import type { KyaOsRuntime } from './kyaos/runtime.js';
import type { DetachedProof } from './kyaos/response-proof.js';
import { buildProtectedResourceMetadata, protectedResourceMetadataUrl, toHttpErrorResponse, type ProtectedResourceMetadata } from './metadata.js';
import { helixidMCPMiddleware, type AuthorizedCaller, type MCPMiddleware } from './middleware.js';
import type { MCPMiddlewareOptions, MiddlewareVerifierOptions } from './types.js';

/**
 * Everything the one-line gate needs: the guard's own options
 * (`MCPMiddlewareOptions`: verifier, toolScopes, openMethods, resourceScopes,
 * promptScopes, oauth, auditSink, needsAuthorization, ...) plus where it
 * sits. The same names as helix_mcp_middleware's `HelixMcpGate`.
 */
export interface HelixMcpGateOptions extends MCPMiddlewareOptions {
  /** This server's MCP endpoint URL, e.g. `https://orders.example/mcp`. Its path is gated; the RFC 9728 metadata is served for it. */
  resource: string;
  /** Advertised in the RFC 9728 metadata for OAuth clients. */
  authorizationServers?: string[];
  /** `resource_name` in the RFC 9728 metadata. */
  resourceName?: string;
  /** `scopes_supported` in the RFC 9728 metadata; default every scope in toolScopes, resourceScopes and promptScopes. */
  scopesSupported?: string[];
  /**
   * The tool-call lifecycle (KYA-OS AAP-1): `session.established`, then
   * `tool.call.started` / `completed` / `failed` (through `wrapTool`), or
   * `tool.call.denied` when the gate refuses. Its `toolAuditSink()` is the
   * guard's `auditSink` unless one is given.
   */
  audit?: McpAuditTrail;
  /**
   * The KYA-OS layer (story L2-A): the handshake tool (open to anonymous
   * agents, listed with no scope and any level), sessions, and a
   * server-signed proof on every tool call outcome (through `wrapTool`).
   */
  kyaos?: KyaOsRuntime;
  /** Where the replay store is read from (`KYAOS_NONCE_STORE`, ...) when the verifier is built here and names none; default `process.env`. */
  env?: Record<string, string | undefined>;
  /** Largest request body read, in bytes; default 1 MB. */
  maxBodyBytes?: number;
  /** Take the caller's address from the first `X-Forwarded-For` entry (only behind a proxy you run); default the socket's. */
  trustProxy?: boolean;
  /** Called for errors that are not the caller's fault (answered 500, or 503 when an authorization server is down). */
  onServerError?: (error: unknown) => void;
}

/** What the gate hands the MCP handler behind it, on `req.helixMcp`. */
export interface HelixMcpRequestState {
  /** The JSON-RPC body as read (KYA-OS control arguments stripped from allowed tool calls): give it to the transport. */
  body: unknown;
  /** The audited call (`audit` option), when this request is one. */
  call: ToolCallAudit | undefined;
  /** The caller each allowed `tools/call` came from, in order, by tool name. */
  callers: Map<string, AuthorizedCaller[]>;
  /** KYA-OS: the agent the handshake's credential identified, if any. */
  authenticatedAgentDid: string | undefined;
  /**
   * Wraps a tool handler so it runs as the gate allowed it: inside the
   * caller's delegation context (story L3-D), audited (A-2: intent before,
   * completion after), with the KYA-OS response proof signed over its result.
   */
  wrapTool<A extends unknown[], R>(name: string, handler: (...args: A) => Promise<R> | R): (...args: A) => Promise<R>;
  /** KYA-OS: the handshake tool's result for `args` (open to anonymous agents; a valid credential makes the session authenticated). */
  handshake(args: unknown): Promise<Record<string, unknown>>;
}

export type GatedRequest = IncomingMessage & { helixMcp?: HelixMcpRequestState; body?: unknown };
export type GateNext = (error?: unknown) => void;

/** A Node / Express / Connect middleware: `app.use(helixMcpGate({...}))`, or `gate(req, res, () => handler(req, res))` on `node:http`. */
export type HelixMcpGate = ((req: GatedRequest, res: ServerResponse, next: GateNext) => void) & {
  readonly guard: MCPMiddleware;
  readonly metadata: ProtectedResourceMetadata;
  readonly metadataUrl: string;
  readonly mcpPath: string;
};

const DEFAULT_MAX_BODY_BYTES = 1_000_000;

class BodyError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function readBody(req: GatedRequest, max: number): Promise<unknown> {
  // A framework that already parsed the body (express.json()) left it on req.body.
  if (req.body !== undefined && typeof req.body !== 'string' && !Buffer.isBuffer(req.body)) return req.body;
  const chunks: Buffer[] = [];
  let size = 0;
  if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
    chunks.push(Buffer.from(req.body));
  } else {
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > max) throw new BodyError(413, 'Request body too large');
      chunks.push(chunk as Buffer);
    }
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new BodyError(400, 'Request body is not valid JSON');
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify(body));
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

/** The code a refused or failed call is audited with: the error's code (never its message), else `server_error`. */
function auditCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code.toLowerCase() : 'server_error';
}

/** Whether a request carries a credential at all: an Authorization header, or a KYA-OS proof or chain in `_meta`. */
const carriesCredential = (headers: IncomingMessage['headers'], meta: Record<string, unknown> | undefined): boolean =>
  headers.authorization !== undefined || sdk.verifier.readRequestProof(meta) !== undefined || sdk.verifier.readCarriedChain(meta) !== undefined;

function clientIpOf(req: IncomingMessage, trustProxy: boolean): string | undefined {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.socket?.remoteAddress ?? undefined;
}

const isBuiltVerifier = (value: unknown): boolean => typeof (value as { verifyCall?: unknown } | undefined)?.verifyCall === 'function';

/**
 * The HTTP layer of an MCP server gated by HelixID, in one line:
 *
 * ```ts
 * app.use(helixMcpGate({ resource: 'https://orders.example/mcp', verifier, toolScopes, audit }));
 * ```
 *
 * For each POST to the MCP path it reads the JSON-RPC body, passes every
 * request through the guard (open methods pass; every other needs a verified
 * caller, and every refusal is audited), answers a refusal with 401 / 403 /
 * 400 and `WWW-Authenticate` pointing at the RFC 9728 metadata (503 with
 * Retry-After when an authorization server is down), runs the KYA-OS session
 * layer when `kyaos` is set, and hands the rest to the next handler with
 * `req.helixMcp` (the body, and `wrapTool` for its tool handlers). It serves
 * the RFC 9728 metadata itself. Other methods on the MCP path answer 405:
 * the gate is for stateless Streamable HTTP with JSON responses, where every
 * message is verified. Any other path goes to `next()`.
 */
export function helixMcpGate(options: HelixMcpGateOptions): HelixMcpGate {
  const { resource, authorizationServers, resourceName, scopesSupported, audit, kyaos, env, maxBodyBytes, trustProxy, onServerError, ...auth } = options;
  // The handshake needs an identified caller, not a scope: listed with none, at any level (it opens a session, it acts on nothing).
  const toolScopes = kyaos && auth.toolScopes ? { ...auth.toolScopes, [kyaos.handshakeToolName]: [] } : auth.toolScopes;
  // The replay store: the KYA-OS runtime's, else the one the environment names (KYAOS_NONCE_STORE), shared by every instance that names it.
  const verifier =
    auth.verifier === undefined || isBuiltVerifier(auth.verifier) || (auth.verifier as MiddlewareVerifierOptions).nonceStore !== undefined
      ? auth.verifier
      : {
          ...(auth.verifier as MiddlewareVerifierOptions),
          nonceStore: kyaos?.nonceStore ?? deferredNonceStoreFromEnv(env ?? process.env, { now: (auth.verifier as MiddlewareVerifierOptions).clock ?? Date.now }),
        };
  const guard = helixidMCPMiddleware({
    ...auth,
    ...(verifier === undefined ? {} : { verifier }),
    ...(toolScopes === undefined ? {} : { toolScopes }),
    ...(kyaos ? { tools: { ...auth.tools, [kyaos.handshakeToolName]: { minimumLevel: 'L1' as const } } } : {}),
    ...(auth.auditSink === undefined && audit ? { auditSink: audit.toolAuditSink() } : {}),
  });

  const mcpPath = new URL(resource).pathname;
  const metadataUrl = protectedResourceMetadataUrl(resource);
  const metadataPath = new URL(metadataUrl).pathname;
  const advertised = scopesSupported ?? [
    ...new Set([...Object.values(auth.toolScopes ?? {}), ...Object.values(auth.resourceScopes ?? {}), ...Object.values(auth.promptScopes ?? {})].flat()),
  ];
  const metadata = buildProtectedResourceMetadata({
    resource,
    scopesSupported: advertised,
    ...(resourceName ? { resourceName } : {}),
    ...(authorizationServers ? { authorizationServers } : {}),
  });

  const serverError = (res: ServerResponse, error: unknown): void => {
    onServerError?.(error);
    if (res.headersSent) return;
    // The caller's token was not shown to be bad; its authorization server could not be asked. Say so, and invite a retry.
    if (error instanceof AuthorizationServerUnavailableError) {
      sendJson(res, 503, { error: 'temporarily_unavailable', error_description: 'The authorization server could not be reached' }, { 'retry-after': '5' });
      return;
    }
    sendJson(res, 500, { error: 'server_error' });
  };

  const handle = async (req: GatedRequest, res: ServerResponse, next: GateNext): Promise<void> => {
    let body: unknown;
    try {
      body = await readBody(req, maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
    } catch (error) {
      const status = error instanceof BodyError ? error.status : 400;
      sendJson(res, status, { jsonrpc: '2.0', id: null, error: { code: -32700, message: (error as Error).message } });
      return;
    }
    const messages: unknown[] = Array.isArray(body) ? body : [body];
    const toolCalls = messages.map(asRecord).filter((message): message is Record<string, unknown> => message?.['method'] === 'tools/call');
    const clientIp = clientIpOf(req, trustProxy === true);
    // One audited call per request: its first tools/call (the KYA-OS handshake is no gated tool call).
    const firstName = asRecord(toolCalls[0]?.['params'])?.['name'];
    const first = typeof firstName === 'string' ? firstName : undefined;
    const call = audit && toolCalls.length > 0 && !(kyaos && kyaos.isHandshake(first)) ? audit.beginToolCall(first !== undefined ? { toolName: first } : {}) : undefined;

    const serve = async (): Promise<void> => {
      // KYA-OS: the proof of each allowed call is signed inside its tool handler (the result is only known there).
      const finishers = new Map<string, Array<(result: Record<string, unknown>) => Promise<Record<string, unknown>>>>();
      // Story L3-D: the delegation each allowed call carries, which its handler may forward downstream.
      const delegations = new Map<string, Array<DelegationContext | undefined>>();
      const callers = new Map<string, AuthorizedCaller[]>();
      const allowed = (tool: string, caller: AuthorizedCaller, sessionId?: string): void => {
        callers.set(tool, [...(callers.get(tool) ?? []), caller]);
        delegations.set(tool, [
          ...(delegations.get(tool) ?? []),
          delegationContextOf(caller, { ...(sessionId === undefined ? {} : { sessionId }), ...(call ? { correlationId: call.correlationId } : {}) }),
        ]);
      };
      let authenticatedAgentDid: string | undefined;

      // A refusal is answered by the guard's code and audited as a denied call (or a failed one when it is a server fault).
      const refuse = async (error: unknown, proof?: DetachedProof): Promise<void> => {
        const denial = toHttpErrorResponse(error, { resourceMetadataUrl: metadataUrl, proof });
        if (!denial) {
          await call?.failed(auditCode(error));
          serverError(res, error);
          return;
        }
        await call?.denied(auditCode(error));
        sendJson(res, denial.status, denial.body, { 'www-authenticate': denial.headers['WWW-Authenticate'] });
      };

      // Every request but tools/call: the guard lets its open methods through and checks and audits the rest.
      for (const message of messages) {
        const request = asRecord(message);
        const method = request?.['method'];
        if (typeof method !== 'string' || method === 'tools/call') continue;
        const params = asRecord(request!['params']);
        const meta = asRecord(params?.['_meta']);
        try {
          await guard.authorize({ method, request: { method, ...(params ? { params } : {}) }, ...(meta ? { _meta: meta } : {}), headers: req.headers, ...(clientIp ? { clientIp } : {}) });
        } catch (error) {
          await refuse(error);
          return;
        }
      }

      for (const message of toolCalls) {
        const params = asRecord(message['params']) ?? {};
        const name = typeof params['name'] === 'string' ? params['name'] : undefined;
        const tool = name ?? '';
        const input = asRecord(params['arguments']);
        const meta = asRecord(params['_meta']);
        const toolCall = {
          ...(name !== undefined ? { name } : {}),
          ...(input ? { input } : {}),
          ...(meta ? { _meta: meta } : {}),
          // The request as received: the KYA-OS proof's requestHash is recomputed over exactly this (story F-2).
          request: { method: 'tools/call', params },
          headers: req.headers,
          ...(clientIp ? { clientIp } : {}),
        };

        if (kyaos && kyaos.isHandshake(name)) {
          // Open to anonymous agents (so not sent to the guard, which would audit a missing credential as a refusal);
          // a credential, when sent, must be good and makes the session an authenticated one.
          if (carriesCredential(req.headers, meta)) {
            try {
              authenticatedAgentDid = (await guard.authorize(toolCall)).agentDid;
            } catch (error) {
              await refuse(error);
              return;
            }
          }
          continue;
        }

        if (!kyaos) {
          try {
            allowed(tool, await guard.authorize(toolCall));
          } catch (error) {
            await refuse(error);
            return;
          }
          continue;
        }

        let caller: AuthorizedCaller | undefined;
        const started = await kyaos.start({ name: tool, arguments: input, _meta: meta }, { authorize: async () => (caller = await guard.authorize(toolCall)) });
        if (started.outcome === 'denied') {
          await refuse(started.error, started.proof);
          return;
        }
        if (started.outcome === 'needs_authorization') {
          // KYA-OS story L3-E: the signed challenge is the call's result, answered here since the tool never runs: audited as denied.
          await call?.denied(auditCode(started.error));
          sendJson(res, 200, { jsonrpc: '2.0', id: message['id'] ?? null, result: started.result });
          return;
        }
        // Control arguments (`_kyaos*`) never reach the tool.
        message['params'] = { ...params, arguments: started.arguments };
        allowed(tool, caller!, started.session?.id);
        finishers.set(tool, [...(finishers.get(tool) ?? []), (result): Promise<Record<string, unknown>> => started.finish(result)]);
      }

      const state: HelixMcpRequestState = {
        body,
        call,
        callers,
        authenticatedAgentDid,
        wrapTool: (name, handler) => async (...args) => {
          const delegation = delegations.get(name)?.shift();
          const run = async (): Promise<unknown> => (delegation ? runWithDelegation(delegation, () => handler(...args)) : handler(...args));
          const result = call ? await runAuditedTool(call, async () => (await run()) as AuditedToolResult) : await run();
          const finish = finishers.get(name)?.shift();
          return (finish ? await finish(result as Record<string, unknown>) : result) as Awaited<ReturnType<typeof handler>>;
        },
        handshake: async (args) => {
          if (!kyaos) throw new Error('helixMcpGate: the handshake needs the `kyaos` option');
          return kyaos.handshakeToolResult(args, { authenticatedAgentDid });
        },
      };
      req.helixMcp = state;
      // The handler runs inside this call's audit context until the response is done.
      await new Promise<void>((resolve) => {
        res.once('close', resolve);
        res.once('finish', resolve);
        next();
      });
    };

    if (call) await call.run(serve);
    else await serve();
  };

  const gate = (req: GatedRequest, res: ServerResponse, next: GateNext): void => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === metadataPath && req.method === 'GET') {
      sendJson(res, 200, metadata);
      return;
    }
    if (path !== mcpPath) {
      next();
      return;
    }
    if (req.method !== 'POST') {
      // Stateless server: no SSE stream to open (GET) and no session to end (DELETE).
      sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      return;
    }
    handle(req, res, next).catch((error: unknown) => serverError(res, error));
  };
  return Object.assign(gate, { guard, metadata, metadataUrl, mcpPath });
}
