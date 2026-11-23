// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  AuthorizationServerUnavailableError,
  delegationContextOf,
  runAuditedTool,
  runWithDelegation,
  type DelegationContext,
  type MiddlewareCaller,
  type AuditedToolResult,
  buildProtectedResourceMetadata,
  helixidMCPMiddleware,
  protectedResourceMetadataUrl,
  serveIdentity,
  toHttpErrorResponse,
  type DetachedProof,
  type KyaOsRuntime,
  type MCPMiddlewareOptions,
  type McpAuditTrail,
  type ServeIdentityOptions,
  type WellKnownMcp,
} from '@helixid/mcp-middleware';
import { z } from 'zod';
import { TOOL_SCOPES, createOrderStore, registerOrderTools, type OrderStore, type ToolWrapper } from './orders.js';
import { FORWARD_TOOL_SCOPES, registerForwardTool, type DownstreamOptions } from './downstream.js';

export interface OrderServerOptions {
  /** This server's MCP endpoint URL, e.g. `http://localhost:3700/mcp`. MCP is served at its path. */
  resource: string;
  /** Advertised in the RFC 9728 metadata for OAuth clients. */
  authorizationServers?: string[];
  /** Everything except the scopes, which this sample fixes in TOOL_SCOPES. */
  auth: Omit<MCPMiddlewareOptions, 'toolScopes' | 'requiredScopes'>;
  /**
   * Records each tool call's lifecycle (KYA-OS AAP-1): `session.established`,
   * then `tool.call.started` / `completed` / `failed`, or `tool.call.denied`
   * when the guard refuses. Pair it with `auth.auditSink: audit.toolAuditSink()`
   * so the guard's own decisions join the same call. With required delivery
   * (A-2) a call that cannot be recorded does not run: a failed session or
   * intent append stops it, and a failed terminal append marks its result
   * degraded (`_meta["org.kya-os/audit"]`).
   */
  audit?: McpAuditTrail;
  /**
   * The KYA-OS layer (story L2-A): the `_kyaos_handshake` tool, sessions,
   * the replay store and a server-signed proof on every tool call outcome.
   * Off when not given.
   */
  kyaos?: KyaOsRuntime;
  /**
   * The KYA-OS discovery document (story L1-D), served at `/.well-known/mcp`
   * from `createWellKnownMcp()`; a disabled one answers 404. Off when not given.
   */
  wellKnown?: WellKnownMcp;
  store?: OrderStore;
  /**
   * KYA-OS story L3-C: the RFC 8935 receiver of Helix's revocation signals
   * (`RevocationSignalClient.webhookHandler()`), mounted at `path`.
   */
  revocationWebhook?: { path: string; handle(req: IncomingMessage, res: ServerResponse): Promise<void> };
  /** Called for errors that are not the caller's fault (they become a 500). */
  onServerError?: (error: unknown) => void;
  /** KYA-OS story C-A: serve this server's own did.json and card.json from its origin. */
  identity?: ServeIdentityOptions;
  /**
   * KYA-OS story L3-D: the downstream order service `forward_lookup_order`
   * calls on the agent's behalf, forwarding its delegation. Off when not given.
   */
  downstream?: DownstreamOptions;
}

const MAX_BODY_BYTES = 1_000_000;

class BodyError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new BodyError(413, 'Request body too large');
    chunks.push(chunk as Buffer);
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

interface ToolCallMessage {
  id?: unknown;
  method: 'tools/call';
  params?: { name?: unknown; arguments?: unknown; _meta?: unknown };
}

type Finisher = (result: CallToolResult) => Promise<CallToolResult>;

const isMissingCredential = (error: unknown): boolean => (error as { code?: unknown } | null)?.code === 'PROOF_MISSING';

/** The handshake tool's input, as the KYA-OS handshake-request schema has it; unknown members are dropped by zod. */
const HANDSHAKE_INPUT = {
  nonce: z.string().min(22),
  audience: z.string().min(1),
  timestamp: z.number().int().min(0),
  agentDid: z.string().optional(),
  clientInfo: z.object({ name: z.string() }).passthrough().optional(),
  clientProtocolVersion: z.string().optional(),
  clientCapabilities: z.record(z.unknown()).optional(),
};

function isToolCall(message: unknown): message is ToolCallMessage {
  return typeof message === 'object' && message !== null && (message as { method?: unknown }).method === 'tools/call';
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

/** The code a refused or failed call is audited with: the error's code (never its message), else `server_error`. */
function auditCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code.toLowerCase() : 'server_error';
}

/**
 * An MCP server over Streamable HTTP (stateless, JSON responses) with every
 * tool call gated by @helixid/mcp-middleware.
 *
 * The gate runs at the HTTP layer, before the MCP transport, so a missing or
 * invalid credential gets a real HTTP 401 with `WWW-Authenticate` pointing at
 * the RFC 9728 metadata (which is how OAuth clients discover the
 * authorization server), and a scope failure gets a 403. Only `tools/call` is
 * gated: `initialize` and `tools/list` stay open. A KYA-OS agent carries its
 * request proof and delegation chain in `params._meta` (story F-2), verified
 * in-process on every call, so the Helix API is never on the request path.
 *
 * With `kyaos` set, the same layer runs the KYA-OS session and proof flow:
 * the `_kyaos_handshake` tool opens a session (credentials, when present,
 * make it an authenticated one); every other tool call is started before
 * the transport sees it (session lookup, authorization, control arguments
 * stripped) and finished inside the tool handler, where the result is
 * hashed and the proof signed into `_meta["org.kya-os/response-proof"]`. A
 * refusal carries its `denied` proof in the 400/401/403 body.
 *
 * With `auth.needsAuthorization` set (story L3-E), a caller whose delegation
 * does not cover the tool gets the signed `needs_authorization` challenge as
 * the call's result, and a retry carrying `_kyaos_resume` and
 * `_kyaos_delegation` is verified through that layer before the tool runs.
 */
export function createOrderServer(options: OrderServerOptions): Server {
  const store = options.store ?? createOrderStore();
  const kyaos = options.kyaos;
  // The handshake needs an identified caller, not a scope: it is listed with none (story F-2), and it opens
  // a session rather than acting on anything, so any verified level will do (story C-C).
  const toolScopes = options.downstream ? { ...TOOL_SCOPES, ...FORWARD_TOOL_SCOPES } : TOOL_SCOPES;
  const guard = helixidMCPMiddleware({
    ...options.auth,
    toolScopes: kyaos ? { ...toolScopes, [kyaos.handshakeToolName]: [] } : toolScopes,
    ...(kyaos ? { tools: { ...options.auth.tools, [kyaos.handshakeToolName]: { minimumLevel: 'L1' as const } } } : {}),
  });
  const mcpPath = new URL(options.resource).pathname;
  const metadataUrl = protectedResourceMetadataUrl(options.resource);
  const metadataPath = new URL(metadataUrl).pathname;
  const metadata = buildProtectedResourceMetadata({
    resource: options.resource,
    scopesSupported: [...new Set(Object.values(toolScopes).flat())],
    resourceName: 'Order Management (HelixID sample)',
    ...(options.authorizationServers ? { authorizationServers: options.authorizationServers } : {}),
  });

  const identity = options.identity ? serveIdentity(options.identity) : undefined;

  const serverError = (res: ServerResponse, error: unknown): void => {
    options.onServerError?.(error);
    if (res.headersSent) return;
    // The caller's token was not shown to be bad; its authorization server
    // could not be asked. Say so, and invite a retry.
    if (error instanceof AuthorizationServerUnavailableError) {
      sendJson(res, 503, { error: 'temporarily_unavailable', error_description: 'The authorization server could not be reached' }, { 'retry-after': '5' });
      return;
    }
    sendJson(res, 500, { error: 'server_error' });
  };

  const handleMcp = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    let body: unknown;
    try {
      body = await readJson(req);
    } catch (error) {
      const status = error instanceof BodyError ? error.status : 400;
      sendJson(res, status, { jsonrpc: '2.0', id: null, error: { code: -32700, message: (error as Error).message } });
      return;
    }

    const toolCalls = (Array.isArray(body) ? body : [body]).filter(isToolCall);
    // One audited call per request: the gated tool call (a batch is audited as its first).
    // The KYA-OS handshake is no gated tool call, so it is not audited as one.
    const first = toolCalls[0];
    const firstName = typeof first?.params?.name === 'string' ? first.params.name : undefined;
    const call =
      options.audit && first && !(kyaos && kyaos.isHandshake(firstName))
        ? options.audit.beginToolCall(firstName !== undefined ? { toolName: firstName } : {})
        : undefined;

    const serve = async (): Promise<void> => {
      // KYA-OS: the proof of each allowed call is signed inside its tool handler
      // (the result is only known there); a batch may call one tool twice.
      const finishers = new Map<string, Finisher[]>();
      // Story L3-D: the delegation each allowed call carries, which its handler may forward downstream.
      const delegations = new Map<string, Array<DelegationContext | undefined>>();
      const allowed = (tool: string, caller: MiddlewareCaller, sessionId?: string): void => {
        const list = delegations.get(tool) ?? [];
        list.push(delegationContextOf(caller, { ...(sessionId === undefined ? {} : { sessionId }), ...(call ? { correlationId: call.correlationId } : {}) }));
        delegations.set(tool, list);
      };
      // The agent the handshake call's credentials identified, if any.
      let authenticatedAgentDid: string | undefined;

      for (const message of toolCalls) {
        const params = message.params ?? {};
        const name = typeof params.name === 'string' ? params.name : undefined;
        const tool = name ?? '';
        const input = asRecord(params.arguments);
        const meta = asRecord(params._meta);
        const toolCall = {
          ...(name !== undefined ? { name } : {}),
          ...(input ? { input } : {}),
          ...(meta ? { _meta: meta } : {}),
          // The request as received: the KYA-OS proof's requestHash is recomputed over exactly this (story F-2).
          request: { method: message.method, params: params as Record<string, unknown> },
          headers: req.headers,
        };
        // A refusal is audited by its code (never its message): denied when the
        // caller is answered 401/403, failed when it is a server fault.
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

        if (kyaos && kyaos.isHandshake(name)) {
          // The handshake is open to anonymous agents; a credential, when sent,
          // must be good and makes the session an authenticated one.
          try {
            authenticatedAgentDid = (await guard.authorize(toolCall)).agentDid;
          } catch (error) {
            if (!isMissingCredential(error)) {
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

        let caller: MiddlewareCaller | undefined;
        const started = await kyaos.start(
          { name: name ?? '', arguments: input, _meta: meta },
          { authorize: async () => (caller = await guard.authorize(toolCall)) },
        );
        if (started.outcome === 'denied') {
          await refuse(started.error, started.proof);
          return;
        }
        if (started.outcome === 'needs_authorization') {
          // KYA-OS story L3-E: the signed challenge is the call's result (a tool error result with the
          // proof in _meta), answered here since the tool itself never runs: audited as a denied call.
          await call?.denied(auditCode(started.error));
          sendJson(res, 200, { jsonrpc: '2.0', id: message.id ?? null, result: started.result });
          return;
        }
        // Control arguments (`_kyaos*`) never reach the tool.
        message.params = { ...params, arguments: started.arguments };
        // `start` authorized the call before allowing it, so the caller is known here.
        allowed(tool, caller!, started.session?.id);
        const list = finishers.get(tool) ?? [];
        list.push((result) => started.finish(result) as Promise<CallToolResult>);
        finishers.set(tool, list);
      }

      // Stateless: a fresh server and transport per request. Leaving out
      // sessionIdGenerator is what makes the transport stateless.
      const server = new McpServer({ name: 'order-management', version: '0.0.0' });
      // A-2: each tool runs audited (runAuditedTool, as auditToolHandlers does),
      // inside L2-A's proof wrapper: in required delivery the intent receipt comes
      // before the handler, and the response proof is signed over the final
      // result, a degraded marker included. The handshake is not a tool call
      // and is not audited.
      const wrap: ToolWrapper = (name, handler) => async (args, extra) => {
        const delegation = delegations.get(name)?.shift();
        const run = (): Promise<CallToolResult> => (delegation ? runWithDelegation(delegation, () => handler(args, extra)) : handler(args, extra));
        const result = call ? ((await runAuditedTool(call, async () => (await run()) as AuditedToolResult)) as CallToolResult) : await run();
        const finish = finishers.get(name)?.shift();
        return finish ? finish(result) : result;
      };
      registerOrderTools(server, store, wrap);
      if (options.downstream) registerForwardTool(server, options.downstream, wrap);
      if (kyaos) {
        server.registerTool(
          kyaos.handshakeToolName,
          {
            title: 'KYA-OS handshake',
            description: 'Opens a KYA-OS session: a fresh nonce, this server as audience, the current Unix time.',
            inputSchema: HANDSHAKE_INPUT,
          },
          async (args) => (await kyaos.handshakeToolResult(args, { authenticatedAgentDid })) as CallToolResult,
        );
      }
      const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      // The MCP SDK's own types don't line up under this repo's
      // exactOptionalPropertyTypes (optional callbacks typed without `| undefined`);
      // the transport is the SDK's own Transport implementation.
      await server.connect(transport as Transport);
      await transport.handleRequest(req, res, body);
    };

    if (call) await call.run(serve);
    else await serve();
  };

  return createServer((req, res) => {
    if (options.wellKnown?.handle(req, res)) return;
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === metadataPath && req.method === 'GET') {
      sendJson(res, 200, metadata);
      return;
    }
    if (options.revocationWebhook !== undefined && path === options.revocationWebhook.path) {
      options.revocationWebhook.handle(req, res).catch((error: unknown) => serverError(res, error));
      return;
    }
    if (req.method === 'GET' && identity?.handle(path, res)) return;
    if (path === mcpPath) {
      if (req.method !== 'POST') {
        // Stateless server: no SSE stream to open (GET) and no session to end (DELETE).
        sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
        return;
      }
      handleMcp(req, res).catch((error: unknown) => serverError(res, error));
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
  });
}
