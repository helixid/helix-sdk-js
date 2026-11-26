// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  AuthorizationServerUnavailableError,
  helixMcpGate,
  serveIdentity,
  type GatedRequest,
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

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify(body));
}

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

/**
 * An MCP server over Streamable HTTP (stateless, JSON responses) with every
 * request gated by @helixid/mcp-middleware's one-line HTTP gate:
 *
 *   const gate = helixMcpGate({ resource, ...auth, toolScopes, audit, kyaos });
 *
 * The gate runs at the HTTP layer, before the MCP transport, so a missing or
 * invalid credential gets a real HTTP 401 with `WWW-Authenticate` pointing at
 * the RFC 9728 metadata (which the gate serves, and which is how OAuth
 * clients discover the authorization server), and a scope failure gets a 403.
 * Every request goes through the guard: its open methods (`initialize`,
 * `notifications/initialized` and `tools/list` by default) pass, every other
 * method needs a verified caller, and every refusal is audited by the
 * middleware itself. A KYA-OS agent carries its request proof and delegation
 * chain in `params._meta` (story F-2), verified in-process on every call, so
 * the Helix API is never on the request path.
 *
 * With `kyaos` set, the gate also runs the KYA-OS session and proof flow: the
 * `_kyaos_handshake` tool opens a session (credentials, when present, make it
 * an authenticated one); every other tool call is started before the
 * transport sees it and finished inside the tool handler (`wrapTool`), where
 * the proof is signed into `_meta["org.kya-os/response-proof"]`. With
 * `auth.needsAuthorization` (story L3-E) a caller lacking the authority gets
 * the signed `needs_authorization` challenge as the call's result.
 *
 * What is left here is the MCP server itself: its tools, wrapped with
 * `req.helixMcp.wrapTool`, and the routes that are not the gate's (identity,
 * discovery, the revocation webhook).
 */
export function createOrderServer(options: OrderServerOptions): Server {
  const store = options.store ?? createOrderStore();
  const kyaos = options.kyaos;
  const toolScopes = options.downstream ? { ...TOOL_SCOPES, ...FORWARD_TOOL_SCOPES } : TOOL_SCOPES;

  // The one line: everything HTTP-side of the HelixID check.
  const gate = helixMcpGate({
    resource: options.resource,
    resourceName: 'Order Management (HelixID sample)',
    ...(options.authorizationServers ? { authorizationServers: options.authorizationServers } : {}),
    ...options.auth,
    toolScopes,
    ...(options.audit ? { audit: options.audit } : {}),
    ...(kyaos ? { kyaos } : {}),
    ...(options.onServerError ? { onServerError: options.onServerError } : {}),
  });

  const identity = options.identity ? serveIdentity(options.identity) : undefined;

  const serverError = (res: ServerResponse, error: unknown): void => {
    options.onServerError?.(error);
    if (res.headersSent) return;
    if (error instanceof AuthorizationServerUnavailableError) {
      sendJson(res, 503, { error: 'temporarily_unavailable', error_description: 'The authorization server could not be reached' }, { 'retry-after': '5' });
      return;
    }
    sendJson(res, 500, { error: 'server_error' });
  };

  // Behind the gate: the MCP server, stateless (a fresh server and transport per request).
  const handleMcp = async (req: GatedRequest, res: ServerResponse): Promise<void> => {
    const gated = req.helixMcp!;
    const server = new McpServer({ name: 'order-management', version: '0.0.0' });
    // Each tool runs as the gate allowed it: in the caller's delegation context, audited (A-2), its response proof signed.
    const wrap: ToolWrapper = (name, handler) => gated.wrapTool(name, handler);
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
        async (args) => (await gated.handshake(args)) as CallToolResult,
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
    await transport.handleRequest(req, res, gated.body);
  };

  return createServer((req: GatedRequest, res) => {
    if (options.wellKnown?.handle(req, res)) return;
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (options.revocationWebhook !== undefined && path === options.revocationWebhook.path) {
      options.revocationWebhook.handle(req, res).catch((error: unknown) => serverError(res, error));
      return;
    }
    if (req.method === 'GET' && identity?.handle(path, res)) return;
    gate(req, res, () => {
      if (path === gate.mcpPath) handleMcp(req, res).catch((error: unknown) => serverError(res, error));
      else sendJson(res, 404, { error: 'not_found' });
    });
  });
}
