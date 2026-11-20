// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { decodeHelixVP, readHelixVPHeader, readHelixVPMeta, type SignedVP } from '@helixid/sdk-js';
import {
  AuthorizationServerUnavailableError,
  buildProtectedResourceMetadata,
  helixidMCPMiddleware,
  protectedResourceMetadataUrl,
  toHttpErrorResponse,
  type MCPMiddlewareOptions,
  type McpAuditTrail,
} from '@helixid/mcp-middleware';
import { TOOL_SCOPES, createOrderStore, registerOrderTools, type OrderStore } from './orders.js';

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
   * so the guard's own decisions join the same call. An audit write that fails
   * fails the call (a 500): a call that cannot be recorded does not run.
   */
  audit?: McpAuditTrail;
  store?: OrderStore;
  /** Called for errors that are not the caller's fault (they become a 500). */
  onServerError?: (error: unknown) => void;
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
  method: 'tools/call';
  params?: { name?: unknown; arguments?: unknown; _meta?: unknown };
}

function isToolCall(message: unknown): message is ToolCallMessage {
  return typeof message === 'object' && message !== null && (message as { method?: unknown }).method === 'tools/call';
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

/**
 * The HelixID VP a tool call presents, decoded, so the audit trail can derive
 * the delegation evidence (SPEC section 7.8). Undefined when there is none or
 * it does not decode: the guard, not this, answers a bad credential.
 */
function presentedVP(headers: IncomingMessage['headers'], meta: Record<string, unknown> | undefined): SignedVP | undefined {
  try {
    const fromMeta = readHelixVPMeta(meta) ?? readHelixVPHeader(headers);
    if (fromMeta) return fromMeta;
    const authorization = headers.authorization;
    const match = typeof authorization === 'string' ? /^helixvp\s+(\S+)$/i.exec(authorization) : null;
    return match ? decodeHelixVP(match[1]!) : undefined;
  } catch {
    return undefined;
  }
}

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
 * gated: `initialize` and `tools/list` stay open, so HelixID clients that send
 * their VP in `params._meta` (not a header) keep working, and a VP is
 * verified once per tool call, not once per request. (A VP is not single-use
 * in Phase 1; see the middleware README.)
 */
export function createOrderServer(options: OrderServerOptions): Server {
  const store = options.store ?? createOrderStore();
  const guard = helixidMCPMiddleware({ ...options.auth, toolScopes: TOOL_SCOPES });
  const mcpPath = new URL(options.resource).pathname;
  const metadataUrl = protectedResourceMetadataUrl(options.resource);
  const metadataPath = new URL(metadataUrl).pathname;
  const metadata = buildProtectedResourceMetadata({
    resource: options.resource,
    scopesSupported: [...new Set(Object.values(TOOL_SCOPES).flat())],
    resourceName: 'Order Management (HelixID sample)',
    ...(options.authorizationServers ? { authorizationServers: options.authorizationServers } : {}),
  });

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
    const first = toolCalls[0];
    const call =
      options.audit && first
        ? options.audit.beginToolCall({
            ...(typeof first.params?.name === 'string' ? { toolName: first.params.name } : {}),
            credential: presentedVP(req.headers, asRecord(first.params?._meta)),
          })
        : undefined;

    const serve = async (): Promise<void> => {
      for (const message of toolCalls) {
        const params = message.params ?? {};
        const input = asRecord(params.arguments);
        const meta = asRecord(params._meta);
        try {
          await guard({
            ...(typeof params.name === 'string' ? { name: params.name } : {}),
            ...(input ? { input } : {}),
            ...(meta ? { _meta: meta } : {}),
            headers: req.headers,
          });
        } catch (error) {
          const denial = toHttpErrorResponse(error, { resourceMetadataUrl: metadataUrl });
          if (!denial) {
            await call?.failed(auditCode(error));
            serverError(res, error);
            return;
          }
          await call?.denied(auditCode(error));
          sendJson(res, denial.status, denial.body, { 'www-authenticate': denial.headers['WWW-Authenticate'] });
          return;
        }
      }

      // Stateless: a fresh server and transport per request. Leaving out
      // sessionIdGenerator is what makes the transport stateless.
      const server = new McpServer({ name: 'order-management', version: '0.0.0' });
      registerOrderTools(server, store);
      const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      // The MCP SDK's own types don't line up under this repo's
      // exactOptionalPropertyTypes (optional callbacks typed without `| undefined`);
      // the transport is the SDK's own Transport implementation.
      await server.connect(transport as Transport);
      await call?.started();
      try {
        await transport.handleRequest(req, res, body);
      } catch (error) {
        await call?.failed('handler_error');
        throw error;
      }
      await call?.completed();
    };

    if (call) await call.run(serve);
    else await serve();
  };

  return createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === metadataPath && req.method === 'GET') {
      sendJson(res, 200, metadata);
      return;
    }
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
