// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story L3-D in the sample: `forward_lookup_order` looks an order up
 * at another order service (service B) on the calling agent's behalf. The
 * tool knows nothing about identity: it calls B through `withDelegation`,
 * which forwards the chain the agent presented here, signs the delegation
 * proof for B's host and audits the attachment. B verifies all of it with
 * its own local verifier; nothing is shared between the two services.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { withDelegation, type OutboundAudit } from '@helixid/mcp-middleware';
import type { kyaos } from '@helixid/sdk-js';
import { z } from 'zod';
import type { ToolWrapper } from './orders.js';

export const FORWARD_TOOL = 'forward_lookup_order';
/** The forwarding tool needs what the downstream lookup needs. */
export const FORWARD_TOOL_SCOPES: Record<string, string[]> = { [FORWARD_TOOL]: ['orders:read'] };

export interface DownstreamOptions {
  /** Service B's MCP endpoint, e.g. `http://127.0.0.1:3911/mcp`. */
  url: string;
  /** This server's Signer: the delegation proof's `iss`. */
  signer: kyaos.Signer;
  /** Also send the advisory `KYA-OS-Delegation-Chain` / `KYA-OS-Granted-Scopes` headers. */
  advisoryHeaders?: boolean | undefined;
  /** Where each attachment is audited (`McpAuditTrail.outboundAudit()`, a log line, ...). */
  audit?: OutboundAudit | undefined;
  fetch?: typeof fetch | undefined;
  /** Milliseconds since the epoch, for the proof's `iat`; default `Date.now`. */
  clock?: (() => number) | undefined;
  /** Where a failed audit write is reported; default `console.error`. */
  onAuditError?: ((error: unknown) => void) | undefined;
}

const orderId = z.string().regex(/^ORD-\d{4,}$/, 'expected an order id like ORD-1001');

export function registerForwardTool(server: McpServer, downstream: DownstreamOptions, wrap: ToolWrapper): void {
  const forward = withDelegation(downstream.fetch ?? fetch, {
    signer: downstream.signer,
    advisoryHeaders: downstream.advisoryHeaders ?? false,
    ...(downstream.audit === undefined ? {} : { audit: downstream.audit }),
    ...(downstream.clock === undefined ? {} : { clock: downstream.clock }),
    // eslint-disable-next-line no-console -- the sample's one line for a failed audit write
    onAuditError: downstream.onAuditError ?? ((error): void => console.error('outbound delegation audit failed:', error instanceof Error ? error.message : error)),
  });
  server.registerTool(
    FORWARD_TOOL,
    {
      title: 'Look up an order at the downstream service',
      description: 'Asks the downstream order service for an order, on the calling agent\'s delegated authority.',
      inputSchema: { orderId },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    wrap(FORWARD_TOOL, async ({ orderId: id }): Promise<CallToolResult> => {
      const response = await forward(downstream.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: id } } }),
      });
      const body = (await response.json().catch(() => undefined)) as { error?: unknown; result?: { isError?: boolean } } | undefined;
      const failed = !response.ok || body?.error !== undefined || body?.result?.isError === true;
      return {
        content: [{ type: 'text', text: JSON.stringify({ downstreamStatus: response.status, downstream: body ?? null }) }],
        ...(failed ? { isError: true } : {}),
      };
    }),
  );
}
