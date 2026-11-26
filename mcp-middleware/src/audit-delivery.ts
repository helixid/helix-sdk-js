// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Audit delivery for MCP tool calls (story A-2 point 3; AUDITABILITY.md,
 * Delivery semantics).
 *
 * `createHelixAuditDelivery` is the sink an `McpAuditTrail` reports through:
 * submissions to the HelixID recorder (`POST /v1/audit/submissions`) under
 * `audit.delivery`, which is `required` by default, `buffered` with a
 * durable outbox directory (an ephemeral outbox is refused at startup), or
 * `best-effort` only with AAP-1 accepted explicitly.
 *
 * `runAuditedTool` wraps one tool handler: the intent event
 * (`tool.call.started`) must be receipted before the handler runs, so in
 * `required` mode a failed intent append answers `audit_delivery_failed` and
 * the handler never runs; a terminal append (`tool.call.completed`) that
 * fails after the handler ran returns the handler's result marked degraded
 * (`_meta["org.kya-os/audit"] = { status: "degraded", reason }`, `isError`),
 * the reference middleware's marker, instead of pretending the lifecycle is
 * complete. `auditToolHandlers` applies it to every tool a server registers.
 */

import {
  DurableOutbox,
  HttpAuditRecorderClient,
  MemoryAuditOutbox,
  createAuditDelivery,
  type AuditDeliveryMode,
  type AuditDeliverySink,
  type AuditOutboxProvider,
  type AuditProducerEvent,
} from '@helixid/sdk-js';
import type { ToolCallAudit } from './audit.js';

/** The `_meta` member the reference middleware reports audit status under. */
export const AUDIT_META_KEY = 'org.kya-os/audit';

/** The parts of an MCP `CallToolResult` this module reads and writes. */
export interface AuditedToolResult {
  content?: unknown[];
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [member: string]: unknown;
}

/** A copy of `result` marked as an error whose audit delivery failed. */
export function markAuditDegraded<T extends AuditedToolResult>(result: T, reason: string): T {
  const meta = { ...(result._meta ?? {}) };
  const previous = meta[AUDIT_META_KEY];
  meta[AUDIT_META_KEY] = { ...(typeof previous === 'object' && previous !== null ? (previous as Record<string, unknown>) : {}), status: 'degraded', reason };
  return { ...result, _meta: meta, isError: true };
}

/** The answer when the intent could not be recorded: the handler did not run. */
export function auditUnavailableResponse(reason: string): AuditedToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify({ success: false, error: { code: 'audit_delivery_failed', message: reason } }) }],
    isError: true,
    _meta: { [AUDIT_META_KEY]: { status: 'degraded', reason } },
  };
}

export interface RunAuditedToolOptions {
  /** Called when an append fails (the intent, or the terminal one). */
  onAuditError?: (error: unknown, phase: 'intent' | 'terminal') => void;
}

/**
 * Runs `handler` as one audited tool call: intent first (its receipt before
 * the handler runs), terminal after; see the module comment for failures.
 * A handler that throws is recorded as `tool.call.failed` (code
 * `handler_error`, never its message) and its error propagates.
 */
export async function runAuditedTool<T extends AuditedToolResult>(
  call: ToolCallAudit,
  handler: () => Promise<T> | T,
  options: RunAuditedToolOptions = {},
): Promise<T | AuditedToolResult> {
  try {
    await call.started();
  } catch (error) {
    options.onAuditError?.(error, 'intent');
    return auditUnavailableResponse('Required intent audit delivery failed; the tool did not run');
  }
  let result: T;
  try {
    result = await handler();
  } catch (error) {
    await call.failed('handler_error').catch((auditError: unknown) => options.onAuditError?.(auditError, 'terminal'));
    throw error;
  }
  try {
    await call.completed();
  } catch (error) {
    options.onAuditError?.(error, 'terminal');
    return markAuditDegraded(result, 'Required terminal audit delivery failed after the tool ran');
  }
  return result;
}

/** The registration method of an MCP server whose last argument is the tool callback. */
export interface ToolRegistrar {
  registerTool: (...args: never[]) => unknown;
}

/**
 * Makes every tool `server` registers from now on run under
 * `runAuditedTool` for this call. Use it on the per-request server of a
 * stateless transport, before the tools are registered.
 */
export function auditToolHandlers<S extends ToolRegistrar>(server: S, call: ToolCallAudit, options: RunAuditedToolOptions = {}): S {
  const register = server.registerTool.bind(server) as (...args: unknown[]) => unknown;
  (server as unknown as { registerTool: (...args: unknown[]) => unknown }).registerTool = (...args: unknown[]): unknown => {
    const callback = args.at(-1);
    if (typeof callback !== 'function') return register(...args);
    const audited = (...callArgs: unknown[]): Promise<AuditedToolResult> =>
      runAuditedTool(call, () => (callback as (...a: unknown[]) => Promise<AuditedToolResult>)(...callArgs), options);
    return register(...args.slice(0, -1), audited);
  };
  return server;
}

export interface HelixAuditDeliveryOptions {
  /** HelixID API base URL (pass your own; there is no default). */
  baseUrl: string;
  /** Admin or account API key, sent as the bearer token. */
  apiKey: string;
  /** `required` (default), `buffered` or `best-effort`. */
  delivery?: AuditDeliveryMode;
  /** `buffered`: the durable outbox directory. */
  outboxDir?: string;
  /** `buffered`: an outbox of your own; `'memory'` asks for the ephemeral one, which buffered delivery refuses. */
  outbox?: AuditOutboxProvider | 'memory';
  /** `best-effort` only: the operator accepts AAP-1 (capture only). */
  acceptAap1?: boolean;
  /** `buffered`: how often pending items are delivered; default 1000 ms. */
  flushIntervalMs?: number;
  ledgerId?: string;
  timeoutMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
  onDeliveryFailure?: (error: unknown, event: AuditProducerEvent) => void;
}

/**
 * The delivery sink for a Helix-recorded MCP server. Misconfiguration
 * (buffered without a durable outbox, best-effort without accepting AAP-1)
 * throws here, at startup. A buffered sink starts flushing on its interval.
 */
export function createHelixAuditDelivery(options: HelixAuditDeliveryOptions): AuditDeliverySink {
  const outbox =
    options.outbox === 'memory'
      ? new MemoryAuditOutbox()
      : (options.outbox ?? (options.outboxDir !== undefined ? new DurableOutbox({ directory: options.outboxDir }) : undefined));
  const sink = createAuditDelivery({
    recorder: new HttpAuditRecorderClient({
      baseUrl: options.baseUrl,
      apiKey: options.apiKey,
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
      ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    }),
    delivery: options.delivery ?? 'required',
    ...(outbox !== undefined ? { outbox } : {}),
    ...(options.acceptAap1 !== undefined ? { acceptAap1: options.acceptAap1 } : {}),
    ...(options.ledgerId !== undefined ? { ledgerId: options.ledgerId } : {}),
    ...(options.onDeliveryFailure !== undefined ? { onDeliveryFailure: options.onDeliveryFailure } : {}),
  });
  sink.start(options.flushIntervalMs ?? 1_000);
  return sink;
}
