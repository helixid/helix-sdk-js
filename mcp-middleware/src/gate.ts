// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { MCPToolCall } from './types.js';

/**
 * The JSON-RPC methods the guard lets through without a caller, unless the
 * operator sets `openMethods`. Left open on purpose, so any client can see
 * what this server offers before it presents a credential:
 * - `initialize`: the MCP handshake (capabilities, server info);
 * - `notifications/initialized`: the notification a client sends right after
 *   it; it carries nothing and gets no answer;
 * - `tools/list`: the tool catalog.
 * Every other method (`tools/call`, `resources/*`, `prompts/*`, `ping`, ...)
 * needs a verified caller.
 */
export const DEFAULT_OPEN_METHODS: readonly string[] = Object.freeze(['initialize', 'notifications/initialized', 'tools/list']);

/** Methods whose target is a resource URI, checked against `resourceScopes`. */
export const RESOURCE_METHODS: ReadonlySet<string> = new Set(['resources/read', 'resources/subscribe', 'resources/unsubscribe']);
/** Methods whose target is a prompt name, checked against `promptScopes`. */
export const PROMPT_METHODS: ReadonlySet<string> = new Set(['prompts/get']);

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The JSON-RPC method of a call: `method`, else the received request's, else `tools/call` (the guard's original shape). */
export function methodOf(call: MCPToolCall): string {
  if (typeof call.method === 'string' && call.method.length > 0) return call.method;
  const received = call.request?.method;
  return typeof received === 'string' && received.length > 0 ? received : 'tools/call';
}

/** What a call acts on: the tool, resource URI or prompt name (`name`, else the request's `params.name` / `params.uri`). */
export function targetOf(method: string, call: MCPToolCall): string | undefined {
  if (typeof call.name === 'string') return call.name;
  const params = isRecord(call.request?.params) ? call.request.params : undefined;
  const value = RESOURCE_METHODS.has(method) ? params?.['uri'] : params?.['name'];
  return typeof value === 'string' ? value : undefined;
}

/** A header's first value, case-insensitively. */
export function headerOf(headers: MCPToolCall['headers'], name: string): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
    if (key.toLowerCase() !== name) continue;
    const first = Array.isArray(value) ? value[0] : value;
    if (typeof first === 'string' && first.length > 0) return first;
  }
  return undefined;
}

/** The unverified `iss` of a bearer JWT (an opaque token names none). Only ever recorded as unverified. */
export function claimedIssuerOf(headers: MCPToolCall['headers']): string | undefined {
  const match = /^bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*$/i.exec(headerOf(headers, 'authorization') ?? '');
  if (!match) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(match[2]!, 'base64url').toString('utf8')) as unknown;
    return isRecord(claims) && typeof claims['iss'] === 'string' ? claims['iss'] : undefined;
  } catch {
    return undefined;
  }
}

/** The DID a request proof says it is from, unverified (`did` of the proof in `_meta`). */
export function claimedDidOf(meta: Record<string, unknown> | undefined, readProof: (meta: Record<string, unknown> | undefined) => unknown): string | undefined {
  const proof = readProof(meta);
  return isRecord(proof) && typeof proof['did'] === 'string' && proof['did'].startsWith('did:') ? proof['did'] : undefined;
}

/** Error codes that refuse the caller (answered 400/401/403), as opposed to a fault of this server. */
const CALLER_REFUSALS: ReadonlySet<string> = new Set(['PROOF_MISSING', 'PROOF_INVALID', 'OAUTH_TOKEN_INVALID', 'CREDENTIAL_CONFLICT']);

/** The reason code of a refusal of a caller the guard could not identify; undefined for anything else (a server fault). */
export function refusalCodeOf(error: unknown): string | undefined {
  const e = error as { code?: unknown; reasons?: unknown } | null;
  if (e === null || typeof e !== 'object' || typeof e.code !== 'string' || !CALLER_REFUSALS.has(e.code)) return undefined;
  // A refused proof names the verifier's first reason (nonce_replayed, status_revoked, ...); anything else its code.
  if (Array.isArray(e.reasons) && typeof e.reasons[0] === 'string') return e.reasons[0];
  return e.code.toLowerCase();
}
