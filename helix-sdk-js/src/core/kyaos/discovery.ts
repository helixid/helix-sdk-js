// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The client side of KYA-OS discovery (story L1-D; Core L1.10): a server
 * SHOULD serve `/.well-known/mcp` at its origin, and an agent reads its
 * DID, its skew window and its capabilities from there on first contact.
 *
 * `fetchWellKnownMcp(origin)` gets and checks the document;
 * `readWellKnownMcp(value)` checks one already in hand. The checks mirror
 * the `well-known-mcpi.json` schema (required members, patterns, the skew
 * range), and `clockSkewSeconds` comes back with the schema's default when
 * the server left it out, so a client can hand it straight to
 * `verifyResponseProof` and to its own handshake timing.
 */

import { DEFAULT_CLOCK_SKEW_SECONDS, MAX_CLOCK_SKEW_SECONDS, MIN_CLOCK_SKEW_SECONDS } from './handshake.js';

export const WELL_KNOWN_MCP_PATH = '/.well-known/mcp';

export interface WellKnownMcp {
  version: string;
  serverDid: string;
  endpoints: {
    /** The MCP endpoint, absolute once read (relative references are resolved against the document's origin). */
    tools?: string;
    /** `<tools>#_kyaos_handshake` when the server opens sessions; absent on a server without them. */
    handshake?: string;
    [name: string]: string | undefined;
  };
  /** Always present after reading: the server's value, or 120 when it advertised none. */
  clockSkewSeconds: number;
  capabilities: { proofs?: boolean; delegation?: boolean; statusList?: boolean; crisp?: boolean; [name: string]: unknown };
  statusListCredential?: string;
  supportedDidMethods?: string[];
  proofAlgorithms?: string[];
  [name: string]: unknown;
}

export type WellKnownMcpProblem =
  | 'document_not_object'
  | 'version_invalid'
  | 'server_did_invalid'
  | 'endpoints_invalid'
  | 'clock_skew_invalid'
  | 'capabilities_invalid'
  | 'status_list_credential_invalid'
  | 'advisory_list_invalid'
  | 'fetch_failed'
  | 'not_json';

/** A discovery document that cannot be used; `reason` names what was wrong. */
export class WellKnownMcpError extends Error {
  readonly code = 'WELL_KNOWN_MCP_INVALID';
  constructor(
    readonly reason: WellKnownMcpProblem,
    message: string,
  ) {
    super(message);
    this.name = 'WellKnownMcpError';
  }
}

const VERSION = /^\d+\.\d+(\.\d+)?$/;
const SERVER_DID = /^did:(key|web):.+$/;

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

const refuse = (reason: WellKnownMcpProblem, message: string): never => {
  throw new WellKnownMcpError(reason, message);
};

/** Where the document lives for a server at `origin` (a URL whose origin is used; any path is dropped). */
export function wellKnownMcpUrl(origin: string): string {
  return `${new URL(origin).origin}${WELL_KNOWN_MCP_PATH}`;
}

function resolveReference(name: string, value: unknown, origin: string | undefined): string {
  if (typeof value !== 'string') return refuse('endpoints_invalid', `endpoints.${name} must be a string`);
  if (origin === undefined) return value;
  try {
    return new URL(value, origin).href;
  } catch {
    return refuse('endpoints_invalid', `endpoints.${name} is not a URI reference: ${value}`);
  }
}

function stringList(name: string, value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return refuse('advisory_list_invalid', `${name} must be a list of strings`);
  return value as string[];
}

export interface ReadWellKnownMcpOptions {
  /** The origin the document was read from; relative endpoint references are resolved against it. */
  origin?: string;
}

/**
 * Checks a discovery document the way `well-known-mcpi.json` describes it
 * and returns it with `clockSkewSeconds` filled in and endpoints resolved.
 * Members the schema does not name are kept as they are.
 */
export function readWellKnownMcp(value: unknown, options: ReadWellKnownMcpOptions = {}): WellKnownMcp {
  if (!isRecord(value)) return refuse('document_not_object', 'the discovery document must be a JSON object');
  const origin = options.origin !== undefined ? new URL(options.origin).origin : undefined;

  const version = value['version'];
  if (typeof version !== 'string' || !VERSION.test(version)) return refuse('version_invalid', 'version must look like 1.0 or 1.0.0');
  const serverDid = value['serverDid'];
  if (typeof serverDid !== 'string' || !SERVER_DID.test(serverDid)) return refuse('server_did_invalid', 'serverDid must be a did:web or did:key');

  const rawEndpoints = value['endpoints'];
  if (!isRecord(rawEndpoints)) return refuse('endpoints_invalid', 'endpoints must be an object');
  const endpoints: WellKnownMcp['endpoints'] = {};
  for (const [name, reference] of Object.entries(rawEndpoints)) endpoints[name] = resolveReference(name, reference, origin);

  const skew = value['clockSkewSeconds'];
  if (skew !== undefined && (typeof skew !== 'number' || !Number.isFinite(skew) || skew < MIN_CLOCK_SKEW_SECONDS || skew > MAX_CLOCK_SKEW_SECONDS)) {
    return refuse('clock_skew_invalid', `clockSkewSeconds must be a number from ${MIN_CLOCK_SKEW_SECONDS} to ${MAX_CLOCK_SKEW_SECONDS}`);
  }

  const capabilities = value['capabilities'] ?? {};
  if (!isRecord(capabilities)) return refuse('capabilities_invalid', 'capabilities must be an object');
  for (const flag of ['proofs', 'delegation', 'statusList', 'crisp']) {
    if (capabilities[flag] !== undefined && typeof capabilities[flag] !== 'boolean') return refuse('capabilities_invalid', `capabilities.${flag} must be a boolean`);
  }

  const statusListCredential = value['statusListCredential'];
  if (statusListCredential !== undefined) {
    if (typeof statusListCredential !== 'string') return refuse('status_list_credential_invalid', 'statusListCredential must be a URL');
    try {
      new URL(statusListCredential);
    } catch {
      return refuse('status_list_credential_invalid', `statusListCredential is not an absolute URL: ${statusListCredential}`);
    }
  }
  const supportedDidMethods = stringList('supportedDidMethods', value['supportedDidMethods']);
  const proofAlgorithms = stringList('proofAlgorithms', value['proofAlgorithms']);

  return {
    ...value,
    version,
    serverDid,
    endpoints,
    clockSkewSeconds: typeof skew === 'number' ? skew : DEFAULT_CLOCK_SKEW_SECONDS,
    capabilities: capabilities as WellKnownMcp['capabilities'],
    ...(statusListCredential !== undefined ? { statusListCredential: statusListCredential as string } : {}),
    ...(supportedDidMethods !== undefined ? { supportedDidMethods } : {}),
    ...(proofAlgorithms !== undefined ? { proofAlgorithms } : {}),
  };
}

export interface FetchWellKnownMcpOptions {
  /** Default `globalThis.fetch`. */
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

/** GETs `<origin>/.well-known/mcp` and reads it. A non-200 answer or a non-JSON body is a `WellKnownMcpError`. */
export async function fetchWellKnownMcp(origin: string, options: FetchWellKnownMcpOptions = {}): Promise<WellKnownMcp> {
  const url = wellKnownMcpUrl(origin);
  const doFetch = options.fetch ?? globalThis.fetch;
  let response: Response;
  try {
    response = await doFetch(url, { method: 'GET', headers: { accept: 'application/json' }, ...(options.signal ? { signal: options.signal } : {}) });
  } catch (error) {
    return refuse('fetch_failed', `GET ${url} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (response.status !== 200) return refuse('fetch_failed', `GET ${url} answered ${response.status}`);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return refuse('not_json', `GET ${url} did not answer with JSON`);
  }
  return readWellKnownMcp(body, { origin: url });
}
