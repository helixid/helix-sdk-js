// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import ajvFormats, { type FormatsPlugin } from 'ajv-formats';
import type { KyaOsDescription } from './kyaos/describe.js';

/**
 * The KYA-OS discovery document at `/.well-known/mcp` (story L1-D; Core
 * L1.10, RECOMMENDED). The service hosts it, not the agent: one document
 * per MCP server, built once from config, validated against the vendored
 * `well-known-mcpi.json` schema at startup and served as is.
 *
 * Every URL in the document is external: it is built from `publicOrigin`,
 * the origin agents connect to, never from the address the process binds
 * (behind a proxy the two differ). If MCP lives on `mcp.example.com` the
 * document belongs on that host. `docs/well-known.md` has the routing
 * snippets for nginx, an ALB and API Gateway.
 */

export const WELL_KNOWN_MCP_PATH = '/.well-known/mcp';

/** The protocol version the document advertises by default (the reference implementation's handshake says "1.0"). */
export const DEFAULT_WELL_KNOWN_VERSION = '1.0';
/** What the Helix verifier resolves: did:web and did:key (L1-A, C-A). */
export const DEFAULT_SUPPORTED_DID_METHODS: readonly string[] = ['did:web', 'did:key'];
/** What the Helix verifier checks: EdDSA over Ed25519 (L1-C). */
export const DEFAULT_PROOF_ALGORITHMS: readonly string[] = ['EdDSA'];

export interface WellKnownCapabilities {
  /** The server signs a detached proof on every tool call outcome (story L2-A). Taken from `kyaos.capabilities.proofs`. */
  proofs: boolean;
  /** The server verifies W3C delegation credentials carried with a call. */
  delegation: boolean;
  /** The server checks status lists for revocation. */
  statusList: boolean;
  /** The server evaluates CRISP constraints. */
  crisp: boolean;
}

export interface WellKnownMcpDocument {
  version: string;
  serverDid: string;
  endpoints: {
    /** The MCP endpoint, an absolute URL at `publicOrigin`. */
    tools: string;
    /** `<tools>#_kyaos_handshake`: the handshake is a tool on the MCP endpoint. Present only while sessions are enabled. */
    handshake?: string;
  };
  clockSkewSeconds: number;
  capabilities: WellKnownCapabilities;
  /** URL of this server's status list credential, when it publishes one. */
  statusListCredential?: string;
  /** Advisory: the DID methods the verifier resolves. */
  supportedDidMethods: string[];
  /** Advisory: the JWS algorithms the verifier accepts. */
  proofAlgorithms: string[];
}

export interface WellKnownMcpConfig {
  /** Default true. When false the route answers 404 and nothing is built or validated. */
  enabled?: boolean | undefined;
  /** The origin agents connect to (`https://mcp.example.com`). Required while enabled; never the bind address. */
  publicOrigin?: string | undefined;
  /** This server's DID (`did:web:…` or `did:key:…`). Required while enabled. */
  serverDid?: string | undefined;
  /** Default `DEFAULT_WELL_KNOWN_VERSION`. */
  version?: string | undefined;
  /** The MCP endpoint: a path at `publicOrigin` (default `/mcp`) or an absolute URL whose origin is `publicOrigin`. */
  toolsEndpoint?: string | undefined;
  /** The KYA-OS layer's description (`describeKyaOs()` or `runtime.describe()`): proofs, the handshake and the skew. Without it there are no proofs and no handshake. */
  kyaos?: KyaOsDescription | undefined;
  /** Default 120; 30 to 600. With `kyaos` it must equal the runtime's skew (the handshake enforces that one). */
  clockSkewSeconds?: number | undefined;
  /** URL of this server's status list credential. */
  statusListCredential?: string | undefined;
  /** Each true only while that feature is enabled; default false. `proofs` comes from `kyaos`. */
  capabilities?: Partial<Omit<WellKnownCapabilities, 'proofs'>> | undefined;
  /** Default `DEFAULT_SUPPORTED_DID_METHODS`. */
  supportedDidMethods?: readonly string[] | undefined;
  /** Default `DEFAULT_PROOF_ALGORITHMS`. */
  proofAlgorithms?: readonly string[] | undefined;
}

export interface WellKnownMcpResponse {
  status: 200 | 404;
  headers: Record<string, string>;
  body: string;
}

export interface WellKnownMcp {
  readonly enabled: boolean;
  /** `/.well-known/mcp`. */
  readonly path: string;
  /** The validated document, or undefined while disabled. */
  readonly document: WellKnownMcpDocument | undefined;
  /** The HTTP answer for a GET of `path`, for hosts that are not on node:http. */
  respond(): WellKnownMcpResponse;
  /** Answers `req` when it is a GET or HEAD of `path` and returns true; returns false, untouched, for every other request. */
  handle(req: IncomingMessage, res: ServerResponse): boolean;
}

/** Thrown by `createWellKnownMcp` / `buildWellKnownMcp` for a configuration whose document would not validate. */
export class WellKnownMcpError extends Error {
  readonly code = 'WELL_KNOWN_MCP_INVALID';
  constructor(
    message: string,
    /** The schema's own complaints, when validation ran. */
    readonly problems: readonly string[] = [],
  ) {
    super(problems.length > 0 ? `${message}: ${problems.join('; ')}` : message);
    this.name = 'WellKnownMcpError';
  }
}

export type WellKnownMcpValidation = { ok: true } | { ok: false; problems: string[] };

const SCHEMA_URL = new URL('../schemas/well-known-mcpi.json', import.meta.url);
const CLOCK_SKEW = { default: 120, min: 30, max: 600 };
const DID = /^did:(key|web):.+$/;

// ajv and ajv-formats are CommonJS: depending on the loader the default import is the export itself or the module object.
type Ajv2020Class = typeof import('ajv/dist/2020.js').default;
const Ajv2020: Ajv2020Class = (ajv2020 as unknown as { default?: Ajv2020Class }).default ?? (ajv2020 as unknown as Ajv2020Class);
const addFormats: FormatsPlugin = (ajvFormats as unknown as { default?: FormatsPlugin }).default ?? (ajvFormats as unknown as FormatsPlugin);

let validator: ValidateFunction | undefined;

function schemaValidator(): ValidateFunction {
  if (validator) return validator;
  const schema = JSON.parse(readFileSync(SCHEMA_URL, 'utf8')) as object;
  const ajv = new Ajv2020({ allErrors: true });
  addFormats(ajv);
  const compiled = ajv.compile(schema);
  validator = compiled;
  return compiled;
}

const describeProblem = (error: ErrorObject): string => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`;

/** Validates any value against the vendored `well-known-mcpi.json` schema (story L1-D point 1). */
export function validateWellKnownMcp(document: unknown): WellKnownMcpValidation {
  const validate = schemaValidator();
  if (validate(document)) return { ok: true };
  return { ok: false, problems: (validate.errors ?? []).map(describeProblem) };
}

/** `validateWellKnownMcp`, throwing `WellKnownMcpError` instead. */
export function assertWellKnownMcp(document: unknown): asserts document is WellKnownMcpDocument {
  const result = validateWellKnownMcp(document);
  if (!result.ok) throw new WellKnownMcpError('the /.well-known/mcp document does not validate against well-known-mcpi.json', result.problems);
}

function originOf(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) throw new WellKnownMcpError(`${name} is required for the /.well-known/mcp document (the origin agents connect to, e.g. https://mcp.example.com)`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new WellKnownMcpError(`${name} must be an absolute URL, got ${JSON.stringify(value)}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new WellKnownMcpError(`${name} must be http(s), got ${JSON.stringify(value)}`);
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new WellKnownMcpError(`${name} must be an origin with no path, query or fragment, got ${JSON.stringify(value)}; put the MCP path in toolsEndpoint`);
  }
  return url.origin;
}

function toolsUrl(publicOrigin: string, endpoint: string | undefined): string {
  const reference = endpoint ?? '/mcp';
  let url: URL;
  try {
    url = new URL(reference, publicOrigin);
  } catch {
    throw new WellKnownMcpError(`toolsEndpoint must be a path or an absolute URL, got ${JSON.stringify(reference)}`);
  }
  if (url.origin !== publicOrigin) {
    throw new WellKnownMcpError(`toolsEndpoint ${JSON.stringify(reference)} is not at publicOrigin ${publicOrigin}: the document carries the URLs agents connect to`);
  }
  return url.href;
}

function skewOf(config: WellKnownMcpConfig): number {
  const configured = config.clockSkewSeconds;
  const runtime = config.kyaos?.clockSkewSeconds;
  if (configured !== undefined && (!Number.isInteger(configured) || configured < CLOCK_SKEW.min || configured > CLOCK_SKEW.max)) {
    throw new WellKnownMcpError(`clockSkewSeconds must be an integer from ${CLOCK_SKEW.min} to ${CLOCK_SKEW.max}, got ${String(configured)}`);
  }
  if (configured !== undefined && runtime !== undefined && configured !== runtime) {
    throw new WellKnownMcpError(`clockSkewSeconds ${configured} differs from the KYA-OS runtime's ${runtime}: the handshake enforces the runtime's, so advertise that one`);
  }
  return configured ?? runtime ?? CLOCK_SKEW.default;
}

/**
 * Builds the document from config and validates it against the schema; a
 * configuration that cannot produce a valid document throws
 * `WellKnownMcpError` with the reason, so a misconfigured server fails at
 * startup instead of advertising something no client can use.
 */
export function buildWellKnownMcp(config: WellKnownMcpConfig): WellKnownMcpDocument {
  const publicOrigin = originOf(config.publicOrigin, 'publicOrigin');
  const serverDid = config.serverDid;
  if (serverDid === undefined || serverDid.length === 0) throw new WellKnownMcpError('serverDid is required for the /.well-known/mcp document');
  if (!DID.test(serverDid)) throw new WellKnownMcpError(`serverDid must be a did:web or did:key, got ${JSON.stringify(serverDid)}`);
  const tools = toolsUrl(publicOrigin, config.toolsEndpoint);
  const kyaos = config.kyaos;
  // The handshake is a tool on the MCP endpoint: its reference is rebuilt on
  // the public tools URL so a runtime described with an internal endpoint
  // never leaks that address.
  const handshake = kyaos?.endpoints.handshake !== undefined ? `${tools}#${kyaos.handshakeTool}` : undefined;
  const document: WellKnownMcpDocument = {
    version: config.version ?? DEFAULT_WELL_KNOWN_VERSION,
    serverDid,
    endpoints: { tools, ...(handshake !== undefined ? { handshake } : {}) },
    clockSkewSeconds: skewOf(config),
    capabilities: {
      proofs: kyaos?.capabilities.proofs === true,
      delegation: config.capabilities?.delegation === true,
      statusList: config.capabilities?.statusList === true,
      crisp: config.capabilities?.crisp === true,
    },
    ...(config.statusListCredential !== undefined ? { statusListCredential: config.statusListCredential } : {}),
    supportedDidMethods: [...(config.supportedDidMethods ?? DEFAULT_SUPPORTED_DID_METHODS)],
    proofAlgorithms: [...(config.proofAlgorithms ?? DEFAULT_PROOF_ALGORITHMS)],
  };
  assertWellKnownMcp(document);
  return document;
}

const NOT_FOUND = JSON.stringify({ error: 'not_found' });

/**
 * The `/.well-known/mcp` route: on by default (L1.10 is RECOMMENDED), 404
 * when `enabled: false`. Built and validated once, here, at startup.
 */
export function createWellKnownMcp(config: WellKnownMcpConfig = {}): WellKnownMcp {
  const enabled = config.enabled ?? true;
  const document = enabled ? buildWellKnownMcp(config) : undefined;
  const body = document ? JSON.stringify(document) : NOT_FOUND;
  const respond = (): WellKnownMcpResponse => ({
    status: document ? 200 : 404,
    headers: { 'content-type': 'application/json', 'cache-control': document ? 'public, max-age=300' : 'no-store' },
    body,
  });
  const handle = (req: IncomingMessage, res: ServerResponse): boolean => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return false;
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path !== WELL_KNOWN_MCP_PATH) return false;
    const answer = respond();
    res.writeHead(answer.status, { ...answer.headers, 'content-length': String(Buffer.byteLength(answer.body)) });
    res.end(req.method === 'HEAD' ? undefined : answer.body);
    return true;
  };
  return { enabled, path: WELL_KNOWN_MCP_PATH, document, respond, handle };
}
