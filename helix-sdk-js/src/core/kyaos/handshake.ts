// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The KYA-OS session handshake, client side and the format rules both sides
 * share (conformance L2.1, L2.2, L2.6, L2.7, L2.9, L2.14, L2.15; schemas
 * `handshake-request.json` and `handshake-response.json`).
 *
 * A client calls the server's `_kyaos_handshake` tool with
 * {@link createHandshakeRequest}: a fresh 16-byte nonce written as 22
 * base64url characters, the server's DID (or public origin) as audience and
 * the current Unix time. The server answers with a `kyaos_<uuid-v4>` session
 * id that later calls carry as the `_kyaos_session` control argument.
 */

import { randomBytes, randomUUID } from 'node:crypto';

/** Name of the tool the middleware registers for the handshake; the `_kyaos_` prefix keeps it off the service's own tools. */
export const HANDSHAKE_TOOL_NAME = '_kyaos_handshake';
/** The control argument a tool call carries its session id in (stripped before the handler, never hashed). */
export const SESSION_CONTROL_ARGUMENT = '_kyaos_session';
export const SESSION_ID_PREFIX = 'kyaos_';
export const PROTOCOL_VERSION = '1.0';

export const NONCE_BYTES = 16;
/** 16 bytes of base64url without padding. */
export const NONCE_MIN_LENGTH = 22;
export const DEFAULT_CLOCK_SKEW_SECONDS = 120;
export const MIN_CLOCK_SKEW_SECONDS = 30;
export const MAX_CLOCK_SKEW_SECONDS = 600;
/** Idle time after which a session is gone (schema `sessionTtl` is seconds; the config is minutes). */
export const DEFAULT_SESSION_TTL_MINUTES = 30;

export interface HandshakeClientInfo {
  name: string;
  title?: string;
  version?: string;
  platform?: string;
  vendor?: string;
  persistentId?: string;
  clientId?: string;
}

export interface HandshakeRequest {
  nonce: string;
  audience: string;
  /** Unix seconds. */
  timestamp: number;
  agentDid?: string;
  clientInfo?: HandshakeClientInfo;
  clientProtocolVersion?: string;
  clientCapabilities?: Record<string, unknown>;
}

export interface HandshakeResponse {
  sessionId: string;
  serverDid: string;
  protocolVersion: string;
  serverCapabilities?: { proofs?: boolean; delegation?: boolean; statusList?: boolean; [name: string]: unknown };
  /** Seconds. */
  sessionTtl?: number;
  /** Echo of the client's nonce. */
  nonce?: string;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const DID = /^did:[a-z0-9]+:.+$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROTOCOL = /^\d+\.\d+$/;
const REQUEST_MEMBERS = new Set(['nonce', 'audience', 'timestamp', 'agentDid', 'clientInfo', 'clientProtocolVersion', 'clientCapabilities']);
const CLIENT_INFO_MEMBERS = new Set(['name', 'title', 'version', 'platform', 'vendor', 'persistentId', 'clientId']);

/** A fresh nonce: `NONCE_BYTES` random bytes as base64url without padding (L2.2, L2.6). */
export function generateNonce(random: (size: number) => Uint8Array = randomBytes): string {
  return Buffer.from(random(NONCE_BYTES)).toString('base64url');
}

/** Strict base64url of at least 16 bytes: alphabet only, no padding, no white space, a decodable length. */
export function isValidNonce(value: unknown): value is string {
  return typeof value === 'string' && value.length >= NONCE_MIN_LENGTH && value.length % 4 !== 1 && BASE64URL.test(value);
}

export function isDid(value: unknown): value is string {
  return typeof value === 'string' && DID.test(value);
}

/** `kyaos_<uuid-v4>` (L2.7). */
export function generateSessionId(uuid: () => string = randomUUID): string {
  return `${SESSION_ID_PREFIX}${uuid()}`;
}

export function isSessionId(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(SESSION_ID_PREFIX) && UUID_V4.test(value.slice(SESSION_ID_PREFIX.length));
}

/** A skew the config may set: an integer number of seconds from 30 to 600, default 120 (L2.9). */
export function clockSkewSeconds(value: number | undefined): number {
  if (value === undefined) return DEFAULT_CLOCK_SKEW_SECONDS;
  if (!Number.isInteger(value) || value < MIN_CLOCK_SKEW_SECONDS || value > MAX_CLOCK_SKEW_SECONDS) {
    throw new RangeError(`clockSkewSeconds must be an integer from ${MIN_CLOCK_SKEW_SECONDS} to ${MAX_CLOCK_SKEW_SECONDS}`);
  }
  return value;
}

/** Whether `timestamp` (Unix seconds) is within `skewSeconds` of `nowSeconds`, either side (L2.3, L2.4). */
export function withinSkew(timestamp: number, nowSeconds: number, skewSeconds: number): boolean {
  return Math.abs(nowSeconds - timestamp) <= skewSeconds;
}

export interface CreateHandshakeRequestOptions {
  /** The server's DID, or its public origin. */
  audience: string;
  agentDid?: string;
  clientInfo?: HandshakeClientInfo;
  clientCapabilities?: Record<string, unknown>;
  /** Milliseconds since the epoch; default `Date.now()`. */
  now?: number;
  nonce?: string;
}

/** A handshake request with a fresh nonce and the current timestamp (L2.15). */
export function createHandshakeRequest(options: CreateHandshakeRequestOptions): HandshakeRequest {
  return {
    nonce: options.nonce ?? generateNonce(),
    audience: options.audience,
    timestamp: Math.floor((options.now ?? Date.now()) / 1000),
    ...(options.agentDid !== undefined ? { agentDid: options.agentDid } : {}),
    ...(options.clientInfo !== undefined ? { clientInfo: options.clientInfo } : {}),
    clientProtocolVersion: PROTOCOL_VERSION,
    ...(options.clientCapabilities !== undefined ? { clientCapabilities: options.clientCapabilities } : {}),
  };
}

export type HandshakeFormatProblem =
  | 'request_not_object'
  | 'unknown_member'
  | 'nonce_invalid'
  | 'audience_invalid'
  | 'timestamp_invalid'
  | 'agent_did_invalid'
  | 'client_info_invalid'
  | 'client_protocol_version_invalid'
  | 'client_capabilities_invalid';

export type HandshakeFormatResult =
  | { ok: true; request: HandshakeRequest }
  | { ok: false; problem: HandshakeFormatProblem; message: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function clientInfoProblem(value: unknown): string | undefined {
  if (!isRecord(value)) return 'clientInfo must be an object';
  if (typeof value['name'] !== 'string' || value['name'].length === 0) return 'clientInfo.name must be a non-empty string';
  for (const [name, member] of Object.entries(value)) {
    if (!CLIENT_INFO_MEMBERS.has(name)) return `clientInfo has an unknown member ${name}`;
    if (typeof member !== 'string') return `clientInfo.${name} must be a string`;
  }
  return undefined;
}

/**
 * Checks a handshake request's shape against `handshake-request.json`
 * (L2.14): the three required members, their types, the nonce's base64url
 * form and length, the DID form of `agentDid`, and no unknown members.
 * Time and audience are the server's to judge; see the middleware.
 */
export function validateHandshakeFormat(value: unknown): HandshakeFormatResult {
  if (!isRecord(value)) return { ok: false, problem: 'request_not_object', message: 'handshake request must be an object' };
  for (const name of Object.keys(value)) {
    if (!REQUEST_MEMBERS.has(name)) return { ok: false, problem: 'unknown_member', message: `handshake request has an unknown member ${name}` };
  }
  if (!isValidNonce(value['nonce'])) {
    return { ok: false, problem: 'nonce_invalid', message: `nonce must be base64url of at least ${NONCE_MIN_LENGTH} characters` };
  }
  if (typeof value['audience'] !== 'string' || value['audience'].length === 0) {
    return { ok: false, problem: 'audience_invalid', message: 'audience must be a non-empty string' };
  }
  const timestamp = value['timestamp'];
  if (typeof timestamp !== 'number' || !Number.isInteger(timestamp) || timestamp < 0) {
    return { ok: false, problem: 'timestamp_invalid', message: 'timestamp must be a non-negative integer (Unix seconds)' };
  }
  if (value['agentDid'] !== undefined && !isDid(value['agentDid'])) {
    return { ok: false, problem: 'agent_did_invalid', message: 'agentDid must be a DID' };
  }
  if (value['clientInfo'] !== undefined) {
    const problem = clientInfoProblem(value['clientInfo']);
    if (problem !== undefined) return { ok: false, problem: 'client_info_invalid', message: problem };
  }
  const version = value['clientProtocolVersion'];
  if (version !== undefined && (typeof version !== 'string' || !PROTOCOL.test(version))) {
    return { ok: false, problem: 'client_protocol_version_invalid', message: 'clientProtocolVersion must look like 1.0' };
  }
  if (value['clientCapabilities'] !== undefined && !isRecord(value['clientCapabilities'])) {
    return { ok: false, problem: 'client_capabilities_invalid', message: 'clientCapabilities must be an object' };
  }
  return { ok: true, request: value as unknown as HandshakeRequest };
}
