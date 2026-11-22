// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The hashes a KYA-OS response proof binds (SPEC §7.3, story L2-A).
 *
 * - The covered request is `{method, params}` with `params._meta` removed
 *   and, on `tools/call`, every `_kyaos*` control argument removed; `params`
 *   is left out where the request has none.
 * - The covered response is the result body as the client receives it
 *   (body profile, `prf` absent) or that body minus its top-level `_meta`
 *   (envelope profile, `prf` = {@link RESPONSE_PROOF_ENVELOPE_PROFILE}), so
 *   the proof can travel inside `_meta` without hashing itself.
 *
 * Both sides hash the JSON that goes on the wire: values are JSON
 * round-tripped first, so an `undefined` member or a `toJSON` on the server
 * side never makes the server and the client hash different texts.
 */

import { hashJson } from './jcs.js';

/** Prefix of the tool-call control arguments a server strips before its handler and never hashes. */
export const CONTROL_ARGUMENT_PREFIX = '_kyaos';

/** Profile discriminator (`prf` claim) of a proof whose responseHash covers the result minus its top-level `_meta`. */
export const RESPONSE_PROOF_ENVELOPE_PROFILE = 'org.kya-os/response-proof.envelope';

export interface CoveredRequestInput {
  method: string;
  params?: Record<string, unknown> | undefined;
}

export function isControlArgument(name: string): boolean {
  return name.startsWith(CONTROL_ARGUMENT_PREFIX);
}

/** `args` without its `_kyaos*` members. */
export function stripControlArguments(args: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(args).filter(([name]) => !isControlArgument(name)));
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The JSON value `value` serialises to: what the other side receives. */
export function wireJson<T>(value: T): T {
  const text = JSON.stringify(value);
  return text === undefined ? value : (JSON.parse(text) as T);
}

/** The covered request of SPEC §7.3: method and params minus `_meta`, arguments minus `_kyaos*`. */
export function coveredRequest(request: CoveredRequestInput): Record<string, unknown> {
  const covered: Record<string, unknown> = { method: request.method };
  if (request.params !== undefined) {
    const params: Record<string, unknown> = { ...request.params };
    delete params['_meta'];
    if (request.method === 'tools/call') {
      const args = params['arguments'];
      params['arguments'] = stripControlArguments(isRecord(args) ? args : {});
    }
    covered['params'] = params;
  }
  return covered;
}

/** `sha256:<hex>` of the covered request. */
export function hashRequest(request: CoveredRequestInput): string {
  return hashJson(coveredRequest(wireJson(request)));
}

/** The response value a proof's responseHash covers under `profile`. */
export function coveredResponse(result: unknown, profile?: string | undefined): unknown {
  const wire = wireJson(result);
  if (profile === RESPONSE_PROOF_ENVELOPE_PROFILE && isRecord(wire)) {
    const rest = { ...wire };
    delete rest['_meta'];
    return rest;
  }
  return wire;
}

/** `sha256:<hex>` of the covered response. */
export function hashResponse(result: unknown, profile?: string | undefined): string {
  return hashJson(coveredResponse(result, profile));
}
