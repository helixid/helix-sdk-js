// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * SPEC.md §7.8 delegation binding, read as the SDK reads it (KYA-OS story
 * F-2): a credential's signed form, the credential and chain digests, the id
 * a credential shows and the reference it goes by. Ported from helix-core's
 * story A-1 `src/core/audit/references.ts` (stories rule 24: the SDK carries
 * its own copy), so a proof's `delegationChainDigest` and `delegationRef`
 * are recomputed the way the audit trail records them.
 */

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { CanonicalJsonError, canonicalize } from '../jcs.js';

/** SPEC §7.8: a credential whose arrays and objects nest deeper has no signed form. */
export const MAX_CREDENTIAL_NESTING = 64;
export const MAX_REFERENCE_LENGTH = 256;
export const CREDENTIAL_DIGEST_DOMAIN = 'org.kya-os.delegation.credential.v1';
export const CHAIN_DIGEST_DOMAIN = 'org.kya-os.delegation.chain.v1';
const DIGEST_FORM = /^sha256:[0-9a-f]{64}$/;

/** The code points that do not print (SPEC §7.8; `unseen-code-points.json`), frozen, first and last of each run. */
export const UNSEEN_CODE_POINT_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x034f, 0x034f], [0x0600, 0x0605], [0x061c, 0x061c],
  [0x06dd, 0x06dd], [0x070f, 0x070f], [0x0890, 0x0891], [0x08e2, 0x08e2], [0x115f, 0x1160], [0x17b4, 0x17b5],
  [0x180b, 0x180f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0x3164, 0x3164], [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff], [0xffa0, 0xffa0], [0xfff0, 0xfffb], [0x110bd, 0x110bd], [0x110cd, 0x110cd], [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0000, 0xe0fff],
];

function isUnseen(code: number): boolean {
  return UNSEEN_CODE_POINT_RANGES.some(([first, last]) => code >= first && code <= last);
}

/** True when `text` holds a character that does not print, or a surrogate without its pair. */
export function hasUnprintableCharacter(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      if (isUnseen(0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00))) return true;
      i += 1;
      continue;
    }
    if ((unit >= 0xdc00 && unit <= 0xdfff) || isUnseen(unit)) return true;
  }
  return false;
}

/** UTF-8 bytes of `text`, a surrogate without its pair written as the three bytes of its code point (WTF-8). */
export function wtf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  return Uint8Array.from(out);
}

export function sha256Digest(bytes: Uint8Array): string {
  return `sha256:${bytesToHex(sha256(bytes))}`;
}

/** `sha256:` of `UTF8(domain) || 0x00 || UTF8(JCS(value))`; throws `CanonicalJsonError` for a value with no JCS form. */
export function domainDigest(domain: string, value: unknown): string {
  const prefix = new TextEncoder().encode(`${domain}\u0000`);
  const body = new TextEncoder().encode(canonicalize(value));
  const data = new Uint8Array(prefix.length + body.length);
  data.set(prefix, 0);
  data.set(body, prefix.length);
  return sha256Digest(data);
}

/** The nesting depth of a JSON text's arrays and objects, counted before it is parsed. */
export function jsonTextNestingDepth(text: string, limit = MAX_CREDENTIAL_NESTING): number {
  let depth = 0;
  let deepest = 0;
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (escaped) escaped = false;
    else if (inString) {
      if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === '{' || ch === '[') {
      depth += 1;
      if (depth > deepest) deepest = depth;
      if (deepest > limit) return limit + 1;
    } else if (ch === '}' || ch === ']') depth -= 1;
  }
  return deepest;
}

/** The nesting depth of a parsed value, iteratively: the value itself is level 1. */
export function valueNestingDepth(value: unknown, limit = MAX_CREDENTIAL_NESTING): number {
  if (typeof value !== 'object' || value === null) return 0;
  let deepest = 0;
  const stack: Array<{ value: object; depth: number }> = [{ value, depth: 1 }];
  while (stack.length > 0) {
    const { value: current, depth } = stack.pop()!;
    if (depth > deepest) deepest = depth;
    if (deepest > limit) return limit + 1;
    for (const child of Array.isArray(current) ? current : Object.values(current)) {
      if (typeof child === 'object' && child !== null) stack.push({ value: child, depth: depth + 1 });
    }
  }
  return deepest;
}

const BASE64_VALUE: Record<string, number> = {};
'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split('').forEach((ch, index) => {
  BASE64_VALUE[ch] = index;
});
BASE64_VALUE['-'] = 62;
BASE64_VALUE['_'] = 63;
BASE64_VALUE['+'] = 62;
BASE64_VALUE['/'] = 63;
const WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f']);

/**
 * Base64 read as SPEC §7.8 step 1 reads it, six bits a character, ASCII
 * whitespace passed over, bits short of a byte dropped. `urlOnly`: a VC-JWT
 * segment (base64url only, `=` completing the last group alone); otherwise a
 * `proofValue` (either alphabet, `=` in any number after the last
 * character). Undefined when the string is not one.
 */
export function readSignatureBase64(text: string, urlOnly: boolean): Uint8Array | undefined {
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  let count = 0;
  let padding = 0;
  for (const ch of text) {
    if (WHITESPACE.has(ch)) continue;
    if (ch === '=') {
      padding += 1;
      continue;
    }
    if (padding > 0) return undefined;
    if (urlOnly && (ch === '+' || ch === '/')) return undefined;
    const value = BASE64_VALUE[ch];
    if (value === undefined) return undefined;
    count += 1;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  if (urlOnly) {
    const lastGroup = count % 4;
    if (lastGroup === 1 || (padding > 0 && (lastGroup === 0 || padding !== 4 - lastGroup))) return undefined;
  }
  return Uint8Array.from(bytes);
}

const base64UrlNoPad = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);
const nonEmpty = (value: unknown): string | undefined => (typeof value === 'string' && value.length > 0 ? value : undefined);

/** SPEC §7.8 step 1: the signed form of a credential, or undefined when it has none. */
export function credentialSignedForm(credential: unknown): JsonObject | undefined {
  if (typeof credential === 'string') {
    const segments = credential.split('.');
    if (segments.length !== 3 || segments[0] === '' || segments[1] === '') return undefined;
    const bytes = readSignatureBase64(segments[2]!, true);
    if (bytes === undefined || bytes.length === 0) return undefined;
    return { jwt: `${segments[0]}.${segments[1]}`, signature: base64UrlNoPad(bytes) };
  }
  if (!isObject(credential)) return undefined;
  const proof = credential['proof'];
  if (!isObject(proof)) return undefined;
  if (valueNestingDepth(credential) > MAX_CREDENTIAL_NESTING) return undefined;
  const proofValue = proof['proofValue'];
  const bytes = typeof proofValue === 'string' ? readSignatureBase64(proofValue, false) : undefined;
  if (bytes === undefined || bytes.length === 0) return undefined;
  const rest: JsonObject = { ...credential };
  delete rest['proof'];
  return { credential: rest, signature: base64UrlNoPad(bytes) };
}

/** SPEC §7.8 step 2: the digest over a credential's signed form, or undefined when it has none. */
export function credentialDigest(credential: unknown): string | undefined {
  const form = credentialSignedForm(credential);
  if (form === undefined) return undefined;
  try {
    return domainDigest(CREDENTIAL_DIGEST_DOMAIN, form);
  } catch (error) {
    if (error instanceof CanonicalJsonError) return undefined;
    throw error;
  }
}

/** SPEC §7.8 step 3: the chain digest over its credentials root first, or undefined when one has no signed form. */
export function chainDigest(chain: unknown): string | undefined {
  if (!Array.isArray(chain) || chain.length === 0) return undefined;
  const digests: string[] = [];
  for (const credential of chain) {
    const digest = credentialDigest(credential);
    if (digest === undefined) return undefined;
    digests.push(digest);
  }
  return domainDigest(CHAIN_DIGEST_DOMAIN, digests);
}

function readJwtPayload(jwt: string): JsonObject | undefined {
  const segments = jwt.split('.');
  if (segments.length !== 3) return undefined;
  const bytes = readSignatureBase64(segments[1]!, true);
  if (bytes === undefined) return undefined;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return undefined;
  }
  if (text.charCodeAt(0) === 0xfeff || jsonTextNestingDepth(text) > MAX_CREDENTIAL_NESTING) return undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function delegationIdOf(object: JsonObject): string | undefined {
  const subject = object['credentialSubject'];
  const delegation = isObject(subject) ? subject['delegation'] : undefined;
  return isObject(delegation) ? nonEmpty(delegation['id']) : undefined;
}

/** SPEC §7.8 step 1: the id a credential shows in the form it was presented in, or undefined. */
export function credentialShownId(credential: unknown): string | undefined {
  if (typeof credential === 'string') {
    const payload = readJwtPayload(credential);
    const vc = payload?.['vc'];
    if (!isObject(vc)) return undefined;
    return nonEmpty(vc['id']) ?? nonEmpty(payload!['jti']) ?? delegationIdOf(vc);
  }
  if (!isObject(credential)) return undefined;
  return nonEmpty(credential['id']) ?? delegationIdOf(credential);
}

/** SPEC §7.8 step 2: the reference for a credential id. */
export function delegationReference(id: string): string {
  if (id.length > MAX_REFERENCE_LENGTH || hasUnprintableCharacter(id) || DIGEST_FORM.test(id) || id === 'unknown') {
    return sha256Digest(wtf8Bytes(id));
  }
  return id;
}

/** The `delegationRef` of a credential, or undefined when it shows no id. */
export function delegationRef(credential: unknown): string | undefined {
  const id = credentialShownId(credential);
  return id === undefined ? undefined : delegationReference(id);
}
