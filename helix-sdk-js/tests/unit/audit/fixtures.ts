// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Locates helix-core's fixture directory, the cross-language contract of the
 * audit module: `HELIX_CORE_FIXTURES_DIR`, else the `helix-core` checkout
 * beside this workspace (the story worktree `.worktrees/a-1/helix-core` is
 * tried before a sibling `helix-core` at each ancestor). Fixture-driven tests
 * skip, with a clear message, when the file is absent.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe } from 'vitest';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const AUDIT_EVENTS = 'kya-os-helix/audit-events.json';

function candidates(): string[] {
  const env = process.env['HELIX_CORE_FIXTURES_DIR'];
  const out = env ? [env] : [];
  let dir = PACKAGE_ROOT;
  for (let i = 0; i < 6; i += 1) {
    dir = dirname(dir);
    out.push(join(dir, '.worktrees', 'a-1', 'helix-core', 'fixtures'), join(dir, 'helix-core', 'fixtures'));
  }
  return out;
}

/** The fixture directory holding `kya-os-helix/audit-events.json`, or undefined. */
export const FIXTURES_DIR: string | undefined = candidates().find((dir) => existsSync(join(dir, AUDIT_EVENTS)));

export function loadFixture<T>(relative: string): T {
  if (FIXTURES_DIR === undefined) throw new Error('helix-core fixtures not found');
  return JSON.parse(readFileSync(join(FIXTURES_DIR, relative), 'utf8')) as T;
}

/** A describe block that runs only when the helix-core fixtures are present. */
export function describeFixture(name: string, body: () => void): void {
  if (FIXTURES_DIR === undefined) {
    describe.skip(`${name} (skipped: helix-core/fixtures/${AUDIT_EVENTS} not found; set HELIX_CORE_FIXTURES_DIR)`, body);
    return;
  }
  describe(name, body);
}

export interface PartyRefJson {
  kind: string;
  [key: string]: unknown;
}

export interface AuditEventsFixture {
  trail: {
    sourceId: string;
    producer: PartyRefJson;
    tenantRef: PartyRefJson;
    binding: string;
    privacy: { classification: string; retentionClass: string };
  };
  events: Array<{ name: string; input: Record<string, unknown>; event: Record<string, unknown>; canonical: string; digest: string }>;
  chain: { sourceId: string; entries: Array<{ event: Record<string, unknown>; canonical: string; digest: string }> };
  tool_names: { input: Record<string, unknown>; included: Record<string, unknown>; withheld: Record<string, unknown> };
  rejections: Array<{ name: string; event: unknown; path: string }>;
  references: Array<{ input: string; max_length?: number; output: string }>;
  delegation: Array<{ name: string; credential: unknown; delegation_ref: string | null; credential_digest: string | null }>;
  delegation_chain: {
    credentials: unknown[];
    digests: string[];
    chain_digest: string;
    too_long_chain_length: number;
    too_long_chain_digests: null;
    unsigned_member_digests: null;
  };
  evidence: {
    key_hex: string;
    key_id: string;
    tenant: PartyRefJson;
    purpose: string;
    aad_utf8: string;
    plaintext_utf8: string;
    media_type: string;
    ref: Record<string, unknown>;
    ciphertext_b64url: string;
    wrong_purpose: string;
    wrong_tenant: PartyRefJson;
  };
  evidence_event: { event: Record<string, unknown>; canonical: string; digest: string };
}

export interface AuditIntegrityVector {
  id: string;
  expected: 'pass' | 'fail';
  input: { event?: unknown; eventCanonical?: string; eventDigest?: string; canonicalization?: { value: unknown; canonical: string } };
}

export const auditEventsFixture = (): AuditEventsFixture => loadFixture<AuditEventsFixture>(AUDIT_EVENTS);
export const auditIntegrityVectors = (): AuditIntegrityVector[] =>
  loadFixture<{ vectors: AuditIntegrityVector[] }>('kya-os/conformance/vectors/audit-integrity.json').vectors;
