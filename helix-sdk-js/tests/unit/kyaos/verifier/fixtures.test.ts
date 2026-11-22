// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS story F-2: the JavaScript verifier over the shared fixture set
 * helix-core generated with it (fixtures/verifier/*.json), case by case:
 * the verdict, the level, the effective scopes, the reason codes and the
 * chain summary must be the ones recorded. helix-sdk-py's
 * tests/test_verifier.py runs the same cases to the same expectations, which
 * is the parity the story asks for; e2e-playwright runs both.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { coreFixturesDir, fixtureSkipReason } from '../fixtures.js';
import { haveVerifierFixtures, loadCases, loadEnvironment, runCase, type SeamCalls } from './harness.js';

if (!haveVerifierFixtures) console.warn(`[verifier fixtures] skipped: ${fixtureSkipReason}`);
const describeWithFixtures = describe.skipIf(!haveVerifierFixtures);

describeWithFixtures('fixtures/verifier: every case comes to the recorded verdict', () => {
  const env = loadEnvironment();
  const files = loadCases();

  it('covers the five case files', () => {
    expect(Object.keys(files)).toEqual(['chain', 'proof', 'seams', 'status', 'valid']);
    expect(Object.values(files).reduce((sum, cases) => sum + cases.length, 0)).toBeGreaterThanOrEqual(90);
  });

  for (const [file, cases] of Object.entries(files)) {
    describe(file, () => {
      for (const fixture of cases) {
        it(`${fixture.name}: ${fixture.description}`, async () => {
          expect(await runCase(env, fixture)).toEqual(fixture.expected);
        });
      }
    });
  }

  it('refuses an over-long chain before any DID resolution (zero resolver calls)', async () => {
    const fixture = files['chain']!.find((candidate) => candidate.name === 'chain_too_long')!;
    const calls: SeamCalls = { resolveDid: [], fetchStatusList: [], nonces: [] };
    const result = await runCase(env, fixture, calls);
    expect(result.reasons).toEqual([verifier.ReasonCodes.CHAIN_TOO_LONG]);
    expect(calls.resolveDid).toEqual([]);
    expect(calls.fetchStatusList).toEqual([]);
    expect(calls.nonces).toEqual([]);
  });

  it('refuses a failed carried chain without any further lookup', async () => {
    const fixture = files['chain']!.find((candidate) => candidate.name === 'no_fallback_after_failed_chain')!;
    const calls: SeamCalls = { resolveDid: [], fetchStatusList: [], nonces: [] };
    const result = await runCase(env, fixture, calls);
    expect(result.ok).toBe(false);
    // The proof's DID was resolved for the signature; the chain's issuers never were, and no status list was read.
    expect(calls.resolveDid).toEqual([env.keys['agent']!.did]);
    expect(calls.fetchStatusList).toEqual([]);
  });

  it('records every reason code the two languages share', () => {
    const codes = new Set(Object.values(files).flatMap((cases) => cases.flatMap((fixture) => fixture.expected.reasons)));
    for (const code of codes) expect(verifier.ALL_REASON_CODES).toContain(code);
    expect(codes.size).toBeGreaterThanOrEqual(40);
  });

  it('is the environment the generator wrote: keys resolve to their documents', () => {
    for (const key of Object.values(env.keys)) {
      expect(env.did_documents[key.did]).toEqual(key.did_document);
      expect(verifier.didKeyDocument(key.did)?.verificationMethod?.[0]?.publicKeyJwk?.x).toBe(Buffer.from(key.public_key_hex, 'hex').toString('base64url'));
    }
  });
});

describeWithFixtures('fixtures/kya-os-helix/credentials.json: the chain evaluator ported byte for byte (story F-1)', () => {
  interface Fixture {
    now: string;
    chains: { name: string; hops: unknown[]; options: { resource?: string; resourceOwner?: string; now: string; maxChainLength?: number }; expected: Record<string, unknown> }[];
    effective_scopes: { name: string; attestations: string[]; leaf_allowed_action: string[]; catalog: string[]; expected: string[] }[];
    card_levels: { name: string; expected_check: { verified: string[]; unverified: string[] }; proof_floor_ok: boolean; revocation_fresh: boolean; expected_level: string }[];
    schema_rejections: { name: string; kind: 'identity' | 'attestation' | 'hop'; document: unknown; violation_path: string }[];
  }
  const fixture = JSON.parse(readFileSync(join(coreFixturesDir, 'kya-os-helix/credentials.json'), 'utf8')) as Fixture;

  it('evaluates every chain case to the recorded verdict', () => {
    expect(fixture.chains.length).toBeGreaterThan(20);
    for (const chain of fixture.chains) {
      const evaluation = verifier.evaluateDelegationChain(chain.hops, {
        ...(chain.options.resource === undefined ? {} : { resource: chain.options.resource }),
        ...(chain.options.resourceOwner === undefined ? {} : { resourceOwner: chain.options.resourceOwner }),
        ...(chain.options.maxChainLength === undefined ? {} : { maxChainLength: chain.options.maxChainLength }),
        now: Date.parse(chain.options.now),
      });
      const { reasons: _reasons, invocationTarget: _target, ...comparable } = evaluation;
      expect(comparable, chain.name).toEqual(chain.expected);
    }
  });

  it('derives every effective-scopes case', () => {
    for (const scopes of fixture.effective_scopes) {
      expect(verifier.deriveEffectiveScopes(scopes.attestations, scopes.leaf_allowed_action, scopes.catalog), scopes.name).toEqual(scopes.expected);
    }
  });

  it('derives every card level', () => {
    for (const level of fixture.card_levels) {
      expect(verifier.deriveConformanceLevel(level.expected_check, level.proof_floor_ok, level.revocation_fresh), level.name).toBe(level.expected_level);
    }
  });

  it('refuses every schema rejection at the recorded path', () => {
    for (const rejection of fixture.schema_rejections) {
      const violations = verifier.credentialSchemaViolations(rejection.kind, rejection.document);
      expect(violations.length, rejection.name).toBeGreaterThan(0);
      expect(violations[0]!.path, rejection.name).toBe(rejection.violation_path);
    }
  });
});
