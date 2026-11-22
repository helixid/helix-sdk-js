// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS story C-C over helix-core's fixtures/kya-os-helix/request-proof.json
 * (generated with this verifier, on the F-2 environment): the §11.2 order,
 * the carrier keys and chains verified without a proof. helix-sdk-py's
 * port runs the same cases (held until its L2-A base merges).
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { coreFixturesDir, fixtureSkipReason, loadFixture } from '../fixtures.js';
import { fixtureSeams, haveVerifierFixtures, loadEnvironment, runCase, type FixtureCase } from './harness.js';

interface RequestProofCase extends Omit<FixtureCase, 'input' | 'expected'> {
  input: FixtureCase['input'] & { meta?: unknown };
  expected: FixtureCase['expected'] & { agentDid?: string; proofFloor: boolean; proofAssurance?: string; warnings: string[] };
}

const present = haveVerifierFixtures && existsSync(join(coreFixturesDir, 'kya-os-helix/request-proof.json'));
if (!present) console.warn(`[request-proof fixtures] skipped: ${fixtureSkipReason}`);

describe.skipIf(!present)('fixtures/kya-os-helix/request-proof.json: story C-C cases come to the recorded verdict', () => {
  const env = loadEnvironment();
  const { cases } = loadFixture<{ cases: RequestProofCase[] }>('kya-os-helix/request-proof.json');

  it('holds the order, carrier-key and chain-without-proof cases', () => {
    expect(cases.length).toBeGreaterThanOrEqual(25);
    for (const prefix of ['order_', 'canonical_key', 'legacy_key', 'chain_without_proof_']) {
      expect(cases.some((fixture) => fixture.name.startsWith(prefix)), prefix).toBe(true);
    }
  });

  for (const fixture of cases) {
    it(`${fixture.name}: ${fixture.description}`, async () => {
      const input: verifier.VerifierInput =
        fixture.input.meta === undefined
          ? (fixture.input as verifier.VerifierInput)
          : {
              proof: verifier.readRequestProof(fixture.input.meta),
              ...(verifier.readCarriedChain(fixture.input.meta) === undefined ? {} : { chain: verifier.readCarriedChain(fixture.input.meta) }),
              ...(fixture.input.request === undefined ? {} : { request: fixture.input.request as verifier.ProofRequest }),
              ...(fixture.input.card === undefined ? {} : { card: fixture.input.card }),
            };
      const comparable = await runCase(env, { ...fixture, input } as FixtureCase);
      const result = await verifier.verify(input, fixtureSeams(env, fixture.seams, fixture.now), fixture.options as unknown as verifier.VerifierOptions);
      expect({
        ...comparable,
        ...(result.agentDid === undefined ? {} : { agentDid: result.agentDid }),
        proofFloor: result.proofFloor,
        ...(result.proofAssurance === undefined ? {} : { proofAssurance: result.proofAssurance }),
        warnings: result.warnings,
      }).toEqual(fixture.expected);
    });
  }
});
