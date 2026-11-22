// Copyright 2026 DgVerse LLP
// KYA-OS story F-2: the SDK's ConformanceAdapter over the seven pinned vector categories
// of the vendored suite (helix-core fixtures/kya-os, a4d7f61, suite 1.10.0).
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { conformance } from '../../../../src/core/kyaos/index.js';
import { coreFixturesDir, fixtureSkipReason, haveCoreFixtures } from '../fixtures.js';

if (!haveCoreFixtures) console.warn(`[conformance] skipped: ${fixtureSkipReason}`);

describe.skipIf(!haveCoreFixtures)('KYA-OS conformance vectors through HelixConformanceAdapter', () => {
  const vectorsDir = join(coreFixturesDir, 'kya-os/conformance/vectors');

  it('passes every vector of the seven categories story F-2 pins', async () => {
    const vectors = conformance.loadVectors(vectorsDir, conformance.F2_CATEGORIES);
    const report = await conformance.runConformance(new conformance.HelixConformanceAdapter(), vectors);
    const failures = report.results.filter((result) => !result.ok).map((result) => `${result.id}: expected ${result.expected}, got ${result.actual} (${result.detail ?? ''})`);
    expect(failures).toEqual([]);
    expect(Object.keys(report.categories).sort()).toEqual([...conformance.F2_CATEGORIES].sort());
    expect(report.total).toBe(153);
    expect(report.categories).toEqual({
      "signed-proof": { total: 62, passed: 62 },
      "delegation-chain": { total: 20, passed: 20 },
      "status-list": { total: 50, passed: 50 },
      "did-key-resolution": { total: 3, passed: 3 },
      "did-web-resolution": { total: 3, passed: 3 },
      "card-proof": { total: 7, passed: 7 },
      "entity-card": { total: 8, passed: 8 },
    });
    expect(conformance.formatReport(report)).toContain('RESULT: PASS');
  });
});
