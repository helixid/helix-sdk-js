// Copyright 2026 DgVerse LLP
// KYA-OS story L3-C: a revoked chain whose result names no code is still refused, as status_revoked.
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/core/kyaos/verifier/revocation.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/core/kyaos/verifier/revocation.js')>();
  return { ...original, checkChainRevocation: vi.fn(async () => ({ revoked: true, fresh: false, index: 0 })) };
});

const { verifier } = await import('../../../../src/core/kyaos/index.js');
const { fixtureSeams, haveVerifierFixtures, loadCases, loadEnvironment } = await import('./harness.js');

describe.skipIf(!haveVerifierFixtures)('chain revocation without a code', () => {
  it('refuses with status_revoked and names the hop', async () => {
    const env = loadEnvironment();
    const fixture = loadCases()['valid']!.find((entry) => entry.name === 'two_hop_chain')!;
    const result = await verifier.verify(fixture.input as never, fixtureSeams(env, fixture.seams, fixture.now), fixture.options as never);
    expect(result).toMatchObject({ ok: false, reasons: [verifier.ReasonCodes.STATUS_REVOKED] });
    expect(result.messages[0]).toBe('hop 0: revoked');
  });
});
