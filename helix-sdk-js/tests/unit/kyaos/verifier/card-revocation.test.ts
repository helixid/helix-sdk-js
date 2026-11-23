// Copyright 2026 DgVerse LLP
// The card's own revocation entry (SPEC-ENTITY-CARD §10.3; Cleanup, Harish's pick A): the paths the
// shared fixtures do not reach. A missing status seam, a checker that throws, a verdict with no code.
import { describe, expect, it } from 'vitest';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { fixtureSeams, haveVerifierFixtures, loadCases, loadEnvironment } from './harness.js';

describe.skipIf(!haveVerifierFixtures)("the card's revocation entry", () => {
  const env = haveVerifierFixtures ? loadEnvironment() : (undefined as never);
  const live = haveVerifierFixtures ? loadCases()['status']!.find((entry) => entry.name === 'live_card')! : (undefined as never);
  const run = (seams: Partial<verifier.VerifierSeams>) =>
    verifier.verify(live.input as never, { ...fixtureSeams(env, live.seams, live.now), ...seams }, live.options as never);

  it('is read through the revocation seam, and the call stays fresh when it is read live', async () => {
    const seen: unknown[] = [];
    const result = await run({ checkRevocation: async (credential) => (seen.push(credential), { revoked: false, fresh: true }) });
    expect(result).toMatchObject({ ok: true, fresh: true });
    const card = live.input.card as { id: string; revocation: Record<string, string> };
    expect(seen).toContainEqual({ issuer: card.id, credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', ...card.revocation } });
  });

  it('refuses when no status seam can read it, when the checker throws, and as status_revoked when a verdict names no code', async () => {
    const missing = await run({ fetchStatusList: undefined, checkRevocation: undefined });
    expect(missing.reasons[0]).toBe(verifier.ReasonCodes.STATUS_SEAM_MISSING);
    const hopsOk = { revoked: false, fresh: true } as const;
    const throwing = await run({ checkRevocation: async (credential) => { if ((credential as { issuer: string }).issuer === (live.input.card as { id: string }).id) throw new Error('boom'); return hopsOk; } });
    expect([throwing.ok, throwing.reasons[0]]).toEqual([false, verifier.ReasonCodes.STATUS_UNAVAILABLE]);
    const bare = await run({ checkRevocation: async (credential) => ((credential as { issuer: string }).issuer === (live.input.card as { id: string }).id ? { revoked: true, fresh: false } : hopsOk) });
    expect([bare.reasons[0], bare.messages[0]]).toEqual([verifier.ReasonCodes.STATUS_REVOKED, "the card's revocation entry: revoked"]);
  });
});
