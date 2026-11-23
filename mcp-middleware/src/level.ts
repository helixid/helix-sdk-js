// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The minimum Card level a tool demands (KYA-OS story C-C point 7,
 * SPEC-ENTITY-CARD.md §9). Scopes say whether the agent may do the action,
 * from its chain; the level says how sure the verifier is that the caller
 * is that agent right now. Under KYA-OS a request proof is optional per
 * request, so the minimum is explicit: `L3` for every tool by default (what
 * Helix always demanded: a fresh signature on every call), lowered per tool.
 *
 * The verifier derives the level (`deriveConformanceLevel`, §9.4) and never
 * reads the card's own `conformanceLevel`. A proof without a token `cnf` to
 * fuse with is L3-minus (§8.6); whether L3-minus satisfies an L3 tool is
 * `l3MinusSatisfiesL3`, default true, as §9.4 lets the proof floor hold.
 */

import { kyaos } from '@helixid/sdk-js';

export type MinimumLevel = kyaos.verifier.ConformanceLevel;
/** The level a call came to: `L3-minus` is an L3 without the token `cnf` fusion. */
export type DerivedLevel = MinimumLevel | 'L3-minus';

export const MINIMUM_LEVELS: readonly MinimumLevel[] = ['L1', 'L2', 'L3'];
export const DEFAULT_MINIMUM_LEVEL: MinimumLevel = 'L3';

export interface LevelPolicy {
  /** Every tool's minimum; default `L3`. */
  minimumLevel?: MinimumLevel | undefined;
  /** Per-tool overrides: `{ lookup_order: { minimumLevel: 'L2' } }`. */
  tools?: Record<string, { minimumLevel?: MinimumLevel | undefined }> | undefined;
  /** Whether L3-minus (a proof with no token `cnf` to fuse) satisfies an `L3` minimum; default true. */
  l3MinusSatisfiesL3?: boolean | undefined;
}

/** `deriveConformanceLevel(check, proofFloor, revocationFresh)` (§9.4), as the verifier runs it. */
export const deriveConformanceLevel = kyaos.verifier.deriveConformanceLevel;

const RANK: Record<MinimumLevel, number> = { L1: 1, L2: 2, L3: 3 };

/** Throws on a policy that names a level that does not exist, so a typo never lowers a tool's bar. */
export function assertLevelPolicy(policy: LevelPolicy): void {
  const check = (where: string, level: unknown): void => {
    if (level !== undefined && !MINIMUM_LEVELS.includes(level as MinimumLevel)) {
      throw new Error(`helixidMCPMiddleware: ${where} must be one of ${MINIMUM_LEVELS.join(', ')}`);
    }
  };
  check('minimumLevel', policy.minimumLevel);
  for (const [name, tool] of Object.entries(policy.tools ?? {})) check(`tools.${name}.minimumLevel`, tool?.minimumLevel);
}

/** The minimum a tool demands: its override, else the policy's, else `L3`. */
export function minimumLevelFor(policy: LevelPolicy, toolName: string | undefined): MinimumLevel {
  const own = toolName !== undefined && Object.hasOwn(policy.tools ?? {}, toolName) ? policy.tools![toolName]?.minimumLevel : undefined;
  return own ?? policy.minimumLevel ?? DEFAULT_MINIMUM_LEVEL;
}

/** The level a verified call came to: the verifier's level, `L3-minus` when its L3 rests on an unfused proof. */
export function derivedLevelOf(level: MinimumLevel, proofAssurance: kyaos.verifier.ProofAssurance | undefined): DerivedLevel {
  return level === 'L3' && proofAssurance === 'L3-minus' ? 'L3-minus' : level;
}

/** Whether `derived` meets `minimum` under the policy's L3-minus setting. */
export function meetsMinimumLevel(derived: DerivedLevel, minimum: MinimumLevel, l3MinusSatisfiesL3 = true): boolean {
  if (derived === 'L3-minus') return minimum !== 'L3' || l3MinusSatisfiesL3;
  return RANK[derived] >= RANK[minimum];
}
