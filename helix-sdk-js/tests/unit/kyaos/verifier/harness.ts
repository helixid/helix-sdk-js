// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The fixture harness of the local verifier (KYA-OS story F-2): reads
 * helix-core's `fixtures/verifier/*.json` and builds each case's seams from
 * the environment exactly as helix-core's generator and helix-sdk-py's
 * tests do, so every consumer judges the same inputs through the same seams.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { coreFixturesDir } from '../fixtures.js';

export const verifierFixturesDir = join(coreFixturesDir, 'verifier');
export const haveVerifierFixtures = existsSync(join(verifierFixturesDir, 'environment.json'));

export interface FixtureStatusList {
  encoded_list: string;
  issuer?: string;
  status_purpose?: string | string[];
  id?: string;
  valid_from?: string;
  valid_until?: string;
  fresh?: boolean;
}

export interface SeamSetting {
  resolveDid: 'documents' | 'missing' | 'unknown' | 'throws';
  resolveDidKeys: 'documents' | 'missing' | 'empty' | 'throws';
  fetchStatusList: 'lists' | 'missing' | 'throws';
  nonceStore: 'fresh' | 'replayed' | 'missing' | 'throws';
  clock: 'fixed' | 'missing';
  trustedIssuers: '*' | string[];
  resolveCard: string;
}

export interface FixtureCase {
  name: string;
  description: string;
  input: { proof?: unknown; chain?: unknown; request?: unknown; card?: unknown };
  seams: SeamSetting;
  options: Record<string, unknown>;
  now: number;
  expected: { ok: boolean; level: string; effectiveScopes: string[]; reasons: string[]; chainSummary: Record<string, unknown> };
}

export interface FixtureEnvironment {
  now: string;
  keys: Record<string, { private_key_hex: string; public_key_hex: string; did: string; kid: string; did_document: Record<string, unknown> }>;
  did_documents: Record<string, Record<string, unknown>>;
  status_lists: Record<string, FixtureStatusList>;
  cards: Record<string, unknown>;
}

export function loadEnvironment(): FixtureEnvironment {
  return JSON.parse(readFileSync(join(verifierFixturesDir, 'environment.json'), 'utf8')) as FixtureEnvironment;
}

/** Every case file (all `*.json` but `environment.json`), by file name. */
export function loadCases(): Record<string, FixtureCase[]> {
  const files: Record<string, FixtureCase[]> = {};
  for (const name of readdirSync(verifierFixturesDir).filter((entry) => entry.endsWith('.json') && entry !== 'environment.json').sort()) {
    files[name.replace(/\.json$/, '')] = (JSON.parse(readFileSync(join(verifierFixturesDir, name), 'utf8')) as { cases: FixtureCase[] }).cases;
  }
  return files;
}

/** What the harness records about the seams a case touched, for the tests that assert on it. */
export interface SeamCalls {
  resolveDid: string[];
  fetchStatusList: string[];
  nonces: string[];
}

/** The seams of a case, from the environment: the one definition the generator and the Python tests share. */
export function fixtureSeams(env: FixtureEnvironment, setting: SeamSetting, now: number, calls?: SeamCalls): verifier.VerifierSeams {
  const usedNonces = new Set<string>();
  const resolveDid: verifier.VerifierSeams['resolveDid'] = async (did) => {
    calls?.resolveDid.push(did);
    if (setting.resolveDid === 'throws') throw new Error('resolver down');
    if (setting.resolveDid === 'unknown') return null;
    return (env.did_documents[did] as never) ?? null;
  };
  const resolveDidKeys: verifier.VerifierSeams['resolveDidKeys'] = async (did) => {
    if (setting.resolveDidKeys === 'throws') throw new Error('keys down');
    if (setting.resolveDidKeys === 'empty') return [];
    const document = env.did_documents[did];
    if (document === undefined) throw new Error(`no document for ${did}`);
    return verifier.ed25519KeysOf(document as never);
  };
  const fetchStatusList: verifier.FetchStatusList = async (url) => {
    calls?.fetchStatusList.push(url);
    if (setting.fetchStatusList === 'throws') throw new Error('status service down');
    const list = env.status_lists[url];
    if (list === undefined) return undefined;
    return {
      bits: verifier.decodeStatusListBits(list.encoded_list),
      ...(list.issuer === undefined ? {} : { issuer: list.issuer }),
      ...(list.status_purpose === undefined ? {} : { statusPurpose: list.status_purpose }),
      ...(list.id === undefined ? {} : { id: list.id }),
      ...(list.valid_from === undefined ? {} : { validFrom: list.valid_from }),
      ...(list.valid_until === undefined ? {} : { validUntil: list.valid_until }),
      fresh: list.fresh ?? true,
    };
  };
  const nonceStore: verifier.NonceStoreSeam = {
    insert: async (nonce, did) => {
      calls?.nonces.push(nonce);
      if (setting.nonceStore === 'throws') throw new Error('nonce store down');
      const key = `${did ?? ''}|${nonce}`;
      if (setting.nonceStore === 'replayed' || usedNonces.has(key)) return false;
      usedNonces.add(key);
      return true;
    },
  };
  const resolveCard = async (): Promise<unknown> => {
    if (setting.resolveCard === 'throws') throw new Error('card host down');
    return env.cards[setting.resolveCard];
  };
  return {
    ...(setting.resolveCard === 'missing' ? {} : { resolveCard }),
    ...(setting.resolveDid === 'missing' ? {} : { resolveDid }),
    ...(setting.resolveDidKeys === 'missing' ? {} : { resolveDidKeys }),
    ...(setting.fetchStatusList === 'missing' ? {} : { fetchStatusList }),
    ...(setting.nonceStore === 'missing' ? {} : { nonceStore }),
    ...(setting.clock === 'missing' ? {} : { clock: () => now }),
    trustedIssuers: setting.trustedIssuers,
  };
}

/** Runs one fixture case through the verifier and returns the comparable part of the result. */
export async function runCase(env: FixtureEnvironment, fixture: FixtureCase, calls?: SeamCalls): Promise<FixtureCase['expected']> {
  const result = await verifier.verify(fixture.input as verifier.VerifierInput, fixtureSeams(env, fixture.seams, fixture.now, calls), fixture.options as unknown as verifier.VerifierOptions);
  return {
    ok: result.ok,
    level: result.level,
    effectiveScopes: result.effectiveScopes,
    reasons: result.reasons,
    chainSummary: {
      depth: result.chainSummary.depth,
      ...(result.chainSummary.responsibleParty === undefined ? {} : { responsibleParty: result.chainSummary.responsibleParty }),
      ...(result.chainSummary.leafInvoker === undefined ? {} : { leafInvoker: result.chainSummary.leafInvoker }),
      ...(result.chainSummary.invocationTarget === undefined ? {} : { invocationTarget: result.chainSummary.invocationTarget }),
      allowedAction: result.chainSummary.allowedAction,
      fresh: result.chainSummary.fresh,
    },
  };
}
