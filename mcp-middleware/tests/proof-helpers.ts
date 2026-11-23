// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story F-2 test helpers: an agent that mints request proofs, and a
 * local verifier whose seams read the shared fixture environment
 * (helix-core fixtures/verifier/environment.json, the sibling checkout or
 * `HELIX_CORE_FIXTURES_DIR`) so a test can present a real signed chain and
 * an attested card without a network.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDIDDocument, generateKeyPair, kyaos } from '@helixid/sdk-js';
import { MemoryNonceStore } from '../src/kyaos/nonce-store.js';
import { createLocalVerifier, type LocalVerifier, type LocalVerifierOptions } from '../src/verify-locally.js';

export const coreFixturesDir: string =
  process.env['HELIX_CORE_FIXTURES_DIR'] ?? resolve(fileURLToPath(new URL('../../', import.meta.url)), '../helix-core/fixtures');
export const verifierFixturesDir = join(coreFixturesDir, 'verifier');
export const haveVerifierFixtures = existsSync(join(verifierFixturesDir, 'environment.json'));

export interface FixtureEnvironment {
  now: string;
  keys: Record<string, { private_key_hex: string; public_key_hex: string; did: string; kid: string; did_document: Record<string, unknown> }>;
  did_documents: Record<string, Record<string, unknown>>;
  status_lists: Record<string, { encoded_list: string; issuer?: string; status_purpose?: string | string[]; id?: string; valid_from?: string; valid_until?: string; fresh?: boolean }>;
  cards: Record<string, unknown>;
}

export interface FixtureCase {
  name: string;
  input: { proof?: unknown; chain?: unknown; request?: kyaos.verifier.ProofRequest; card?: unknown };
  options: Record<string, unknown>;
  seams: Record<string, unknown>;
  expected: { ok: boolean; reasons: string[] };
}

export function loadEnvironment(): FixtureEnvironment {
  return JSON.parse(readFileSync(join(verifierFixturesDir, 'environment.json'), 'utf8')) as FixtureEnvironment;
}

export function loadCases(file: string): FixtureCase[] {
  return (JSON.parse(readFileSync(join(verifierFixturesDir, `${file}.json`), 'utf8')) as { cases: FixtureCase[] }).cases;
}

export const NOW_MS = Date.parse('2026-06-01T00:00:00Z');

/** An agent of its own, with a did:web document the verifier resolves through `documents`. */
export function makeAgent(did = 'did:web:agent.helix.test'): { did: string; signer: kyaos.Signer; document: Record<string, unknown>; publicKeyHex: string } {
  const keys = generateKeyPair();
  const signer = new kyaos.EnvSigner({ did, envVar: 'AGENT_KEY', env: { AGENT_KEY: keys.privateKey } });
  return { did, signer, document: buildDIDDocument(did, keys.publicKey) as unknown as Record<string, unknown>, publicKeyHex: keys.publicKey };
}

export interface FixtureVerifierOptions extends Partial<LocalVerifierOptions> {
  env?: FixtureEnvironment | undefined;
  /** Extra DID documents, by DID. */
  documents?: Record<string, unknown> | undefined;
}

/** A local verifier over the fixture environment plus any extra documents, with a fixed clock. */
export function fixtureVerifier(serviceDid: string, options: FixtureVerifierOptions = {}): LocalVerifier {
  const env = options.env;
  const documents: Record<string, unknown> = { ...(env?.did_documents ?? {}), ...(options.documents ?? {}) };
  const resolveDid: kyaos.verifier.DidResolver = async (did) => (documents[did] as never) ?? kyaos.verifier.didKeyDocument(did) ?? null;
  const fetchStatusList: kyaos.verifier.FetchStatusList = async (url) => {
    const list = env?.status_lists[url];
    if (list === undefined) return undefined;
    return {
      bits: kyaos.verifier.decodeStatusListBits(list.encoded_list),
      ...(list.issuer === undefined ? {} : { issuer: list.issuer }),
      ...(list.status_purpose === undefined ? {} : { statusPurpose: list.status_purpose }),
      ...(list.id === undefined ? {} : { id: list.id }),
      ...(list.valid_from === undefined ? {} : { validFrom: list.valid_from }),
      ...(list.valid_until === undefined ? {} : { validUntil: list.valid_until }),
      fresh: list.fresh ?? true,
    };
  };
  const { env: _env, documents: _documents, ...rest } = options;
  return createLocalVerifier({
    serviceDid,
    clock: () => NOW_MS,
    nonceStore: new MemoryNonceStore({ now: () => NOW_MS }),
    resolveDid,
    fetchStatusList,
    reportVerification: () => undefined,
    ...rest,
  });
}

/** The signer of a fixture key. */
export function fixtureSigner(env: FixtureEnvironment, label: string): kyaos.Signer {
  const key = env.keys[label]!;
  // The fixture names its own kid (its did_documents publish `#key-1`), so pin it rather than the did:key default.
  return new kyaos.EnvSigner({ did: key.did, kid: key.kid.slice(key.kid.indexOf('#') + 1), envVar: 'FIXTURE_KEY', env: { FIXTURE_KEY: key.private_key_hex } });
}

/** The `_meta` of a tool call: the request proof minted now, and the chain when given. */
export async function proofMeta(
  signer: kyaos.Signer,
  audience: string,
  call: { name: string; input?: Record<string, unknown> | undefined },
  chain?: unknown,
  options: { now?: number; legacyKey?: boolean; cnfJkt?: string } = {},
): Promise<Record<string, unknown>> {
  const request: kyaos.verifier.ProofRequest = { method: 'tools/call', params: { name: call.name, ...(call.input === undefined ? {} : { arguments: call.input }) } };
  const proof = await kyaos.verifier.signRequestProof(request, signer, { audience, now: options.now ?? NOW_MS, ...(options.cnfJkt === undefined ? {} : { cnfJkt: options.cnfJkt }) });
  return {
    [options.legacyKey ? kyaos.verifier.LEGACY_REQUEST_PROOF_META_KEY : kyaos.verifier.REQUEST_PROOF_META_KEY]: proof,
    ...(chain === undefined ? {} : { [kyaos.verifier.DELEGATION_CHAIN_META_KEY]: chain }),
  };
}

/** The RFC 7638 thumbprint of an Ed25519 public key given as hex: what `cnf.jkt` carries. */
export function thumbprintOfHex(publicKeyHex: string): string {
  return kyaos.verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKeyHex, 'hex').toString('base64url') });
}
