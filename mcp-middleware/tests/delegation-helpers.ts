// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story L3-D test helpers, over the helix-core verifier fixture world
 * (fixtures/verifier/environment.json): hops and attestations signed with
 * the fixture keys (eddsa-jcs-2022), an Entity Card for any DID, and a
 * second service B with a did:web of its own.
 */

import { base58btcEncode, buildDIDDocument, generateKeyPair, kyaos, signData } from '@helixid/sdk-js';
import type { FixtureEnvironment } from './proof-helpers.js';

/** `doc` with an eddsa-jcs-2022 DataIntegrityProof by fixture key `label` (its #key-1). */
export function signWith(env: FixtureEnvironment, label: string, doc: Record<string, unknown>): Record<string, unknown> {
  const key = env.keys[label]!;
  const unsecured = { ...doc };
  delete unsecured['proof'];
  const config = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-01-01T00:00:00Z', verificationMethod: key.kid, proofPurpose: 'assertionMethod' };
  const signature = signData(kyaos.verifier.hashData({ ...config, '@context': unsecured['@context'] }, unsecured), key.private_key_hex);
  return { ...unsecured, proof: { ...config, proofValue: `z${base58btcEncode(new Uint8Array(Buffer.from(signature, 'hex')))}` } };
}

export interface HopSpec {
  id: string;
  issuer: string;
  invoker: string;
  parentCapability: string;
  invocationTarget: string;
  allowedAction: string[];
  validUntil?: string;
  caveats?: Array<Record<string, unknown>>;
  status: { url: string; index: string };
}

/** A §6.10 hop signed by fixture key `label`. */
export function hop(env: FixtureEnvironment, label: string, spec: HopSpec): Record<string, unknown> {
  return signWith(env, label, {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1', 'https://kya-os.org/ns/delegation/v1'],
    id: spec.id,
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: spec.issuer,
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: spec.validUntil ?? '2026-11-01T00:00:00Z',
    credentialSubject: {
      id: spec.id,
      invoker: spec.invoker,
      parentCapability: spec.parentCapability,
      invocationTarget: spec.invocationTarget,
      allowedAction: spec.allowedAction,
      ...(spec.caveats === undefined ? {} : { caveats: spec.caveats }),
    },
    credentialStatus: {
      id: `${spec.status.url}#${spec.status.index}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: spec.status.index,
      statusListCredential: spec.status.url,
    },
  });
}

/** The attested agent card of the fixture, re-issued for `did`: one Helix attestation per capability on the Helix list from index 5. */
export function cardFor(env: FixtureEnvironment, did: string, capabilities: string[], responsibleParty?: string): Record<string, unknown> {
  const template = env.cards['attested'] as Record<string, unknown>;
  const helix = env.keys['helix']!.did;
  return {
    ...template,
    id: did,
    kid: `${did}#key-1`,
    ...(responsibleParty === undefined ? {} : { responsibleParty }),
    capabilities: capabilities.map((capability, index) => ({
      name: capability,
      attestations: [
        {
          vc: signWith(env, 'helix', {
            '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
            id: `urn:uuid:00000000-0000-4000-8000-0000000d30${String(index).padStart(2, '0')}`,
            type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
            issuer: helix,
            validFrom: '2026-01-01T00:00:00Z',
            validUntil: '2026-12-31T00:00:00Z',
            credentialSubject: { id: did, capability },
            credentialStatus: {
              id: `https://helix.example/status/1#${5 + index}`,
              type: 'BitstringStatusListEntry',
              statusPurpose: 'revocation',
              statusListIndex: String(5 + index),
              statusListCredential: 'https://helix.example/status/1',
            },
          }),
        },
      ],
    })),
  };
}

/** A service of its own with a did:web on `host`, whose document the verifiers resolve through `documents`. */
export function serviceOn(host: string): { did: string; host: string; signer: kyaos.Signer; document: Record<string, unknown> } {
  const did = `did:web:${encodeURIComponent(host)}:services:0b`;
  const keys = generateKeyPair();
  return {
    did,
    host,
    signer: new kyaos.EnvSigner({ did, envVar: 'SERVICE_KEY', env: { SERVICE_KEY: keys.privateKey } }),
    document: buildDIDDocument(did, keys.publicKey) as unknown as Record<string, unknown>,
  };
}

/** 32 zero bytes, GZIP, base64url: a list with nothing revoked. */
export const EMPTY_LIST = 'H4sIAAAAAAAC_2NgwA8ArVUKGSAAAAA';

/** A copy of the fixture world with an extra empty revocation list owned by `label` at `url`. */
export function withList(env: FixtureEnvironment, label: string, url: string): FixtureEnvironment {
  return {
    ...env,
    status_lists: {
      ...env.status_lists,
      [url]: { encoded_list: EMPTY_LIST, issuer: env.keys[label]!.did, status_purpose: 'revocation', id: url, valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' },
    },
  };
}
