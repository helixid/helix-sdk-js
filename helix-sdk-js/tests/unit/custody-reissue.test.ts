// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** KYA-OS story C-E point 4: a self-custody issuer reissues its hop for a delegate's new key. */

import { describe, expect, it } from 'vitest';
import { EnvSigner, reissueHop, signDataIntegrity } from '../../src/core/custody/index.js';
import { verifier } from '../../src/core/kyaos/index.js';
import { buildDIDDocument, generateKeyPair } from '../../src/index.js';

const ISSUER = 'did:web:issuer.example:accounts:01';
const DELEGATE = 'did:web:helix.example:agents:02';
const keys = generateKeyPair();
const signer = new EnvSigner({ did: ISSUER, kid: 'key-1', envVar: 'K', env: { K: keys.privateKey } });
const resolveDid = async () => buildDIDDocument(ISSUER, keys.publicKey) as never;
const STATUS = { type: 'BitstringStatusListEntry' as const, statusPurpose: 'revocation' as const, statusListIndex: '7', statusListCredential: 'https://issuer.example/status/1' };

async function oldHop(): Promise<Record<string, unknown>> {
  return signDataIntegrity(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:zcap:old',
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: ISSUER,
      validFrom: '2026-06-01T00:00:00Z',
      validUntil: '2027-06-01T00:00:00Z',
      credentialSubject: { id: 'urn:zcap:old', invoker: DELEGATE, parentCapability: 'did:web:orders.example', invocationTarget: 'did:web:orders.example', allowedAction: ['orders:read'], caveats: [{ type: 'MaxAmount', limit: '10' }] },
      credentialStatus: { ...STATUS, statusListIndex: '1', id: 'https://issuer.example/status/1#1' },
    },
    signer,
    '2026-06-01T00:00:00Z',
  );
}

describe('reissueHop (story C-E)', () => {
  it('keeps the grant, takes a new id and status entry, and is signed again by its issuer', async () => {
    const old = await oldHop();
    expect(await verifier.verifyDataIntegrity(old, resolveDid)).toMatchObject({ ok: true });
    const fresh = await reissueHop(old, { signer, statusEntry: STATUS, id: 'urn:zcap:new', created: '2026-06-02T00:00:00Z' });
    expect(fresh).toMatchObject({
      id: 'urn:zcap:new',
      issuer: ISSUER,
      validFrom: '2026-06-01T00:00:00Z',
      validUntil: '2027-06-01T00:00:00Z',
      credentialSubject: { id: 'urn:zcap:new', invoker: DELEGATE, allowedAction: ['orders:read'], caveats: [{ type: 'MaxAmount', limit: '10' }] },
      credentialStatus: { ...STATUS, id: 'https://issuer.example/status/1#7' },
      proof: { created: '2026-06-02T00:00:00Z', verificationMethod: `${ISSUER}#key-1` },
    });
    expect(await verifier.verifyDataIntegrity(fresh, resolveDid)).toMatchObject({ ok: true, issuer: ISSUER });
    const generated = await reissueHop(old, { signer, statusEntry: { ...STATUS, id: 'x#1' } });
    expect(generated['id']).toMatch(/^urn:zcap:/);
    expect(generated['credentialStatus']).toMatchObject({ id: 'x#1' });
  });

  it('refuses a hop it did not issue, a hop with no subject, and a signer that is not the issuer or signs badly', async () => {
    const old = await oldHop();
    const stranger = new EnvSigner({ did: 'did:web:stranger.example', envVar: 'K', env: { K: keys.privateKey } });
    await expect(reissueHop(old, { signer: stranger, statusEntry: STATUS })).rejects.toThrow(/not the issuer of this hop/);
    await expect(reissueHop({ ...old, credentialSubject: null }, { signer, statusEntry: STATUS })).rejects.toThrow(/no credentialSubject/);
    await expect(signDataIntegrity(old, signer)).rejects.toThrow(/already carries a proof/);
    await expect(signDataIntegrity({ issuer: 'did:web:x' }, signer)).rejects.toThrow(/not the issuer/);
    await expect(signDataIntegrity({ issuer: ISSUER }, { did: ISSUER, kid: '', sign: signer.sign.bind(signer) })).rejects.toThrow(/fragment/);
    await expect(signDataIntegrity({ issuer: ISSUER }, { did: ISSUER, kid: 'k', sign: async () => new Uint8Array(3) })).rejects.toThrow(/64-byte/);
  });
});
