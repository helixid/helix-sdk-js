// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '../../../src/index.js';
import { publicKeyToMultibase } from '../../../src/core/keys.js';
import { DEFAULT_KID_FRAGMENT, EnvSigner, defaultKidFragment, signJws, verifyJwsByKid } from '../../../src/core/kyaos/index.js';
import { didKeyDocument } from '../../../src/core/kyaos/verifier/resolve.js';
import { EnvSigner as CustodyEnvSigner, kidFragment } from '../../../src/core/custody/signer.js';

const keys = generateKeyPair();
const multibase = publicKeyToMultibase(keys.publicKey);
const DID_KEY = `did:key:${multibase}`;
const env = { K: keys.privateKey };

describe('the default kid of a signer (F-1 fix: a did:key signs as its own verification method)', () => {
  it('is the multibase value for a did:key and key-1 for any other DID', () => {
    expect(defaultKidFragment(DID_KEY)).toBe(multibase);
    expect(defaultKidFragment('did:web:helix.example')).toBe(DEFAULT_KID_FRAGMENT);
    expect(defaultKidFragment('did:key:')).toBe(DEFAULT_KID_FRAGMENT);
  });

  it('a did:key EnvSigner names did:key:z…#z…, which its did:key document defines, so a JWS verifies', async () => {
    const signer = new EnvSigner({ did: DID_KEY, envVar: 'K', env });
    expect(signer.kid).toBe(multibase);
    expect(signer.verificationMethodId).toBe(`${DID_KEY}#${multibase}`);
    const jws = await signJws({ sub: 'x' }, signer);
    const verified = await verifyJwsByKid(jws, async (did) => didKeyDocument(did));
    expect(verified.kid).toBe(`${DID_KEY}#${multibase}`);
  });

  it('an explicit kid still wins, and a did:web keeps key-1', () => {
    expect(new EnvSigner({ did: DID_KEY, kid: '#key-1', envVar: 'K', env }).kid).toBe('key-1');
    expect(new EnvSigner({ did: 'did:web:helix.example', envVar: 'K', env }).kid).toBe('key-1');
  });

  it('the custody signer and kidFragment use the same default', () => {
    expect(kidFragment(DID_KEY)).toBe(multibase);
    expect(kidFragment('did:web:helix.example')).toBe('key-1');
    expect(new CustodyEnvSigner({ did: DID_KEY, envVar: 'K', env }).kid).toBe(multibase);
  });
});
