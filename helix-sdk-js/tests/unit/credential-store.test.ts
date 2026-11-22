// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the SDK's CredentialStore and the owner-signed attestation path.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CredentialStore,
  signAttestationDocument,
  type BitstringStatusEntry,
  type CredentialSigner,
  type StoredCredential,
} from '../../src/index.js';
import { base58btcDecode, toCanonicalJson } from '../../src/core/vp-crypto.js';
import { derivePublicKey, publicKeyToMultibase } from '../../src/core/keys.js';

const OWNER_KEY = '5'.repeat(64);
const OWNER_DID = `did:key:${publicKeyToMultibase(derivePublicKey(OWNER_KEY))}`;
const AGENT_DID = 'did:key:z6MkAgent';
const RESOURCE = 'did:web:service.example:orders';

/** A Signer over a key held only here: the SDK never sees it, only the bytes to sign. */
function signer(privateKeyHex: string, did: string, kid = 'key-1'): CredentialSigner & { calls: number } {
  const s = {
    did,
    kid,
    calls: 0,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      s.calls += 1;
      return ed25519.sign(data, privateKeyHex);
    },
  };
  return s;
}

const entry = (index: number): BitstringStatusEntry => ({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: 'https://helix.example/status/1' });

function identity(agentDid = AGENT_DID): StoredCredential {
  return { id: 'urn:uuid:identity', type: ['VerifiableCredential', 'AgentIdentityCredential'], issuer: 'did:web:helix.example', credentialSubject: { id: agentDid, name: 'agent', responsibleParty: OWNER_DID } };
}

function hop(id: string, invoker: string, parent: string, issuer = 'did:key:z6MkParent', target = RESOURCE): StoredCredential {
  return {
    id,
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer,
    validUntil: '2027-01-01T00:00:00Z',
    credentialSubject: { id, invoker, parentCapability: parent, invocationTarget: target, allowedAction: ['read:orders'] },
  };
}

function attestation(id: string, capability: string): StoredCredential {
  return { id, type: ['VerifiableCredential', 'CapabilityAttestationCredential'], issuer: OWNER_DID, credentialSubject: { id: AGENT_DID, capability } };
}

/** Verifies an eddsa-jcs-2022 proof the way helix-core does, from the document alone. */
function proofHolds(document: Record<string, unknown>, publicKeyHex: string): boolean {
  const { proof, ...unsecured } = document as { proof: Record<string, unknown> };
  const { proofValue, ...options } = proof;
  const config = unsecured['@context'] === undefined ? options : { ...options, '@context': unsecured['@context'] };
  const data = new Uint8Array(64);
  data.set(sha256(utf8ToBytes(toCanonicalJson(config))), 0);
  data.set(sha256(utf8ToBytes(toCanonicalJson(unsecured))), 32);
  return ed25519.verify(base58btcDecode((proofValue as string).slice(1)), data, publicKeyHex);
}

describe('CredentialStore', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  it('holds identity, attestations and hops apart, routes by type, and round-trips through JSON', () => {
    const store = new CredentialStore();
    expect(store.identity).toBeNull();
    expect(store.agentDid).toBeUndefined();
    store.add(identity()).add(attestation('a1', 'read:orders')).add(hop('urn:zcap:root', AGENT_DID, RESOURCE));
    expect(store.agentDid).toBe(AGENT_DID);
    expect(store.attestations).toHaveLength(1);
    expect(store.hops).toHaveLength(1);
    expect(() => store.add({ id: 'x', type: ['VerifiableCredential', 'HelixAgentCredential'], issuer: 'did:x', credentialSubject: {} })).toThrow('not an identity');
    expect(() => store.add({ id: 'x', type: 'VerifiableCredential' as unknown as string[], issuer: 'did:x', credentialSubject: {} })).toThrow('not an identity');
    expect(() => store.setIdentity(attestation('a', 'x'))).toThrow('not an AgentIdentityCredential');
    expect(() => store.addAttestation(identity())).toThrow('not a CapabilityAttestationCredential');
    expect(() => store.addHop(identity())).toThrow('not a DelegationCredential');
    const copy = CredentialStore.fromJSON(JSON.stringify(store.toJSON()));
    expect(copy.toJSON()).toEqual(store.toJSON());
    expect(CredentialStore.fromJSON(store.toJSON()).hops).toHaveLength(1);
    const onboarded = CredentialStore.fromOnboarding({ identity: identity(), attestations: [attestation('a1', 'read:orders')] });
    expect(onboarded.attestedCapabilities()).toEqual(['read:orders']);
    expect(CredentialStore.fromOnboarding({ identity: identity() }).attestations).toEqual([]);
    expect(new CredentialStore({ identity: { ...identity(), credentialSubject: { name: 'no id' } } }).agentDid).toBeUndefined();
  });

  it('replaces a credential with the same id, removes attestations by capability and hops by id', () => {
    const store = new CredentialStore({ identity: identity() });
    store.addAttestation(attestation('a1', 'read:orders')).addAttestation(attestation('a2', 'read:orders')).addAttestation(attestation('a3', 'write:orders'));
    store.addAttestation({ ...attestation('a3', 'write:orders'), issuer: 'did:web:helix.example' });
    expect(store.attestations).toHaveLength(3);
    expect(store.attestations[2]!.issuer).toBe('did:web:helix.example');
    expect(store.attestedCapabilities()).toEqual(['read:orders', 'write:orders']);
    expect(store.removeAttestation('read:orders')).toBe(2);
    expect(store.removeAttestation('read:orders')).toBe(0);
    expect(store.attestedCapabilities()).toEqual(['write:orders']);
    store.addAttestation({ ...attestation('a4', 'x'), credentialSubject: { id: AGENT_DID } });
    expect(store.attestedCapabilities()).toEqual(['write:orders']);
    store.addHop(hop('urn:zcap:root', AGENT_DID, RESOURCE));
    store.addHop({ ...hop('urn:zcap:root', AGENT_DID, RESOURCE), validUntil: '2026-06-01T00:00:00Z' });
    expect(store.hops).toHaveLength(1);
    expect(store.removeHop('urn:zcap:root')).toBe(true);
    expect(store.removeHop('urn:zcap:root')).toBe(false);
  });

  describe('presentChain', () => {
    it('returns the identity and the hops root to leaf that delegate to the agent', () => {
      const store = new CredentialStore({ identity: identity() });
      store.addHop(hop('urn:zcap:root', 'did:key:z6MkParent', RESOURCE, 'did:key:z6MkUser'));
      store.addHop(hop('urn:zcap:leaf', AGENT_DID, 'urn:zcap:root'));
      const chain = store.presentChain();
      expect(chain.identity.id).toBe('urn:uuid:identity');
      expect(chain.hops.map((h) => h.id)).toEqual(['urn:zcap:root', 'urn:zcap:leaf']);
      expect(store.presentChain({ invocationTarget: RESOURCE }).hops).toHaveLength(2);
      expect(store.presentChain({ invocationTarget: 'did:web:other' }).hops).toEqual([]);
    });

    it('picks the latest chain for the agent, reads a controller as the delegate, and refuses what does not link up', () => {
      const store = new CredentialStore({ identity: identity() });
      store.addHop(hop('urn:zcap:r1', AGENT_DID, RESOURCE));
      store.addHop({ ...hop('urn:zcap:r2', AGENT_DID, 'did:web:other', 'did:key:z6MkOther', 'did:web:other'), credentialSubject: { id: 'urn:zcap:r2', controller: AGENT_DID, parentCapability: 'did:web:other', invocationTarget: 'did:web:other', allowedAction: [] } });
      expect(store.presentChain().hops.map((h) => h.id)).toEqual(['urn:zcap:r2']);
      expect(store.presentChain({ invocationTarget: RESOURCE }).hops.map((h) => h.id)).toEqual(['urn:zcap:r1']);
      store.addHop(hop('urn:zcap:orphan', AGENT_DID, 'urn:zcap:missing'));
      expect(() => store.presentChain()).toThrow('names a parent capability the store does not hold');
      const loop = new CredentialStore({ identity: identity() });
      loop.addHop(hop('urn:zcap:a', 'did:key:z6MkB', 'urn:zcap:b'));
      loop.addHop(hop('urn:zcap:b', AGENT_DID, 'urn:zcap:a'));
      expect(() => loop.presentChain()).toThrow('does not terminate at a root');
      expect(() => new CredentialStore().presentChain()).toThrow('no identity credential stored');
      const noDelegate = new CredentialStore({ identity: identity() });
      noDelegate.addHop({ ...hop('urn:zcap:x', AGENT_DID, RESOURCE), credentialSubject: { id: 'urn:zcap:x', parentCapability: RESOURCE, invocationTarget: RESOURCE, allowedAction: [] } });
      expect(noDelegate.presentChain().hops).toEqual([]);
    });
  });

  describe('signAttestations (the owner path)', () => {
    it('signs one attestation per capability with the owner Signer, stores them, sends nothing, and never sees a key', async () => {
      const store = new CredentialStore({ identity: identity() });
      const owner = signer(OWNER_KEY, OWNER_DID);
      const signed = await store.signAttestations(['read:orders', 'read:catalog'], owner, {
        validUntil: '2026-12-31T00:00:00Z',
        validFrom: '2026-01-01T00:00:00Z',
        statusEntries: [entry(1), entry(2)],
        ids: ['urn:uuid:a1', 'urn:uuid:a2'],
        created: '2026-01-01T00:00:00Z',
      });
      expect(signed.map((a) => a.credentialSubject)).toEqual([
        { id: AGENT_DID, capability: 'read:orders' },
        { id: AGENT_DID, capability: 'read:catalog' },
      ]);
      expect(signed[0]).toMatchObject({ id: 'urn:uuid:a1', issuer: OWNER_DID, validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-12-31T00:00:00Z', credentialStatus: entry(1), type: ['VerifiableCredential', 'CapabilityAttestationCredential'] });
      expect(signed[0]!.proof).toMatchObject({ type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-01-01T00:00:00Z', verificationMethod: `${OWNER_DID}#key-1`, proofPurpose: 'assertionMethod' });
      expect(proofHolds(signed[0]!, derivePublicKey(OWNER_KEY))).toBe(true);
      expect(proofHolds({ ...signed[1]!, validUntil: '2030-01-01T00:00:00Z' }, derivePublicKey(OWNER_KEY))).toBe(false);
      expect(store.attestedCapabilities()).toEqual(['read:orders', 'read:catalog']);
      // Self-custody invariant: no request left this process, and the signer was asked for bytes only.
      expect(fetch).not.toHaveBeenCalled();
      expect(owner.calls).toBe(2);
      expect(JSON.stringify(signed)).not.toContain(OWNER_KEY);
    });

    it('defaults ids, validFrom and created, takes an explicit subject, and refuses bad input', async () => {
      const store = new CredentialStore();
      const owner = signer(OWNER_KEY, OWNER_DID, '#key-1');
      const [signed] = await store.signAttestations(['read:orders'], owner, { subjectDid: AGENT_DID, validUntil: '2026-12-31T00:00:00Z', statusEntries: [entry(1)] });
      expect(signed!.id).toMatch(/^urn:uuid:/);
      expect(signed!.proof.verificationMethod).toBe(`${OWNER_DID}#key-1`);
      expect(Date.parse(signed!.validFrom)).toBeGreaterThan(0);
      await expect(store.signAttestations(['read:orders'], owner, { validUntil: 'x', statusEntries: [entry(1)] })).rejects.toThrow('subjectDid is required');
      await expect(store.signAttestations(['a', 'b'], owner, { subjectDid: AGENT_DID, validUntil: 'x', statusEntries: [entry(1)] })).rejects.toThrow('one status entry per capability');
      await expect(store.signAttestations(['read orders'], owner, { subjectDid: AGENT_DID, validUntil: 'x', statusEntries: [entry(1)] })).rejects.toThrow('capability must be');
      const short: CredentialSigner = { did: OWNER_DID, kid: 'key-1', sign: async () => new Uint8Array(3) };
      await expect(store.signAttestations(['read:orders'], short, { subjectDid: AGENT_DID, validUntil: 'x', statusEntries: [entry(1)] })).rejects.toThrow('64-byte');
      await expect(signAttestationDocument({ issuer: 'did:web:other' }, owner, 'now')).rejects.toThrow('is not the issuer');
      // A document without @context signs over its proof options alone.
      const bare = await signAttestationDocument({ issuer: OWNER_DID, id: 'urn:uuid:bare' }, owner, '2026-01-01T00:00:00Z');
      expect(proofHolds(bare, derivePublicKey(OWNER_KEY))).toBe(true);
    });
  });
});

describe('cross-implementation: the helix-core credential fixture', () => {
  const fixturesDir = process.env['HELIX_CORE_FIXTURES_DIR'] ?? join(fileURLToPath(new URL('../../../../helix-core/fixtures/', import.meta.url)));
  const path = join(fixturesDir, 'kya-os-helix/credentials.json');
  const available = existsSync(path);

  it.skipIf(!available)('signs the owner-signed attestation of fixtures/kya-os-helix/credentials.json byte for byte', async () => {
    const fixture = JSON.parse(readFileSync(path, 'utf8')) as {
      keys: Record<string, { private_key_hex: string; did: string }>;
      attestations: { name: string; signer: string; input: { subjectDid: string; capability: string; validUntil: string; id: string; validFrom: string; proofCreated: string }; credential: Record<string, unknown> & { credentialStatus: BitstringStatusEntry } }[];
    };
    const ownerSigned = fixture.attestations.find((a) => a.signer === 'owner')!;
    const owner = fixture.keys['owner']!;
    const store = new CredentialStore();
    const [signed] = await store.signAttestations([ownerSigned.input.capability], signer(owner.private_key_hex, owner.did), {
      subjectDid: ownerSigned.input.subjectDid,
      validUntil: ownerSigned.input.validUntil,
      validFrom: ownerSigned.input.validFrom,
      statusEntries: [ownerSigned.credential.credentialStatus],
      ids: [ownerSigned.input.id],
      created: ownerSigned.input.proofCreated,
    });
    expect(signed).toEqual(ownerSigned.credential);
    expect(store.presentChain.bind(store)).toThrow('no identity credential stored');
  });
});
