// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import { digestBytes } from '../../../src/audit/digest.js';
import {
  AuditEvidenceError,
  EvidenceEncryptor,
  MemoryEvidenceStore,
  assertEvidenceMatchesRef,
  evidenceAad,
  type EncryptedEvidence,
} from '../../../src/audit/evidence.js';
import type { EvidenceRef, PartyRef } from '../../../src/audit/types.js';
import { auditEventsFixture, describeFixture } from './fixtures.js';

const TENANT: PartyRef = { kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-v1' };
const KEY_HEX = '6d7d51f0ff998063f440f7891c0a2832346aaf1008884df5c4a4c254ef9479b5';
const aad = evidenceAad(TENANT, 'tool.call.arguments');

describeFixture('fixture evidence', () => {
  const { evidence } = auditEventsFixture();
  const encryptor = new EvidenceEncryptor({ key: evidence.key_hex, keyId: evidence.key_id });
  const ciphertext = Uint8Array.from(Buffer.from(evidence.ciphertext_b64url, 'base64url'));
  const ref = evidence.ref as unknown as EvidenceRef;
  const tenant = evidence.tenant as PartyRef;

  it('derives the authenticated data as JCS({purpose, tenant})', () => {
    expect(Buffer.from(evidenceAad(tenant, evidence.purpose)).toString('utf8')).toBe(evidence.aad_utf8);
  });

  it('decrypts with the right tenant and purpose', () => {
    const plaintext = encryptor.decrypt({ ref, ciphertext }, evidenceAad(tenant, evidence.purpose));
    expect(Buffer.from(plaintext).toString('utf8')).toBe(evidence.plaintext_utf8);
    expect(ref.plaintextCommitment).toBe(digestBytes(plaintext));
    expect(ref.ciphertextDigest).toBe(digestBytes(ciphertext));
    expect(ref.size).toBe(String(ciphertext.byteLength));
  });

  it('refuses the wrong purpose, the wrong tenant and a flipped byte', () => {
    expect(() => encryptor.decrypt({ ref, ciphertext }, evidenceAad(tenant, evidence.wrong_purpose))).toThrow(AuditEvidenceError);
    expect(() => encryptor.decrypt({ ref, ciphertext }, evidenceAad(evidence.wrong_tenant as PartyRef, evidence.purpose))).toThrow(
      'authenticated data does not match',
    );
    const flipped = Uint8Array.from(ciphertext);
    flipped[0] = flipped[0]! ^ 0x01;
    expect(() => encryptor.decrypt({ ref, ciphertext: flipped }, evidenceAad(tenant, evidence.purpose))).toThrow('does not match its reference');
    expect(() => assertEvidenceMatchesRef({ ref, ciphertext: flipped })).toThrow(AuditEvidenceError);
  });

  it('re-encrypts to the identical reference and ciphertext given the fixture nonce and object id', () => {
    const stream = [Buffer.from(ref.encryption.nonce, 'base64url'), Buffer.from(ref.objectId.slice('evi_'.length), 'base64url')];
    const deterministic = new EvidenceEncryptor({ key: evidence.key_hex, keyId: evidence.key_id, randomBytes: () => Uint8Array.from(stream.shift()!) });
    const encrypted = deterministic.encrypt({
      plaintext: evidence.plaintext_utf8,
      mediaType: evidence.media_type,
      aad: evidenceAad(tenant, evidence.purpose),
      commitPlaintext: true,
    });
    expect(encrypted.ref).toEqual(ref);
    expect(Buffer.from(encrypted.ciphertext).toString('base64url')).toBe(evidence.ciphertext_b64url);
  });
});

describe('EvidenceEncryptor', () => {
  it('takes a 32-byte key, raw or hex, and a key id', () => {
    expect(new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k' }).keyId).toBe('k');
    expect(new EvidenceEncryptor({ key: Buffer.from(KEY_HEX, 'hex'), keyId: 'k' }).keyId).toBe('k');
    expect(() => new EvidenceEncryptor({ key: 'not-hex', keyId: 'k' })).toThrow(TypeError);
    expect(() => new EvidenceEncryptor({ key: new Uint8Array(16), keyId: 'k' })).toThrow('32 bytes');
    expect(() => new EvidenceEncryptor({ key: KEY_HEX, keyId: '' })).toThrow('keyId must be non-empty');
  });

  it('encrypts with fresh randomness: an opaque id, a 12-byte nonce, ciphertext || tag, and the AAD digest', () => {
    const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });
    const a = encryptor.encrypt({ plaintext: 'hello', mediaType: 'text/plain', aad });
    const b = encryptor.encrypt({ plaintext: Buffer.from('hello'), mediaType: 'text/plain', aad });
    expect(a.ref.objectId).toMatch(/^evi_[A-Za-z0-9_-]{22}$/);
    expect(a.ref.objectId).not.toBe(b.ref.objectId);
    expect(a.ref.encryption).toMatchObject({ suite: 'A256GCM', keyId: 'k1', aadDigest: digestBytes(aad) });
    expect(Buffer.from(a.ref.encryption.nonce, 'base64url')).toHaveLength(12);
    expect(a.ciphertext).toHaveLength(5 + 16);
    expect(a.ref.size).toBe('21');
    expect(a.ref.mediaType).toBe('text/plain');
    expect(a.ref.plaintextCommitment).toBeUndefined();
    expect(a.ref.ciphertextDigest).toBe(digestBytes(a.ciphertext));
    expect(Object.isFrozen(a.ref)).toBe(true);
    expect(Buffer.from(encryptor.decrypt(a, aad)).toString('utf8')).toBe('hello');
    expect(Buffer.from(encryptor.decrypt(b, aad)).toString('utf8')).toBe('hello');
  });

  it('commits to the plaintext on request', () => {
    const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });
    const committed = encryptor.encrypt({ plaintext: 'hello', mediaType: 'text/plain', aad, commitPlaintext: true });
    expect(committed.ref.plaintextCommitment).toBe(digestBytes(Buffer.from('hello')));
    expect(Buffer.from(encryptor.decrypt(committed, aad)).toString('utf8')).toBe('hello');
    const wrongCommitment = { ciphertext: committed.ciphertext, ref: { ...committed.ref, plaintextCommitment: digestBytes(Buffer.from('other')) } };
    expect(() => encryptor.decrypt(wrongCommitment, aad)).toThrow('does not match its commitment');
  });

  it('refuses empty authenticated data on both sides', () => {
    const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });
    expect(() => encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad: new Uint8Array(0) })).toThrow('requires tenant-scoped authenticated data');
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad });
    expect(() => encryptor.decrypt(object, new Uint8Array(0))).toThrow('requires tenant-scoped authenticated data');
  });

  it('refuses another suite or key id, a ciphertext that does not match, and a ciphertext shorter than its tag', () => {
    const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad });
    expect(() => encryptor.decrypt({ ...object, ref: { ...object.ref, encryption: { ...object.ref.encryption, keyId: 'k2' } } }, aad)).toThrow(
      'another suite or key',
    );
    expect(() =>
      encryptor.decrypt({ ...object, ref: { ...object.ref, encryption: { ...object.ref.encryption, suite: 'XCHACHA' as 'A256GCM' } } }, aad),
    ).toThrow(AuditEvidenceError);
    expect(() => encryptor.decrypt({ ...object, ref: { ...object.ref, size: '1' } }, aad)).toThrow('does not match its reference');
    const short = Uint8Array.from([1, 2, 3]);
    const shortRef: EvidenceRef = { ...object.ref, ciphertextDigest: digestBytes(short), size: '3' };
    expect(() => encryptor.decrypt({ ref: shortRef, ciphertext: short }, aad)).toThrow('shorter than its authentication tag');
  });

  it('refuses a ciphertext under another key with the same key id (AEAD failure)', () => {
    const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });
    const other = new EvidenceEncryptor({ key: 'ff'.repeat(32), keyId: 'k1' });
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad });
    expect(() => other.decrypt(object, aad)).toThrow('AEAD verification failed');
    const error = (() => {
      try {
        other.decrypt(object, aad);
      } catch (thrown) {
        return thrown as AuditEvidenceError;
      }
      return undefined;
    })();
    expect(error).toBeInstanceOf(AuditEvidenceError);
    expect(error?.code).toBe('AUDIT_EVIDENCE_INVALID');
    expect(error?.httpStatus).toBe(400);
    expect(error?.name).toBe('AuditEvidenceError');
  });
});

describe('MemoryEvidenceStore', () => {
  const encryptor = new EvidenceEncryptor({ key: KEY_HEX, keyId: 'k1' });

  it('stores an object once, returns the existing reference on a repeat, and refuses a collision', async () => {
    const store = new MemoryEvidenceStore();
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad });
    expect(await store.putIfAbsent(object)).toBe(object.ref);
    expect(await store.putIfAbsent({ ref: { ...object.ref }, ciphertext: object.ciphertext })).toBe(object.ref);
    const other = encryptor.encrypt({ plaintext: 'y', mediaType: 't', aad });
    const collision: EncryptedEvidence = { ref: { ...other.ref, objectId: object.ref.objectId }, ciphertext: other.ciphertext };
    await expect(store.putIfAbsent(collision)).rejects.toThrow('collision');
  });

  it('refuses bytes that do not match their reference, and answers null for an unknown id', async () => {
    const store = new MemoryEvidenceStore();
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 't', aad });
    await expect(store.putIfAbsent({ ref: object.ref, ciphertext: Uint8Array.from([9]) })).rejects.toThrow('do not match');
    expect(await store.get('evi_missing')).toBeNull();
    await store.putIfAbsent(object);
    const found = await store.get(object.ref.objectId);
    expect(found).toEqual(object);
    // Copies, not the stored bytes.
    found!.ciphertext[0] = found!.ciphertext[0]! ^ 0xff;
    expect((await store.get(object.ref.objectId))!.ciphertext).toEqual(object.ciphertext);
  });
});
