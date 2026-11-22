// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Story L3-C on the SDK side: status-list readers (proof before bits, both
 * formats, both proof suites), the keeper, the revocation checker (fail
 * closed, cached, stale reads demoted), the chain walk, the status cache and
 * the revocation signal (RFC 8417 SET).
 */

import { describe, expect, it } from 'vitest';
import { signJws, verifier } from '../../../../src/core/kyaos/index.js';
import {
  bitsWith,
  encodeBits,
  entryFor,
  makeIssuer,
  resolveDidKey,
  servingFetch,
  signDataIntegrity,
  signLegacy,
  signedList,
  unsignedList,
} from './revocation-helpers.js';
import { fixtureSeams, haveVerifierFixtures, loadCases, loadEnvironment } from './harness.js';

const { ReasonCodes } = verifier;
const URL_A = 'https://status.example.com/v1/status-list/a';
const NOW = Date.parse('2026-06-01T00:00:00Z');

async function readError(promise: Promise<unknown>): Promise<verifier.StatusListError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(verifier.StatusListError);
    return error as verifier.StatusListError;
  }
  throw new Error('expected the read to fail');
}

describe('status-list readers', () => {
  const issuer = makeIssuer();
  const other = makeIssuer();
  const options = { resolveDid: resolveDidKey };

  it('reads a signed Bitstring list: proof verified, bits MSB first, window and purpose kept', async () => {
    const read = await verifier.readBitstringStatusList(signedList({ url: URL_A, issuer, bits: bitsWith(4, [3]) }), options);
    expect(read).toMatchObject({ issuer: issuer.did, statusPurpose: 'revocation', id: URL_A, fresh: true, proofVerified: true });
    expect(verifier.readStatusBit(read.bits, 3)).toBe(1);
    expect(verifier.readStatusBit(read.bits, 4)).toBe(0);
    expect(read.validFrom).toBe('2026-01-01T00:00:00Z');
    expect(read.validUntil).toBe('2027-01-01T00:00:00Z');
  });

  it('reads a Bitstring list with several purposes, and one stated with bare base64url', async () => {
    const list = unsignedList({ url: URL_A, issuer, purpose: ['revocation', 'suspension'] });
    (list['credentialSubject'] as Record<string, unknown>)['encodedList'] = encodeBits(bitsWith(2), false);
    const read = await verifier.readStatusListCredential(signDataIntegrity(list, issuer), { ...options, fresh: false });
    expect(read.statusPurpose).toEqual(['revocation', 'suspension']);
    expect(read.fresh).toBe(false);
  });

  it('reads a StatusList2021 list under both proof suites; Helix never issues one', async () => {
    const list = unsignedList({ url: URL_A, issuer, format: 'statuslist2021', bits: bitsWith(2, [9]), validUntil: '2027-01-01T00:00:00Z' });
    for (const signed of [signDataIntegrity(list, issuer), signLegacy(list, issuer)]) {
      const read = await verifier.readStatusList2021(signed, options);
      expect(read).toMatchObject({ issuer: issuer.did, statusPurpose: 'revocation', validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' });
      expect(verifier.readStatusBit(read.bits, 9)).toBe(1);
    }
  });

  it('never reads an unsigned list, one with a bad proof, or one signed by another key', async () => {
    expect((await readError(verifier.readBitstringStatusList(unsignedList({ url: URL_A, issuer }), options))).code).toBe(ReasonCodes.STATUS_LIST_PROOF_INVALID);
    const tampered = signedList({ url: URL_A, issuer });
    (tampered['credentialSubject'] as Record<string, unknown>)['encodedList'] = encodeBits(bitsWith(16, [1]));
    const bad = await readError(verifier.readBitstringStatusList(tampered, options));
    expect(bad.code).toBe(ReasonCodes.STATUS_LIST_PROOF_INVALID);
    expect(bad.message).toMatch(/signature_invalid/);
    const forged = signDataIntegrity(unsignedList({ url: URL_A, issuer }), other);
    expect((await readError(verifier.readBitstringStatusList(forged, options))).message).toMatch(/proof_issuer_mismatch/);
    const legacyForged = signLegacy(unsignedList({ url: URL_A, issuer, format: 'statuslist2021' }), other);
    expect((await readError(verifier.readStatusList2021(legacyForged, options))).code).toBe(ReasonCodes.STATUS_LIST_PROOF_INVALID);
  });

  it('refuses proofs it cannot check', async () => {
    const list = unsignedList({ url: URL_A, issuer });
    expect((await readError(verifier.readBitstringStatusList({ ...list, proof: 'x' }, options))).message).toMatch(/no single proof object/);
    expect((await readError(verifier.readBitstringStatusList({ ...list, proof: { type: 'RsaSignature2018' } }, options))).message).toMatch(/not one a status list/);
    expect((await readError(verifier.readBitstringStatusList({ ...list, issuer: 'nobody', proof: { type: 'DataIntegrityProof' } }, options))).message).toMatch(/no issuer DID/);
    const legacy = signLegacy(unsignedList({ url: URL_A, issuer, format: 'statuslist2021' }), issuer);
    const throwing: verifier.DidResolver = async () => {
      throw new Error('resolver down');
    };
    expect((await readError(verifier.readStatusList2021(legacy, { resolveDid: throwing }))).message).toMatch(/resolver down/);
    expect((await readError(verifier.readStatusList2021(legacy, { resolveDid: async () => null }))).message).toMatch(/did not resolve/);
  });

  it('refuses lists of the wrong shape before looking at their proof', async () => {
    const malformed = async (document: unknown, read = verifier.readBitstringStatusList): Promise<string> => {
      const error = await readError(read(document, options));
      expect(error.code).toBe(ReasonCodes.STATUS_LIST_MALFORMED);
      return error.message;
    };
    expect(await malformed(null)).toMatch(/not a JSON object/);
    expect(await malformed(signedList({ url: URL_A, issuer, format: 'statuslist2021' }))).toMatch(/BitstringStatusListCredential/);
    expect(await malformed(signedList({ url: URL_A, issuer }), verifier.readStatusList2021)).toMatch(/StatusList2021Credential/);
    expect(await malformed({ type: ['VerifiableCredential'], credentialSubject: {} }, verifier.readStatusListCredential)).toMatch(/neither/);
    expect(await malformed(signedList({ url: URL_A, issuer, purpose: [] }))).toMatch(/statusPurpose/);
    expect(await malformed(signedList({ url: URL_A, issuer, format: 'statuslist2021', purpose: ['revocation'] }), verifier.readStatusList2021)).toMatch(/one statusPurpose/);
    const noList = unsignedList({ url: URL_A, issuer });
    delete (noList['credentialSubject'] as Record<string, unknown>)['encodedList'];
    expect(await malformed(signDataIntegrity(noList, issuer))).toMatch(/encodedList/);
    expect(await malformed(signDataIntegrity({ ...unsignedList({ url: URL_A, issuer }), id: 7 }, issuer))).toMatch(/id is not a string/);
    expect(await malformed(signedList({ url: URL_A, issuer, validUntil: '2027-02-30T00:00:00Z' }))).toMatch(/validUntil is not/);
    expect(await malformed(signedList({ url: URL_A, issuer, validFrom: '2026-01-01' }))).toMatch(/validFrom is not/);
    const notGzip = unsignedList({ url: URL_A, issuer });
    (notGzip['credentialSubject'] as Record<string, unknown>)['encodedList'] = `u${Buffer.from('plain').toString('base64url')}`;
    expect(await malformed(signDataIntegrity(notGzip, issuer))).toMatch(/does not inflate/);
  });

  it('knows a calendar date-time from one no calendar has', () => {
    expect(verifier.isCalendarDateTime('2028-02-29T00:00:00+05:30')).toBe(true);
    expect(verifier.isCalendarDateTime('2027-02-29T00:00:00Z')).toBe(false);
    expect(verifier.isCalendarDateTime('2027-01-01T00:00:60Z')).toBe(false);
    expect(verifier.isCalendarDateTime('2027-01-01T00:00:00')).toBe(false);
    expect(verifier.statusListFormat('x')).toBeUndefined();
    expect(verifier.statusListFormat({ type: 'x', credentialSubject: {} })).toBeUndefined();
  });

  it('createStatusListFetcher reads over the injected fetch and fails closed when it cannot', async () => {
    const fetcher = servingFetch(new Map<string, unknown>([[URL_A, signedList({ url: URL_A, issuer })], ['https://down.example/l', 503]]));
    const fetchStatusList = verifier.createStatusListFetcher({ fetch: fetcher, resolveDid: resolveDidKey });
    expect((await fetchStatusList(URL_A))?.proofVerified).toBe(true);
    const unavailable = await readError(fetchStatusList('https://down.example/l'));
    expect(unavailable.code).toBe(ReasonCodes.STATUS_UNAVAILABLE);
    expect(unavailable.message).toMatch(/503/);
    const throwing = verifier.createStatusListFetcher({
      fetch: async () => {
        throw new Error('refused: private address');
      },
      resolveDid: resolveDidKey,
    });
    expect((await readError(throwing(URL_A))).message).toMatch(/private address/);
  });
});

describe('keeper', () => {
  it('decides by exact URL, then origin, then pinned root, then the credential issuer', () => {
    const config = verifier.statusConfiguration({
      statusListIssuers: { 'did:web:svc': ['https://svc.example'], 'did:web:exact': ['https://svc.example/one'] },
      trustedRootIssuer: 'did:web:root',
      trustedRootStatusList: 'https://root.example/l',
    });
    expect(verifier.keeper('https://svc.example/one', 'did:web:o', config)).toEqual({ did: 'did:web:exact', unbound: false });
    expect(verifier.keeper('https://svc.example/two', 'did:web:o', config)).toEqual({ did: 'did:web:svc', unbound: false });
    expect(verifier.keeper('https://svc.example.evil/x', 'did:web:o', config)).toEqual({ did: 'did:web:o', unbound: true });
    expect(verifier.keeper('https://root.example/l', 'did:web:o', config)).toEqual({ did: 'did:web:root', unbound: true });
    expect(verifier.mayOmitListId('https://o.example/l', 'did:web:o', config)).toBe(false);
    expect(verifier.mayOmitListId('https://o.example/l', 'did:web:o', verifier.NO_STATUS_CONFIGURATION)).toBe(true);
    expect(verifier.mayOmitListId('https://o.example/l', 'did:web:o', verifier.statusConfiguration({ trustedRootIssuer: 'did:web:o' }))).toBe(true);
    expect(verifier.mayOmitListId('https://o.example/l', 'did:web:o', verifier.statusConfiguration({ trustedRootIssuer: 'did:web:r' }))).toBe(false);
    expect(verifier.mayOmitListId('https://svc.example/x', 'did:web:o', config)).toBe(false);
  });
});

describe('createRevocationChecker', () => {
  const issuer = makeIssuer();
  const service = makeIssuer();

  function setup(lists: Array<[string, unknown]>, cacheOptions?: verifier.StatusCacheOptions, extra: Partial<verifier.RevocationCheckerOptions> = {}) {
    const bodies = new Map<string, unknown>(lists);
    const fetcher = servingFetch(bodies);
    let now = NOW;
    const clock = (): number => now;
    const cache = cacheOptions === undefined ? undefined : new verifier.StatusCache({ clock, ...cacheOptions });
    const checker = verifier.createRevocationChecker({ fetchStatusList: verifier.createStatusListFetcher({ fetch: fetcher, resolveDid: resolveDidKey }), cache, ...extra });
    return {
      bodies,
      fetcher,
      cache,
      advance: (seconds: number) => {
        now += seconds * 1000;
      },
      check: (index: number, overrides: Partial<verifier.RevocationSubject> = {}, scopes?: string[]) =>
        checker({ id: `urn:uuid:cred-${index}`, issuer: issuer.did, credentialStatus: entryFor(URL_A, index), ...overrides }, { now, scopes }),
    };
  }

  it('reads a clear bit live as not revoked and fresh, a set bit as revoked', async () => {
    const { check } = setup([[URL_A, signedList({ url: URL_A, issuer, bits: bitsWith(16, [5]) })]]);
    expect(await check(4)).toEqual({ revoked: false, fresh: true });
    expect(await check(5)).toMatchObject({ revoked: true, fresh: false, code: ReasonCodes.STATUS_REVOKED });
  });

  it('fails closed: unreachable, unsigned, bad proof, wrong purpose, out of range, malformed entry, outside the window', async () => {
    const tampered = signedList({ url: URL_A, issuer });
    (tampered['credentialSubject'] as Record<string, unknown>)['encodedList'] = encodeBits(bitsWith(16, [1]));
    const cases: Array<[unknown, number, Partial<verifier.RevocationSubject>, string]> = [
      [undefined, 1, {}, ReasonCodes.STATUS_UNAVAILABLE],
      [unsignedList({ url: URL_A, issuer }), 1, {}, ReasonCodes.STATUS_LIST_PROOF_INVALID],
      [tampered, 1, {}, ReasonCodes.STATUS_LIST_PROOF_INVALID],
      [signedList({ url: URL_A, issuer, purpose: 'suspension' }), 1, {}, ReasonCodes.STATUS_LIST_MISMATCH],
      [signedList({ url: URL_A, issuer, bits: bitsWith(1) }), 9, {}, ReasonCodes.STATUS_ENTRY_MALFORMED],
      [signedList({ url: URL_A, issuer, validUntil: '2026-05-01T00:00:00Z' }), 1, {}, ReasonCodes.STATUS_STALE],
      [signedList({ url: URL_A, issuer: service }), 1, {}, ReasonCodes.STATUS_LIST_MISMATCH],
      [signedList({ url: URL_A, issuer }), 1, { credentialStatus: { ...entryFor(URL_A, 1), statusSize: 2 } }, ReasonCodes.STATUS_ENTRY_MALFORMED],
      [signedList({ url: URL_A, issuer }), 1, { credentialStatus: { ...entryFor(URL_A, 1), statusListIndex: '-1' } }, ReasonCodes.STATUS_ENTRY_MALFORMED],
      [signedList({ url: URL_A, issuer }), 1, { credentialStatus: null as never }, ReasonCodes.STATUS_ENTRY_MALFORMED],
    ];
    for (const [body, index, overrides, code] of cases) {
      const { check } = setup(body === undefined ? [] : [[URL_A, body]]);
      expect(await check(index, overrides), code).toMatchObject({ revoked: true, fresh: false, code });
    }
  });

  it('holds the list to its keeper: a bound service signs for the URL, the credential issuer then may not', async () => {
    const bound = { statusListIssuers: { [service.did]: ['https://status.example.com'] } };
    const byService = setup([[URL_A, signedList({ url: URL_A, issuer: service })]], undefined, bound);
    expect(await byService.check(1)).toEqual({ revoked: false, fresh: true });
    const byIssuer = setup([[URL_A, signedList({ url: URL_A, issuer })]], undefined, bound);
    expect(await byIssuer.check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_LIST_MISMATCH });
    const noId = setup([[URL_A, signedList({ url: URL_A, issuer: service, omitId: true })]], undefined, bound);
    expect(await noId.check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_LIST_MISMATCH });
    expect(() => verifier.createRevocationChecker({ fetchStatusList: async () => undefined, statusListIssuers: { a: ['https://x/'] } })).toThrow(TypeError);
  });

  it('reads the pinned root\'s list for a hop below it only when the root\'s own entry names it (rule 3)', async () => {
    const root = makeIssuer();
    const { check } = setup([[URL_A, signedList({ url: URL_A, issuer: root })]], undefined, { trustedRootIssuer: root.did });
    const checker = verifier.createRevocationChecker({
      fetchStatusList: verifier.createStatusListFetcher({ fetch: servingFetch(new Map([[URL_A, signedList({ url: URL_A, issuer: root })]])), resolveDid: resolveDidKey }),
      trustedRootIssuer: root.did,
    });
    const hop = { id: 'urn:uuid:h', issuer: issuer.did, credentialStatus: entryFor(URL_A, 3) };
    expect(await checker(hop, { now: NOW, root: { issuer: root.did, statusListCredential: URL_A } })).toEqual({ revoked: false, fresh: true });
    expect(await checker(hop, { now: NOW, root: { issuer: root.did, statusListCredential: 'https://other.example/l' } })).toMatchObject({ revoked: true });
    expect(await check(3)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_LIST_MISMATCH });
  });

  it('serves a cached verdict and list as not fresh, and reads live again after the TTL', async () => {
    const { check, fetcher, advance } = setup([[URL_A, signedList({ url: URL_A, issuer })]], { statusCacheTtl: 120 });
    expect(await check(1)).toEqual({ revoked: false, fresh: true });
    expect(await check(1)).toEqual({ revoked: false, fresh: false });
    expect(await check(2)).toEqual({ revoked: false, fresh: false });
    expect(fetcher.calls).toHaveLength(1);
    advance(121);
    expect(await check(1)).toEqual({ revoked: false, fresh: true });
    expect(fetcher.calls).toHaveLength(2);
  });

  it('keeps a list read live earlier in the same verification live for a second credential on it', async () => {
    const fetcher = servingFetch(new Map<string, unknown>([[URL_A, signedList({ url: URL_A, issuer })]]));
    const cache = new verifier.StatusCache({ clock: () => NOW });
    const checker = verifier.createRevocationChecker({ fetchStatusList: verifier.createStatusListFetcher({ fetch: fetcher, resolveDid: resolveDidKey }), cache });
    const reads = new Map<string, verifier.StatusListRead>();
    const subject = (index: number): verifier.RevocationSubject => ({ id: `urn:uuid:r-${index}`, issuer: issuer.did, credentialStatus: entryFor(URL_A, index) });
    expect(await checker(subject(1), { now: NOW, reads })).toEqual({ revoked: false, fresh: true });
    expect(await checker(subject(2), { now: NOW, reads })).toEqual({ revoked: false, fresh: true });
    expect(fetcher.calls).toHaveLength(1);
    // The next verification has its own reads: the cache answers, not fresh.
    expect(await checker(subject(3), { now: NOW, reads: new Map() })).toEqual({ revoked: false, fresh: false });
  });

  it('holds reads for high-privilege scopes to their shorter TTL', async () => {
    const { check, fetcher, advance } = setup([[URL_A, signedList({ url: URL_A, issuer })]], { statusCacheTtl: 300, highPrivilegeScopes: ['orders:admin'] });
    await check(1, {}, ['orders:read']);
    advance(61);
    expect(await check(1, {}, ['orders:read'])).toEqual({ revoked: false, fresh: false });
    expect(await check(1, {}, ['orders:admin'])).toEqual({ revoked: false, fresh: true });
    expect(fetcher.calls).toHaveLength(2);
  });

  it('caches a revoked verdict, not an unreadable one', async () => {
    const { check, fetcher, bodies } = setup([[URL_A, signedList({ url: URL_A, issuer, bits: bitsWith(16, [1]) })]], {});
    expect(await check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_REVOKED });
    expect(await check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_REVOKED });
    expect(fetcher.calls).toHaveLength(1);
    const unread = setup([[URL_A, 500]], {});
    expect(await unread.check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_UNAVAILABLE });
    unread.bodies.set(URL_A, signedList({ url: URL_A, issuer }));
    expect(await unread.check(1)).toEqual({ revoked: false, fresh: true });
    expect(bodies.size).toBe(1);
  });

  it('serves a stale list read inside its window past its validUntil only within the staleness window, as not fresh', async () => {
    const { check, advance, cache } = setup(
      [[URL_A, signedList({ url: URL_A, issuer, validUntil: '2026-06-01T00:01:00Z' })]],
      { statusCacheTtl: 600, maxStaleSeconds: 120, maxClockSkewMs: 0 },
    );
    expect(await check(1)).toEqual({ revoked: false, fresh: true });
    advance(90);
    // Past validUntil, inside the staleness window: a cached read, allowed and not fresh (a Card L3 request becomes L2).
    expect(await check(2)).toEqual({ revoked: false, fresh: false });
    advance(120);
    // Past validUntil + staleness: the cache drops it, the live read is outside its window and refused.
    expect(await check(3)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_STALE });
    expect(cache).toBeDefined();
  });

  it('drops a credential\'s verdict and its list at once on invalidate, and every list for an unknown credential', async () => {
    const { check, fetcher, bodies, cache } = setup([[URL_A, signedList({ url: URL_A, issuer })]], { statusCacheTtl: 300 });
    expect(await check(1)).toEqual({ revoked: false, fresh: true });
    bodies.set(URL_A, signedList({ url: URL_A, issuer, bits: bitsWith(16, [1, 2]) }));
    expect(await check(1)).toEqual({ revoked: false, fresh: false });
    expect(await cache!.invalidate('urn:uuid:cred-1')).toBe('credential');
    expect(await check(1)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_REVOKED });
    expect(await cache!.invalidate('urn:uuid:never-seen')).toBe('all-lists');
    expect(await check(2)).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_REVOKED });
    // A duplicate delete is harmless.
    expect(await cache!.invalidate('urn:uuid:cred-1')).toBe('credential');
    expect(fetcher.calls.length).toBeGreaterThanOrEqual(3);
  });

  it('keeps no verdict for a credential without an id, and treats a verdict for another entry as a miss', async () => {
    const { check, fetcher } = setup([[URL_A, signedList({ url: URL_A, issuer })]], {});
    await check(1, { id: undefined });
    await check(1, { id: undefined });
    expect(fetcher.calls).toHaveLength(1);
    await check(1);
    expect(await check(1, { credentialStatus: entryFor(URL_A, 2) })).toEqual({ revoked: false, fresh: false });
  });

  it('revocationCheckerOf is F-2\'s plain reading: no cache, every read live', async () => {
    const checker = verifier.revocationCheckerOf(async () => ({ bits: bitsWith(1, [0]) }));
    expect(await checker({ issuer: 'did:web:o', credentialStatus: entryFor(URL_A, 0) }, { now: NOW })).toMatchObject({ revoked: true, code: ReasonCodes.STATUS_REVOKED });
  });
});

describe('checkChainRevocation', () => {
  const hops = [0, 1, 2].map((index) => ({ id: `urn:uuid:hop-${index}`, issuer: `did:web:i${index}`, credentialStatus: entryFor(`https://s.example/${index}`, index) }));

  it('walks root to leaf and stops at the first revoked hop', async () => {
    const seen: string[] = [];
    const result = await verifier.checkChainRevocation(
      hops,
      async (hop) => {
        seen.push(hop.id!);
        return hop.id === 'urn:uuid:hop-1' ? { revoked: true, fresh: false, code: ReasonCodes.STATUS_REVOKED, message: 'gone' } : { revoked: false, fresh: true };
      },
      { now: NOW },
    );
    expect(result).toEqual({ revoked: true, fresh: false, index: 1, code: ReasonCodes.STATUS_REVOKED, message: 'gone' });
    expect(seen).toEqual(['urn:uuid:hop-0', 'urn:uuid:hop-1']);
  });

  it('returns fresh as the AND of every read, passes the root, and turns a throwing check into status_unavailable', async () => {
    const roots: unknown[] = [];
    const mixed = await verifier.checkChainRevocation(
      hops,
      async (hop, context) => {
        roots.push(context.root);
        return { revoked: false, fresh: hop.id !== 'urn:uuid:hop-2' };
      },
      { now: NOW },
    );
    expect(mixed).toEqual({ revoked: false, fresh: false });
    expect(roots[0]).toEqual({ issuer: 'did:web:i0', statusListCredential: 'https://s.example/0' });
    expect(await verifier.checkChainRevocation(hops, async () => ({ revoked: false, fresh: true }), { now: NOW })).toEqual({ revoked: false, fresh: true });
    const thrown = await verifier.checkChainRevocation(
      hops,
      async () => {
        throw new Error('boom');
      },
      { now: NOW },
    );
    expect(thrown).toMatchObject({ revoked: true, index: 0, code: ReasonCodes.STATUS_UNAVAILABLE });
    const silent = await verifier.checkChainRevocation(hops, async () => ({ revoked: true, fresh: false }), { now: NOW });
    expect(silent.code).toBe(ReasonCodes.STATUS_REVOKED);
    expect(await verifier.checkChainRevocation([], async () => ({ revoked: true, fresh: false }), { now: NOW })).toEqual({ revoked: false, fresh: true });
  });
});

describe('StatusCache', () => {
  it('validates its settings: the high-privilege TTL is at most 60 s and at most the TTL', () => {
    expect(() => new verifier.StatusCache({ highPrivilegeTtl: 61 })).toThrow(/at most 60/);
    expect(() => new verifier.StatusCache({ statusCacheTtl: 0 })).toThrow(/positive/);
    expect(() => new verifier.StatusCache({ maxStaleSeconds: -1 })).toThrow(/non-negative/);
    expect(() => new verifier.StatusCache({ maxClockSkewMs: 700_000 })).toThrow(/600000/);
    const cache = new verifier.StatusCache({ statusCacheTtl: 30, highPrivilegeScopes: ['admin'] });
    expect(cache.highPrivilegeTtl).toBe(30);
    expect(cache.ttlFor(['admin'])).toBe(30);
    expect(new verifier.StatusCache({ highPrivilegeTtl: 10, highPrivilegeScopes: ['admin'] }).ttlFor(['admin', 'read'])).toBe(10);
    expect(new verifier.StatusCache().ttlFor()).toBe(verifier.DEFAULT_STATUS_CACHE_TTL_SECONDS);
  });

  it('keeps only live, proof-verified reads it may serve, and reads a corrupt entry as a miss', async () => {
    const store = new verifier.MemoryStatusCacheStore();
    const cache = new verifier.StatusCache({ store, clock: () => NOW });
    const read = { bits: bitsWith(2), proofVerified: true, fresh: true, validUntil: '2027-01-01T00:00:00Z' };
    await cache.setList(URL_A, { ...read, proofVerified: false });
    await cache.setList(URL_A, { ...read, fresh: false });
    await cache.setList(URL_A, { ...read, validUntil: 'not a date' });
    await cache.setList(URL_A, { ...read, validUntil: '2026-01-01T00:00:00Z' });
    expect(store.size).toBe(0);
    await cache.setList(URL_A, { bits: bitsWith(2), proofVerified: true, issuer: 'did:web:o', statusPurpose: 'revocation', id: URL_A, validFrom: '2026-01-01T00:00:00Z' });
    expect(await cache.getList(URL_A)).toMatchObject({ fresh: false, proofVerified: true, issuer: 'did:web:o', id: URL_A, validFrom: '2026-01-01T00:00:00Z' });
    await store.set(`kyaos:status:list:0:${URL_A}`, '{not json', 1000);
    expect(await cache.getList(URL_A)).toBeUndefined();
    const key = { credentialId: 'c', url: URL_A, index: '1', purpose: 'revocation', issuer: 'did:web:o', keeper: 'did:web:o' };
    await cache.setVerdict(key, { revoked: true, code: 'status_revoked', message: 'gone' });
    expect(await cache.getVerdict(key)).toEqual({ revoked: true, code: 'status_revoked', message: 'gone' });
    await store.set('kyaos:status:verdict:c', '{not json', 1000);
    expect(await cache.getVerdict(key)).toBeUndefined();
    expect(await cache.invalidate('c')).toBe('all-lists');
    // A stored verdict with no URL drops every list too.
    await store.set('kyaos:status:verdict:d', JSON.stringify({ fingerprint: 'x' }), 1000);
    expect(await cache.invalidate('d')).toBe('all-lists');
  });

  it('MemoryStatusCacheStore expires entries and counts', async () => {
    let now = 0;
    const store = new verifier.MemoryStatusCacheStore({ now: () => now });
    await store.set('k', 'v', 10);
    expect(await store.get('k')).toBe('v');
    now = 11;
    expect(await store.get('k')).toBeUndefined();
    expect(await store.increment('n')).toBe(1);
    await store.set('bad', 'x', 100);
    expect(await store.increment('bad')).toBe(1);
    await store.delete('n');
    expect(await store.get('n')).toBeUndefined();
    expect(new verifier.MemoryStatusCacheStore().size).toBe(0);
  });
});

describe('revocation signal (RFC 8417 SET)', () => {
  const helix = makeIssuer();
  const stranger = makeIssuer();
  const options = { trustedIssuers: [helix.did], resolveDid: resolveDidKey, now: NOW };

  it('signs one SET per credential carrying only its id, and verifies it', async () => {
    const set = await verifier.signRevocationSignal({ credentialId: 'urn:uuid:c1', iat: NOW / 1000, jti: 'urn:uuid:j1', aud: 'did:web:svc' }, helix.signer);
    const header = JSON.parse(Buffer.from(set.split('.')[0]!, 'base64url').toString()) as Record<string, unknown>;
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'secevent+jwt', kid: helix.kid });
    const payload = JSON.parse(Buffer.from(set.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;
    expect(payload).toEqual({
      iss: helix.did,
      iat: NOW / 1000,
      jti: 'urn:uuid:j1',
      aud: 'did:web:svc',
      events: { [verifier.REVOCATION_EVENT_TYPE]: { subject: { format: 'uri', uri: 'urn:uuid:c1' } } },
    });
    expect(await verifier.verifyRevocationSignal(set, options)).toEqual({
      ok: true,
      signal: { jti: 'urn:uuid:j1', iss: helix.did, iat: NOW / 1000, aud: 'did:web:svc', credentialId: 'urn:uuid:c1' },
    });
    const plain = await verifier.signRevocationSignal({ credentialId: 'urn:uuid:c2' }, helix.signer);
    expect(await verifier.verifyRevocationSignal(plain, { ...options, now: Date.now() })).toMatchObject({ ok: true, signal: { credentialId: 'urn:uuid:c2' } });
    await expect(verifier.signRevocationSignal({ credentialId: '' }, helix.signer)).rejects.toThrow(TypeError);
  });

  it('ignores a signal from an unknown issuer or with a bad signature', async () => {
    const foreign = await verifier.signRevocationSignal({ credentialId: 'urn:uuid:c1', iat: NOW / 1000 }, stranger.signer);
    expect(await verifier.verifyRevocationSignal(foreign, options)).toMatchObject({ ok: false, reason: verifier.SignalReasons.UNKNOWN_ISSUER });
    // Claims to be Helix, signed by another key.
    const forged = await verifier.signRevocationSignal({ credentialId: 'urn:uuid:c1', iat: NOW / 1000 }, { ...stranger.signer, did: helix.did, kid: helix.kid.split('#')[1]! });
    expect(await verifier.verifyRevocationSignal(forged, options)).toMatchObject({ ok: false, reason: verifier.SignalReasons.BAD_SIGNATURE });
    const resolverDown = await verifier.signRevocationSignal({ credentialId: 'urn:uuid:c1', iat: NOW / 1000 }, helix.signer);
    expect(
      await verifier.verifyRevocationSignal(resolverDown, {
        ...options,
        resolveDid: async () => {
          throw new Error('down');
        },
      }),
    ).toMatchObject({ ok: false, reason: verifier.SignalReasons.BAD_SIGNATURE });
  });

  it('refuses malformed SETs, wrong events and stale ones', async () => {
    const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = (header: unknown, payload: unknown): string => `${encode(header)}.${encode(payload)}.${Buffer.alloc(64).toString('base64url')}`;
    const reason = async (set: unknown): Promise<string> => {
      const verdict = await verifier.verifyRevocationSignal(set, options);
      return verdict.ok ? 'ok' : verdict.reason;
    };
    expect(await reason(42)).toBe('signal_malformed');
    expect(await reason('a.b')).toBe('signal_malformed');
    expect(await reason('!.!.!')).toBe('signal_malformed');
    expect(await reason(unsigned({ alg: 'EdDSA', kid: helix.kid }, {}))).toBe('signal_malformed');
    expect(await reason(unsigned({ alg: 'EdDSA', kid: helix.kid, typ: 'secevent+jwt' }, 'x'))).toBe('signal_malformed');
    expect(await reason(`${encode({ alg: 'EdDSA', kid: helix.kid, typ: 'secevent+jwt' })}.%%%.${Buffer.alloc(64).toString('base64url')}`)).toBe('signal_malformed');
    expect(await reason(unsigned({ alg: 'EdDSA', kid: helix.kid, typ: 'secevent+jwt' }, { iss: 'helix' }))).toBe('signal_malformed');
    const signed = async (payload: Record<string, unknown>): Promise<string> => signJws(payload, helix.signer, { header: { typ: 'secevent+jwt' } });
    const event = { [verifier.REVOCATION_EVENT_TYPE]: { subject: { format: 'uri', uri: 'urn:uuid:c' } } };
    const base = { iss: helix.did, iat: NOW / 1000, jti: 'j', events: event };
    expect(await reason(await signed({ ...base, jti: undefined }))).toBe('signal_malformed');
    expect(await reason(await signed({ ...base, events: {} }))).toBe('signal_wrong_event');
    expect(await reason(await signed({ ...base, events: { ...event, other: {} } }))).toBe('signal_wrong_event');
    expect(await reason(await signed({ ...base, events: { [verifier.REVOCATION_EVENT_TYPE]: { subject: { format: 'email', email: 'x' } } } }))).toBe('signal_wrong_event');
    expect(await reason(await signed({ ...base, iat: NOW / 1000 + 3600 }))).toBe('signal_stale');
    expect(await reason(await signed({ ...base, iat: NOW / 1000 - 2 * 86400 }))).toBe('signal_stale');
  });
});

describe('verify() with the revocation seam', () => {
  it.skipIf(!haveVerifierFixtures)('a live read gives L3, the same chain from the cache gives L2 (fresh: false); a revoked hop is refused', async () => {
    const env = loadEnvironment();
    const fixture = loadCases()['valid']!.find((entry) => entry.name === 'two_hop_chain')!;
    const plain = fixtureSeams(env, fixture.seams, fixture.now);
    const cache = new verifier.StatusCache({ clock: () => fixture.now });
    const checkRevocation = verifier.createRevocationChecker({ fetchStatusList: plain.fetchStatusList!, cache });
    const run = (seams: verifier.VerifierSeams) => verifier.verify(fixture.input as verifier.VerifierInput, seams, fixture.options as unknown as verifier.VerifierOptions);
    const live = await run({ ...fixtureSeams(env, fixture.seams, fixture.now), checkRevocation });
    expect(live).toMatchObject({ ok: true, level: 'L3', fresh: true, chainSummary: { fresh: true } });
    const cached = await run({ ...fixtureSeams(env, fixture.seams, fixture.now), checkRevocation });
    expect(cached).toMatchObject({ ok: true, level: 'L2', fresh: false, chainSummary: { fresh: false } });
    const revokedRoot: verifier.RevocationChecker = async (hop) =>
      hop.id === (fixture.input.chain as Array<{ id: string }>)[0]!.id ? { revoked: true, fresh: false, code: ReasonCodes.STATUS_REVOKED, message: 'root revoked' } : { revoked: false, fresh: true };
    const refused = await run({ ...fixtureSeams(env, fixture.seams, fixture.now), checkRevocation: revokedRoot });
    expect(refused).toMatchObject({ ok: false, reasons: [ReasonCodes.STATUS_REVOKED] });
    expect(refused.messages[0]).toMatch(/^hop 0: root revoked/);
    const noReason: verifier.RevocationChecker = async () => ({ revoked: true, fresh: false });
    expect((await run({ ...fixtureSeams(env, fixture.seams, fixture.now), checkRevocation: noReason })).messages[0]).toMatch(/hop 0: revoked/);
  });
});
