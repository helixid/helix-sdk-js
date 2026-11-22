// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Revocation checking (KYA-OS story L3-C points 2, 4 and 6; SPEC.md §6.5,
 * §6.6, §6.10).
 *
 * The {@link RevocationChecker} seam answers one question per credential,
 * `{ revoked, fresh }`, fail-closed: an unreachable, malformed, unsigned,
 * badly signed, wrong-purpose or out-of-range list, or one outside its
 * window, is `revoked: true`. `fresh` is true only for a verdict read live
 * from the list for this verification; a cached verdict or list is
 * `fresh: false`, which demotes a Card L3 request to L2.
 *
 * {@link createRevocationChecker} builds one from a `fetchStatusList` seam
 * (which verifies each list's proof before decoding it, see
 * ./status-list-reader.ts), the keeper configuration (./keeper.ts) and an
 * optional {@link StatusCache}. {@link checkChainRevocation} walks a chain
 * root to leaf with it, stops at the first revoked or unresolvable hop, and
 * returns `fresh` as the AND of every read.
 */

import { ReasonCodes, type ReasonCode } from './codes.js';
import type { BitstringStatusEntry } from './credentials.js';
import { NO_STATUS_CONFIGURATION, keeper as keeperOf, mayOmitListId, statusConfiguration, type StatusConfiguration, type StatusConfigurationInput } from './keeper.js';
import type { StatusCache } from './status-cache.js';
import { StatusListError } from './status-list-reader.js';
import { checkStatusEntry, parseStatusListIndex, type FetchStatusList, type StatusListRead } from './status.js';

/** The members of a credential a revocation check reads. */
export interface RevocationSubject {
  /** The credential id: the key a revocation signal names. */
  id?: string | undefined;
  issuer: string;
  credentialStatus: BitstringStatusEntry;
}

export interface RevocationContext {
  /** Epoch ms. */
  now: number;
  /** The scopes the request touches, which pick the cache TTL (high-privilege scopes ≤ 60 s). */
  scopes?: readonly string[] | undefined;
  /** The chain's root, when the verifier pins it and its proof verified: rule 3 of the keeper (SPEC.md §6.6). */
  root?: { issuer: string; statusListCredential?: string | undefined } | undefined;
  /**
   * The lists read live during this one verification, by URL: a second
   * credential on a list read a moment ago for the same request is read from
   * here, and stays live (`fresh`), instead of from the cache.
   */
  reads?: Map<string, StatusListRead> | undefined;
}

export interface RevocationVerdict {
  revoked: boolean;
  /** True only when the verdict was read live for this verification. */
  fresh: boolean;
  /** Why the credential reads as revoked (`status_revoked`, `status_unavailable`, ...); absent when it is not. */
  code?: ReasonCode | undefined;
  message?: string | undefined;
}

/** The seam: one credential's revocation verdict. Never throws for a bad list; every failure is `revoked: true`. */
export type RevocationChecker = (credential: RevocationSubject, context: RevocationContext) => Promise<RevocationVerdict>;

export interface RevocationCheckerOptions {
  /** Reads a list by URL, its proof verified before its bits; throws a `StatusListError` (or anything) when it cannot. */
  fetchStatusList: FetchStatusList;
  /** The cache of lists and verdicts; without one every read is live. */
  cache?: StatusCache | undefined;
  /** Clock tolerance on list windows, ms; default 120,000. */
  maxClockSkewMs?: number | undefined;
  /** Issuer DID to the exact URLs and `https:` origins bound to it (keeper rules 1 and 2). */
  statusListIssuers?: Record<string, string[]> | undefined;
  /** A pinned root issuer (keeper rule 3), when the verifier pins one. */
  trustedRootIssuer?: string | undefined;
}

const revoked = (code: ReasonCode, message: string, fresh = false): RevocationVerdict => ({ revoked: true, fresh, code, message });

/** The configuration with the chain's pinned root, when its own entry names a list, added for rule 3. */
function withRoot(base: StatusConfiguration, pinnedRoot: string | undefined, root: RevocationContext['root']): StatusConfiguration {
  if (pinnedRoot === undefined || root === undefined || root.issuer !== pinnedRoot || root.statusListCredential === undefined) return base;
  return { ...base, root: pinnedRoot, rootList: root.statusListCredential };
}

/**
 * A {@link RevocationChecker} over a `fetchStatusList` seam. Order: the
 * entry (statusSize, index), before any fetch; the keeper; a cached verdict;
 * a cached list or a live read; the entry against the list; the verdict
 * cached. Only a live, proof-verified read made inside its window is cached.
 */
export function createRevocationChecker(options: RevocationCheckerOptions): RevocationChecker {
  const base: StatusConfiguration =
    options.statusListIssuers === undefined && options.trustedRootIssuer === undefined
      ? NO_STATUS_CONFIGURATION
      : statusConfiguration({ statusListIssuers: options.statusListIssuers, trustedRootIssuer: options.trustedRootIssuer } satisfies StatusConfigurationInput);
  const cache = options.cache;
  return async (credential, context) => {
    const entry = credential.credentialStatus;
    if (entry === null || typeof entry !== 'object' || typeof entry.statusListCredential !== 'string') {
      return revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, 'the credential has no usable credentialStatus');
    }
    if (entry.statusSize !== undefined && entry.statusSize !== 1) {
      return revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, 'statusSize must be 1 for a revocation entry');
    }
    if (parseStatusListIndex(entry.statusListIndex) === undefined) {
      return revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, 'statusListIndex is not a non-negative decimal string');
    }
    const url = entry.statusListCredential;
    const config = withRoot(base, options.trustedRootIssuer, context.root);
    const kept = keeperOf(url, credential.issuer, config);
    const scopes = context.scopes ?? [];
    const verdictKey =
      cache !== undefined && typeof credential.id === 'string' && credential.id.length > 0
        ? { credentialId: credential.id, url, index: entry.statusListIndex, purpose: entry.statusPurpose, issuer: credential.issuer, keeper: kept.did }
        : undefined;

    if (verdictKey !== undefined) {
      const cached = await cache!.getVerdict(verdictKey, scopes);
      if (cached !== undefined) {
        return cached.revoked
          ? revoked((cached.code as ReasonCode | undefined) ?? ReasonCodes.STATUS_REVOKED, cached.message ?? 'cached: revoked')
          : { revoked: false, fresh: false };
      }
    }

    let read: StatusListRead | undefined = context.reads?.get(url) ?? (cache === undefined ? undefined : await cache.getList(url, scopes));
    if (read === undefined) {
      try {
        read = await options.fetchStatusList(url);
      } catch (error) {
        const code = error instanceof StatusListError ? error.code : ReasonCodes.STATUS_UNAVAILABLE;
        return revoked(code, `status list could not be read: ${(error as Error).message}`);
      }
      if (read !== undefined) {
        context.reads?.set(url, read);
        if (cache !== undefined) await cache.setList(url, read);
      }
    }
    const status = checkStatusEntry(entry, credential.issuer, read, {
      now: context.now,
      maxClockSkewMs: options.maxClockSkewMs,
      keeper: kept.did,
      mayOmitId: mayOmitListId(url, credential.issuer, config),
      // A cached list was held to its window when it was kept and is served past it only within the staleness window.
      checkWindow: read?.fresh !== false,
    });
    const verdict: RevocationVerdict = status.ok ? { revoked: false, fresh: status.fresh } : revoked(status.code, status.message);
    // Only what a live read decided is worth keeping; a list that could not be read is retried next time.
    const decided = status.ok || status.code === ReasonCodes.STATUS_REVOKED;
    if (verdictKey !== undefined && read?.fresh !== false && decided) {
      await cache!.setVerdict(verdictKey, { revoked: verdict.revoked, code: verdict.code, message: verdict.message });
    }
    return verdict;
  };
}

/** A {@link RevocationChecker} over a bare `fetchStatusList` seam, no cache, no bindings: F-2's reading. */
export function revocationCheckerOf(fetchStatusList: FetchStatusList, maxClockSkewMs?: number): RevocationChecker {
  return createRevocationChecker({ fetchStatusList, maxClockSkewMs });
}

export interface ChainRevocationResult {
  revoked: boolean;
  /** The AND of every read's `fresh`; false whenever the chain reads as revoked. */
  fresh: boolean;
  /** Index (root = 0) of the first revoked or unresolvable hop. */
  index?: number | undefined;
  code?: ReasonCode | undefined;
  message?: string | undefined;
}

/**
 * Walks `hops` root to leaf with `checker`, stopping at the first revoked or
 * unresolvable hop (cascading revocation: a revoked ancestor revokes every
 * hop below it). The root's own entry is handed to each check as rule 3's
 * pinned-root URL.
 */
export async function checkChainRevocation(
  hops: readonly RevocationSubject[],
  checker: RevocationChecker,
  context: RevocationContext,
): Promise<ChainRevocationResult> {
  const root = hops[0];
  const rootContext: RevocationContext = {
    ...context,
    ...(root === undefined ? {} : { root: { issuer: root.issuer, statusListCredential: root.credentialStatus?.statusListCredential } }),
  };
  let fresh = true;
  for (let index = 0; index < hops.length; index += 1) {
    let verdict: RevocationVerdict;
    try {
      verdict = await checker(hops[index]!, rootContext);
    } catch (error) {
      verdict = revoked(ReasonCodes.STATUS_UNAVAILABLE, `the revocation check failed: ${(error as Error).message}`);
    }
    if (verdict.revoked) {
      return { revoked: true, fresh: false, index, code: verdict.code ?? ReasonCodes.STATUS_REVOKED, message: verdict.message };
    }
    fresh &&= verdict.fresh;
  }
  return { revoked: false, fresh };
}
