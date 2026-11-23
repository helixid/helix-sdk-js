// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * In-process verification of every tool call (KYA-OS story F-2): the
 * middleware runs `@helixid/sdk-js`'s local verifier on the request proof
 * and the carried chain, with seams built from local config and public
 * resolution only:
 *
 * - the middleware's `NonceStore` (story L2-A; shared across instances
 *   through Redis or DynamoDB) as the replay store;
 * - DID documents over HTTPS (did:web) or offline (did:key), through an
 *   injected `fetch` where the host has a SafeFetch;
 * - status lists over HTTPS, each list's own proof verified before any bit
 *   is read, through a revocation checker that fails closed and a
 *   `StatusCache` (story L3-C: `statusCacheTtl`, `highPrivilegeScopes` held
 *   to ≤ 60 s, cached reads reported `fresh: false`), which a
 *   `RevocationSignalClient` invalidates at once on a revocation signal;
 *   in multi-instance mode the cache lives in the shared Redis;
 * - Entity Cards over HTTPS;
 * - `trustedIssuers` (default `'*'`) and `maxChainLength` (default 10).
 *
 * The Helix API is never asked: a call verifies with the API down, and a
 * credential issued by any Helix deployment verifies here from the presented
 * artifacts and public resolution alone (stories rule 4). Each verification
 * is handed to `reportVerification`, the hook story A-1's audit trail
 * connects; until it is, the default says once that verifications go
 * unrecorded.
 */

import { kyaos } from '@helixid/sdk-js';
import { MemoryNonceStore, type NonceStore } from './kyaos/nonce-store.js';
import { createResolutionFetch, type ResolverFetch } from './resolution-fetch.js';

export type { ResolverFetch } from './resolution-fetch.js';

/** What `reportVerification` receives for every local verification. */
export interface VerificationReport {
  /** ISO 8601 time the verification ran. */
  timestamp: string;
  serviceDid: string;
  toolName?: string | undefined;
  agentDid?: string | undefined;
  ok: boolean;
  level: kyaos.verifier.ConformanceLevel;
  proofAssurance?: kyaos.verifier.ProofAssurance | undefined;
  /** True when a request proof verified (story C-C); false for a call verified on its chain alone. */
  proofFloor: boolean;
  /** True when the L3 rests on a proof with no token `cnf` to fuse with (§8.6). */
  l3Minus: boolean;
  /** `cnf` diagnostics: `cnf_present_but_token_unfused` (§8.6). */
  cnfDiagnostics: string[];
  effectiveScopes: string[];
  reasons: string[];
  fresh: boolean;
  chainDepth: number;
}

export type ReportVerification = (report: VerificationReport) => void | Promise<void>;


export interface LocalVerifierOptions {
  /** This service's DID: the proof's audience and, unless `resource` is set, the chain's resource. */
  serviceDid: string;
  /** The `invocationTarget` every carried chain must name; default `serviceDid`. */
  resource?: string | undefined;
  /** When set, the root hop's issuer must be this DID. */
  resourceOwner?: string | undefined;
  /** When set, the root hop's issuer must be one of these DIDs. */
  trustedRootIssuers?: readonly string[] | undefined;
  /** `'*'` (default) trusts every attestation issuer; a list trusts those DIDs only (stories rule 9). */
  trustedIssuers?: kyaos.verifier.TrustedIssuers | undefined;
  /** The longest carried chain parsed; default 10. */
  maxChainLength?: number | undefined;
  /** Clock skew on the proof window, seconds; default 5. */
  skewSeconds?: number | undefined;
  /** Clock tolerance on credential and status-list windows, ms; default 120,000. */
  maxClockSkewMs?: number | undefined;
  /** The scopes this service offers; `effectiveScopes` is intersected with it. Default: the leaf's own. */
  catalog?: readonly string[] | undefined;
  /** The replay store; default a `MemoryNonceStore` (this instance only). Share the runtime's store across instances. */
  nonceStore?: NonceStore | undefined;
  /**
   * How DID documents, status lists and cards are fetched: the host's
   * SafeFetch (story C-A). Default: `createResolutionFetch` (https only,
   * public IP literals only, same-origin redirects, 5 s, 1 MiB).
   */
  fetch?: ResolverFetch | undefined;
  /** Development only: also read `http:` URLs on loopback hosts (a did:web on `127.0.0.1`, say). */
  allowLoopbackHttp?: boolean | undefined;
  /** A DID resolver of the host's own, in place of the built-in did:key / did:web one. */
  resolveDid?: kyaos.verifier.DidResolver | undefined;
  /** The `resolveDidKeys` seam; default: every Ed25519 key the resolved document publishes. */
  resolveDidKeys?: kyaos.verifier.VerifierSeams['resolveDidKeys'];
  /** The status-list seam; default: fetch the list at its URL, verify its proof, then decode it (story L3-C). */
  fetchStatusList?: kyaos.verifier.FetchStatusList | undefined;
  /** The revocation seam; default: a checker over `fetchStatusList` with `statusCache`. */
  checkRevocation?: kyaos.verifier.RevocationChecker | undefined;
  /**
   * The status cache (story L3-C point 6), or its options. Default: one in
   * memory with `statusCacheTtl` 300 s; pass a `RedisStatusCacheStore` as
   * `store` to share it between instances, next to the nonce store.
   */
  statusCache?: kyaos.verifier.StatusCache | kyaos.verifier.StatusCacheOptions | undefined;
  /** Issuer DID to the status-list URLs or `https:` origins bound to it (SPEC.md §6.6 keeper rules 1 and 2). */
  statusListIssuers?: Record<string, string[]> | undefined;
  /** Entity Cards by agent DID, from local config, read before `resolveCard`. */
  cards?: Record<string, unknown> | undefined;
  /** The card seam; default: the `KyaOsEntityCard` service of the agent's DID document, fetched. */
  resolveCard?: ((did: string) => Promise<unknown>) | undefined;
  /** Story A-1's hook; default: a no-op that logs once that verifications are unrecorded. */
  reportVerification?: ReportVerification | undefined;
  /** Called when `reportVerification` throws; reporting never blocks a call. */
  onReportError?: ((error: unknown) => void) | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
  /** Where the default report hook says verifications are unrecorded; default `console.warn`. */
  log?: ((message: string) => void) | undefined;
}

/** A tool call as the middleware sees it, for `verifyCall`. */
export interface LocalVerifierCall {
  name?: string | undefined;
  input?: Record<string, unknown> | undefined;
  /** The request's `params._meta`: the proof under `org.kya-os/request-proof`, the chain under `org.kya-os/delegation-chain`. */
  _meta?: Record<string, unknown> | undefined;
  /** The JSON-RPC request as received, when the host has it; it is hashed as sent. Default: rebuilt from `name`, `input` and `_meta`. */
  request?: kyaos.verifier.ProofRequest | undefined;
  /** The access token's `cnf.jkt`, when the call came with a sender-constrained token: the §8.6 fusion. */
  tokenCnfJkt?: string | undefined;
  /** Default true. False: a call with a chain and no proof is verified on the chain alone, at most L2 (story C-C). */
  requireProof?: boolean | undefined;
}

export interface LocalVerifier {
  readonly serviceDid: string;
  readonly seams: kyaos.verifier.VerifierSeams;
  readonly nonceStore: NonceStore;
  /** The status cache the revocation checker reads; a `RevocationSignalClient` invalidates it. */
  readonly statusCache: kyaos.verifier.StatusCache;
  /** Verifies one tool call from its `_meta`; `undefined` when it carries neither a request proof nor a chain. */
  verifyCall(call: LocalVerifierCall): Promise<kyaos.verifier.VerifierResult | undefined>;
  /** The verifier on explicit input, with this service's seams and options. */
  verify(input: kyaos.verifier.VerifierInput, overrides?: Partial<kyaos.verifier.VerifierOptions>): Promise<kyaos.verifier.VerifierResult>;
}

export const KYA_OS_CARD_SERVICE_TYPE = 'KyaOsEntityCard';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `https://` only, unless the host is loopback and `allowLoopbackHttp` is set, where `http://` is used. */
export function resolutionUrl(url: string, allowLoopbackHttp: boolean): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  const loopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '[::1]';
  if (parsed.protocol === 'https:') {
    if (loopback && allowLoopbackHttp) parsed.protocol = 'http:';
    return parsed.toString();
  }
  if (parsed.protocol === 'http:' && loopback && allowLoopbackHttp) return parsed.toString();
  return undefined;
}

/** The URL the `KyaOsEntityCard` service of a DID document names, or undefined. */
export function cardEndpointOf(document: unknown): string | undefined {
  if (!isRecord(document) || !Array.isArray(document['service'])) return undefined;
  for (const service of document['service']) {
    if (!isRecord(service)) continue;
    const type = service['type'];
    const types = Array.isArray(type) ? type : [type];
    if (types.includes(KYA_OS_CARD_SERVICE_TYPE) && typeof service['serviceEndpoint'] === 'string') return service['serviceEndpoint'];
  }
  return undefined;
}

/** The default `reportVerification`: says once that verifications go unrecorded until story A-1 connects the trail. */
// eslint-disable-next-line no-console -- the default reporter's one line of output goes to the console
export function unrecordedReporter(log: (message: string) => void = (message) => console.warn(message)): ReportVerification {
  let said = false;
  return () => {
    if (said) return;
    said = true;
    log('[kya-os] local verifications are unrecorded: no reportVerification hook is set (story A-1 connects the audit trail)');
  };
}

/** The JSON-RPC request a call's proof binds: the one received when the host has it, else rebuilt as `tools/call`. */
export function requestOf(call: LocalVerifierCall): kyaos.verifier.ProofRequest {
  return (
    call.request ?? {
      method: 'tools/call',
      params: {
        ...(call.name === undefined ? {} : { name: call.name }),
        ...(call.input === undefined ? {} : { arguments: call.input }),
        ...(call._meta === undefined ? {} : { _meta: call._meta }),
      },
    }
  );
}

export function createLocalVerifier(options: LocalVerifierOptions): LocalVerifier {
  if (typeof options.serviceDid !== 'string' || !options.serviceDid.startsWith('did:')) {
    throw new Error('createLocalVerifier: serviceDid must be a DID');
  }
  const clock = options.clock ?? Date.now;
  const nonceStore = options.nonceStore ?? new MemoryNonceStore({ now: clock });
  const allowLoopbackHttp = options.allowLoopbackHttp ?? false;
  // A host's own fetch (its SafeFetch) is held to the URL policy here; the default applies it itself.
  const hostFetch = options.fetch;
  const doFetch: ResolverFetch =
    hostFetch === undefined
      ? createResolutionFetch({ allowLoopbackHttp })
      : async (url): ReturnType<ResolverFetch> => {
          const target = resolutionUrl(url, allowLoopbackHttp);
          // A URL that is not read is refused here; the caller reports it unresolved or unavailable.
          if (target === undefined) throw new Error(`refusing to fetch ${url}: only https: URLs are read`);
          return hostFetch(target);
        };
  const fetchJson = async (url: string): Promise<unknown> => {
    const response = await doFetch(url);
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return response.json();
  };
  const resolveDid: kyaos.verifier.DidResolver = options.resolveDid ?? kyaos.verifier.createDidResolver({ fetch: doFetch });
  const resolveDidKeys = options.resolveDidKeys ?? kyaos.verifier.createDidKeysResolver(resolveDid);
  // Every list's proof is verified, by its issuer's assertionMethod key, before any bit is read (story L3-C point 2).
  const fetchStatusList: kyaos.verifier.FetchStatusList = options.fetchStatusList ?? kyaos.verifier.createStatusListFetcher({ fetch: doFetch, resolveDid });
  // A cache the host built (possibly from another copy of the SDK, so no instanceof), else one from the options.
  const given = options.statusCache;
  const statusCache: kyaos.verifier.StatusCache =
    given !== undefined && typeof (given as kyaos.verifier.StatusCache).invalidate === 'function' && typeof (given as kyaos.verifier.StatusCache).getList === 'function'
      ? (given as kyaos.verifier.StatusCache)
      : new kyaos.verifier.StatusCache({
          clock,
          ...((given as kyaos.verifier.StatusCacheOptions | undefined) ?? {}),
          ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
        });
  const checkRevocation =
    options.checkRevocation ??
    kyaos.verifier.createRevocationChecker({
      fetchStatusList,
      cache: statusCache,
      ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
      ...(options.statusListIssuers === undefined ? {} : { statusListIssuers: options.statusListIssuers }),
      ...(options.resourceOwner === undefined ? {} : { trustedRootIssuer: options.resourceOwner }),
    });
  const resolveCard = async (did: string): Promise<unknown> => {
    const configured = options.cards?.[did];
    if (configured !== undefined) return configured;
    if (options.resolveCard !== undefined) return options.resolveCard(did);
    const document = await resolveDid(did);
    const endpoint = cardEndpointOf(document);
    if (endpoint === undefined) return undefined;
    return fetchJson(endpoint);
  };
  const report = options.reportVerification ?? unrecordedReporter(options.log);
  const seams: kyaos.verifier.VerifierSeams = {
    resolveDid,
    resolveDidKeys,
    fetchStatusList,
    checkRevocation,
    resolveCard,
    nonceStore,
    clock,
    trustedIssuers: options.trustedIssuers ?? '*',
  };
  const baseOptions: kyaos.verifier.VerifierOptions = {
    expectedAudience: options.serviceDid,
    resource: options.resource ?? options.serviceDid,
    ...(options.resourceOwner === undefined ? {} : { resourceOwner: options.resourceOwner }),
    ...(options.trustedRootIssuers === undefined ? {} : { trustedRootIssuers: options.trustedRootIssuers }),
    ...(options.maxChainLength === undefined ? {} : { maxChainLength: options.maxChainLength }),
    ...(options.skewSeconds === undefined ? {} : { skewSeconds: options.skewSeconds }),
    ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
    ...(options.catalog === undefined ? {} : { catalog: options.catalog }),
  };

  const verify = (input: kyaos.verifier.VerifierInput, overrides: Partial<kyaos.verifier.VerifierOptions> = {}): Promise<kyaos.verifier.VerifierResult> =>
    kyaos.verifier.verify(input, seams, { ...baseOptions, ...overrides });

  const verifyCall = async (call: LocalVerifierCall): Promise<kyaos.verifier.VerifierResult | undefined> => {
    const proof = kyaos.verifier.readRequestProof(call._meta);
    const chain = kyaos.verifier.readCarriedChain(call._meta);
    if (proof === undefined && chain === undefined) return undefined;
    const request = requestOf(call);
    const result = await verify(
      { proof, ...(chain === undefined ? {} : { chain }), request },
      {
        ...(call.tokenCnfJkt === undefined ? {} : { tokenCnfJkt: call.tokenCnfJkt }),
        ...(call.requireProof === undefined ? {} : { requireProof: call.requireProof }),
      },
    );
    const entry: VerificationReport = {
      timestamp: new Date(clock()).toISOString(),
      serviceDid: options.serviceDid,
      toolName: call.name,
      agentDid: result.agentDid ?? result.proofDid,
      ok: result.ok,
      level: result.level,
      proofAssurance: result.proofAssurance,
      proofFloor: result.proofFloor,
      l3Minus: result.level === 'L3' && result.proofAssurance === 'L3-minus',
      cnfDiagnostics: result.warnings.filter((warning) => warning.startsWith('cnf_')),
      effectiveScopes: result.effectiveScopes,
      reasons: result.reasons,
      fresh: result.fresh,
      chainDepth: result.chainSummary.depth,
    };
    try {
      await report(entry);
    } catch (error) {
      options.onReportError?.(error);
    }
    return result;
  };

  return { serviceDid: options.serviceDid, seams, nonceStore, statusCache, verifyCall, verify };
}
