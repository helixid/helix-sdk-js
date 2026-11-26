// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The keeper rules follow the KYA-OS suite's independent reading
// (decentralized-identity/kya-os-mcp, conformance/status_list.py at a4d7f61,
// MIT licensed, Copyright (c) 2026 KYA-OS).

/**
 * Who keeps a status-list URL (SPEC.md §6.6; KYA-OS stories F-2 and L3-C).
 * Every `statusListCredential` URL has exactly one keeper, decided before
 * the list is fetched, from the verifier's configuration and the signed
 * credentials, never from the list:
 *
 * 1. the issuer the configuration binds that exact URL to;
 * 2. the issuer the configuration binds the URL's `https:` origin to;
 * 3. the root of the chain, when the verifier pins it and the root's own
 *    credential names the same URL, byte for byte;
 * 4. the credential's own issuer.
 *
 * A list is read for a credential only when the list's `issuer` is the
 * keeper. Comparisons are on the bytes as written: no URL parsing, no
 * normalisation, so every implementation decides alike.
 */

const ORIGIN = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/;
const ORIGIN_IN_ANY_FORM = /^https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?(\/?)$/;

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The verifier's status-list configuration: issuer DID to the URLs or `https:` origins it keeps, and the pinned root. */
export interface StatusConfiguration {
  /** The root issuer the verifier pins (its resource owner, or a trusted root), for rule 3. */
  root: string | undefined;
  /** The URL the pinned root's own credential names, read only from a root credential whose proof verified. */
  rootList: string | undefined;
  /** Issuer DID to the exact URLs and `https:` origins bound to it. */
  services: Record<string, string[]>;
}

export interface StatusConfigurationInput {
  trustedRootIssuer?: string | undefined;
  trustedRootStatusList?: string | undefined;
  statusListIssuers?: Record<string, string[]> | undefined;
}

/** The words a binding §6.6 says is mistaken is refused in, or undefined. */
export function mistakenBinding(binding: string): string | undefined {
  const written = ORIGIN_IN_ANY_FORM.exec(binding);
  if (written !== null && written[1] === '/') return 'statusListIssuers binds an origin followed by "/"';
  if (written !== null && /[A-Z]/.test(binding)) return 'statusListIssuers binds an origin whose host is not in lower case';
  if (binding.endsWith('/')) return 'statusListIssuers binds a URL that ends in "/"';
  return undefined;
}

/** The configuration an input states, or a thrown `TypeError` for one that is not well formed (one URL bound to two issuers, say). */
export function statusConfiguration(input: StatusConfigurationInput): StatusConfiguration {
  for (const member of ['trustedRootIssuer', 'trustedRootStatusList'] as const) {
    const value = input[member];
    if (value !== undefined && (typeof value !== 'string' || value.length === 0)) throw new TypeError(`${member} is not a non-empty string`);
  }
  const services = input.statusListIssuers ?? {};
  if (!isObject(services)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
  const bound = new Map<string, string>();
  for (const [did, bindings] of Object.entries(services)) {
    if (did === '' || !Array.isArray(bindings)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
    for (const binding of bindings as unknown[]) {
      if (typeof binding !== 'string' || !/^https?:\/\//.test(binding)) throw new TypeError('statusListIssuers does not map issuers to lists of URLs');
      const mistaken = mistakenBinding(binding);
      if (mistaken !== undefined) throw new TypeError(mistaken);
      if ((bound.get(binding) ?? did) !== did) throw new TypeError('statusListIssuers binds one URL to two issuers');
      bound.set(binding, did);
    }
  }
  return { root: input.trustedRootIssuer, rootList: input.trustedRootStatusList, services: services as Record<string, string[]> };
}

/** The one issuer whose list is read at `url` for a credential `owner` issued, and whether no binding names it. */
export function keeper(url: string, owner: string, config: StatusConfiguration): { did: string; unbound: boolean } {
  for (const [did, bindings] of Object.entries(config.services)) if (bindings.includes(url)) return { did, unbound: false };
  for (const [did, bindings] of Object.entries(config.services)) {
    for (const binding of bindings) {
      if (ORIGIN.test(binding) && ['/', '?', '#'].some((mark) => url.startsWith(binding + mark))) return { did, unbound: false };
    }
  }
  if (config.root !== undefined && config.rootList === url) return { did: config.root, unbound: true };
  return { did: owner, unbound: true };
}

/**
 * Whether a list that states no `id` may be read at `url` for `owner`'s
 * credential: only when the credential's own issuer keeps the URL unbound
 * and nobody else keeps any URL (no other pinned root, no other configured
 * issuer). Any other list must state the URL as its `id`.
 */
export function mayOmitListId(url: string, owner: string, config: StatusConfiguration): boolean {
  const kept = keeper(url, owner, config);
  if (!kept.unbound || kept.did !== owner) return false;
  if (config.root !== undefined && config.root !== owner) return false;
  return Object.keys(config.services).every((did) => did === owner);
}

/** An empty configuration: every URL is kept by the credential's own issuer (rule 4). */
export const NO_STATUS_CONFIGURATION: StatusConfiguration = Object.freeze({ root: undefined, rootList: undefined, services: Object.freeze({}) as Record<string, string[]> });
