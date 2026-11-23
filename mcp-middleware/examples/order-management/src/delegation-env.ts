// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { InboundDelegationSettings } from '@helixid/mcp-middleware';

/**
 * Story L3-D: which services' forwarded chains this server honours, from
 * `KYAOS_FORWARDERS`: unset or `*` any (the default), `none` none, else a
 * comma-separated list of DIDs. Throws on an entry that is not a DID.
 */
export function forwardersFromEnv(raw: string | undefined): InboundDelegationSettings['forwarders'] {
  const value = raw?.trim() ?? '';
  if (value === '' || value === '*') return '*';
  if (value.toLowerCase() === 'none') return [];
  const dids = value.split(',').map((did) => did.trim()).filter((did) => did.length > 0);
  if (dids.some((did) => !did.startsWith('did:'))) throw new Error('KYAOS_FORWARDERS must be *, none, or a list of DIDs');
  return dids;
}

/** The startup line's words for a forwarders setting (`false`: inbound delegation off). */
export function describeForwarders(setting: InboundDelegationSettings['forwarders'] | false): string {
  if (setting === false) return 'none (inbound delegation off)';
  if (setting === undefined || setting === '*') return 'any service';
  return setting.length === 0 ? 'none' : setting.join(', ');
}
