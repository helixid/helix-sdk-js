// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { createWellKnownMcp, type KyaOsRuntime, type WellKnownMcp } from '@helixid/mcp-middleware';

/**
 * The sample's KYA-OS discovery document (story L1-D) from its environment,
 * the twin of helix-sdk-py's `well_known_from_env` / `describe_well_known`:
 *
 *   WELL_KNOWN_MCP=0        the route answers 404
 *   WELL_KNOWN_MCP=1        a SERVICE_DID the document cannot carry is an error, not an "off" notice
 *   KYAOS_PUBLIC_ORIGIN     the origin in every URL (default: the origin of MCP_RESOURCE)
 *   STATUS_LIST_CREDENTIAL  advertised as statusListCredential
 *
 * A document that would not validate throws `WellKnownMcpError`; `main.ts`
 * turns that into a startup failure.
 */

export interface WellKnownFromEnv {
  /** The route to mount, or undefined when the server has none (and answers 404 anyway). */
  wellKnown: WellKnownMcp | undefined;
  /** Why the document is not served, for the startup line. */
  off: string | undefined;
}

export function wellKnownFromEnv(
  env: Record<string, string | undefined>,
  resource: string,
  serviceDid: string | undefined,
  kyaos: KyaOsRuntime | undefined,
): WellKnownFromEnv {
  const setting = env['WELL_KNOWN_MCP'];
  if (setting === '0') return { wellKnown: createWellKnownMcp({ enabled: false }), off: 'off (WELL_KNOWN_MCP=0): 404' };
  if (!serviceDid) return { wellKnown: undefined, off: 'off (set SERVICE_DID)' };
  if (!/^did:(web|key):/.test(serviceDid) && setting !== '1') {
    return {
      wellKnown: undefined,
      off: `off (SERVICE_DID ${serviceDid} is not a did:web or did:key, which the document's serverDid must be; WELL_KNOWN_MCP=1 makes this an error)`,
    };
  }
  const url = new URL(resource);
  const wellKnown = createWellKnownMcp({
    publicOrigin: env['KYAOS_PUBLIC_ORIGIN'] || url.origin,
    serverDid: serviceDid,
    toolsEndpoint: url.pathname,
    ...(kyaos ? { kyaos: kyaos.describe() } : {}),
    ...(env['STATUS_LIST_CREDENTIAL'] ? { statusListCredential: env['STATUS_LIST_CREDENTIAL'] } : {}),
  });
  return { wellKnown, off: undefined };
}

/** The `Discovery:` startup line's text. */
export function describeWellKnown({ wellKnown, off }: WellKnownFromEnv): string {
  const document = wellKnown?.document;
  if (!document) return off ?? 'off';
  return (
    `${new URL(document.endpoints.tools).origin}/.well-known/mcp, serverDid ${document.serverDid}, skew ${document.clockSkewSeconds} s, ` +
    `handshake ${document.endpoints.handshake ? 'advertised' : 'absent'} (route the path at that origin to this server: see mcp-middleware/docs/well-known.md)`
  );
}
