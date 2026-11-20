// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { kyaos } from '@helixid/sdk-js';

/**
 * What the KYA-OS layer advertises (story L2-A point 7). Story L1-D serves
 * `/.well-known/mcp` and reads these values from here: `endpoints.handshake`
 * only while sessions are enabled, `clockSkewSeconds` as configured, and
 * `capabilities.proofs` true because every tool call is answered with a
 * response proof.
 */

export interface DescribeKyaOsOptions {
  /** Default 120; 30 to 600. */
  clockSkewSeconds?: number | undefined;
  session?: { enabled?: boolean | undefined } | undefined;
  /** The MCP endpoint the handshake tool is called on, as a URI reference (`/mcp`, or `https://mcp.example.com/mcp`). Default `/mcp`. */
  toolsEndpoint?: string | undefined;
}

export interface KyaOsDescription {
  endpoints: { handshake?: string };
  clockSkewSeconds: number;
  capabilities: { proofs: true };
  /** The handshake is a tool, not a route: this is its name on `endpoints.handshake`'s MCP endpoint. */
  handshakeTool: typeof kyaos.HANDSHAKE_TOOL_NAME;
}

export function describeKyaOs(options: DescribeKyaOsOptions = {}): KyaOsDescription {
  const sessions = options.session?.enabled ?? true;
  const tools = options.toolsEndpoint ?? '/mcp';
  return {
    endpoints: sessions ? { handshake: `${tools}#${kyaos.HANDSHAKE_TOOL_NAME}` } : {},
    clockSkewSeconds: kyaos.clockSkewSeconds(options.clockSkewSeconds),
    capabilities: { proofs: true },
    handshakeTool: kyaos.HANDSHAKE_TOOL_NAME,
  };
}
