// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A point 7: what L1-D advertises in /.well-known/mcp.
import { describe, expect, it } from 'vitest';
import { describeKyaOs } from '../../src/kyaos/index.js';

describe('describeKyaOs', () => {
  it('advertises the handshake tool on the MCP endpoint, the skew and proofs', () => {
    expect(describeKyaOs()).toEqual({
      endpoints: { handshake: '/mcp#_kyaos_handshake' },
      clockSkewSeconds: 120,
      capabilities: { proofs: true },
      handshakeTool: '_kyaos_handshake',
    });
    expect(describeKyaOs({ clockSkewSeconds: 300, toolsEndpoint: 'https://mcp.example.com/mcp' })).toMatchObject({
      endpoints: { handshake: 'https://mcp.example.com/mcp#_kyaos_handshake' },
      clockSkewSeconds: 300,
    });
  });

  it('omits endpoints.handshake while sessions are disabled, and refuses a skew outside 30 to 600', () => {
    expect(describeKyaOs({ session: { enabled: false } }).endpoints).toEqual({});
    expect(describeKyaOs({ session: { enabled: true } }).endpoints.handshake).toBe('/mcp#_kyaos_handshake');
    expect(describeKyaOs({ session: {} }).endpoints.handshake).toBeDefined();
    expect(() => describeKyaOs({ clockSkewSeconds: 10 })).toThrow(RangeError);
  });
});
