import { describe, expect, it } from 'vitest';
import {
  checkScope,
  requireScope,
  VPBuilder,
  verifyVP,
  type VerifyVPResult,
} from '../../src/index.js';

describe('standalone SDK exports', () => {
  it('exports core VP helpers without a HelixClient', () => {
    expect(VPBuilder).toBeDefined();
    expect(verifyVP).toBeDefined();
  });

  it('checks and requires scopes from a verification result', () => {
    const result: VerifyVPResult = {
      valid: true,
      agentDid: 'did:key:zAgent',
      privilegeScopes: ['read:orders'],
      effectiveScopes: ['read:orders'],
      vpId: 'vp:helix:test',
      delegationChain: [],
    };

    expect(checkScope(result, 'read:orders')).toBe(true);
    expect(checkScope(result, 'write:orders')).toBe(false);
    expect(() => requireScope(result, 'write:orders')).toThrow('Required scope: write:orders');

    // Enforcement reads effectiveScopes: a grant intersection narrower than
    // privilegeScopes must gate the scope check (§2.7).
    const narrowed: VerifyVPResult = { ...result, effectiveScopes: [] };
    expect(checkScope(narrowed, 'read:orders')).toBe(false);
    expect(() => requireScope(narrowed, 'read:orders')).toThrow('Required scope: read:orders');
  });
});
