// Copyright 2026 DgVerse LLP
// KYA-OS story C-B: the trusted-issuer setting in both modes (stories rule 9).
import { describe, expect, it } from 'vitest';
import { DEFAULT_TRUSTED_ISSUERS, attestationTrust, isTrustedIssuer, type TrustedIssuers } from '../src/index.js';

const helix = 'did:web:helix.example';
const owner = 'did:key:z6MkOwner';

describe('trustedIssuers', () => {
  it("ships as allow-all ('*')", () => {
    expect(DEFAULT_TRUSTED_ISSUERS).toBe('*');
    expect(isTrustedIssuer(owner)).toBe(true);
    expect(isTrustedIssuer(helix, '*')).toBe(true);
    expect(attestationTrust(owner)).toBe('verified');
  });

  it('with a list set, an unlisted issuer is unverified and a listed one verified', () => {
    const list: TrustedIssuers = [helix];
    expect(isTrustedIssuer(helix, list)).toBe(true);
    expect(isTrustedIssuer(owner, list)).toBe(false);
    expect(attestationTrust(owner, list)).toBe('unverified');
    expect(attestationTrust(helix, list)).toBe('verified');
    expect(isTrustedIssuer(owner, [helix, owner])).toBe(true);
    expect(isTrustedIssuer(helix, [])).toBe(false);
  });

  it('fails closed on anything that is neither the wildcard nor a list', () => {
    expect(isTrustedIssuer(helix, helix as unknown as TrustedIssuers)).toBe(false);
    expect(isTrustedIssuer(undefined as unknown as string, [helix])).toBe(false);
  });
});
