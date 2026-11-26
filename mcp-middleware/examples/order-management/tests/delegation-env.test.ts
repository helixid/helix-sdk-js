// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { describe, expect, it } from 'vitest';
import { describeForwarders, forwardersFromEnv } from '../src/delegation-env.js';

describe('KYAOS_FORWARDERS (story L3-D)', () => {
  it('defaults to any service; none and a DID list are read; a non-DID entry is refused', () => {
    expect(forwardersFromEnv(undefined)).toBe('*');
    expect(forwardersFromEnv(' ')).toBe('*');
    expect(forwardersFromEnv('*')).toBe('*');
    expect(forwardersFromEnv('NONE')).toEqual([]);
    expect(forwardersFromEnv('did:key:a, did:web:b ,')).toEqual(['did:key:a', 'did:web:b']);
    expect(() => forwardersFromEnv('did:key:a,orders')).toThrow(/list of DIDs/);
  });

  it('describes the setting for the startup line', () => {
    expect(describeForwarders(undefined)).toBe('any service');
    expect(describeForwarders('*')).toBe('any service');
    expect(describeForwarders([])).toBe('none');
    expect(describeForwarders(['did:key:a', 'did:key:b'])).toBe('did:key:a, did:key:b');
    expect(describeForwarders(false)).toBe('none (inbound delegation off)');
  });
});
