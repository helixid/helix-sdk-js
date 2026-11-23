// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { describe, expect, it } from 'vitest';
import { describeLevelSettings, readLevelSettings } from '../src/levels.js';

const TOOLS = ['lookup_order', 'cancel_order'];

describe('readLevelSettings (story C-C)', () => {
  it('reads nothing from an empty environment: the middleware defaults (L3, L3-minus accepted) apply', () => {
    expect(readLevelSettings({}, TOOLS)).toEqual({});
    expect(readLevelSettings({ KYAOS_MINIMUM_LEVEL: ' ', KYAOS_TOOL_LEVELS: '', KYAOS_L3_MINUS_SATISFIES_L3: '' }, TOOLS)).toEqual({});
    expect(describeLevelSettings({})).toBe('minimum level L3');
  });

  it('reads the default minimum, per-tool minimums and the L3-minus switch', () => {
    const settings = readLevelSettings({ KYAOS_MINIMUM_LEVEL: 'L2', KYAOS_TOOL_LEVELS: 'lookup_order=L1, cancel_order = L3,', KYAOS_L3_MINUS_SATISFIES_L3: '0' }, TOOLS);
    expect(settings).toEqual({ minimumLevel: 'L2', tools: { lookup_order: { minimumLevel: 'L1' }, cancel_order: { minimumLevel: 'L3' } }, l3MinusSatisfiesL3: false });
    expect(describeLevelSettings(settings)).toBe('minimum level L2 (lookup_order L1, cancel_order L3), L3-minus refused for L3');
    expect(readLevelSettings({ KYAOS_L3_MINUS_SATISFIES_L3: '1' }, TOOLS)).toEqual({ l3MinusSatisfiesL3: true });
  });

  it('refuses a level that does not exist, an entry that is not tool=level, an unknown tool and a bad switch', () => {
    expect(() => readLevelSettings({ KYAOS_MINIMUM_LEVEL: 'L4' }, TOOLS)).toThrow('KYAOS_MINIMUM_LEVEL: L4 is not one of L1, L2, L3');
    expect(() => readLevelSettings({ KYAOS_TOOL_LEVELS: 'lookup_order=l2' }, TOOLS)).toThrow('KYAOS_TOOL_LEVELS: l2 is not one of');
    expect(() => readLevelSettings({ KYAOS_TOOL_LEVELS: 'lookup_order' }, TOOLS)).toThrow('lookup_order is not tool=level');
    expect(() => readLevelSettings({ KYAOS_TOOL_LEVELS: '=L2' }, TOOLS)).toThrow('is not tool=level');
    expect(() => readLevelSettings({ KYAOS_TOOL_LEVELS: 'lookup_order=L2=L3' }, TOOLS)).toThrow('is not tool=level');
    expect(() => readLevelSettings({ KYAOS_TOOL_LEVELS: 'drop_tables=L1' }, TOOLS)).toThrow('drop_tables=L1 is not tool=level for a tool of this server');
    expect(() => readLevelSettings({ KYAOS_L3_MINUS_SATISFIES_L3: 'yes' }, TOOLS)).toThrow('must be 0 or 1');
  });
});
