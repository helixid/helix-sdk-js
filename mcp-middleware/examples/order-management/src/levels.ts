// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { MINIMUM_LEVELS, type MCPMiddlewareOptions, type MinimumLevel } from '@helixid/mcp-middleware';

export type LevelSettings = Pick<MCPMiddlewareOptions, 'minimumLevel' | 'tools' | 'l3MinusSatisfiesL3'>;

/** The variables `readLevelSettings` reads; set without SERVICE_DID they are a configuration error. */
export const LEVEL_VARIABLES = ['KYAOS_MINIMUM_LEVEL', 'KYAOS_TOOL_LEVELS', 'KYAOS_L3_MINUS_SATISFIES_L3'] as const;

function levelOf(name: string, raw: string | undefined): MinimumLevel | undefined {
  const value = raw?.trim();
  if (!value) return undefined;
  if (!MINIMUM_LEVELS.includes(value as MinimumLevel)) throw new Error(`${name}: ${value} is not one of ${MINIMUM_LEVELS.join(', ')}`);
  return value as MinimumLevel;
}

/**
 * The minimum Card level settings of story C-C from the environment:
 * `KYAOS_MINIMUM_LEVEL` (L1, L2 or L3; default L3), `KYAOS_TOOL_LEVELS`
 * (`tool=level,...`, tools of this server only) and
 * `KYAOS_L3_MINUS_SATISFIES_L3` (`0` or `1`; default 1). Throws on anything
 * else, so a typo never lowers a tool's bar.
 */
export function readLevelSettings(env: Readonly<Record<string, string | undefined>>, toolNames: readonly string[]): LevelSettings {
  const settings: LevelSettings = {};
  const minimumLevel = levelOf('KYAOS_MINIMUM_LEVEL', env['KYAOS_MINIMUM_LEVEL']);
  if (minimumLevel !== undefined) settings.minimumLevel = minimumLevel;
  const toolLevels = env['KYAOS_TOOL_LEVELS']?.trim();
  if (toolLevels) {
    const tools: NonNullable<LevelSettings['tools']> = {};
    for (const entry of toolLevels.split(',').map((item) => item.trim()).filter((item) => item.length > 0)) {
      const [tool, level, ...rest] = entry.split('=').map((part) => part.trim());
      const minimum = levelOf('KYAOS_TOOL_LEVELS', level);
      if (!tool || minimum === undefined || rest.length > 0 || !toolNames.includes(tool)) {
        throw new Error(`KYAOS_TOOL_LEVELS: ${entry} is not tool=level for a tool of this server`);
      }
      tools[tool] = { minimumLevel: minimum };
    }
    settings.tools = tools;
  }
  const l3Minus = env['KYAOS_L3_MINUS_SATISFIES_L3']?.trim();
  if (l3Minus) {
    if (l3Minus !== '0' && l3Minus !== '1') throw new Error('KYAOS_L3_MINUS_SATISFIES_L3 must be 0 or 1');
    settings.l3MinusSatisfiesL3 = l3Minus === '1';
  }
  return settings;
}

/** One line for the startup log: the default minimum and the per-tool ones. */
export function describeLevelSettings(settings: LevelSettings): string {
  const tools = Object.entries(settings.tools ?? {}).map(([tool, setting]) => `${tool} ${setting.minimumLevel}`);
  return `minimum level ${settings.minimumLevel ?? 'L3'}${tools.length > 0 ? ` (${tools.join(', ')})` : ''}${settings.l3MinusSatisfiesL3 === false ? ', L3-minus refused for L3' : ''}`;
}
