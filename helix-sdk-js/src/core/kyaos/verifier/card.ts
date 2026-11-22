// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The Entity Card as the verifier reads it (SPEC-ENTITY-CARD.md §4): the
 * strict vendored schema (`additionalProperties: false`, an unknown member
 * refuses the card, never strips it), and the members the verifier uses:
 * `id`, `capabilities`, `responsibleParty`, `revocation`. The level is never
 * read off the card.
 */

import { ENTITY_CARD_SCHEMA } from './card-schema.js';
import { validateJsonSchema } from './json-schema.js';

export type EntityType = 'mcp' | 'agent' | 'client' | 'verifier' | 'human';

export interface EntityCard {
  id: string;
  entityType: EntityType;
  name: string;
  kid?: string;
  capabilities?: unknown[];
  conformanceLevel?: 'L1' | 'L2' | 'L3';
  responsibleParty?: string;
  principal?: string;
  delegationRef?: string;
  revocation?: { statusListCredential: string; statusListIndex: string; statusSize?: number };
  proofProfile?: string;
  [member: string]: unknown;
}

/** Every way `value` fails the strict card schema, as `path: message`; empty when it is a card. */
export function validateEntityCard(value: unknown): string[] {
  return validateJsonSchema(ENTITY_CARD_SCHEMA, value).map((violation) => `${violation.path}: ${violation.message}`);
}

export function isEntityCard(value: unknown): value is EntityCard {
  return validateEntityCard(value).length === 0;
}
