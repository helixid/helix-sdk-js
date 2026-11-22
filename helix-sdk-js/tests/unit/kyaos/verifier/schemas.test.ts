// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// KYA-OS story F-2: the SDK's copies of the credential schemas (helix-core
// src/core/schemas/*.schema.json, story F-1) and of the vendored Entity Card
// schema (fixtures/kya-os/schemas/kya-os-card.schema.json) must not drift.

import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifier } from '../../../../src/core/kyaos/index.js';
import { coreFixturesDir, haveCoreFixtures } from '../fixtures.js';

const coreSchemasDir = resolve(coreFixturesDir, '../src/core/schemas');
const haveCoreSchemas = existsSync(join(coreSchemasDir, 'delegation-hop.schema.json'));

describe.skipIf(!haveCoreSchemas)('credential schemas copied from helix-core', () => {
  for (const [constant, file] of [
    [verifier.IDENTITY_CREDENTIAL_SCHEMA, 'identity-credential'],
    [verifier.CAPABILITY_ATTESTATION_SCHEMA, 'capability-attestation'],
    [verifier.DELEGATION_HOP_SCHEMA, 'delegation-hop'],
  ] as const) {
    it(`${file}.schema.json is the same value`, () => {
      expect(constant).toEqual(JSON.parse(readFileSync(join(coreSchemasDir, `${file}.schema.json`), 'utf8')));
    });
  }
});

describe.skipIf(!haveCoreFixtures)('the Entity Card schema copied from the vendored suite', () => {
  it('is the same value as fixtures/kya-os/schemas/kya-os-card.schema.json', () => {
    expect(verifier.ENTITY_CARD_SCHEMA).toEqual(JSON.parse(readFileSync(join(coreFixturesDir, 'kya-os/schemas/kya-os-card.schema.json'), 'utf8')));
  });
});

describe('the schemas evaluate under the SDK evaluator', () => {
  it('every keyword of each schema is supported', () => {
    for (const schema of [verifier.IDENTITY_CREDENTIAL_SCHEMA, verifier.CAPABILITY_ATTESTATION_SCHEMA, verifier.DELEGATION_HOP_SCHEMA, verifier.ENTITY_CARD_SCHEMA]) {
      expect(() => verifier.assertSupportedSchema(schema)).not.toThrow();
    }
  });
});
