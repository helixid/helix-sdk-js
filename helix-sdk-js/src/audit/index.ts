// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// KYA-OS auditability (story A-1, AAP-1 Recorded): typed producer events,
// the trail that emits them, references, digests and the evidence vault. A
// port of helix-core's `src/core/audit/`, function for function; the fixture
// `helix-core/fixtures/kya-os-helix/audit-events.json` is the contract.
export * from './canonical.js';
export * from './types.js';
export * from './schema.js';
export * from './digest.js';
export * from './references.js';
export * from './evidence.js';
export * from './sink.js';
export * from './trail.js';
// Story A-2: delivery to the authoritative recorder (required, buffered, best-effort).
export * from './recorder-client.js';
export * from './outbox.js';
export * from './outbox-contract.js';
export * from './delivery.js';
