// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS primitives the SDK carries itself (stories rule 24): RFC 8785
 * canonical JSON and hashing (L1-B), EdDSA JWS and the Signer (L1-C), the
 * session handshake and the detached response proof (L2-A), the per-request
 * holder-of-key proof and the carried chain (C-C).
 */
export * from './jcs.js';
export * from './signer.js';
export * from './jws.js';
export * from './hash.js';
export * from './handshake.js';
export * from './response-proof.js';
export * as verifier from './verifier/index.js';
export * as conformance from './conformance/index.js';
export * from './request-proof.js';
