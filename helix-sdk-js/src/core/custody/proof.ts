// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Proof of possession of a client-held key (KYA-OS story F-3), the same
 * bytes helix-core checks (`fixtures/kya-os-helix/custody.json`):
 * `helix-enroll:v1:<did>:<kid>:<nonce>` for `helix init`,
 * `helix-rotate:v1:<did>:<kid>:<issuedAt>` for a custody change to self.
 * The signature is the raw Ed25519 signature, base64url without padding.
 */

import type { Signer } from './signer.js';

export const ENROLLMENT_PROOF_PREFIX = 'helix-enroll:v1';
export const ROTATION_PROOF_PREFIX = 'helix-rotate:v1';

function messageOf(parts: string[]): Uint8Array {
  for (const part of parts) {
    if (typeof part !== 'string' || part.length === 0 || /\s/.test(part)) {
      throw new Error('proof message parts must be non-empty strings without whitespace');
    }
  }
  return new TextEncoder().encode(parts.join(':'));
}

export function enrollmentProofMessage(input: { did: string; kid: string; nonce: string }): Uint8Array {
  return messageOf([ENROLLMENT_PROOF_PREFIX, input.did, input.kid, input.nonce]);
}

export function rotationProofMessage(input: { did: string; kid: string; issuedAt: string }): Uint8Array {
  return messageOf([ROTATION_PROOF_PREFIX, input.did, input.kid, input.issuedAt]);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Strict base64url (no padding, no other characters), or undefined. */
export function base64UrlDecode(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return undefined;
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

/** The rotation proof a custody change to self carries: the new key's signature, made by its own Signer. */
export async function rotationProof(signer: Signer, did: string, kid: string, issuedAt: string = new Date().toISOString()): Promise<{ issuedAt: string; signature: string }> {
  return { issuedAt, signature: base64UrlEncode(await signer.sign(rotationProofMessage({ did, kid, issuedAt }))) };
}
