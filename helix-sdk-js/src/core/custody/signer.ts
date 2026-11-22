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
 * The Signer the agent runtime signs through (KYA-OS stories L1-C, F-3).
 *
 * Same shape as helix-core's `Signer` and the SDK port of story L2-A
 * (`kyaos.Signer`), so any of them fits wherever the SDK takes a Signer.
 * Two kinds exist now, chosen by key custody (story F-3):
 *
 * - `self`: `EnvSigner`, the private key in an environment variable on the
 *   agent's own host (PEM, wallet, WebCrypto and KMS adapters are phase 4);
 * - `helix`: `HelixCustodialSigner`, which asks the Helix API to sign with
 *   the key Helix holds for the agent.
 *
 * Application code takes a Signer and never learns which one it got.
 */

import * as ed25519 from '@noble/ed25519';
import { derivePublicKey, normalizeEd25519PrivateKey } from '../keys.js';

export interface Signer {
  /** DID of the key's controller. */
  readonly did: string;
  /** Verification-method fragment, without the `#` (for example `key-1`). */
  readonly kid: string;
  /** Raw Ed25519 signature (64 bytes) over `data`. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export const DEFAULT_SIGNING_KEY_ENV_VAR = 'HELIX_SIGNING_KEY';
export const DEFAULT_KID_FRAGMENT = 'key-1';

/** `kid` as a fragment: accepts `key-1`, `#key-1` or `<did>#key-1` (which must be this DID's). */
export function kidFragment(did: string, kid: string = DEFAULT_KID_FRAGMENT): string {
  let fragment = kid;
  if (fragment.startsWith(`${did}#`)) fragment = fragment.slice(did.length + 1);
  fragment = fragment.replace(/^#/, '');
  if (fragment.length === 0 || fragment.includes('#')) {
    throw new Error(`kid ${kid} is not a verification-method fragment of ${did}`);
  }
  return fragment;
}

/** `<did>#<kid>`, what a proof's verificationMethod or a JWS header names. */
export function verificationMethodOf(signer: Pick<Signer, 'did' | 'kid'>): string {
  return `${signer.did}#${signer.kid}`;
}

export interface EnvSignerOptions {
  did: string;
  /** Fragment or full verification-method id. Default `key-1`. */
  kid?: string;
  /** Variable holding the private key (raw 32-byte hex or PKCS8 seed hex). Default `HELIX_SIGNING_KEY`. */
  envVar?: string;
  env?: Readonly<Record<string, string | undefined>>;
}

/**
 * Self-custody: the private key is read from an environment variable at
 * every `sign()` and never held by the instance, so logging or serialising
 * the signer shows the DID and kid only.
 */
export class EnvSigner implements Signer {
  readonly did: string;
  readonly kid: string;
  readonly #envVar: string;
  readonly #env: Readonly<Record<string, string | undefined>>;

  constructor(options: EnvSignerOptions) {
    if (typeof options.did !== 'string' || !options.did.startsWith('did:')) throw new Error('EnvSigner: did must be a DID');
    this.did = options.did;
    this.kid = kidFragment(options.did, options.kid);
    this.#envVar = options.envVar ?? DEFAULT_SIGNING_KEY_ENV_VAR;
    this.#env = options.env ?? process.env;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return ed25519.signAsync(data, this.#secret());
  }

  publicKeyHex(): string {
    return derivePublicKey(Buffer.from(this.#secret()).toString('hex'));
  }

  #secret(): Uint8Array {
    const value = this.#env[this.#envVar];
    if (value === undefined || value.trim() === '') throw new Error(`EnvSigner: environment variable ${this.#envVar} is not set`);
    return normalizeEd25519PrivateKey(value);
  }
}
