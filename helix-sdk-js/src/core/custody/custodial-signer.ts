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
 * HelixCustodialSigner (KYA-OS story F-3 point 3): the Signer of a
 * custodial (`keyCustody: helix`) agent, service or owner. It holds no key:
 * `sign()` sends the bytes to the Helix API's signing endpoint, which signs
 * with the key Helix holds in its KeyStore and audits the signature. Because
 * it is a `Signer` like `EnvSigner`, application code is the same in both
 * custody modes; only the line that constructs the signer differs.
 *
 * Custodial agents are labelled `custody: helix` and are not part of any
 * KYA-OS conformance claim (SPEC §4.5). Verifiers still accept their proofs.
 */

import { HelixCustodyClient, type CustodySubjectKind, type FetchLike } from './client.js';
import { base64UrlDecode, base64UrlEncode } from './proof.js';
import { kidFragment, type Signer } from './signer.js';

export interface HelixCustodialSignerOptions {
  apiUrl: string;
  did: string;
  /** Fragment or full verification-method id of the Helix-held key. Default `key-1`. */
  kid?: string | undefined;
  /** What the DID is. Default `agent`. */
  subject?: CustodySubjectKind | undefined;
  adminApiKey?: string | undefined;
  apiKey?: string | undefined;
  fetch?: FetchLike | undefined;
  /** An existing custody client, instead of the connection options above. */
  client?: HelixCustodyClient | undefined;
}

export class HelixCustodialSigner implements Signer {
  readonly did: string;
  readonly kid: string;
  readonly #client: HelixCustodyClient;
  readonly #subject: CustodySubjectKind;

  constructor(options: HelixCustodialSignerOptions) {
    if (typeof options?.did !== 'string' || !options.did.startsWith('did:')) throw new Error('HelixCustodialSigner: did must be a DID');
    this.did = options.did;
    this.kid = kidFragment(options.did, options.kid);
    this.#subject = options.subject ?? 'agent';
    this.#client =
      options.client ??
      new HelixCustodyClient({ apiUrl: options.apiUrl, adminApiKey: options.adminApiKey, apiKey: options.apiKey, fetch: options.fetch });
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array)) throw new Error('HelixCustodialSigner: data to sign must be bytes');
    const response = await this.#client.sign(this.did, { payload: base64UrlEncode(data), kid: this.kid }, this.#subject);
    if (response.kid !== `${this.did}#${this.kid}`) {
      throw new Error(`HelixCustodialSigner: Helix signed with ${response.kid}, not ${this.did}#${this.kid}`);
    }
    const signature = typeof response.signature === 'string' ? base64UrlDecode(response.signature) : undefined;
    if (!signature || signature.length !== 64) throw new Error('HelixCustodialSigner: Helix did not return a 64-byte Ed25519 signature');
    return signature;
  }
}
