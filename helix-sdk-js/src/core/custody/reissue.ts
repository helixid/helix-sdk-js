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
 * `reissueHop` (KYA-OS story C-E point 4): the SDK side of hop reissue for an
 * issuer that holds its own key. When a delegate rotates its key, Helix
 * reissues the hops it can sign and lists the rest as
 * `hopReissue.pendingIssuers`; each of those issuers rebuilds its hop here
 * (same parent, target, actions, caveats and window, a new id and the status
 * entry it gives) and signs it with its own Signer. Nothing goes to Helix.
 */

import { randomUUID } from 'node:crypto';
import { base58btcEncode } from '../vp-crypto.js';
import { hashData, issuerOf } from '../kyaos/verifier/data-integrity.js';
import type { Signer } from './signer.js';

/** The Bitstring status entry a hop carries; on the issuer's own list (story L3-C). */
export interface HopStatusEntry {
  id?: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

export interface ReissueHopOptions {
  /** The hop's issuer: the Signer must be the old hop's `issuer`. */
  signer: Signer;
  /** The new hop's entry on the issuer's own status list. */
  statusEntry: HopStatusEntry;
  /** The new capability id; default `urn:zcap:<uuid>`. */
  id?: string;
  /** The proof's `created`; default now. */
  created?: string;
}

const ED25519_SIGNATURE_LENGTH = 64;

/**
 * Adds an `eddsa-jcs-2022` proof for `assertionMethod` by `signer`, which
 * must be the document's issuer (the same bytes helix-core's
 * `signDataIntegrity` signs).
 */
export async function signDataIntegrity<T extends Record<string, unknown>>(document: T, signer: Signer, created: string = new Date().toISOString()): Promise<T & { proof: Record<string, unknown> }> {
  if (document['proof'] !== undefined) throw new Error('signDataIntegrity: document already carries a proof');
  if (issuerOf(document['issuer']) !== signer.did) throw new Error(`signDataIntegrity: signer ${signer.did} is not the issuer of the document`);
  const fragment = signer.kid.replace(/^#/, '');
  if (fragment.length === 0 || fragment.includes('#')) throw new Error('signDataIntegrity: signer kid must be a verification-method fragment');
  const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created, verificationMethod: `${signer.did}#${fragment}`, proofPurpose: 'assertionMethod' };
  const config: Record<string, unknown> = { ...proof, ...(document['@context'] === undefined ? {} : { '@context': document['@context'] }) };
  const signature = await signer.sign(hashData(config, document));
  if (!(signature instanceof Uint8Array) || signature.length !== ED25519_SIGNATURE_LENGTH) throw new Error('signDataIntegrity: signer did not return a 64-byte Ed25519 signature');
  return { ...document, proof: { ...proof, proofValue: `z${base58btcEncode(signature)}` } };
}

/** The old hop rebuilt with a new id and status entry, signed again by its issuer. */
export async function reissueHop(hop: Record<string, unknown>, options: ReissueHopOptions): Promise<Record<string, unknown>> {
  const subject = hop['credentialSubject'] as Record<string, unknown> | undefined;
  if (subject === undefined || subject === null || typeof subject !== 'object') throw new Error('reissueHop: the hop has no credentialSubject');
  if (issuerOf(hop['issuer']) !== options.signer.did) throw new Error(`reissueHop: ${options.signer.did} is not the issuer of this hop`);
  const id = options.id ?? `urn:zcap:${randomUUID()}`;
  const { proof: _proof, credentialStatus: _status, id: _id, ...kept } = hop;
  void _proof;
  void _status;
  void _id;
  const statusEntry = { ...options.statusEntry, id: options.statusEntry.id ?? `${options.statusEntry.statusListCredential}#${options.statusEntry.statusListIndex}` };
  const unsigned = { ...kept, id, credentialSubject: { ...subject, id }, credentialStatus: statusEntry };
  return signDataIntegrity(unsigned, options.signer, options.created);
}
