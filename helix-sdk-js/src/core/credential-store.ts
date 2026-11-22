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
 * KYA-OS story F-1 (credential split): what an agent's SDK holds and what it
 * sends. Three kinds of credential, kept apart so changing one never touches
 * another:
 *
 * - the identity credential Helix issued (no scopes);
 * - one capability attestation per scope (`CapabilityAttestationCredential`),
 *   signed by the owner through {@link CredentialStore.signAttestations} or
 *   by the Helix issuer at onboarding; these resolve from the Entity Card,
 *   so they are stored but not carried in requests;
 * - delegation hops (`DelegationCredential`, SPEC.md §6.10), of which
 *   {@link CredentialStore.presentChain} returns the agent's chain root to
 *   leaf beside the identity: that is what a request carries.
 *
 * Self-custody invariant (stories rule 7): nothing here talks to an API, and
 * signing goes through a Signer that keeps the key wherever it lives.
 */

import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { base58btcEncode, toCanonicalJson } from './vp-crypto.js';

/** Whoever holds an Ed25519 key and signs with it: the same shape as helix-core's Signer (story L1-C). */
export interface CredentialSigner {
  readonly did: string;
  /** Verification-method fragment without `#` (for example `key-1`). */
  readonly kid: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface BitstringStatusEntry {
  id?: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
}

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

/** A credential as the store reads it: the members it needs to route and order, the rest untouched. */
export interface StoredCredential {
  '@context'?: unknown;
  id: string;
  type: string[];
  issuer: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown> & { id?: string };
  proof?: DataIntegrityProof | Record<string, unknown>;
  [member: string]: unknown;
}

export interface CapabilityAttestation extends StoredCredential {
  validFrom: string;
  validUntil: string;
  credentialSubject: { id: string; capability: string };
  credentialStatus: BitstringStatusEntry;
  proof: DataIntegrityProof;
}

export interface DelegationHop extends StoredCredential {
  validUntil: string;
  credentialSubject: {
    id: string;
    invoker?: string;
    controller?: string;
    parentCapability: string;
    invocationTarget: string;
    allowedAction: string[];
    caveats?: Record<string, unknown>[];
  };
}

export interface CredentialStoreData {
  identity: StoredCredential | null;
  attestations: StoredCredential[];
  hops: StoredCredential[];
}

/** What a request carries (story F-1 point 7): the identity, then the hops root to leaf. */
export interface PresentedChain {
  identity: StoredCredential;
  hops: StoredCredential[];
}

export interface SignAttestationsOptions {
  /** The agent the attestations are about; default the stored identity's subject. */
  subjectDid?: string;
  validUntil: string;
  /** One status entry per capability, in order: the owner's own status list, or entries Helix handed out. */
  statusEntries: readonly BitstringStatusEntry[];
  validFrom?: string;
  /** Each attestation's `id`, in order; default `urn:uuid:` values. */
  ids?: readonly string[];
  /** The proof's `created`; default now. */
  created?: string;
}

export const IDENTITY_CREDENTIAL_TYPE = 'AgentIdentityCredential';
export const CAPABILITY_ATTESTATION_TYPE = 'CapabilityAttestationCredential';
export const DELEGATION_CREDENTIAL_TYPE = 'DelegationCredential';

const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const HELIX_CONTEXT = 'https://helixid.io/contexts/v1';

function kindOf(credential: StoredCredential): 'identity' | 'attestation' | 'hop' | undefined {
  const types = Array.isArray(credential.type) ? credential.type : [];
  if (types.includes(IDENTITY_CREDENTIAL_TYPE)) return 'identity';
  if (types.includes(CAPABILITY_ATTESTATION_TYPE)) return 'attestation';
  if (types.includes(DELEGATION_CREDENTIAL_TYPE)) return 'hop';
  return undefined;
}

function invokerOf(hop: StoredCredential): string | undefined {
  const subject = hop.credentialSubject as { invoker?: unknown; controller?: unknown };
  if (typeof subject.invoker === 'string') return subject.invoker;
  if (typeof subject.controller === 'string') return subject.controller;
  return undefined;
}

function uuid(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * `eddsa-jcs-2022` as the KYA-OS reference and helix-core write it:
 * SHA-256(canonical proof options with the document @context) followed by
 * SHA-256(canonical unsecured document), Ed25519 over the two, base58btc.
 * Canonical JSON is the SDK's sorted-key form, which equals RFC 8785 for
 * these documents (strings, arrays and objects only; story L2-A's port of
 * helix-core's `canonicalize` replaces it for the general case).
 */
export async function signAttestationDocument<T extends Record<string, unknown>>(
  document: T,
  signer: CredentialSigner,
  created: string,
): Promise<T & { proof: DataIntegrityProof }> {
  if (document['issuer'] !== signer.did) {
    throw new Error(`signer ${signer.did} is not the issuer of the document`);
  }
  const fragment = signer.kid.replace(/^#/, '');
  const proof: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created,
    verificationMethod: `${signer.did}#${fragment}`,
    proofPurpose: 'assertionMethod',
  };
  const config: Record<string, unknown> = { ...proof };
  if (document['@context'] !== undefined) config['@context'] = document['@context'];
  const proofHash = sha256(utf8ToBytes(toCanonicalJson(config)));
  const documentHash = sha256(utf8ToBytes(toCanonicalJson(document)));
  const data = new Uint8Array(proofHash.length + documentHash.length);
  data.set(proofHash, 0);
  data.set(documentHash, proofHash.length);
  const signature = await signer.sign(data);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error('signer did not return a 64-byte Ed25519 signature');
  }
  return { ...document, proof: { ...proof, proofValue: `z${base58btcEncode(signature)}` } };
}

export class CredentialStore {
  private identityCredential: StoredCredential | null;
  private readonly attestationList: StoredCredential[];
  private readonly hopList: StoredCredential[];

  constructor(initial: Partial<CredentialStoreData> = {}) {
    this.identityCredential = initial.identity ?? null;
    this.attestationList = [...(initial.attestations ?? [])];
    this.hopList = [...(initial.hops ?? [])];
  }

  /** The store `POST /v1/agents` leaves an agent with: its identity and its onboarding attestations. */
  static fromOnboarding(response: { identity: StoredCredential; attestations?: StoredCredential[] }): CredentialStore {
    return new CredentialStore({ identity: response.identity, attestations: response.attestations ?? [] });
  }

  static fromJSON(json: string | CredentialStoreData): CredentialStore {
    const data = typeof json === 'string' ? (JSON.parse(json) as CredentialStoreData) : json;
    return new CredentialStore(data);
  }

  toJSON(): CredentialStoreData {
    return { identity: this.identityCredential, attestations: [...this.attestationList], hops: [...this.hopList] };
  }

  get identity(): StoredCredential | null {
    return this.identityCredential;
  }

  get attestations(): readonly StoredCredential[] {
    return this.attestationList;
  }

  get hops(): readonly StoredCredential[] {
    return this.hopList;
  }

  /** The agent DID the identity names, if an identity is stored. */
  get agentDid(): string | undefined {
    const id = this.identityCredential?.credentialSubject.id;
    return typeof id === 'string' ? id : undefined;
  }

  /** Routes a credential by its type; refuses anything that is none of the three. */
  add(credential: StoredCredential): this {
    switch (kindOf(credential)) {
      case 'identity':
        return this.setIdentity(credential);
      case 'attestation':
        return this.addAttestation(credential);
      case 'hop':
        return this.addHop(credential);
      default:
        throw new Error('credential is not an identity, a capability attestation or a delegation hop');
    }
  }

  setIdentity(credential: StoredCredential): this {
    if (kindOf(credential) !== 'identity') throw new Error('not an AgentIdentityCredential');
    this.identityCredential = credential;
    return this;
  }

  addAttestation(credential: StoredCredential): this {
    if (kindOf(credential) !== 'attestation') throw new Error('not a CapabilityAttestationCredential');
    this.replaceById(this.attestationList, credential);
    return this;
  }

  addHop(credential: StoredCredential): this {
    if (kindOf(credential) !== 'hop') throw new Error('not a DelegationCredential');
    this.replaceById(this.hopList, credential);
    return this;
  }

  private replaceById(list: StoredCredential[], credential: StoredCredential): void {
    const index = list.findIndex((item) => item.id === credential.id);
    if (index === -1) list.push(credential);
    else list[index] = credential;
  }

  /** Drops every attestation of `capability`; returns how many went. */
  removeAttestation(capability: string): number {
    const before = this.attestationList.length;
    for (let index = before - 1; index >= 0; index -= 1) {
      if (this.attestationList[index]!.credentialSubject['capability'] === capability) this.attestationList.splice(index, 1);
    }
    return before - this.attestationList.length;
  }

  removeHop(id: string): boolean {
    const index = this.hopList.findIndex((hop) => hop.id === id);
    if (index === -1) return false;
    this.hopList.splice(index, 1);
    return true;
  }

  /** The capability names attested, in store order, each once. */
  attestedCapabilities(): string[] {
    const names: string[] = [];
    for (const attestation of this.attestationList) {
      const name = attestation.credentialSubject['capability'];
      if (typeof name === 'string' && !names.includes(name)) names.push(name);
    }
    return names;
  }

  /**
   * The identity plus the hops that delegate to this agent, ordered root to
   * leaf by following each hop's `parentCapability` up to the root (whose
   * parent is the resource itself). With several chains ending at the agent,
   * `invocationTarget` picks one; otherwise the most recently added wins.
   * Throws without an identity or when the chain does not link up.
   */
  presentChain(options: { invocationTarget?: string } = {}): PresentedChain {
    const identity = this.identityCredential;
    if (identity === null) throw new Error('no identity credential stored');
    const agentDid = this.agentDid;
    const leaves = this.hopList.filter(
      (hop) =>
        invokerOf(hop) === agentDid &&
        (options.invocationTarget === undefined || hop.credentialSubject['invocationTarget'] === options.invocationTarget),
    );
    const leaf = leaves[leaves.length - 1];
    if (leaf === undefined) return { identity, hops: [] };
    const byCapability = new Map(this.hopList.map((hop) => [hop.credentialSubject['id'] as string, hop]));
    const chain: StoredCredential[] = [leaf];
    let current = leaf;
    while (current.credentialSubject['parentCapability'] !== current.credentialSubject['invocationTarget']) {
      const parent = byCapability.get(current.credentialSubject['parentCapability'] as string);
      if (parent === undefined) throw new Error(`hop ${current.id} names a parent capability the store does not hold`);
      if (chain.includes(parent) || chain.length >= 10) throw new Error('delegation chain does not terminate at a root');
      chain.unshift(parent);
      current = parent;
    }
    return { identity, hops: chain };
  }

  /**
   * The owner's path (story C-B): one `CapabilityAttestationCredential` per
   * capability, signed here by the owner's Signer, stored, and returned for
   * `POST /v1/agents/{id}/attestations` to keep a copy. No key leaves the
   * Signer and nothing is sent.
   */
  async signAttestations(
    capabilities: readonly string[],
    signer: CredentialSigner,
    options: SignAttestationsOptions,
  ): Promise<CapabilityAttestation[]> {
    const subjectDid = options.subjectDid ?? this.agentDid;
    if (subjectDid === undefined) throw new Error('subjectDid is required when no identity is stored');
    if (options.statusEntries.length !== capabilities.length) {
      throw new Error('one status entry per capability is required');
    }
    const signed: CapabilityAttestation[] = [];
    for (const [index, capability] of capabilities.entries()) {
      if (typeof capability !== 'string' || capability === '' || /\s/.test(capability)) {
        throw new Error('capability must be a non-empty string without whitespace');
      }
      const document = {
        '@context': [VC_V2_CONTEXT, HELIX_CONTEXT],
        id: options.ids?.[index] ?? `urn:uuid:${uuid()}`,
        type: ['VerifiableCredential', CAPABILITY_ATTESTATION_TYPE],
        issuer: signer.did,
        validFrom: options.validFrom ?? new Date().toISOString(),
        validUntil: options.validUntil,
        credentialSubject: { id: subjectDid, capability },
        credentialStatus: options.statusEntries[index]!,
      };
      const attestation = (await signAttestationDocument(document, signer, options.created ?? new Date().toISOString())) as CapabilityAttestation;
      this.addAttestation(attestation);
      signed.push(attestation);
    }
    return signed;
  }
}
