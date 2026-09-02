import { signData } from './core/keys.js';
import type { SignedVC } from './core/schemas/vc.js';
import type { StatusListCredential } from './core/status-list-schema.js';
import type { HelixClient } from './client/HelixClient.js';

/** SP-held issuer key material. The SP signs grants with its own key, which never leaves this process. */
export interface IssuerKeyMaterial {
  did: string;
  privateKeyHex: string;
}

export interface IssueGrantOptions {
  agentDid: string;
  userDid: string;
  scopes: string[];
  durability: 'standing' | 'session';
  serviceDid?: string;
  statusList: StatusListCredential; // current list, unmodified
  statusListCredentialUrl: string; // public URL of the list above
}

export interface IssueGrantResult {
  grantVC: SignedVC;
  /**
   * Same object as `options.statusList` — issuance doesn't set bits (only
   * revocation does), returned for drop-in compatibility with the old
   * `@helixid/core` `issueGrant()` call shape.
   */
  updatedStatusList: StatusListCredential;
}

/**
 * Builds and signs a DelegationGrantCredential via the API's prepare/finalize
 * endpoints (see docs/proposal-sdk-api-only.md). Payload construction — index
 * allocation on the status list included — happens server-side; only the
 * signature is produced locally, so the SP's issuer key never leaves this
 * process.
 */
export async function issueGrant(
  options: IssueGrantOptions,
  issuerWallet: IssuerKeyMaterial,
  client: HelixClient,
): Promise<IssueGrantResult> {
  const prepared = await client.prepareGrant({
    issuerDid: issuerWallet.did,
    agentDid: options.agentDid,
    userDid: options.userDid,
    scopes: options.scopes,
    durability: options.durability,
    ...(options.serviceDid !== undefined ? { serviceDid: options.serviceDid } : {}),
    statusList: options.statusList,
    statusListCredentialUrl: options.statusListCredentialUrl,
  });

  const signatureHex = signData(
    Buffer.from(prepared.canonicalHash, 'hex'),
    issuerWallet.privateKeyHex,
  );

  const grantVC = await client.finalizeGrant({
    token: prepared.token,
    verificationMethod: `${issuerWallet.did}#key-1`,
    signatureHex,
  });

  return { grantVC, updatedStatusList: options.statusList };
}

// --- Local (non-API) revocation ---
//
// Unlike issueGrant() above, revocation stays entirely local: the SP owns
// its own status list (it is not registered with helix-api at all in the
// independent-SP case -- see examples/e2e-consent-demo in helix-server),
// so there is nothing for a central API to prepare/finalize here. This is
// the direct SDK-side port of helix-api/src/core/grant.ts's revokeGrant(),
// which duplicates the same logic for helix-api's own internal use.

import { createEd25519Proof, type LinkedDataProof } from './core/proof.js';
import { setBit } from './core/status-list-schema.js';
import { ValidationError } from './errors/index.js';

export type RevokeGrantTarget = { vc: SignedVC } | { statusListIndex: string };

export type SignedStatusListCredential = StatusListCredential & { proof: LinkedDataProof };

export async function revokeGrant(
  currentStatusList: StatusListCredential,
  issuerWallet: IssuerKeyMaterial,
  target: RevokeGrantTarget,
): Promise<SignedStatusListCredential> {
  const index =
    'vc' in target ? target.vc.credentialStatus?.statusListIndex : target.statusListIndex;

  if (!index) {
    throw new ValidationError(
      'No statusListIndex available to revoke — VC has no credentialStatus, or no index was provided',
    );
  }
  const numericIndex = Number(index);
  if (!Number.isInteger(numericIndex) || numericIndex < 0) {
    throw new ValidationError(`statusListIndex is not a valid list index: ${index}`);
  }

  const { proof: _staleProof, ...unsigned } = currentStatusList as StatusListCredential & {
    proof?: unknown;
  };
  const payload = {
    ...unsigned,
    credentialSubject: {
      ...unsigned.credentialSubject,
      encodedList: setBit(unsigned.credentialSubject.encodedList, numericIndex, 1),
    },
  };

  return {
    ...payload,
    proof: await createEd25519Proof(payload, issuerWallet.privateKeyHex, `${issuerWallet.did}#key-1`),
  };
}
