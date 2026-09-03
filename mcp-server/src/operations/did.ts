import { access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { buildDIDDocument } from '@helixid/cli/core/did';
import { generateKeyPair, publicKeyToMultibase } from '@helixid/cli/core/keys';
import { requireHederaOperator, requirePassphrase } from '@helixid/cli/lib/env';
import { saveNewWallet } from '@helixid/cli/lib/wallet';
import { statusListCreate } from './statusList.js';

export interface DidCreateInput {
  method: 'web' | 'hedera' | 'key';
  domain?: string | undefined;
  network?: 'testnet' | 'previewnet' | 'mainnet' | undefined;
  wallet: string;
  /** did:web only — set false to skip creating the initial status list. */
  statusList?: boolean | undefined;
  statusListLength?: number | undefined;
  statusListOutput?: string | undefined;
  statusListBaseUrl?: string | undefined;
}

export interface DidCreateResult {
  did: string;
  walletPath: string;
  didDocument?: Record<string, unknown>;
  didDocumentUrl?: string;
  statusList?: { output: string; baseUrl: string; length: number };
  hedera?: { transactionId: string; topicId: string };
}

const DEFAULT_STATUS_LIST_LENGTH = 131072;

export async function didCreate(input: DidCreateInput): Promise<DidCreateResult> {
  const passphrase = requirePassphrase();

  let walletAlreadyExists = true;
  try {
    await access(input.wallet);
  } catch {
    walletAlreadyExists = false;
  }
  if (walletAlreadyExists) {
    throw new Error(`Wallet file already exists: ${input.wallet}. Use a different path or remove the file.`);
  }

  const keyPair = generateKeyPair();

  if (input.method === 'web') {
    if (!input.domain) {
      throw new Error('domain is required for method "web"');
    }
    const did = `did:web:${input.domain}`;
    const didDocument = buildDIDDocument(did, keyPair.publicKey);
    await saveNewWallet(input.wallet, passphrase, did, keyPair);

    const result: DidCreateResult = {
      did,
      walletPath: input.wallet,
      didDocument: didDocument as unknown as Record<string, unknown>,
      didDocumentUrl: `https://${input.domain}/.well-known/did.json`,
    };

    if (input.statusList !== false) {
      const output = input.statusListOutput ?? join(dirname(input.wallet), 'status-list.json');
      const baseUrl =
        input.statusListBaseUrl ?? `https://${input.domain}/.well-known/helix-status-list.json`;
      const length = input.statusListLength ?? DEFAULT_STATUS_LIST_LENGTH;

      await statusListCreate({ length, output, baseUrl, wallet: input.wallet });
      result.statusList = { output, baseUrl, length };
    }

    return result;
  }

  if (input.method === 'key') {
    const did = `did:key:${publicKeyToMultibase(keyPair.publicKey)}`;
    await saveNewWallet(input.wallet, passphrase, did, keyPair);
    return { did, walletPath: input.wallet };
  }

  if (input.method === 'hedera') {
    let anchorDidHedera: typeof import('@helixid/did-hedera').anchorDidHedera;
    try {
      ({ anchorDidHedera } = await import('@helixid/did-hedera'));
    } catch {
      throw new Error('Hedera DID method requires: npm install @helixid/did-hedera');
    }

    const network = input.network ?? 'testnet';
    const { operatorId, operatorKey } = requireHederaOperator();

    const anchorResult = await anchorDidHedera({
      privateKeyHex: keyPair.privateKey,
      operatorId,
      operatorKey,
      network,
    });

    await saveNewWallet(input.wallet, passphrase, anchorResult.did, keyPair);

    return {
      did: anchorResult.did,
      walletPath: input.wallet,
      hedera: { transactionId: anchorResult.transactionId, topicId: anchorResult.topicId },
    };
  }

  throw new Error(`Unknown method: ${input.method as string}`);
}
