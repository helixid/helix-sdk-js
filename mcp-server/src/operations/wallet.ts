import { requirePassphrase } from '@helixid/cli/lib/env';
import { loadWallet } from '@helixid/cli/lib/wallet';

export interface WalletInspectInput {
  wallet: string;
}

export interface WalletInspectCredential {
  id: string;
  scopes: string[];
  expires: string | null;
}

export interface WalletInspectResult {
  did: string;
  publicKey: string;
  credentials: WalletInspectCredential[];
}

export async function walletInspect(input: WalletInspectInput): Promise<WalletInspectResult> {
  const passphrase = requirePassphrase();
  const wallet = await loadWallet(input.wallet, passphrase);

  const credentials: WalletInspectCredential[] = wallet.credentials.map((vc) => {
    const subject = vc.credentialSubject as Record<string, unknown>;
    const scopes = Array.isArray(subject['privilegeScopes'])
      ? (subject['privilegeScopes'] as string[])
      : [];
    return { id: vc.id, scopes, expires: vc.validUntil ?? null };
  });

  return {
    did: wallet.getDID(),
    publicKey: wallet.getPublicKey(),
    credentials,
  };
}
