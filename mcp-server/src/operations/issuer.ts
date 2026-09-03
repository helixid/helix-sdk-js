import { requirePassphrase } from '@helixid/cli/lib/env';
import { loadIssuerKeyMaterial } from '@helixid/cli/lib/wallet';

export interface IssuerInitInput {
  wallet: string;
}

export interface IssuerInitResult {
  did: string;
  publicKeyHex: string;
  verificationMethod: string;
}

export async function issuerInit(input: IssuerInitInput): Promise<IssuerInitResult> {
  const passphrase = requirePassphrase();
  const issuer = await loadIssuerKeyMaterial(input.wallet, passphrase);

  return {
    did: issuer.did,
    publicKeyHex: issuer.publicKeyHex,
    verificationMethod: `${issuer.did}#key-1`,
  };
}
