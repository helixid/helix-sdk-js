import { readFile, writeFile } from 'node:fs/promises';
import { requirePassphrase } from '@helixid/cli/lib/env';
import { parseStatusListFile, revokeCredentialInStatusList } from '@helixid/cli/lib/issuer-ops';
import { loadIssuerKeyMaterial } from '@helixid/cli/lib/wallet';

export interface RevokeInput {
  vcId: string;
  statusList: string;
  wallet: string;
}

export interface RevokeResult {
  vcId: string;
  index: number;
  previousBit: 0 | 1;
}

export async function revoke(input: RevokeInput): Promise<RevokeResult> {
  const passphrase = requirePassphrase();
  const issuer = await loadIssuerKeyMaterial(input.wallet, passphrase);

  let statusListRaw: unknown;
  try {
    statusListRaw = JSON.parse(await readFile(input.statusList, 'utf8'));
  } catch {
    throw new Error(`Status list file not found or invalid: ${input.statusList}`);
  }

  const statusList = parseStatusListFile(statusListRaw);
  const { statusList: updatedList, index, previousBit } = await revokeCredentialInStatusList({
    issuer,
    statusList,
    vcId: input.vcId,
  });

  await writeFile(input.statusList, JSON.stringify(updatedList, null, 2), 'utf8');

  return { vcId: input.vcId, index, previousBit };
}
