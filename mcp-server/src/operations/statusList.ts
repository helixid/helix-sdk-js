import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { buildCliStatusListPayload, signCredential } from '@helixid/cli/lib/issuer-ops';
import { requirePassphrase } from '@helixid/cli/lib/env';
import { loadIssuerKeyMaterial } from '@helixid/cli/lib/wallet';

export interface StatusListCreateInput {
  length: number;
  output: string;
  baseUrl: string;
  wallet: string;
}

export interface StatusListCreateResult {
  output: string;
  baseUrl: string;
  length: number;
}

export async function statusListCreate(input: StatusListCreateInput): Promise<StatusListCreateResult> {
  const passphrase = requirePassphrase();
  const issuer = await loadIssuerKeyMaterial(input.wallet, passphrase);

  const payload = buildCliStatusListPayload(input.baseUrl, issuer.did, input.length);
  const signed = await signCredential(payload, issuer.did, issuer.privateKeyHex);

  await mkdir(dirname(input.output), { recursive: true });
  await writeFile(input.output, JSON.stringify(signed, null, 2), 'utf8');

  return { output: input.output, baseUrl: input.baseUrl, length: input.length };
}
