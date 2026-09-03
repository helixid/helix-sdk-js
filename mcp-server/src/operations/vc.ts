import { readFile, writeFile } from 'node:fs/promises';
import { requirePassphrase } from '@helixid/cli/lib/env';
import { parseDuration } from '@helixid/cli/lib/duration';
import { issueAgentCredential, parseStatusListFile } from '@helixid/cli/lib/issuer-ops';
import { loadIssuerKeyMaterial, loadWallet } from '@helixid/cli/lib/wallet';

export interface VcIssueInput {
  agentDid: string;
  scopes: string;
  expires: string;
  statusList: string;
  baseUrl: string;
  wallet: string;
  output?: string | undefined;
  maxDelegationDepth?: number | undefined;
}

export interface VcIssueResult {
  vc: Record<string, unknown>;
  vcId: string;
  scopes: string[];
  expiresAt: string;
  statusIndex: number;
  outputPath?: string;
}

export async function vcIssue(input: VcIssueInput): Promise<VcIssueResult> {
  const passphrase = requirePassphrase();
  const issuer = await loadIssuerKeyMaterial(input.wallet, passphrase);
  const scopes = input.scopes.split(',').map((scope) => scope.trim()).filter(Boolean);
  if (scopes.length === 0) {
    throw new Error('At least one scope is required in scopes');
  }

  let statusListRaw: unknown;
  try {
    statusListRaw = JSON.parse(await readFile(input.statusList, 'utf8'));
  } catch {
    throw new Error(`Status list file not found or invalid: ${input.statusList}`);
  }

  const statusList = parseStatusListFile(statusListRaw);
  const expiresMs = parseDuration(input.expires);

  const { vc, statusList: updatedList, index } = await issueAgentCredential({
    issuer,
    agentDid: input.agentDid,
    scopes,
    expiresMs,
    statusList,
    baseUrl: input.baseUrl,
    maxDelegationDepth: input.maxDelegationDepth ?? 1,
  });

  await writeFile(input.statusList, JSON.stringify(updatedList, null, 2), 'utf8');

  const result: VcIssueResult = {
    vc: vc as unknown as Record<string, unknown>,
    vcId: vc.id,
    scopes,
    expiresAt: vc.validUntil,
    statusIndex: index,
  };

  if (input.output) {
    await writeFile(input.output, JSON.stringify(vc, null, 2), 'utf8');
    result.outputPath = input.output;
  }

  return result;
}

export interface VcSelfIssueInput {
  scopes: string;
  expires: string;
  wallet: string;
}

export interface VcSelfIssueResult {
  scopes: string[];
  expires: string;
  walletPath: string;
}

export async function vcSelfIssue(input: VcSelfIssueInput): Promise<VcSelfIssueResult> {
  const passphrase = requirePassphrase();
  const wallet = await loadWallet(input.wallet, passphrase);
  const scopes = input.scopes.split(',').map((scope) => scope.trim()).filter(Boolean);

  await wallet.selfIssueVC({ scopes, expiresIn: input.expires });

  return { scopes, expires: input.expires, walletPath: input.wallet };
}
