import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { didCreate } from '../src/operations/did.js';
import { issuerInit } from '../src/operations/issuer.js';
import { revoke } from '../src/operations/revoke.js';
import { statusListCreate } from '../src/operations/statusList.js';
import { vcIssue } from '../src/operations/vc.js';
import { walletInspect } from '../src/operations/wallet.js';
import { loadWallet } from '@helixid/cli/lib/wallet';

describe('mcp-server operations', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'helix-mcp-server-'));
    process.env.HELIX_WALLET_PASSPHRASE = 'test-passphrase';
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
    delete process.env.HELIX_WALLET_PASSPHRASE;
  });

  it('did_create requires HELIX_WALLET_PASSPHRASE', async () => {
    delete process.env.HELIX_WALLET_PASSPHRASE;
    await expect(
      didCreate({ method: 'key', wallet: join(tempDir, 'agent.enc') }),
    ).rejects.toThrow('HELIX_WALLET_PASSPHRASE environment variable is required');
  });

  it('did_create method web creates a wallet, DID document, and a status list by default', async () => {
    const walletPath = join(tempDir, 'issuer.enc');

    const result = await didCreate({ method: 'web', domain: 'example.com', wallet: walletPath });

    expect(result.did).toBe('did:web:example.com');
    expect(result.didDocument?.['id']).toBe('did:web:example.com');
    expect(result.statusList?.output).toBe(join(tempDir, 'status-list.json'));

    const saved = JSON.parse(await readFile(walletPath, 'utf8'));
    expect(saved.did).toBe('did:web:example.com');

    const statusList = JSON.parse(await readFile(result.statusList!.output, 'utf8'));
    expect(statusList.issuer).toBe('did:web:example.com');
    expect(statusList.proof?.proofValue).toBeTruthy();
  });

  it('did_create method web with statusList: false skips the status list', async () => {
    const walletPath = join(tempDir, 'issuer-optout.enc');

    const result = await didCreate({
      method: 'web',
      domain: 'example.com',
      wallet: walletPath,
      statusList: false,
    });

    expect(result.statusList).toBeUndefined();
    await expect(readFile(join(tempDir, 'status-list.json'), 'utf8')).rejects.toThrow();
  });

  it('did_create method key creates a did:key wallet', async () => {
    const walletPath = join(tempDir, 'agent.enc');
    const result = await didCreate({ method: 'key', wallet: walletPath });
    expect(result.did).toMatch(/^did:key:z/);
  });

  it('did_create refuses to overwrite an existing wallet file', async () => {
    const walletPath = join(tempDir, 'agent.enc');
    await didCreate({ method: 'key', wallet: walletPath });

    await expect(didCreate({ method: 'key', wallet: walletPath })).rejects.toThrow(
      'Wallet file already exists',
    );
  });

  it('issuer_init reports the issuer DID and public key', async () => {
    const walletPath = join(tempDir, 'issuer.enc');
    await didCreate({ method: 'web', domain: 'example.com', wallet: walletPath });

    const result = await issuerInit({ wallet: walletPath });

    expect(result.did).toBe('did:web:example.com');
    expect(result.verificationMethod).toBe('did:web:example.com#key-1');
  });

  it('status_list_create writes a signed status list file', async () => {
    const walletPath = join(tempDir, 'issuer.enc');
    const outputPath = join(tempDir, 'status', '1.json');
    await didCreate({ method: 'web', domain: 'example.com', wallet: walletPath, statusList: false });

    const result = await statusListCreate({
      length: 128,
      output: outputPath,
      baseUrl: 'https://example.com/status/1',
      wallet: walletPath,
    });

    expect(result.output).toBe(outputPath);
    const saved = JSON.parse(await readFile(outputPath, 'utf8'));
    expect(saved.id).toBe('https://example.com/status/1');
    expect(saved.proof?.proofValue).toBeTruthy();
  });

  it('vc_issue issues a VC and updates the status list, then revoke flips its bit', async () => {
    const issuerWallet = join(tempDir, 'issuer.enc');
    const agentWallet = join(tempDir, 'agent.enc');
    const statusListPath = join(tempDir, 'status.json');
    const vcOutput = join(tempDir, 'vc.json');

    await didCreate({ method: 'web', domain: 'example.com', wallet: issuerWallet, statusList: false });
    const agent = await didCreate({ method: 'key', wallet: agentWallet });
    await statusListCreate({
      length: 128,
      output: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
    });

    const issued = await vcIssue({
      agentDid: agent.did,
      scopes: 'read:orders,write:bookings',
      expires: '90d',
      statusList: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
      output: vcOutput,
    });

    expect(issued.scopes).toEqual(['read:orders', 'write:bookings']);
    expect(issued.statusIndex).toBe(0);
    expect(issued.outputPath).toBe(vcOutput);

    const revoked = await revoke({ vcId: issued.vcId, statusList: statusListPath, wallet: issuerWallet });
    expect(revoked.index).toBe(0);
    expect(revoked.previousBit).toBe(0);

    const updatedList = JSON.parse(await readFile(statusListPath, 'utf8'));
    expect(updatedList.helixIndexRegistry?.[issued.vcId]).toBe(0);
  });

  it('vc_issue rejects an empty scopes list', async () => {
    const issuerWallet = join(tempDir, 'issuer.enc');
    const statusListPath = join(tempDir, 'status.json');
    await didCreate({ method: 'web', domain: 'example.com', wallet: issuerWallet, statusList: false });
    await statusListCreate({
      length: 128,
      output: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
    });

    await expect(
      vcIssue({
        agentDid: 'did:key:zSomeAgent',
        scopes: '  ,  ',
        expires: '90d',
        statusList: statusListPath,
        baseUrl: 'https://example.com/status/1',
        wallet: issuerWallet,
      }),
    ).rejects.toThrow('At least one scope is required');
  });

  it('revoke on an unknown VC ID throws a clear error', async () => {
    const issuerWallet = join(tempDir, 'issuer.enc');
    const statusListPath = join(tempDir, 'status.json');
    await didCreate({ method: 'web', domain: 'example.com', wallet: issuerWallet, statusList: false });
    await statusListCreate({
      length: 128,
      output: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
    });

    await expect(
      revoke({ vcId: 'urn:uuid:missing', statusList: statusListPath, wallet: issuerWallet }),
    ).rejects.toThrow('VC ID not found');
  });

  it('wallet_inspect reports a credential added to the agent wallet', async () => {
    const issuerWallet = join(tempDir, 'issuer.enc');
    const agentWallet = join(tempDir, 'agent.enc');
    const statusListPath = join(tempDir, 'status.json');

    await didCreate({ method: 'web', domain: 'example.com', wallet: issuerWallet, statusList: false });
    const agent = await didCreate({ method: 'key', wallet: agentWallet });
    await statusListCreate({
      length: 128,
      output: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
    });
    const issued = await vcIssue({
      agentDid: agent.did,
      scopes: 'read:orders',
      expires: '90d',
      statusList: statusListPath,
      baseUrl: 'https://example.com/status/1',
      wallet: issuerWallet,
    });

    // No agent self-issuance anymore — add the issuer-signed VC directly,
    // same as a real onboarding flow hands one to a wallet.
    const wallet = await loadWallet(agentWallet, 'test-passphrase');
    await wallet.addCredential(issued.vc as any);

    const inspected = await walletInspect({ wallet: agentWallet });
    expect(inspected.credentials).toHaveLength(1);
    expect(inspected.credentials[0]?.scopes).toEqual(['read:orders']);
  });

  it('wallet_inspect never returns a private key field', async () => {
    const agentWallet = join(tempDir, 'agent.enc');
    await didCreate({ method: 'key', wallet: agentWallet });

    const result = await walletInspect({ wallet: agentWallet });

    expect(result.did).toMatch(/^did:key:z/);
    expect(JSON.stringify(result)).not.toMatch(/privateKey/i);
  });
});
