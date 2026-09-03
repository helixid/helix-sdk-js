import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('helix did create --method hedera without did-hedera', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'helix-cli-hedera-'));
    process.env.HELIX_WALLET_PASSPHRASE = 'test-passphrase';
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    await rm(tempDir, { recursive: true, force: true });
    delete process.env.HELIX_WALLET_PASSPHRASE;
  });

  it('throws install instruction when did-hedera cannot be imported', async () => {
    vi.doMock('@helixid/did-hedera', () => {
      throw new Error('Cannot find module @helixid/did-hedera');
    });

    const { runDidCreate } = await import('../src/commands/did.js');

    await expect(runDidCreate({
      method: 'hedera',
      network: 'testnet',
      wallet: join(tempDir, 'issuer.enc'),
    })).rejects.toThrow('Hedera DID method requires: npm install @helixid/did-hedera');
  });
});
