import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer } from '../src/server.js';

const EXPECTED_TOOLS = [
  'did_create',
  'issuer_init',
  'status_list_create',
  'vc_issue',
  'vc_self_issue',
  'revoke',
  'wallet_inspect',
];

async function connectedClient() {
  const server = createServer();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('helix-mcp-server', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'helix-mcp-server-e2e-'));
    process.env.HELIX_WALLET_PASSPHRASE = 'test-passphrase';
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
    delete process.env.HELIX_WALLET_PASSPHRASE;
  });

  it('registers every platform-operator tool', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name).sort()).toEqual([...EXPECTED_TOOLS].sort());
  });

  it('did_create tool call returns structured content over the wire', async () => {
    const client = await connectedClient();
    const walletPath = join(tempDir, 'agent.enc');

    const result = await client.callTool({
      name: 'did_create',
      arguments: { method: 'key', wallet: walletPath },
    });

    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ type: string; text: string }>;
    const payload = JSON.parse(content[0]!.text);
    expect(payload.did).toMatch(/^did:key:z/);
  });

  it('a failing tool call comes back as isError, not a thrown/killed connection', async () => {
    const client = await connectedClient();

    const result = await client.callTool({
      name: 'wallet_inspect',
      arguments: { wallet: join(tempDir, 'does-not-exist.enc') },
    });

    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]!.text).toContain('Wallet file not found');

    // The server process must still be alive and answer further calls.
    const followUp = await client.listTools();
    expect(followUp.tools.length).toBeGreaterThan(0);
  });
});
