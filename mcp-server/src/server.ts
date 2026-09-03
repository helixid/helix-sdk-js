import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { didCreate } from './operations/did.js';
import { issuerInit } from './operations/issuer.js';
import { revoke } from './operations/revoke.js';
import { statusListCreate } from './operations/statusList.js';
import { vcIssue, vcSelfIssue } from './operations/vc.js';
import { walletInspect } from './operations/wallet.js';

function ok(data: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function fail(err: unknown): CallToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: 'text', text: message }], isError: true };
}

export function createServer(): McpServer {
  const server = new McpServer({ name: 'helix-mcp-server', version: '0.1.0' });

  server.registerTool(
    'did_create',
    {
      title: 'Create a HelixID DID and wallet',
      description:
        'Create a new DID (did:web, did:key, or did:hedera) and its encrypted wallet file. ' +
        'did:web also creates its initial status list unless statusList is set to false. ' +
        'Requires the HELIX_WALLET_PASSPHRASE environment variable.',
      inputSchema: {
        method: z.enum(['web', 'hedera', 'key']),
        domain: z.string().optional().describe('Domain for did:web (required for method "web")'),
        network: z.enum(['testnet', 'previewnet', 'mainnet']).optional().describe('Hedera network (method "hedera" only)'),
        wallet: z.string().describe('Path to write the new encrypted wallet file'),
        statusList: z.boolean().optional().describe('did:web only — set false to skip creating the initial status list'),
        statusListLength: z.number().int().positive().optional().describe('Status list capacity in bits'),
        statusListOutput: z.string().optional().describe('Status list output file path'),
        statusListBaseUrl: z.string().optional().describe('Public URL where the status list will be served'),
      },
    },
    async (args) => {
      try {
        return ok(await didCreate(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'issuer_init',
    {
      title: 'Verify an issuer wallet is ready',
      description: 'Load an issuer wallet and report its DID and public key. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        wallet: z.string().describe('Path to issuer wallet file'),
      },
    },
    async (args) => {
      try {
        return ok(await issuerInit(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'status_list_create',
    {
      title: 'Create a signed BitstringStatusList credential',
      description:
        'Create a signed BitstringStatusList credential file for VC revocation tracking. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        length: z.number().int().positive().describe('Status list capacity in bits'),
        output: z.string().describe('Output file path'),
        baseUrl: z.string().describe('Public URL where the status list will be served'),
        wallet: z.string().describe('Path to issuer wallet file'),
      },
    },
    async (args) => {
      try {
        return ok(await statusListCreate(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'vc_issue',
    {
      title: 'Issue a HelixAgentCredential',
      description:
        'Issue a HelixAgentCredential to an agent DID, consuming the next available status list index. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        agentDid: z.string().describe('Agent DID'),
        scopes: z.string().describe('Comma-separated privilege scopes'),
        expires: z.string().describe('Validity duration, e.g. 90d, 24h'),
        statusList: z.string().describe('Path to status list JSON file (updated in place)'),
        baseUrl: z.string().describe('Public status list URL'),
        wallet: z.string().describe('Path to issuer wallet file'),
        output: z.string().optional().describe('Output VC file path'),
        maxDelegationDepth: z.number().int().nonnegative().optional().describe('Max delegation depth (default 1)'),
      },
    },
    async (args) => {
      try {
        return ok(await vcIssue(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'vc_self_issue',
    {
      title: 'Self-issue a dev-only credential',
      description:
        'Issue a self-signed dev credential directly into an agent wallet. Not trusted in production — ' +
        'verifyVP() rejects self-signed credentials outside dev mode. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        scopes: z.string().describe('Comma-separated privilege scopes'),
        expires: z.string().describe('Validity duration, e.g. 24h'),
        wallet: z.string().describe('Path to agent wallet file'),
      },
    },
    async (args) => {
      try {
        return ok(await vcSelfIssue(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'revoke',
    {
      title: 'Revoke a credential',
      description: 'Revoke a credential by flipping its status list bit. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        vcId: z.string().describe('VC ID to revoke'),
        statusList: z.string().describe('Path to status list JSON file (updated in place)'),
        wallet: z.string().describe('Path to issuer wallet file'),
      },
    },
    async (args) => {
      try {
        return ok(await revoke(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'wallet_inspect',
    {
      title: 'Inspect a wallet',
      description: 'Inspect wallet contents — DID, public key, and stored credentials. Never returns the private key. Requires HELIX_WALLET_PASSPHRASE.',
      inputSchema: {
        wallet: z.string().describe('Path to wallet file'),
      },
    },
    async (args) => {
      try {
        return ok(await walletInspect(args));
      } catch (err) {
        return fail(err);
      }
    },
  );

  return server;
}
