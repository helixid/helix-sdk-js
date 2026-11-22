// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Epic: Audit Payload Enrichment + Consent Events, under KYA-OS AAP-1
// (story A-1): the SDK records typed producer events.
//   §1  — VP_REJECTED enrichment moved server-side with VP verification (see
//         the SDK-API-only design); helix-api records `proof.rejected` itself.
//   §2a — `consent.approved` fires when a grant VC lands in the wallet. This is
//         still SDK-side: the wallet reacting to a credential it already holds
//         locally, recorded through an `AuditTrail` whose sink is
//         `HelixClient.auditSink()` (`POST /v1/audit-log/events`).
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AgentWallet } from '../../src/wallet/AgentWallet.js';
import { generateKeyPair } from '../../src/core/keys.js';
import { HelixClient } from '../../src/client/HelixClient.js';
import { AUDIT_BINDING_MCP, type AuditProducerEvent, type AuditTrailEntry, parseAuditEvent } from '../../src/audit/index.js';
import type { SignedVC } from '../../src/core/schemas/vc.js';

/** HttpAdapter-shaped mock. Passing `adminApiKey` or `apiKey` to the client is what gates audit emission. */
function mockHttp(): { post: ReturnType<typeof vi.fn> } {
  return { post: vi.fn().mockResolvedValue({}) };
}

function auditEvents(http: { post: ReturnType<typeof vi.fn> }): AuditProducerEvent[] {
  return http.post.mock.calls.filter((call) => call[0] === '/v1/audit-log/events').map((call) => call[1] as AuditProducerEvent);
}

describe('§2a consent.approved', () => {
  let workDir: string;
  let walletPath: string;

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), 'helix-consent-audit-'));
    walletPath = join(workDir, 'agent.enc');
  });

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true });
  });

  /** Writes a wallet file the way `helix did create` does, then loads it. */
  async function seededWallet(client?: HelixClient): Promise<AgentWallet> {
    const keyPair = generateKeyPair();
    const now = new Date().toISOString();
    await new AgentWallet().save(
      {
        did: 'did:web:wallet-holder.example',
        publicKeyHex: keyPair.publicKey,
        privateKeyHex: keyPair.privateKey,
        credentials: [],
        createdAt: now,
        updatedAt: now,
      },
      'pw',
      walletPath,
    );
    return AgentWallet.load(walletPath, 'pw', client);
  }

  function grantVC(agentDid: string, id = 'vc:helix:grant-1'): SignedVC {
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id,
      type: ['VerifiableCredential', 'DelegationGrantCredential'],
      issuer: 'did:web:airline.example',
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 86_400_000).toISOString(),
      credentialSubject: {
        id: agentDid,
        type: 'DelegationGrant',
        userDid: 'did:key:zUser',
        scopes: ['book:flight'],
        durability: 'standing',
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:airline.example#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'sig',
      },
    } as unknown as SignedVC;
  }

  function agentVC(agentDid: string): SignedVC {
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'vc:helix:agent-1',
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      issuer: 'did:web:platform.example',
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 86_400_000).toISOString(),
      credentialSubject: {
        id: agentDid,
        type: 'HelixAgent',
        privilegeScopes: ['read:catalog'],
        agentName: 'test-agent',
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:platform.example#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'sig',
      },
    } as unknown as SignedVC;
  }

  it('records a typed consent.approved event when a DelegationGrantCredential is stored', async () => {
    const http = mockHttp();
    const client = new HelixClient('http://localhost', { adminApiKey: 'test-admin-key' });
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    await wallet.addCredential(grantVC(wallet.did));

    const [event] = auditEvents(http);
    expect(event).toBeDefined();
    // The body is a strict producer event, as the API will validate it.
    expect(parseAuditEvent(event)).toEqual(event);
    expect(event).toMatchObject({
      eventType: 'consent.approved',
      binding: AUDIT_BINDING_MCP,
      tenantRef: { kind: 'pairwise_did', did: wallet.did },
      source: { producer: { kind: 'pairwise_did', did: wallet.did }, sourceId: `helix-sdk-js:${wallet.did}`, sourceSequence: '1' },
      actor: { kind: 'pairwise_did', did: wallet.did },
      responsibleParty: { kind: 'public_did', did: 'did:key:zUser' },
      resource: { kind: 'public_did', did: 'did:web:airline.example' },
      action: { category: 'consent' },
      outcome: 'succeeded',
      evidence: [],
      details: { family: 'consent', phase: 'approved', consentRef: 'vc:helix:grant-1' },
    });
    // Never the scopes, durability or any other grant content: only references.
    const text = JSON.stringify(event);
    expect(text).not.toContain('book:flight');
    expect(text).not.toContain('standing');
  });

  it('chains the wallet source across grants', async () => {
    const http = mockHttp();
    const client = new HelixClient('http://localhost', { apiKey: 'hak_test' });
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    await wallet.addCredential(grantVC(wallet.did, 'vc:helix:grant-1'));
    await wallet.addCredential(grantVC(wallet.did, 'vc:helix:grant-2'));

    const events = auditEvents(http);
    expect(events.map((event) => event.source.sourceSequence)).toEqual(['1', '2']);
    expect(events[1]!.source.previousSourceEventDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(events.map((event) => (event.details as { consentRef?: string }).consentRef)).toEqual(['vc:helix:grant-1', 'vc:helix:grant-2']);
  });

  it('leaves out the responsible party and resource when the grant shows no user or issuer', async () => {
    const http = mockHttp();
    const client = new HelixClient('http://localhost', { adminApiKey: 'test-admin-key' });
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    const bare = grantVC(wallet.did) as unknown as { issuer?: string; credentialSubject: { userDid?: string } };
    delete bare.issuer;
    delete bare.credentialSubject.userDid;
    await wallet.addCredential(bare as unknown as SignedVC);

    const [event] = auditEvents(http);
    expect(event).toBeDefined();
    expect(event!.responsibleParty).toBeUndefined();
    expect(event!.resource).toBeUndefined();
  });

  it('stays silent for ordinary (non-grant) credentials', async () => {
    const http = mockHttp();
    const client = new HelixClient('http://localhost', { adminApiKey: 'test-admin-key' });
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    await wallet.addCredential(agentVC(wallet.did));

    expect(auditEvents(http)).toHaveLength(0);
  });

  it('still stores the grant when no client is attached', async () => {
    const wallet = await seededWallet();

    await expect(wallet.addCredential(grantVC(wallet.did))).resolves.toBeUndefined();
    expect(wallet.credentials.map((vc) => vc.id)).toContain('vc:helix:grant-1');
  });

  it('still stores the grant when the audit POST fails', async () => {
    const http = mockHttp();
    http.post.mockRejectedValue(new Error('helix-api unreachable'));
    const client = new HelixClient('http://localhost', { adminApiKey: 'test-admin-key' });
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    await expect(wallet.addCredential(grantVC(wallet.did))).resolves.toBeUndefined();
    expect(wallet.credentials.map((vc) => vc.id)).toContain('vc:helix:grant-1');
  });

  it('does not emit when the client has no API key (audit disabled)', async () => {
    const http = { post: vi.fn().mockResolvedValue({}) };
    const client = new HelixClient('http://localhost');
    client.__setTestHttpAdapter(http);
    const wallet = await seededWallet(client);

    await wallet.addCredential(grantVC(wallet.did));

    expect(auditEvents(http)).toHaveLength(0);
  });
});

describe('HelixClient.recordAuditEvent / auditSink', () => {
  const event = { eventType: 'session.established' } as unknown as AuditProducerEvent;
  const entry = { event, canonical: '{}', eventDigest: `sha256:${'0'.repeat(64)}` } as AuditTrailEntry;

  it('posts the event as the body of POST /v1/audit-log/events', async () => {
    const http = mockHttp();
    const client = new HelixClient('http://localhost', { apiKey: 'hak_test' });
    client.__setTestHttpAdapter(http);
    await client.recordAuditEvent(event);
    expect(http.post).toHaveBeenCalledWith('/v1/audit-log/events', event);
    await client.auditSink().append(entry);
    expect(http.post).toHaveBeenCalledTimes(2);
    expect(http.post.mock.calls[1]).toEqual(['/v1/audit-log/events', event]);
  });

  it('is a no-op without an API key, and lets a failed POST propagate', async () => {
    const silent = mockHttp();
    const noKey = new HelixClient('http://localhost');
    noKey.__setTestHttpAdapter(silent);
    await noKey.recordAuditEvent(event);
    await noKey.auditSink().append(entry);
    expect(silent.post).not.toHaveBeenCalled();

    const failing = mockHttp();
    failing.post.mockRejectedValue(new Error('helix-api unreachable'));
    const client = new HelixClient('http://localhost', { adminApiKey: 'k' });
    client.__setTestHttpAdapter(failing);
    await expect(client.recordAuditEvent(event)).rejects.toThrow('helix-api unreachable');
    await expect(client.auditSink().append(entry)).rejects.toThrow('helix-api unreachable');
  });
});
