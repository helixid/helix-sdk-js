// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import { HelixCustodyClient, activateAgent, changeToSelfCustody, helixInit, type HelixInitResult } from '@helixid/sdk-js';
import { success, warn } from '../lib/output.js';

export interface InitOptions {
  token: string;
  out: string;
  apiUrl: string;
  did?: string;
  kid?: string;
  activate?: boolean;
  envVar?: string;
}

function report(result: HelixInitResult): void {
  console.log('');
  console.log(`DID:        ${result.did}`);
  console.log(`Key:        ${result.kid} (${result.label}, generated here; only the public key was sent)`);
  console.log(`DID hosting: ${result.didHosting}`);
  console.log(`Status:     ${result.status}`);
  console.log(`Files:      ${result.files.didDocument}`);
  console.log(`            ${result.files.card}`);
  console.log(`            ${result.files.signingKey} (private key, mode 0600: keep it on this host)`);
  console.log(`            ${result.files.summary}`);
  if (result.vcId) console.log(`Credential: ${result.vcId}`);
}

/**
 * `helix init` (KYA-OS story F-3): self-custody onboarding with an
 * enrollment token from the console. The key is generated here and never
 * leaves this host; with own hosting, publish the two documents and the
 * agent is activated once they resolve from your domain.
 */
export async function runInit(options: InitOptions): Promise<HelixInitResult> {
  const result = await helixInit({
    apiUrl: options.apiUrl,
    enrollmentToken: options.token,
    outDir: options.out,
    ...(options.did ? { did: options.did } : {}),
    ...(options.kid ? { kid: options.kid } : {}),
    ...(options.activate === false ? { activate: false } : {}),
    ...(options.envVar ? { envVar: options.envVar } : {}),
  });
  if (result.status === 'active') {
    success(`Agent enrolled and active: ${result.did}`);
  } else {
    warn(`Agent enrolled, waiting for its documents on your domain: ${result.did}`);
  }
  report(result);
  republishNotice(result);
  if (result.status === 'pending_resolution') {
    console.log('');
    console.log('Publish the two documents on your domain:');
    console.log(`  ${result.files.didDocument}  ->  ${result.didDocumentUrl}`);
    console.log(`  ${result.files.card}  ->  ${result.cardUrl}`);
    if (result.resolution && !result.resolution.ok) console.log(`  (not resolving yet: ${result.resolution.reason})`);
    console.log('Helix activates the agent once both resolve: it checks in the background, and in the console when the agent is open.');
    console.log(`To check now: helix activate --token <token> --out ${options.out}`);
  }
  return result;
}

export interface ActivateCommandOptions {
  token: string;
  out: string;
  apiUrl: string;
}

/** `helix activate`: once the documents are published on the owner's domain. */
export async function runActivate(options: ActivateCommandOptions): Promise<HelixInitResult> {
  const result = await activateAgent({ apiUrl: options.apiUrl, enrollmentToken: options.token, outDir: options.out });
  if (result.status === 'active') {
    success(`Agent active: ${result.did}`);
  } else {
    warn(`Not active yet: ${result.resolution?.reason ?? 'the documents do not resolve from your domain'}`);
  }
  republishNotice(result);
  return result;
}

/** On activation Helix returns the card with the agent's attestations: say where to republish it. */
function republishNotice(result: HelixInitResult): void {
  if (!result.cardUpdated) return;
  console.log('');
  console.log('card.json now carries the attestations Helix issued; republish it:');
  console.log(`  ${result.files.card}  ->  ${result.cardUrl}`);
}

export interface CustodyTakeOptions {
  did: string;
  out: string;
  apiUrl: string;
  apiKey?: string;
  adminKey?: string;
  subject?: 'agent' | 'service' | 'owner';
  overlap?: number;
}

/**
 * `helix custody take`: change a custodial subject to self-custody (story
 * F-3 point 6, a key rotation). The new key is generated here; Helix lists
 * both keys during the overlap and shreds the key it held.
 */
export async function runCustodyTake(options: CustodyTakeOptions): Promise<void> {
  const client = new HelixCustodyClient({ apiUrl: options.apiUrl, apiKey: options.apiKey, adminApiKey: options.adminKey });
  const { result, files } = await changeToSelfCustody({
    client,
    did: options.did,
    outDir: options.out,
    ...(options.subject ? { subject: options.subject } : {}),
    ...(options.overlap === undefined ? {} : { overlapSeconds: options.overlap }),
  });
  success(`${options.did} is now ${result.label}`);
  console.log(`New key:      ${result.kid} (generated here; private key in ${files.signingKey})`);
  console.log(`Previous key: ${result.previousKid}, in the DID document until ${result.retiresAt}${result.previousKeyShredded ? ', shredded in Helix' : ''}`);
  if (result.hopReissue.pending) console.log(`Hops:         not reissued (${result.hopReissue.note ?? 'story C-E'})`);
  if (result.publishRequired) console.log(`Publish the updated did.json and card.json from ${options.out} on your domain.`);
}
