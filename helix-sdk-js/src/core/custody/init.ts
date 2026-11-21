// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * `helix init` (KYA-OS story F-3 point 2): self-custody onboarding with an
 * enrollment token from the console.
 *
 * 1. asks Helix for the enrollment challenge (the agent's DID, kid, nonce);
 * 2. generates the Ed25519 key here (story L1-A `generateAgentKey`);
 * 3. registers only the public JWK, with a proof of possession over the
 *    nonce; the request carries no private material (checked before it is
 *    sent, and refused by Helix if it did);
 * 4. writes `did.json` and `card.json` to the output directory, ready to
 *    publish, plus `signing-key.env` (the private key, mode 0600, for the
 *    agent's `EnvSigner`) and `helix-agent.json` (public facts);
 * 5. with `own` hosting, checks the documents resolve from the owner's
 *    domain (SafeFetch) and only then asks Helix to activate the agent,
 *    which checks again; with `helix` hosting, Helix already publishes them
 *    and the agent is active.
 */

import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as ed25519 from '@noble/ed25519';
import { generateAgentKey, toPublicKeyJwk, type AgentKey, type AgentPublicKeyJwk } from '../agent-key.js';
import { normalizeEd25519PrivateKey } from '../keys.js';
import { resolveEntityCard, sameDid, type ResolveEntityCardOptions } from '../entity-card.js';
import { HelixCustodyClient, type DidHostingMode, type FetchLike, type OnboardingResult } from './client.js';
import { base64UrlEncode, enrollmentProofMessage, rotationProofMessage } from './proof.js';
import { DEFAULT_SIGNING_KEY_ENV_VAR, kidFragment } from './signer.js';

export const INIT_FILES = {
  didDocument: 'did.json',
  card: 'card.json',
  signingKey: 'signing-key.env',
  summary: 'helix-agent.json',
} as const;

export interface HelixInitOptions {
  apiUrl: string;
  enrollmentToken: string;
  /** Where `did.json`, `card.json`, `signing-key.env` and `helix-agent.json` are written. */
  outDir: string;
  /** Own hosting: the did:web you expect; refused if Helix recorded another. */
  did?: string | undefined;
  /** Verification-method fragment for the new key. Default: the one Helix proposes (`key-1`). */
  kid?: string | undefined;
  /** Own hosting: check the documents resolve and activate. Default true. */
  activate?: boolean | undefined;
  /** Name of the variable `signing-key.env` sets. Default `HELIX_SIGNING_KEY`. */
  envVar?: string | undefined;
  /** For the API calls. */
  fetch?: FetchLike | undefined;
  /** For the own-domain resolution check; default the SDK's SafeFetch. */
  resolveFetch?: ResolveEntityCardOptions['fetch'];
  /** Injected for tests. */
  generateKey?: (() => AgentKey) | undefined;
}

export interface ResolutionCheck {
  ok: boolean;
  reason?: string | undefined;
}

export interface HelixInitResult {
  did: string;
  kid: string;
  keyCustody: 'self';
  didHosting: DidHostingMode;
  status: OnboardingResult['status'];
  label: OnboardingResult['label'];
  publicKeyJwk: AgentPublicKeyJwk;
  envVar: string;
  files: { didDocument: string; card: string; signingKey: string; summary: string };
  didDocumentUrl: string;
  cardUrl: string;
  /** Own hosting: what the resolution check found. */
  resolution?: ResolutionCheck | undefined;
  vcId?: string | undefined;
}

interface Summary {
  did: string;
  kid: string;
  keyCustody: 'self';
  didHosting: DidHostingMode;
  publicKeyJwk: AgentPublicKeyJwk;
  didDocumentUrl: string;
  cardUrl: string;
  envVar: string;
}

/**
 * Whether `did` resolves, from its own domain, to a DID document listing
 * `kid` with this public key and an Entity Card carrying the same key.
 */
export async function checkOwnHosting(
  did: string,
  key: { kid: string; publicKeyJwk: AgentPublicKeyJwk },
  options: ResolveEntityCardOptions = {},
): Promise<ResolutionCheck> {
  let resolved;
  try {
    resolved = await resolveEntityCard(did, options);
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
  const methods = (resolved.didDocument as { verificationMethod?: { id?: unknown; publicKeyJwk?: { x?: unknown } }[] }).verificationMethod ?? [];
  const fragment = key.kid.slice(key.kid.indexOf('#'));
  if (!methods.some((method) => (method.id === key.kid || method.id === fragment) && method.publicKeyJwk?.x === key.publicKeyJwk.x)) {
    return { ok: false, reason: `the DID document served for ${did} does not list ${key.kid} with this key` };
  }
  if (resolved.card.publicKeyJwk !== undefined && resolved.card.publicKeyJwk.x !== key.publicKeyJwk.x) {
    return { ok: false, reason: `the card served for ${did} carries another key` };
  }
  return { ok: true };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function filesIn(outDir: string): HelixInitResult['files'] {
  return {
    didDocument: join(outDir, INIT_FILES.didDocument),
    card: join(outDir, INIT_FILES.card),
    signingKey: join(outDir, INIT_FILES.signingKey),
    summary: join(outDir, INIT_FILES.summary),
  };
}

export async function helixInit(options: HelixInitOptions): Promise<HelixInitResult> {
  if (typeof options?.enrollmentToken !== 'string' || options.enrollmentToken.length === 0) throw new Error('helix init: an enrollment token is required');
  if (typeof options.outDir !== 'string' || options.outDir.length === 0) throw new Error('helix init: an output directory is required');
  const client = new HelixCustodyClient({ apiUrl: options.apiUrl, fetch: options.fetch });
  const envVar = options.envVar ?? DEFAULT_SIGNING_KEY_ENV_VAR;

  const challenge = await client.enrollmentChallenge(options.enrollmentToken);
  if (options.did !== undefined && !sameDid(options.did, challenge.did)) {
    throw new Error(`helix init: this enrollment token is for ${challenge.did}, not ${options.did}`);
  }
  const fragment = kidFragment(challenge.did, options.kid ?? challenge.kid);
  const kid = `${challenge.did}#${fragment}`;

  const key = (options.generateKey ?? generateAgentKey)();
  const seed = normalizeEd25519PrivateKey(key.privateKeyHex);
  const publicKeyJwk = toPublicKeyJwk(key.publicKeyHex);
  const signature = base64UrlEncode(await ed25519.signAsync(enrollmentProofMessage({ did: challenge.did, kid, nonce: challenge.nonce }), seed));
  const enrolled = await client.enroll({ enrollmentToken: options.enrollmentToken, publicKeyJwk, kid: fragment, signature });
  if (!enrolled.documents) throw new Error('helix init: Helix did not return the DID document and card');

  const files = filesIn(options.outDir);
  await mkdir(options.outDir, { recursive: true });
  await writeJson(files.didDocument, enrolled.documents.didDocument);
  await writeJson(files.card, enrolled.documents.card);
  await writeFile(
    files.signingKey,
    `# The private key of ${challenge.did} (${kid}). Self-custody: it never leaves this host.\nHELIX_AGENT_DID=${challenge.did}\nHELIX_AGENT_KID=${fragment}\n${envVar}=${Buffer.from(seed).toString('hex')}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
  await chmod(files.signingKey, 0o600);
  const summary: Summary = {
    did: challenge.did,
    kid,
    keyCustody: 'self',
    didHosting: enrolled.didHosting,
    publicKeyJwk,
    didDocumentUrl: enrolled.documents.didDocumentUrl,
    cardUrl: enrolled.documents.cardUrl,
    envVar,
  };
  await writeJson(files.summary, summary);
  seed.fill(0);

  const result: HelixInitResult = {
    did: challenge.did,
    kid,
    keyCustody: 'self',
    didHosting: enrolled.didHosting,
    status: enrolled.status,
    label: enrolled.label,
    publicKeyJwk,
    envVar,
    files,
    didDocumentUrl: enrolled.documents.didDocumentUrl,
    cardUrl: enrolled.documents.cardUrl,
    ...(enrolled.vcId ? { vcId: enrolled.vcId } : {}),
  };
  if (enrolled.status !== 'pending_resolution' || options.activate === false) return result;
  return activateOwnHosted({ ...result }, options.enrollmentToken, client, options.resolveFetch);
}

async function activateOwnHosted(
  result: HelixInitResult,
  enrollmentToken: string,
  client: HelixCustodyClient,
  resolveFetch: ResolveEntityCardOptions['fetch'],
): Promise<HelixInitResult> {
  const resolution = await checkOwnHosting(result.did, { kid: result.kid, publicKeyJwk: result.publicKeyJwk }, resolveFetch ? { fetch: resolveFetch } : {});
  if (!resolution.ok) return { ...result, resolution };
  const active = await client.activate(result.did, { enrollmentToken });
  return { ...result, status: active.status, resolution, ...(active.vcId ? { vcId: active.vcId } : {}) };
}

export interface ActivateOptions {
  apiUrl: string;
  enrollmentToken: string;
  /** The directory `helix init` wrote. */
  outDir: string;
  fetch?: FetchLike | undefined;
  resolveFetch?: ResolveEntityCardOptions['fetch'];
}

/**
 * `helix activate`: once `did.json` and `card.json` are published on the
 * owner's domain, checks they resolve and asks Helix to activate the agent.
 */
export async function activateAgent(options: ActivateOptions): Promise<HelixInitResult> {
  const files = filesIn(options.outDir);
  const summary = JSON.parse(await readFile(files.summary, 'utf8')) as Summary;
  const client = new HelixCustodyClient({ apiUrl: options.apiUrl, fetch: options.fetch });
  return activateOwnHosted(
    {
      did: summary.did,
      kid: summary.kid,
      keyCustody: 'self',
      didHosting: summary.didHosting,
      status: 'pending_resolution',
      label: 'custody: self',
      publicKeyJwk: summary.publicKeyJwk,
      envVar: summary.envVar,
      files,
      didDocumentUrl: summary.didDocumentUrl,
      cardUrl: summary.cardUrl,
    },
    options.enrollmentToken,
    client,
    options.resolveFetch,
  );
}

export interface ChangeToSelfCustodyOptions {
  client: HelixCustodyClient;
  did: string;
  /** Where the new key's `signing-key.env` and `helix-agent.json` are written. */
  outDir: string;
  subject?: 'agent' | 'service' | 'owner' | undefined;
  /** Fragment for the new key. Default `key-<base36 timestamp>`, unused by any earlier key. */
  kid?: string | undefined;
  overlapSeconds?: number | undefined;
  envVar?: string | undefined;
  generateKey?: (() => AgentKey) | undefined;
}

/**
 * A custody change from `helix` to `self` (KYA-OS story F-3 point 6): the
 * new key is generated here and only its public half and a proof of
 * possession go to Helix, which rotates the DID document (both keys during
 * the overlap) and shreds the key it held.
 */
export async function changeToSelfCustody(options: ChangeToSelfCustodyOptions): Promise<{ result: Awaited<ReturnType<HelixCustodyClient['changeCustody']>>; files: { signingKey: string; summary: string } }> {
  const envVar = options.envVar ?? DEFAULT_SIGNING_KEY_ENV_VAR;
  const fragment = kidFragment(options.did, options.kid ?? `key-${Date.now().toString(36)}`);
  const kid = `${options.did}#${fragment}`;
  const key = (options.generateKey ?? generateAgentKey)();
  const seed = normalizeEd25519PrivateKey(key.privateKeyHex);
  const publicKeyJwk = toPublicKeyJwk(key.publicKeyHex);
  const issuedAt = new Date().toISOString();
  const signature = base64UrlEncode(await ed25519.signAsync(rotationProofMessage({ did: options.did, kid, issuedAt }), seed));
  const result = await options.client.changeCustody(
    options.did,
    { keyCustody: 'self', publicKeyJwk, kid: fragment, proof: { issuedAt, signature }, ...(options.overlapSeconds === undefined ? {} : { overlapSeconds: options.overlapSeconds }) },
    options.subject ?? 'agent',
  );
  await mkdir(options.outDir, { recursive: true });
  const signingKey = join(options.outDir, INIT_FILES.signingKey);
  const summaryPath = join(options.outDir, INIT_FILES.summary);
  await writeFile(signingKey, `# The private key of ${options.did} (${kid}). Self-custody: it never leaves this host.\nHELIX_AGENT_DID=${options.did}\nHELIX_AGENT_KID=${fragment}\n${envVar}=${Buffer.from(seed).toString('hex')}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  await chmod(signingKey, 0o600);
  await writeJson(summaryPath, {
    did: options.did,
    kid,
    keyCustody: 'self',
    didHosting: result.didHosting,
    publicKeyJwk,
    didDocumentUrl: result.documents.didDocumentUrl,
    cardUrl: result.documents.cardUrl,
    envVar,
  } satisfies Summary);
  if (result.publishRequired) {
    await writeJson(join(options.outDir, INIT_FILES.didDocument), result.documents.didDocument);
    await writeJson(join(options.outDir, INIT_FILES.card), result.documents.card);
  }
  seed.fill(0);
  return { result, files: { signingKey, summary: summaryPath } };
}
