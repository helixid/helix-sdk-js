// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The Helix agent registry, and checking a service before calling it
 * (registry v3, 2026-11-24).
 *
 * - **Agents** made discoverable at onboarding ("Make discoverable", on by
 *   default; `discoverable` when an agent is created through the API) are
 *   listed in the Helix registry at https://api.helixid.dev. Anyone can
 *   search it: `findAgents(q)`, `lookup(did)`.
 * - **Services** are not listed anywhere. An agent gets a service's URL from
 *   its user or its configuration, and `resolve(url)` checks the DID the
 *   service publishes at its own address (`/.well-known/mcp`): the DID
 *   document must be fetchable, else the service is refused.
 * - Nothing is public or private. Whether an agent or service can be reached
 *   is up to the network it is hosted on; a DID that can be fetched verifies.
 *
 * ```ts
 * const registry = kyaos.registry.createRegistryClient();
 * const [agent] = await registry.findAgents('travel');
 * const { serviceDid, toolsUrl } = await registry.resolve('https://air.example.com');
 * ```
 *
 * A discoverable self-custody agent registers itself with the Helix registry,
 * signed with its own key: `publish({ signer, helixUrl })` (the deployment it
 * is onboarded on, which the Helix registry asks whether it is discoverable).
 * A custodial agent's deployment does that for it.
 */

import { fetchWellKnownMcp } from './discovery.js';
import { signJws, type JwsDidDocument } from './jws.js';
import type { Signer } from './signer.js';
import { createDidResolver } from './verifier/resolve.js';

/** The Helix registry. Fixed. */
export const HELIX_REGISTRY_ORIGIN = 'https://api.helixid.dev';
export const AGENT_REGISTRY_PATH = '/agent/registry';
export const REGISTRATION_TYP = 'helix-registration+jwt';

// TEST ONLY: a local run stands a loopback deployment in for api.helixid.dev. Not configuration.
const TEST_ONLY_ORIGIN_ENV = 'HELIX_TEST_ONLY_REGISTRY_ORIGIN';

/** One discoverable agent as the Helix registry lists it. */
export interface RegistryAgent {
  agentDid: string;
  name: string | null;
  status: string;
  owner: { did: string | null; name: string | null };
  publishedAt: string | null;
  /** The deployment it is onboarded on. */
  deployment: string;
  [member: string]: unknown;
}

/** A service ready to call: the DID its requests are bound to, where to send them, and its DID document. */
export interface ResolvedService {
  serviceDid: string;
  toolsUrl: string;
  /** The origin the service was reached at. */
  url: string;
  didDocument: JwsDidDocument;
}

export type RegistryProblem = 'no_helix_link' | 'fetch_failed' | 'registry_error' | 'no_url' | 'did_unresolvable' | 'did_mismatch' | 'publish_refused';

export class RegistryError extends Error {
  readonly code = 'REGISTRY_ERROR';
  constructor(
    readonly reason: RegistryProblem,
    message: string,
  ) {
    super(message);
    this.name = 'RegistryError';
  }
}

export interface RegistryClientOptions {
  /** Default `globalThis.fetch`. */
  fetch?: typeof fetch | undefined;
  /** Resolves a service's DID document; default `kyaos.verifier.createDidResolver({ fetch })`. */
  resolveDid?: ((did: string) => Promise<JwsDidDocument | null>) | undefined;
}

export interface ResolveOptions {
  /** The DID the service must have (from configuration, say); refused when /.well-known/mcp names another. */
  expectedDid?: string | undefined;
}

export interface RegistryClient {
  /** The Helix registry's origin. */
  readonly registry: string;
  /** Discoverable agents matching `q` (any word of the name or owner, or an exact DID). */
  findAgents(q: string): Promise<RegistryAgent[]>;
  /** One discoverable agent, or null when the Helix registry does not list it. */
  lookup(agentDid: string): Promise<RegistryAgent | null>;
  /** The service at a URL, checked: its /.well-known/mcp names a DID whose document can be fetched. */
  resolve(url: string, options?: ResolveOptions): Promise<ResolvedService>;
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The Helix registry's origin. */
export function helixRegistryOrigin(): string {
  const override = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[TEST_ONLY_ORIGIN_ENV];
  return override ? new URL(override).origin : HELIX_REGISTRY_ORIGIN;
}

/**
 * The deployment a did:web names: its first segment, %-decoded. https, or
 * http for a loopback host (local runs). Undefined for any other DID.
 */
export function helixOriginOfDid(did: string): string | undefined {
  const match = /^did:web:([^:]+)/.exec(did);
  if (!match) return undefined;
  const host = decodeURIComponent(match[1]!);
  const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0]!;
  try {
    return new URL(`${LOOPBACK.has(hostname) ? 'http' : 'https'}://${host}`).origin;
  } catch {
    return undefined;
  }
}

/** GET as JSON; null on 404. */
async function getJson(doFetch: typeof fetch, url: string): Promise<unknown> {
  let response: Response;
  try {
    response = await doFetch(url, { method: 'GET', headers: { accept: 'application/json' } });
  } catch (error) {
    throw new RegistryError('fetch_failed', `GET ${url} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (response.status === 404) return null;
  if (response.status !== 200) throw new RegistryError('fetch_failed', `GET ${url} answered ${response.status}`);
  try {
    return await response.json();
  } catch {
    throw new RegistryError('fetch_failed', `GET ${url} did not answer with JSON`);
  }
}

export function createRegistryClient(options: RegistryClientOptions = {}): RegistryClient {
  const doFetch = options.fetch ?? globalThis.fetch;
  const registry = helixRegistryOrigin();
  const resolveDid = options.resolveDid ?? createDidResolver({ fetch: (url) => doFetch(url) });

  async function findAgents(q: string): Promise<RegistryAgent[]> {
    const url = `${registry}${AGENT_REGISTRY_PATH}?q=${encodeURIComponent(q)}`;
    const body = await getJson(doFetch, url);
    const list = isRecord(body) ? body['agents'] : undefined;
    if (!Array.isArray(list)) throw new RegistryError('registry_error', `${url} did not answer an agents list`);
    return list.filter((entry): entry is RegistryAgent => isRecord(entry) && typeof entry['agentDid'] === 'string');
  }

  async function lookup(agentDid: string): Promise<RegistryAgent | null> {
    const body = await getJson(doFetch, `${registry}${AGENT_REGISTRY_PATH}/${encodeURIComponent(agentDid)}`);
    const agent = isRecord(body) ? body['agent'] : undefined;
    return isRecord(agent) && agent['agentDid'] === agentDid ? (agent as RegistryAgent) : null;
  }

  async function resolve(url: string, resolveOptions: ResolveOptions = {}): Promise<ResolvedService> {
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      throw new RegistryError('no_url', `Not a URL: ${url}`);
    }
    const { serverDid, endpoints } = await fetchWellKnownMcp(origin, { fetch: doFetch });
    if (resolveOptions.expectedDid !== undefined && serverDid !== resolveOptions.expectedDid) {
      throw new RegistryError('did_mismatch', `${origin} says it is ${serverDid}, not ${resolveOptions.expectedDid}`);
    }
    let didDocument: JwsDidDocument | null;
    try {
      didDocument = await resolveDid(serverDid);
    } catch (error) {
      throw new RegistryError('did_unresolvable', `${serverDid} (named by ${origin}/.well-known/mcp) could not be resolved: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!didDocument) throw new RegistryError('did_unresolvable', `${serverDid} (named by ${origin}/.well-known/mcp) could not be resolved`);
    if (!endpoints.tools) throw new RegistryError('no_url', `${origin}/.well-known/mcp names no tools endpoint`);
    return { serviceDid: serverDid, toolsUrl: endpoints.tools, url: origin, didDocument };
  }

  return { registry, findAgents, lookup, resolve };
}

export interface PublishOptions {
  /** The agent's own key. */
  signer: Signer;
  /** The deployment it is onboarded on (default: its did:web host). It must list the agent as discoverable. */
  helixUrl?: string | undefined;
  fetch?: typeof fetch | undefined;
  /** Default now. */
  now?: Date | undefined;
}

/**
 * Registers a discoverable, self-custody agent with the Helix registry,
 * signed with its own key. The Helix registry checks the signature against
 * its DID document and asks its deployment for the entry.
 */
export async function publish(options: PublishOptions): Promise<RegistryAgent> {
  const doFetch = options.fetch ?? globalThis.fetch;
  const deployment = options.helixUrl ? new URL(options.helixUrl).origin : helixOriginOfDid(options.signer.did);
  if (!deployment) throw new RegistryError('no_helix_link', 'Give a helixUrl or sign with a did:web: there is no deployment for the Helix registry to ask');
  const helix = helixRegistryOrigin();
  const iat = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const registration = await signJws(
    { iss: options.signer.did, sub: options.signer.did, aud: helix, deployment, iat, exp: iat + 300, jti: globalThis.crypto.randomUUID() },
    options.signer,
    { header: { typ: REGISTRATION_TYP } },
  );
  const url = `${helix}${AGENT_REGISTRY_PATH}`;
  let response: Response;
  try {
    response = await doFetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ registration }) });
  } catch (error) {
    throw new RegistryError('fetch_failed', `POST ${url} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (response.status !== 201 || !isRecord(body?.['agent'])) {
    const message = isRecord(body?.['error']) ? String(body['error']['message']) : `answered ${response.status}`;
    throw new RegistryError('publish_refused', `The Helix registry refused the registration: ${message}`);
  }
  return body['agent'] as RegistryAgent;
}
