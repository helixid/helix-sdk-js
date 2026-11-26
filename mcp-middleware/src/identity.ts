// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * The service's own KYA-OS identity, served from its origin (story C-A):
 * `did.json` and `card.json` at the paths its did:web derives, and the
 * claim-minimal projection of the card into MCP `server.json` under
 * `_meta["org.kya-os/card"]` with the canonical `cardRef`.
 *
 * Hosting follows the L1-D cases: route `/{path}/did.json` and
 * `/{path}/card.json` at the public origin to `handle()` (case 1, the
 * proxy forwards them; `publicOrigin` is what the documents name), mount
 * `handle()` in whichever app serves the root (case 2), or write the two
 * documents out as static files (case 3: `didDocument` and `card` are plain
 * JSON). A service whose documents `helix init` already wrote hands them in
 * as `documents` and nothing is rebuilt.
 *
 * Verifier side: `resolveServerCard` reads a `server.json` projection and,
 * when the projection was stripped, falls back to fetching the canonical
 * card through the SDK's SafeFetch.
 */

import type { ServerResponse } from 'node:http';
import {
  buildEntityCard,
  didWebCardUrl,
  didWebDocumentUrl,
  didWebFor,
  kyaOsCardServiceEntry,
  parseDidWeb,
  ownDidWebProblem,
  parseEntityCard,
  resolveEntityCardFromServerMeta,
  serverCardMeta,
  type BuildEntityCardInput,
  type EntityCard,
  type ResolveEntityCardOptions,
  type ResolvedEntityCard,
  type ServerCardMeta,
} from '@helixid/sdk-js';

export interface ServeIdentityOptions {
  /** The origin agents connect to, e.g. `https://mcp.example.com`; behind a proxy the app's bind address is not it. */
  publicOrigin: string;
  /**
   * This service's did:web. Derived from `publicOrigin` and `path` when
   * omitted: `did:web:<host>` at the root, `did:web:<host>:<seg>…` under a path.
   */
  did?: string | undefined;
  /** Where under the origin the documents live (`/mcp` → `did:web:<host>:mcp`). Default: the root. */
  path?: string | undefined;
  /** What the card says; `id` and `didDocument` are filled in. `entityType` defaults to `mcp`. */
  card?: Omit<BuildEntityCardInput, 'id' | 'didDocument' | 'entityType'> & { entityType?: BuildEntityCardInput['entityType'] | undefined };
  /** Other DIDs of this service (its did:key form, a did:hedera). */
  alsoKnownAs?: readonly string[] | undefined;
  /** Other DID-document services to keep beside the card entry. */
  service?: readonly unknown[] | undefined;
  /** Documents `helix init` wrote: served as they are (the card is still checked against the schema). */
  documents?: { didDocument: Record<string, unknown>; card: unknown } | undefined;
}

export interface ServedIdentity {
  did: string;
  didDocumentUrl: string;
  cardUrl: string;
  /** The request paths (`/mcp/did.json`, `/mcp/card.json`; `/.well-known/…` at the root) `handle` answers. */
  paths: { didDocument: string; card: string };
  didDocument: Record<string, unknown>;
  card: EntityCard;
  /** Answers one of the two paths with its JSON; false for any other path. */
  handle(pathname: string, res: ServerResponse): boolean;
  /** `{ "org.kya-os/card": { …summary, "org.kya-os/cardRef": cardUrl } }` to spread into `server.json` `_meta`. */
  serverMeta(options?: { byRef?: boolean }): ServerCardMeta;
  /** `serverJson` with the projection merged into its `_meta`. */
  projectServerJson<T extends { _meta?: Record<string, unknown> }>(serverJson: T, options?: { byRef?: boolean }): T & { _meta: Record<string, unknown> };
}

const DID_CONTEXTS = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'];

function segmentsOf(path: string | undefined): string[] {
  return (path ?? '').split('/').filter((segment) => segment.length > 0);
}

function pathsFor(segments: string[]): { didDocument: string; card: string } {
  if (segments.length === 0) return { didDocument: '/.well-known/did.json', card: '/.well-known/kya-os-card.json' };
  const base = `/${segments.map(encodeURIComponent).join('/')}`;
  return { didDocument: `${base}/did.json`, card: `${base}/card.json` };
}

export function serveIdentity(options: ServeIdentityOptions): ServedIdentity {
  let origin: URL;
  try {
    origin = new URL(options.publicOrigin);
  } catch {
    throw new Error('serveIdentity: publicOrigin must be an absolute URL such as https://mcp.example.com');
  }
  if (origin.protocol !== 'https:' && origin.protocol !== 'http:') throw new Error('serveIdentity: publicOrigin must be an http(s) origin');
  const segments = segmentsOf(options.path ?? (origin.pathname === '/' ? '' : origin.pathname));
  const did = options.did ?? didWebFor(origin.host, segments);
  const parsed = parseDidWeb(did);
  if (parsed === undefined) throw new Error(`serveIdentity: ${did} is not a did:web DID`);
  const problem = ownDidWebProblem(did);
  if (problem !== undefined) throw new Error(`serveIdentity: ${problem}`);
  const paths = pathsFor(parsed.path);
  const publicBase = `${origin.origin}`;
  const didDocumentUrl = origin.protocol === 'https:' && origin.origin === `https://${parsed.host}` ? didWebDocumentUrl(did) : `${publicBase}${paths.didDocument}`;
  const cardUrl = origin.protocol === 'https:' && origin.origin === `https://${parsed.host}` ? didWebCardUrl(did) : `${publicBase}${paths.card}`;

  let didDocument: Record<string, unknown>;
  let card: EntityCard;
  if (options.documents) {
    card = parseEntityCard(options.documents.card);
    didDocument = options.documents.didDocument;
    if (didDocument['id'] !== did) throw new Error(`serveIdentity: the DID document is for ${String(didDocument['id'])}, not ${did}`);
    if (card.id !== did) throw new Error(`serveIdentity: the card is for ${card.id}, not ${did}`);
  } else {
    const input = options.card ?? { name: did };
    card = buildEntityCard({ ...input, entityType: input.entityType ?? 'mcp', id: did, didDocument: didDocumentUrl });
    const kid = card.kid;
    const jwk = card.publicKeyJwk;
    const method = kid !== undefined && jwk !== undefined ? [{ id: kid, type: 'Ed25519VerificationKey2020', controller: did, publicKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x } }] : [];
    didDocument = {
      '@context': DID_CONTEXTS,
      id: did,
      ...(options.alsoKnownAs && options.alsoKnownAs.length > 0 ? { alsoKnownAs: [...options.alsoKnownAs] } : {}),
      verificationMethod: method,
      authentication: method.map((entry) => entry.id),
      assertionMethod: method.map((entry) => entry.id),
      service: [...(options.service ?? []), kyaOsCardServiceEntry(cardUrl)],
    };
  }

  const bodies: Record<string, string> = { [paths.didDocument]: JSON.stringify(didDocument), [paths.card]: JSON.stringify(card) };
  const meta = (byRef?: boolean): ServerCardMeta => serverCardMeta(card, { cardUrl, ...(byRef ? { byRef } : {}) });
  return {
    did,
    didDocumentUrl,
    cardUrl,
    paths,
    didDocument,
    card,
    handle(pathname: string, res: ServerResponse): boolean {
      const body = bodies[pathname];
      if (body === undefined) return false;
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=300' }).end(body);
      return true;
    },
    serverMeta: (serverMetaOptions = {}) => meta(serverMetaOptions.byRef),
    projectServerJson: (serverJson, projectOptions = {}) => ({ ...serverJson, _meta: { ...(serverJson._meta ?? {}), ...meta(projectOptions.byRef) } }),
  };
}

/**
 * The card an MCP `server.json` advertises: the inline summary or `cardRef`
 * under `_meta["org.kya-os/card"]`, dereferenced to the canonical card; a
 * stripped projection falls back to the two-step resolution of `did`.
 */
export function resolveServerCard(serverJson: { _meta?: unknown } | undefined, options: ResolveEntityCardOptions & { did?: string | undefined } = {}): Promise<ResolvedEntityCard> {
  const { did, ...rest } = options;
  return resolveEntityCardFromServerMeta({ serverMeta: serverJson?._meta, did }, rest);
}
