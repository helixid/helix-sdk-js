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
 * The producer outbox for `buffered` delivery (story A-2 point 3;
 * AUDITABILITY.md, Delivery semantics). The response boundary of buffered
 * mode is the outbox acknowledging the item, so the outbox must be durable:
 * an ephemeral one is refused at startup. Items are keyed by
 * `(sourceId, eventId)`; enqueue is idempotent per key and refuses divergent
 * content; `pending()` yields FIFO per source and leaves out dead letters;
 * failures are counted persistently.
 *
 * `AuditOutboxProvider` is the reference interface (upstream
 * `providers/outbox.ts` at a4d7f61). `DurableOutbox` keeps one file per item
 * in a directory, each written to a temporary name, flushed and renamed, so
 * an item is either wholly there or not at all, and it survives a restart.
 */

import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalize } from './canonical.js';
import type { AuditRecorderSubmission } from './recorder-client.js';
import type { EvidenceRef } from './types.js';

export interface AuditOutboxItem {
  eventId: string;
  submission: AuditRecorderSubmission;
  enqueuedAt: number;
  /** Persisted delivery failures; durable adapters use this for retry and dead-letter policy. */
  attempts: number;
}

/** Event ids are unique only within a source, so an outbox shared by sources keys items by both. */
export interface AuditOutboxItemKey {
  sourceId: string;
  eventId: string;
}

export function auditOutboxItemKey(item: AuditOutboxItem): AuditOutboxItemKey {
  return { sourceId: item.submission.producerEvent.source.sourceId, eventId: item.eventId };
}

export interface AuditOutboxProvider {
  readonly capabilities: {
    durability: 'ephemeral' | 'durable';
    fifoPerSource: true;
    keyedBySource?: true;
  };
  enqueue(item: AuditOutboxItem): Promise<void>;
  /** Eligible items, FIFO per source; dead letters are left out. */
  pending(limit?: number): AsyncIterable<AuditOutboxItem>;
  markDelivered(key: AuditOutboxItemKey | string): Promise<void>;
  markFailed(key: AuditOutboxItemKey | string, error: unknown): Promise<void>;
}

/** An item whose content differs from the one already enqueued under its key. */
export class AuditOutboxConflictError extends Error {
  constructor(key: AuditOutboxItemKey) {
    super(`Audit outbox event identity collision: ${key.sourceId} / ${key.eventId}`);
    this.name = 'AuditOutboxConflictError';
  }
}

function storageKey(key: AuditOutboxItemKey): string {
  return `${key.sourceId}\0${key.eventId}`;
}

/** The same submission: ledger, epoch pin, canonical event and evidence bytes. */
export function sameAuditSubmission(left: AuditRecorderSubmission, right: AuditRecorderSubmission): boolean {
  if (
    left.ledgerId !== right.ledgerId ||
    left.expectedLedgerEpochId !== right.expectedLedgerEpochId ||
    canonicalize(left.producerEvent) !== canonicalize(right.producerEvent) ||
    left.encryptedEvidence.length !== right.encryptedEvidence.length
  ) {
    return false;
  }
  return left.encryptedEvidence.every((item, index) => {
    const other = right.encryptedEvidence[index]!;
    return canonicalize(item.ref) === canonicalize(other.ref) && Buffer.from(item.ciphertext).equals(Buffer.from(other.ciphertext));
  });
}

/** Resolves a bare event id to a stored key, only while exactly one source has it pending. */
function resolveKey(key: AuditOutboxItemKey | string, keys: Iterable<AuditOutboxItemKey>): string | undefined {
  if (typeof key !== 'string') return storageKey(key);
  const matches = [...keys].filter((candidate) => candidate.eventId === key);
  if (matches.length > 1) throw new Error(`Audit outbox event id ${key} is pending for several sources; pass its AuditOutboxItemKey`);
  return matches[0] === undefined ? undefined : storageKey(matches[0]);
}

/** Development-only outbox: buffered delivery refuses it, because it does not survive a restart. */
export class MemoryAuditOutbox implements AuditOutboxProvider {
  readonly capabilities = { durability: 'ephemeral' as const, fifoPerSource: true as const, keyedBySource: true as const };
  private readonly items = new Map<string, AuditOutboxItem>();

  async enqueue(item: AuditOutboxItem): Promise<void> {
    const key = auditOutboxItemKey(item);
    const existing = this.items.get(storageKey(key));
    if (existing !== undefined) {
      if (!sameAuditSubmission(existing.submission, item.submission)) throw new AuditOutboxConflictError(key);
      return;
    }
    this.items.set(storageKey(key), { ...item });
  }

  async *pending(limit = Number.MAX_SAFE_INTEGER): AsyncIterable<AuditOutboxItem> {
    let count = 0;
    for (const item of [...this.items.values()]) {
      if (count >= limit) return;
      count += 1;
      yield item;
    }
  }

  async markDelivered(key: AuditOutboxItemKey | string): Promise<void> {
    const stored = resolveKey(key, [...this.items.values()].map(auditOutboxItemKey));
    if (stored !== undefined) this.items.delete(stored);
  }

  async markFailed(key: AuditOutboxItemKey | string): Promise<void> {
    const stored = resolveKey(key, [...this.items.values()].map(auditOutboxItemKey));
    const item = stored === undefined ? undefined : this.items.get(stored);
    if (item !== undefined) this.items.set(stored!, { ...item, attempts: item.attempts + 1 });
  }
}

interface StoredOutboxItem {
  format: 'helix-audit-outbox-item/v1';
  eventId: string;
  enqueuedAt: number;
  attempts: number;
  submission: {
    ledgerId?: string;
    expectedLedgerEpochId?: string;
    producerEvent: AuditRecorderSubmission['producerEvent'];
    encryptedEvidence: Array<{ ref: EvidenceRef; ciphertextBase64url: string }>;
  };
}

interface IndexedItem {
  file: string;
  key: AuditOutboxItemKey;
}

export interface DurableOutboxOptions {
  /** The directory items live in (created if missing). Keep it on persistent storage. */
  directory: string;
  /** Failures after which an item moves to `dead/` and leaves `pending()`; default unlimited. */
  maxAttempts?: number;
}

function toStored(item: AuditOutboxItem): StoredOutboxItem {
  const { submission } = item;
  return {
    format: 'helix-audit-outbox-item/v1',
    eventId: item.eventId,
    enqueuedAt: item.enqueuedAt,
    attempts: item.attempts,
    submission: {
      ...(submission.ledgerId !== undefined ? { ledgerId: submission.ledgerId } : {}),
      ...(submission.expectedLedgerEpochId !== undefined ? { expectedLedgerEpochId: submission.expectedLedgerEpochId } : {}),
      producerEvent: submission.producerEvent,
      encryptedEvidence: submission.encryptedEvidence.map((evidence) => ({
        ref: evidence.ref,
        ciphertextBase64url: Buffer.from(evidence.ciphertext).toString('base64url'),
      })),
    },
  };
}

function fromStored(stored: StoredOutboxItem): AuditOutboxItem {
  if (stored.format !== 'helix-audit-outbox-item/v1') throw new Error('Not a helix audit outbox item');
  return {
    eventId: stored.eventId,
    enqueuedAt: stored.enqueuedAt,
    attempts: stored.attempts,
    submission: {
      ...(stored.submission.ledgerId !== undefined ? { ledgerId: stored.submission.ledgerId } : {}),
      ...(stored.submission.expectedLedgerEpochId !== undefined ? { expectedLedgerEpochId: stored.submission.expectedLedgerEpochId } : {}),
      producerEvent: stored.submission.producerEvent,
      encryptedEvidence: stored.submission.encryptedEvidence.map((evidence) => ({
        ref: evidence.ref,
        ciphertext: new Uint8Array(Buffer.from(evidence.ciphertextBase64url, 'base64url')),
      })),
    },
  };
}

/**
 * A durable outbox in a directory: `pending/<order>-<key digest>.json` per
 * item, `dead/` for dead letters. Writes go to a temporary file that is
 * flushed and renamed into place, then the directory is flushed. Operations
 * are serialized per instance; one producer process owns one directory.
 */
export class DurableOutbox implements AuditOutboxProvider {
  readonly capabilities = { durability: 'durable' as const, fifoPerSource: true as const, keyedBySource: true as const };
  private readonly pendingDir: string;
  private readonly deadDir: string;
  private index: Map<string, IndexedItem> | undefined;
  private nextOrder = 0;
  private tail: Promise<unknown> = Promise.resolve();

  constructor(private readonly options: DurableOutboxOptions) {
    this.pendingDir = join(options.directory, 'pending');
    this.deadDir = join(options.directory, 'dead');
  }

  enqueue(item: AuditOutboxItem): Promise<void> {
    return this.serialized(async () => {
      const index = await this.load();
      const key = auditOutboxItemKey(item);
      const existing = index.get(storageKey(key));
      if (existing !== undefined) {
        const stored = await this.read(join(this.pendingDir, existing.file));
        if (!sameAuditSubmission(stored.submission, item.submission)) throw new AuditOutboxConflictError(key);
        return;
      }
      const file = `${String(this.nextOrder).padStart(16, '0')}-${createHash('sha256').update(storageKey(key)).digest('hex').slice(0, 32)}.json`;
      this.nextOrder += 1;
      await this.writeAtomically(join(this.pendingDir, file), toStored(item));
      index.set(storageKey(key), { file, key });
    });
  }

  async *pending(limit = Number.MAX_SAFE_INTEGER): AsyncIterable<AuditOutboxItem> {
    const files = await this.serialized(async () => [...(await this.load()).values()].map((indexed) => indexed.file).sort());
    let count = 0;
    for (const file of files) {
      if (count >= limit) return;
      let item: AuditOutboxItem;
      try {
        item = await this.read(join(this.pendingDir, file));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; // delivered meanwhile
        throw error;
      }
      count += 1;
      yield item;
    }
  }

  markDelivered(key: AuditOutboxItemKey | string): Promise<void> {
    return this.serialized(async () => {
      const index = await this.load();
      const stored = resolveKey(key, [...index.values()].map((indexed) => indexed.key));
      const indexed = stored === undefined ? undefined : index.get(stored);
      if (indexed === undefined) return;
      await unlink(join(this.pendingDir, indexed.file)).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error;
      });
      await this.syncDirectory(this.pendingDir);
      index.delete(stored!);
    });
  }

  markFailed(key: AuditOutboxItemKey | string): Promise<void> {
    return this.serialized(async () => {
      const index = await this.load();
      const stored = resolveKey(key, [...index.values()].map((indexed) => indexed.key));
      const indexed = stored === undefined ? undefined : index.get(stored);
      if (indexed === undefined) return;
      const path = join(this.pendingDir, indexed.file);
      const item = await this.read(path);
      const failed = { ...item, attempts: item.attempts + 1 };
      if (failed.attempts >= (this.options.maxAttempts ?? Number.POSITIVE_INFINITY)) {
        await this.writeAtomically(join(this.deadDir, indexed.file), toStored(failed));
        await unlink(path);
        await this.syncDirectory(this.pendingDir);
        index.delete(stored!);
        return;
      }
      await this.writeAtomically(path, toStored(failed));
    });
  }

  /** Items that exhausted their attempts, kept for operator inspection and recovery. */
  async deadLetters(): Promise<AuditOutboxItem[]> {
    const files = (await readdir(this.deadDir).catch(() => [] as string[])).filter((file) => file.endsWith('.json')).sort();
    return Promise.all(files.map((file) => this.read(join(this.deadDir, file))));
  }

  private serialized<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.tail.then(operation, operation);
    this.tail = run.catch(() => undefined);
    return run;
  }

  private async load(): Promise<Map<string, IndexedItem>> {
    if (this.index !== undefined) return this.index;
    await mkdir(this.pendingDir, { recursive: true });
    await mkdir(this.deadDir, { recursive: true });
    const index = new Map<string, IndexedItem>();
    const deadFiles = await readdir(this.deadDir);
    for (const file of (await readdir(this.pendingDir)).filter((name) => name.endsWith('.json')).sort()) {
      const item = await this.read(join(this.pendingDir, file));
      const key = auditOutboxItemKey(item);
      index.set(storageKey(key), { file, key });
    }
    const orders = [...[...index.values()].map((indexed) => indexed.file), ...deadFiles].map((file) => Number.parseInt(file.slice(0, 16), 10)).filter(Number.isFinite);
    this.nextOrder = orders.length === 0 ? 0 : Math.max(...orders) + 1;
    this.index = index;
    return index;
  }

  private async read(path: string): Promise<AuditOutboxItem> {
    return fromStored(JSON.parse(await readFile(path, 'utf8')) as StoredOutboxItem);
  }

  private async writeAtomically(path: string, value: StoredOutboxItem): Promise<void> {
    const temporary = `${path}.${randomUUID()}.tmp`;
    const handle = await open(temporary, 'w');
    try {
      await handle.writeFile(JSON.stringify(value), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    await this.syncDirectory(join(path, '..'));
  }

  private async syncDirectory(directory: string): Promise<void> {
    // A directory fsync makes the rename or unlink itself durable; some platforms refuse it, which is not an error here.
    try {
      const handle = await open(directory, 'r');
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
    } catch {
      // ignored: best effort on platforms without directory fsync
    }
  }
}
