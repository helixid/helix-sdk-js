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
 * Producer delivery modes (story A-2 point 3; AUDITABILITY.md, Delivery
 * semantics), as the `AuditSink` behind an `AuditTrail`:
 *
 * | Mode          | Response boundary                         | Honest claim |
 * |---------------|-------------------------------------------|--------------|
 * | `required`    | the recorder's signed receipt obtained    | AAP-2        |
 * | `buffered`    | the durable outbox acknowledged the item  | AAP-2, pending until delivered |
 * | `best-effort` | an append attempted                       | AAP-1 only   |
 *
 * `required` is the default. `buffered` refuses an ephemeral outbox at
 * construction (startup). `best-effort` is refused unless the operator
 * explicitly accepts AAP-1 (`acceptAap1: true`). The producer never sets
 * time, sequence, epoch or signature: it submits the frozen event and checks
 * that the receipt binds it.
 */

import type { AuditOutboxItemKey, AuditOutboxProvider } from './outbox.js';
import { auditOutboxItemKey } from './outbox.js';
import { assertEntryBindsSubmission, type AuditRecorderClient, type AuditRecorderSubmission, type SignedAuditEntry } from './recorder-client.js';
import type { AuditSink } from './sink.js';
import type { AuditProducerEvent, AuditTrailEntry } from './types.js';

export const AUDIT_DELIVERY_MODES = ['required', 'buffered', 'best-effort'] as const;
export type AuditDeliveryMode = (typeof AUDIT_DELIVERY_MODES)[number];

/** Misconfigured delivery, refused at startup. */
export class AuditDeliveryConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditDeliveryConfigError';
  }
}

export interface AuditDeliveryOptions {
  recorder: AuditRecorderClient;
  /** Default `required`. */
  delivery?: AuditDeliveryMode;
  /** Required for `buffered`, and must be durable. */
  outbox?: AuditOutboxProvider;
  /** `best-effort` is refused unless this is true: the operator accepts AAP-1 (capture only). */
  acceptAap1?: boolean;
  /** The ledger the producer expects; the managed recorder routes by tenant when absent. */
  ledgerId?: string;
  /** Pins `required` / `best-effort` appends to one epoch; never applied to buffered items. */
  expectedLedgerEpochId?: string;
  clock?: () => number;
  /** A delivery failed (every mode; in `required` the record also throws). */
  onDeliveryFailure?: (error: unknown, event: AuditProducerEvent) => void;
  /** A committed outbox item could not be acknowledged; it stays pending and redelivers to the same receipt. */
  onAcknowledgementFailure?: (error: unknown, event: AuditProducerEvent) => void;
}

export interface AuditFlushResult {
  delivered: number;
  failed: number;
}

/**
 * The sink that delivers each recorded event to the authoritative recorder
 * under the configured mode. In `required` mode `append` resolves with the
 * signed entry and rejects when it could not be obtained; in `buffered` mode
 * it resolves once the outbox holds the item (`flush()` / `start()` deliver
 * it); in `best-effort` mode it resolves either way.
 */
export class AuditDeliverySink implements AuditSink {
  readonly delivery: AuditDeliveryMode;
  /** The assurance this configuration can honestly claim. */
  readonly profile: 'AAP-1' | 'AAP-2';
  private timer: ReturnType<typeof setInterval> | undefined;
  private flushing: Promise<AuditFlushResult> | undefined;

  constructor(private readonly options: AuditDeliveryOptions) {
    this.delivery = options.delivery ?? 'required';
    if (!AUDIT_DELIVERY_MODES.includes(this.delivery)) {
      throw new AuditDeliveryConfigError(`Unknown audit delivery mode ${String(this.delivery)}; use required, buffered or best-effort`);
    }
    if (this.delivery === 'buffered' && options.outbox?.capabilities.durability !== 'durable') {
      throw new AuditDeliveryConfigError('Buffered audit delivery requires a durable outbox; an ephemeral outbox is refused');
    }
    if (this.delivery === 'best-effort' && options.acceptAap1 !== true) {
      throw new AuditDeliveryConfigError('Best-effort audit delivery is AAP-1 only; set acceptAap1 to accept that explicitly');
    }
    this.profile = this.delivery === 'best-effort' ? 'AAP-1' : 'AAP-2';
  }

  async append(entry: AuditTrailEntry): Promise<SignedAuditEntry | void> {
    const { event } = entry;
    if (this.delivery === 'buffered') {
      // Never epoch-pinned: an item may be delivered after a rollover, where
      // logical-ledger idempotency carries the retry guarantee.
      await this.options.outbox!.enqueue({
        eventId: event.eventId,
        submission: { ...(this.options.ledgerId !== undefined ? { ledgerId: this.options.ledgerId } : {}), producerEvent: event, encryptedEvidence: [] },
        enqueuedAt: (this.options.clock ?? Date.now)(),
        attempts: 0,
      });
      return undefined;
    }
    const submission: AuditRecorderSubmission = {
      ...(this.options.ledgerId !== undefined ? { ledgerId: this.options.ledgerId } : {}),
      ...(this.options.expectedLedgerEpochId !== undefined ? { expectedLedgerEpochId: this.options.expectedLedgerEpochId } : {}),
      producerEvent: event,
      encryptedEvidence: [],
    };
    try {
      return await this.submit(submission);
    } catch (error) {
      this.options.onDeliveryFailure?.(error, event);
      if (this.delivery === 'required') throw error;
      return undefined;
    }
  }

  /**
   * Delivers pending outbox items in order. A failure is counted on the item
   * and blocks the rest of that source for this pass (order within a source
   * is kept); once the recorder committed an item, an acknowledgement failure
   * never turns it into a delivery failure.
   */
  async flush(limit?: number): Promise<AuditFlushResult> {
    if (this.delivery !== 'buffered') return { delivered: 0, failed: 0 };
    if (this.flushing !== undefined) return this.flushing;
    this.flushing = this.flushOnce(limit).finally(() => {
      this.flushing = undefined;
    });
    return this.flushing;
  }

  /** Flushes on an interval until `stop()`; the timer does not keep the process alive. */
  start(intervalMs = 1_000): void {
    if (this.delivery !== 'buffered' || this.timer !== undefined) return;
    this.timer = setInterval(() => void this.flush().catch(() => undefined), intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async flushOnce(limit: number | undefined): Promise<AuditFlushResult> {
    const outbox = this.options.outbox!;
    let delivered = 0;
    let failed = 0;
    const blocked = new Set<string>();
    for await (const item of outbox.pending(limit)) {
      const sourceId = item.submission.producerEvent.source.sourceId;
      if (blocked.has(sourceId)) continue;
      const key: AuditOutboxItemKey | string = outbox.capabilities.keyedBySource === true ? auditOutboxItemKey(item) : item.eventId;
      try {
        await this.submit(item.submission);
      } catch (error) {
        await outbox.markFailed(key, error);
        this.options.onDeliveryFailure?.(error, item.submission.producerEvent);
        blocked.add(sourceId);
        failed += 1;
        continue;
      }
      delivered += 1;
      try {
        await outbox.markDelivered(key);
      } catch (error) {
        this.options.onAcknowledgementFailure?.(error, item.submission.producerEvent);
      }
    }
    return { delivered, failed };
  }

  private async submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry> {
    const entry = await this.options.recorder.submit(submission);
    assertEntryBindsSubmission(entry, submission);
    return entry;
  }
}

export function createAuditDelivery(options: AuditDeliveryOptions): AuditDeliverySink {
  return new AuditDeliverySink(options);
}
