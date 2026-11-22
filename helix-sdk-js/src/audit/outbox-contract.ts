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
 * The outbox provider contract (AUDITABILITY.md: "Run the provider contract
 * kit for every adapter"), ported check for check from upstream
 * `evaluateAuditOutboxProviderContract` (`src/audit/testing/provider-contracts.ts`
 * at a4d7f61): FIFO per source, idempotent enqueue refusing divergent content,
 * failure accounting and acknowledgement, and source-scoped keys.
 */

import { auditOutboxItemKey, type AuditOutboxItem, type AuditOutboxItemKey, type AuditOutboxProvider } from './outbox.js';
import type { AuditProducerEvent } from './types.js';

export interface AuditOutboxContractCheck {
  name: string;
  passed: boolean;
  error?: unknown;
}

export interface AuditOutboxContractReport {
  providerKind: 'outbox';
  passed: boolean;
  checks: AuditOutboxContractCheck[];
}

function expectContract(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function check(checks: AuditOutboxContractCheck[], name: string, execute: () => Promise<void>): Promise<void> {
  try {
    await execute();
    checks.push({ name, passed: true });
  } catch (error) {
    checks.push({ name, passed: false, error });
  }
}

function contractEvent(sequence: number): AuditProducerEvent {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
    eventId: `contract-event-${sequence}`,
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:contract:1',
    occurredAt: 1_750_000_000_000 + sequence,
    tenantRef: { kind: 'pairwise_did', did: 'did:key:zContractTenant' },
    source: { producer: { kind: 'pairwise_did', did: 'did:key:zContractProducer' }, sourceId: 'contract-source', sourceSequence: String(sequence) },
    action: { category: 'tool.call' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'contract' },
  };
}

export function assertAuditOutboxContract(report: AuditOutboxContractReport): void {
  const failures = report.checks.filter((item) => !item.passed);
  if (failures.length > 0) {
    throw new AggregateError(failures.map((item) => item.error), `outbox provider contract failed: ${failures.map((item) => item.name).join(', ')}`);
  }
}

/** Executable FIFO, retry-accounting and acknowledgement contract for outboxes. */
export async function evaluateAuditOutboxProviderContract(
  createProvider: () => AuditOutboxProvider | Promise<AuditOutboxProvider>,
): Promise<AuditOutboxContractReport> {
  const checks: AuditOutboxContractCheck[] = [];
  const ledger = { ledgerId: 'contract-ledger', ledgerEpochId: 'epoch-1' };
  const item = (sequence: number): AuditOutboxItem => ({
    eventId: `contract-event-${sequence}`,
    submission: { ledgerId: ledger.ledgerId, expectedLedgerEpochId: ledger.ledgerEpochId, producerEvent: contractEvent(sequence), encryptedEvidence: [] },
    enqueuedAt: 1_750_000_000_000 + sequence,
    attempts: 0,
  });
  const collect = async (provider: AuditOutboxProvider): Promise<AuditOutboxItem[]> => {
    const values: AuditOutboxItem[] = [];
    for await (const value of provider.pending()) values.push(value);
    return values;
  };
  const keyOf = (provider: AuditOutboxProvider, value: AuditOutboxItem): AuditOutboxItemKey | string =>
    provider.capabilities.keyedBySource === true ? auditOutboxItemKey(value) : value.eventId;

  let keyedBySource = false;
  await check(checks, 'declares and preserves FIFO order per source', async () => {
    const provider = await createProvider();
    keyedBySource = provider.capabilities.keyedBySource === true;
    expectContract(provider.capabilities.fifoPerSource === true, 'fifoPerSource must be true');
    await provider.enqueue(item(1));
    await provider.enqueue(item(2));
    expectContract(
      JSON.stringify((await collect(provider)).map((value) => value.eventId)) === JSON.stringify(['contract-event-1', 'contract-event-2']),
      'pending items were not yielded in enqueue order',
    );
  });

  await check(checks, 'enqueues idempotently and rejects divergent content per event identity', async () => {
    const provider = await createProvider();
    await provider.enqueue(item(1));
    await provider.enqueue(structuredClone(item(1)));
    expectContract((await collect(provider)).length === 1, 'redelivered enqueue duplicated the pending item');
    const divergent = item(1);
    divergent.submission = { ...divergent.submission, producerEvent: { ...divergent.submission.producerEvent, action: { category: 'tampered' } } };
    let rejected = false;
    try {
      await provider.enqueue(divergent);
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'divergent content under one event identity was accepted');
  });

  await check(checks, 'accounts for failures and removes only acknowledged items', async () => {
    const provider = await createProvider();
    await provider.enqueue(item(1));
    await provider.enqueue(item(2));
    await provider.markFailed(keyOf(provider, item(1)), new Error('offline'));
    let pending = await collect(provider);
    expectContract(pending[0]?.attempts === 1, 'failed delivery attempt was not persisted');
    await provider.markDelivered(keyOf(provider, item(1)));
    pending = await collect(provider);
    expectContract(pending.length === 1 && pending[0]?.eventId === 'contract-event-2', 'acknowledgement removed the wrong pending item');
  });

  if (keyedBySource) {
    await check(checks, 'keys items by producer source and event identity', async () => {
      const provider = await createProvider();
      const own = item(1);
      const otherSource: AuditOutboxItem = {
        ...own,
        submission: { ...own.submission, producerEvent: { ...own.submission.producerEvent, source: { ...own.submission.producerEvent.source, sourceId: 'contract-source-2' } } },
      };
      await provider.enqueue(own);
      await provider.enqueue(otherSource);
      expectContract((await collect(provider)).length === 2, "an event ID from one source displaced another source's pending item");
      await provider.markDelivered(auditOutboxItemKey(own));
      const pending = await collect(provider);
      expectContract(
        pending.length === 1 && pending[0]?.submission.producerEvent.source.sourceId === 'contract-source-2',
        "acknowledging one source removed another source's pending item",
      );
    });
  }

  return { providerKind: 'outbox', passed: checks.every((entry) => entry.passed), checks };
}
