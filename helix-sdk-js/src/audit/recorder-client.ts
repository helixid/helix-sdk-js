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
 * The producer's view of the authoritative recorder (story A-2). A producer
 * sends a frozen event and the encrypted evidence it references; the
 * recorder answers with the signed entry (the original one for a
 * redelivery). Nothing a producer sends chooses time, sequence, epoch,
 * predecessor or signature; the producer checks that the answer binds
 * exactly the event it sent.
 */

import { canonicalize } from './canonical.js';
import { auditEventDigest } from './digest.js';
import type { AuditProducerEvent, Digest, EvidenceRef, SignerRef } from './types.js';

/** The recorder's signed receipt core (vendored `audit-receipt.schema.json`). */
export interface AuditRecorderReceiptCore {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0';
  ledgerId: string;
  ledgerEpochId: string;
  sequence: string;
  eventId: string;
  entryDigest: Digest;
  previousEntryDigest: Digest | null;
  recordedAt: number;
  recorder: SignerRef;
  integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026';
}

/** One journal entry as the recorder returns it (vendored `audit-entry.schema.json` plus the receipt). */
export interface SignedAuditEntry {
  core: {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0';
    ledgerId: string;
    ledgerEpochId: string;
    sequence: string;
    previousEntryDigest: Digest | null;
    recordedAt: number;
    recorder: SignerRef;
    eventDigest: Digest;
    event: AuditProducerEvent;
    evidenceManifestDigest: Digest;
    integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026';
  };
  eventDigest: Digest;
  entryDigest: Digest;
  recorderReceipt: { core: AuditRecorderReceiptCore; jws: string };
}

/** What a producer submits: one frozen event and the evidence it references. */
export interface AuditRecorderSubmission {
  ledgerId?: string;
  /** Pins a new append to one epoch. Never set for buffered redelivery (AUDITABILITY.md). */
  expectedLedgerEpochId?: string;
  producerEvent: AuditProducerEvent;
  encryptedEvidence: ReadonlyArray<{ ref: EvidenceRef; ciphertext: Uint8Array }>;
}

/** The recorder port: authority fields are deliberately absent. */
export interface AuditRecorderClient {
  submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry>;
}

/** A submission the recorder did not record (transport failure, a refusal, or an answer that does not bind the event). */
export class AuditDeliveryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'AuditDeliveryError';
  }
}

/**
 * Throws unless the recorder's entry binds exactly the submitted event: the
 * same ledger (when one was named), the same event digest in both places, and
 * the same event in canonical form. An entry from an earlier retained epoch
 * is a legitimate redelivery answer, so the epoch is not compared.
 */
export function assertEntryBindsSubmission(entry: SignedAuditEntry, submission: AuditRecorderSubmission): void {
  const digest = auditEventDigest(submission.producerEvent);
  if (
    (submission.ledgerId !== undefined && entry.core?.ledgerId !== submission.ledgerId) ||
    entry.eventDigest !== digest ||
    entry.core?.eventDigest !== digest ||
    canonicalize(entry.core.event) !== canonicalize(submission.producerEvent)
  ) {
    throw new AuditDeliveryError('Recorder response does not bind the submitted frozen producer event');
  }
}

/** The JSON wire form of a submission (`POST /v1/audit/submissions`, or an `audit` member of another request). */
export function auditSubmissionWire(submission: AuditRecorderSubmission): Record<string, unknown> {
  return {
    ...(submission.ledgerId !== undefined ? { ledgerId: submission.ledgerId } : {}),
    ...(submission.expectedLedgerEpochId !== undefined ? { expectedLedgerEpochId: submission.expectedLedgerEpochId } : {}),
    producerEvent: submission.producerEvent,
    ...(submission.encryptedEvidence.length > 0
      ? {
          encryptedEvidence: submission.encryptedEvidence.map((item) => ({
            ref: item.ref,
            ciphertextBase64url: Buffer.from(item.ciphertext).toString('base64url'),
          })),
        }
      : {}),
  };
}

export interface HttpAuditRecorderClientOptions {
  /** The HelixID API (or a self-hosted recorder) base URL. No default. */
  baseUrl: string;
  /** Admin or account API key, sent as the bearer token. */
  apiKey: string;
  timeoutMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

/** The recorder over HTTP: `POST /v1/audit/submissions`, answered with `{ entry }`. */
export class HttpAuditRecorderClient implements AuditRecorderClient {
  private readonly url: string;
  private readonly doFetch: typeof fetch;

  constructor(private readonly options: HttpAuditRecorderClientOptions) {
    this.url = `${options.baseUrl.replace(/\/+$/, '')}/v1/audit/submissions`;
    this.doFetch = options.fetch ?? fetch;
  }

  async submit(submission: AuditRecorderSubmission): Promise<SignedAuditEntry> {
    let res: Response;
    try {
      res = await this.doFetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.options.apiKey}` },
        body: JSON.stringify(auditSubmissionWire(submission)),
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 5_000),
      });
    } catch (error) {
      throw new AuditDeliveryError('The audit recorder could not be reached', undefined, undefined, { cause: error });
    }
    const body = (await res.json().catch(() => undefined)) as { entry?: SignedAuditEntry; error?: { code?: string; message?: string } } | undefined;
    if (!res.ok || body?.entry === undefined) {
      throw new AuditDeliveryError(`The audit recorder refused the submission (${res.status}${body?.error?.code ? ` ${body.error.code}` : ''})`, res.status, body?.error?.code);
    }
    assertEntryBindsSubmission(body.entry, submission);
    return body.entry;
  }
}
