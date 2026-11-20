// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { kyaos } from '@helixid/sdk-js';

/** Why the KYA-OS layer refused a handshake or a call. */
export type KyaOsReason =
  | kyaos.HandshakeFormatProblem
  | 'sessions_disabled'
  | 'audience_mismatch'
  | 'timestamp_skew'
  | 'nonce_replayed'
  | 'agent_did_mismatch'
  | 'session_id_malformed'
  | 'session_unknown'
  | 'session_agent_mismatch';

/**
 * A refusal by the session, replay or proof layer. `reason` is the machine
 * code (also the `reason` of the denied proof), `message` says why in words.
 * Handshake refusals are answered as the handshake tool's error result;
 * call refusals become a `denied` proof.
 */
export class KyaOsError extends Error {
  public readonly code = 'KYAOS_REJECTED';
  public readonly httpStatus = 400;

  constructor(
    public readonly reason: KyaOsReason,
    message: string,
  ) {
    super(message);
    this.name = 'KyaOsError';
  }
}
