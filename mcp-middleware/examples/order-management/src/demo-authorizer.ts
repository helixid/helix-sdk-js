// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { RetryAuthorizer } from '@helixid/mcp-middleware';

/**
 * The sample's DEMO_MODE stand-in for the retry authorizer of KYA-OS story
 * L3-E, until story F-2 (local chain verification) and L3-H (the root hop
 * signed by the user's did:key at consent) replace it. It reads the
 * DelegationCredential a retry carries in the §6.10 shape and checks only
 * what a structural reader can: the credential is a DelegationCredential
 * for this agent (`invoker`) at this service (`invocationTarget`), covers
 * the scopes the challenge asked for (`allowedAction`), has not expired
 * (`validUntil`) and carries a `proof`. It does not verify that proof: a
 * demo server has no verifier yet, and says so in its startup banner.
 */

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export function demoRetryAuthorizer(serviceDid: string, now: () => number = Date.now): RetryAuthorizer {
  return ({ credential, agentDid, token }) => {
    if (!isRecord(credential)) throw new Error('the delegation credential must be an object');
    const types = Array.isArray(credential['type']) ? credential['type'] : [credential['type']];
    if (!types.includes('DelegationCredential')) throw new Error('not a DelegationCredential');
    const subject = credential['credentialSubject'];
    if (!isRecord(subject)) throw new Error('credentialSubject is missing');
    if (subject['invoker'] !== agentDid) throw new Error(`invoker ${String(subject['invoker'])} is not the caller ${agentDid}`);
    if (subject['invocationTarget'] !== serviceDid) throw new Error(`invocationTarget ${String(subject['invocationTarget'])} is not this service`);
    const allowed = Array.isArray(subject['allowedAction']) ? subject['allowedAction'].filter((a): a is string => typeof a === 'string') : [];
    const uncovered = token.scopes.filter((scope) => !allowed.includes(scope));
    if (uncovered.length > 0) throw new Error(`allowedAction does not cover ${uncovered.join(' ')}`);
    const validUntil = credential['validUntil'];
    if (typeof validUntil === 'string' && Date.parse(validUntil) <= now()) throw new Error('the credential has expired');
    if (!isRecord(credential['proof'])) throw new Error('the credential carries no proof');
    return { scopes: allowed };
  };
}
