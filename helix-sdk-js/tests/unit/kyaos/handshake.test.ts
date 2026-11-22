// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the session handshake, client side and shared format rules (L2.2, L2.6, L2.7, L2.9, L2.14, L2.15).
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_SESSION_TTL_MINUTES,
  HANDSHAKE_TOOL_NAME,
  MAX_CLOCK_SKEW_SECONDS,
  MIN_CLOCK_SKEW_SECONDS,
  NONCE_MIN_LENGTH,
  PROTOCOL_VERSION,
  SESSION_CONTROL_ARGUMENT,
  SESSION_ID_PREFIX,
  clockSkewSeconds,
  createHandshakeRequest,
  generateNonce,
  generateSessionId,
  isDid,
  isSessionId,
  isValidNonce,
  validateHandshakeFormat,
  withinSkew,
  type HandshakeRequest,
} from '../../../src/core/kyaos/index.js';

const AUDIENCE = 'did:web:orders.example';

describe('constants', () => {
  it('names the tool, the control argument and the defaults the story fixes', () => {
    expect(HANDSHAKE_TOOL_NAME).toBe('_kyaos_handshake');
    expect(SESSION_CONTROL_ARGUMENT).toBe('_kyaos_session');
    expect(SESSION_ID_PREFIX).toBe('kyaos_');
    expect(PROTOCOL_VERSION).toBe('1.0');
    expect(NONCE_MIN_LENGTH).toBe(22);
    expect(DEFAULT_CLOCK_SKEW_SECONDS).toBe(120);
    expect(MIN_CLOCK_SKEW_SECONDS).toBe(30);
    expect(MAX_CLOCK_SKEW_SECONDS).toBe(600);
    expect(DEFAULT_SESSION_TTL_MINUTES).toBe(30);
  });
});

describe('nonces (L2.2, L2.6)', () => {
  it('generates 16 random bytes as 22 base64url characters, unique each time', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const nonce = generateNonce();
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(isValidNonce(nonce)).toBe(true);
      seen.add(nonce);
    }
    expect(seen.size).toBe(200);
    expect(generateNonce((size) => new Uint8Array(size))).toBe('AAAAAAAAAAAAAAAAAAAAAA');
  });

  it('accepts only strict base64url of at least 22 characters', () => {
    expect(isValidNonce('k7Hy9mNpQrStUvWxYz01Aa')).toBe(true);
    expect(isValidNonce('k7Hy9mNpQrStUvWxYz01AaBBBB')).toBe(true);
    for (const bad of ['k7Hy9mNpQrStUvWxYz01A', '', 'k7Hy9mNpQrStUvWxYz01Aa==', 'k7Hy9mNpQrStUvWxYz01A+', 'k7Hy9mNpQrStUvWxYz01 a', 'k7Hy9mNpQrStUvWxYz01AaBBB', 42, null, undefined, ['k7Hy9mNpQrStUvWxYz01Aa']]) {
      expect(isValidNonce(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('session ids (L2.7)', () => {
  it('are kyaos_<uuid-v4>', () => {
    const id = generateSessionId();
    expect(id).toMatch(/^kyaos_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(isSessionId(id)).toBe(true);
    expect(generateSessionId(() => '11111111-2222-4333-8444-555555555555')).toBe('kyaos_11111111-2222-4333-8444-555555555555');
    expect(generateSessionId()).not.toBe(generateSessionId());
    for (const bad of ['sess_abc', 'kyaos_', 'kyaos_not-a-uuid', 'kyaos_11111111-2222-1333-8444-555555555555', 7, undefined]) {
      expect(isSessionId(bad), String(bad)).toBe(false);
    }
  });
});

describe('clock skew (L2.3, L2.4, L2.9)', () => {
  it('defaults to 120 s and accepts integers from 30 to 600', () => {
    expect(clockSkewSeconds(undefined)).toBe(120);
    expect(clockSkewSeconds(30)).toBe(30);
    expect(clockSkewSeconds(600)).toBe(600);
    for (const bad of [29, 601, 0, -120, 120.5, NaN, Infinity]) {
      expect(() => clockSkewSeconds(bad), String(bad)).toThrow(RangeError);
    }
  });

  it('withinSkew is inclusive on both sides', () => {
    expect(withinSkew(1000, 1120, 120)).toBe(true);
    expect(withinSkew(1000, 880, 120)).toBe(true);
    expect(withinSkew(1000, 1121, 120)).toBe(false);
    expect(withinSkew(1000, 879, 120)).toBe(false);
    expect(withinSkew(1000, 1000, 0)).toBe(true);
  });
});

describe('createHandshakeRequest (L2.15)', () => {
  it('uses the current timestamp in seconds, a fresh nonce and the protocol version', () => {
    const before = Math.floor(Date.now() / 1000);
    const request = createHandshakeRequest({ audience: AUDIENCE });
    const after = Math.floor(Date.now() / 1000);
    expect(request.timestamp).toBeGreaterThanOrEqual(before);
    expect(request.timestamp).toBeLessThanOrEqual(after);
    expect(isValidNonce(request.nonce)).toBe(true);
    expect(request).toEqual({ nonce: request.nonce, audience: AUDIENCE, timestamp: request.timestamp, clientProtocolVersion: '1.0' });
    expect(validateHandshakeFormat(request)).toEqual({ ok: true, request });
  });

  it('takes a fixed clock, nonce, agentDid, clientInfo and capabilities', () => {
    const request = createHandshakeRequest({
      audience: AUDIENCE,
      now: 1_750_000_000_999,
      nonce: 'k7Hy9mNpQrStUvWxYz01Aa',
      agentDid: 'did:key:z6Mkagent',
      clientInfo: { name: 'e2e', version: '1' },
      clientCapabilities: { proofs: true },
    });
    expect(request).toEqual({
      nonce: 'k7Hy9mNpQrStUvWxYz01Aa',
      audience: AUDIENCE,
      timestamp: 1_750_000_000,
      agentDid: 'did:key:z6Mkagent',
      clientInfo: { name: 'e2e', version: '1' },
      clientProtocolVersion: '1.0',
      clientCapabilities: { proofs: true },
    });
    expect(validateHandshakeFormat(request)).toEqual({ ok: true, request });
  });
});

describe('validateHandshakeFormat (L2.1, L2.14)', () => {
  const good: HandshakeRequest = { nonce: 'k7Hy9mNpQrStUvWxYz01Aa', audience: AUDIENCE, timestamp: 1_710_268_800 };

  it('accepts the schema example and the minimal request', () => {
    expect(validateHandshakeFormat(good)).toEqual({ ok: true, request: good });
    const example = { ...good, agentDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', clientProtocolVersion: '1.0' };
    expect(validateHandshakeFormat(example)).toEqual({ ok: true, request: example });
    expect(validateHandshakeFormat({ ...good, agentDid: 'did:hedera:testnet:z6Mk_0.0.1' }).ok).toBe(true);
    expect(validateHandshakeFormat({ ...good, timestamp: 0 }).ok).toBe(true);
  });

  const refusals: [name: string, value: unknown, problem: string][] = [
    ['not an object', 'nonce', 'request_not_object'],
    ['null', null, 'request_not_object'],
    ['an array', [good], 'request_not_object'],
    ['an unknown member', { ...good, extra: 1 }, 'unknown_member'],
    ['a short nonce', { ...good, nonce: 'k7Hy9mNpQrStUvWxYz01A' }, 'nonce_invalid'],
    ['a padded nonce', { ...good, nonce: 'k7Hy9mNpQrStUvWxYz01Aa==' }, 'nonce_invalid'],
    ['a missing nonce', { audience: AUDIENCE, timestamp: 1 }, 'nonce_invalid'],
    ['a non-string nonce', { ...good, nonce: 12345678901234567890123 }, 'nonce_invalid'],
    ['an empty audience', { ...good, audience: '' }, 'audience_invalid'],
    ['a missing audience', { nonce: good.nonce, timestamp: 1 }, 'audience_invalid'],
    ['a non-string audience', { ...good, audience: ['did:web:x'] }, 'audience_invalid'],
    ['a missing timestamp', { nonce: good.nonce, audience: AUDIENCE }, 'timestamp_invalid'],
    ['a string timestamp', { ...good, timestamp: '1710268800' }, 'timestamp_invalid'],
    ['a fractional timestamp', { ...good, timestamp: 1710268800.5 }, 'timestamp_invalid'],
    ['a negative timestamp', { ...good, timestamp: -1 }, 'timestamp_invalid'],
    ['a millisecond-looking float', { ...good, timestamp: 1.5e12 + 0.5 }, 'timestamp_invalid'],
    ['a non-DID agentDid', { ...good, agentDid: 'agent-1' }, 'agent_did_invalid'],
    ['a non-string agentDid', { ...good, agentDid: 7 }, 'agent_did_invalid'],
    ['a bare did: agentDid', { ...good, agentDid: 'did:web:' }, 'agent_did_invalid'],
    ['clientInfo not an object', { ...good, clientInfo: 'cli' }, 'client_info_invalid'],
    ['clientInfo without name', { ...good, clientInfo: { version: '1' } }, 'client_info_invalid'],
    ['clientInfo with an unknown member', { ...good, clientInfo: { name: 'x', extra: 'y' } }, 'client_info_invalid'],
    ['clientInfo with a non-string member', { ...good, clientInfo: { name: 'x', version: 1 } }, 'client_info_invalid'],
    ['a malformed clientProtocolVersion', { ...good, clientProtocolVersion: 'v1' }, 'client_protocol_version_invalid'],
    ['a non-string clientProtocolVersion', { ...good, clientProtocolVersion: 1 }, 'client_protocol_version_invalid'],
    ['clientCapabilities not an object', { ...good, clientCapabilities: [] }, 'client_capabilities_invalid'],
  ];
  it.each(refusals)('refuses %s', (_name, value, problem) => {
    const result = validateHandshakeFormat(value);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.problem).toBe(problem);
      expect(result.message.length).toBeGreaterThan(0);
    }
  });

  it('isDid accepts any did:<method>:<id>', () => {
    expect(isDid('did:web:x')).toBe(true);
    expect(isDid('did:key:z6Mk')).toBe(true);
    expect(isDid('did:hedera:testnet:abc_0.0.1')).toBe(true);
    expect(isDid('did:WEB:x')).toBe(false);
    expect(isDid('http://x')).toBe(false);
    expect(isDid(1)).toBe(false);
  });
});
