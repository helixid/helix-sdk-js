// The SDK's copy of the error catalog: every class carries a code from the
// catalog and an HTTP status, and mapApiError turns each API error body back
// into its typed class. The VP door's VP_MISSING / VPMissingError are gone
// (KYA-OS story C-C).
import { describe, expect, it } from 'vitest';
import * as errors from '../../../src/errors/index.js';
import { ErrorCode, HelixError, InternalError, mapApiError } from '../../../src/errors/index.js';

const codes = new Set<string>(Object.values(ErrorCode));
const classes = Object.entries(errors).filter(
  (entry): entry is [string, new (...args: unknown[]) => HelixError] =>
    typeof entry[1] === 'function' && entry[1] !== HelixError && entry[1].prototype instanceof HelixError,
);

describe('error catalog', () => {
  it('has a class for most codes and no VP door error', () => {
    expect(classes.length).toBeGreaterThan(50);
    expect(codes.has('VP_MISSING')).toBe(false);
    expect('VPMissingError' in errors).toBe(false);
  });

  it.each(classes)('%s carries a catalog code and an HTTP error status', (_name, ErrorClass) => {
    const error = new ErrorClass('detail');
    expect(error).toBeInstanceOf(HelixError);
    expect(error).toBeInstanceOf(Error);
    expect(codes.has(error.code)).toBe(true);
    expect(error.httpStatus).toBeGreaterThanOrEqual(400);
    expect(error.httpStatus).toBeLessThan(600);
    expect(typeof error.message).toBe('string');
    expect(error.message.length).toBeGreaterThan(0);
  });
});

// Two codes map to the canonical class they were consolidated into.
const consolidated: Record<string, string> = {
  DELEGATION_DEPTH_EXCEEDED: 'MAX_DELEGATION_DEPTH_EXCEEDED',
  DELEGATION_SCOPE_ESCALATION: 'SCOPE_ESCALATION_DENIED',
};

describe('mapApiError', () => {
  it.each([...codes])('maps %s to an error with that code', (code) => {
    const error = mapApiError({ error: { code, message: 'from the API' }, statusCode: 418 });
    expect(error).toBeInstanceOf(HelixError);
    expect(error.code).toBe(consolidated[code] ?? code);
  });

  it('keeps the API status for a code it has no class for', () => {
    const error = mapApiError({ error: { code: 'SOMETHING_NEW', message: 'm' }, status: 409 });
    expect(error.constructor).toBe(HelixError);
    expect(error.httpStatus).toBe(409);
    expect(mapApiError({ error: { code: 'SOMETHING_NEW', message: 'm' } }).httpStatus).toBe(500);
  });

  it('falls back to InternalError when the body has no error code', () => {
    for (const body of [undefined, null, 'text', {}, { error: {} }, { error: { message: 'no code' } }]) {
      expect(mapApiError(body)).toBeInstanceOf(InternalError);
    }
  });
});
