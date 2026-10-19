import { describe, expect, it } from 'vitest';
import {
  HELIX_VP_HEADER,
  HELIX_VP_META_KEY,
  decodeHelixVP,
  encodeHelixVP,
  helixVPHeaders,
  readHelixVPHeader,
  readHelixVPMeta,
  type SignedVP,
} from '../../src/index.js';

const vp = { id: 'vp:helix:test', holder: 'did:agent', proof: { type: 'Ed25519Signature2020' } } as unknown as SignedVP;
const encoded = encodeHelixVP(vp);

describe('VP transport', () => {
  it('round-trips a VP through base64url JSON', () => {
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeHelixVP(encoded)).toEqual(vp);
  });

  it('rejects a value that is not base64url JSON', () => {
    expect(() => decodeHelixVP('not json')).toThrow(expect.objectContaining({ code: 'VP_INVALID_STRUCTURE' }));
  });

  it('builds the X-Helix-VP header', () => {
    expect(helixVPHeaders(vp)).toEqual({ [HELIX_VP_HEADER]: encoded });
  });

  it('reads the header from a plain object in any case', () => {
    expect(readHelixVPHeader({ 'x-helix-vp': encoded })).toEqual(vp);
    expect(readHelixVPHeader({ 'X-HELIX-VP': [encoded] })).toEqual(vp);
    expect(readHelixVPHeader({ authorization: 'Bearer x' })).toBeUndefined();
    expect(readHelixVPHeader(undefined)).toBeUndefined();
  });

  it('reads the header from a Headers instance', () => {
    expect(readHelixVPHeader(new Headers({ 'X-Helix-VP': encoded }))).toEqual(vp);
    expect(readHelixVPHeader(new Headers())).toBeUndefined();
  });

  it('reads the VP from MCP _meta', () => {
    expect(readHelixVPMeta({ [HELIX_VP_META_KEY]: encoded })).toEqual(vp);
    expect(readHelixVPMeta({})).toBeUndefined();
    expect(readHelixVPMeta(undefined)).toBeUndefined();
    expect(() => readHelixVPMeta({ [HELIX_VP_META_KEY]: vp })).toThrow(
      expect.objectContaining({ code: 'VP_INVALID_STRUCTURE' }),
    );
  });
});
