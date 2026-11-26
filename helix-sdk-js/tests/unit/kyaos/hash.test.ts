// Copyright 2026 DgVerse LLP
// KYA-OS story L2-A: the hashes a response proof binds (SPEC section 7.3).
import { describe, expect, it } from 'vitest';
import {
  CONTROL_ARGUMENT_PREFIX,
  RESPONSE_PROOF_ENVELOPE_PROFILE,
  canonicalize,
  coveredRequest,
  coveredResponse,
  hashJson,
  hashRequest,
  hashResponse,
  isControlArgument,
  stripControlArguments,
  wireJson,
} from '../../../src/core/kyaos/index.js';

const emptyArgs = 'sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033';
const msgHi = 'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7';

describe('control arguments', () => {
  it('are the _kyaos* members of a tool call and nothing else', () => {
    expect(CONTROL_ARGUMENT_PREFIX).toBe('_kyaos');
    expect(isControlArgument('_kyaos_session')).toBe(true);
    expect(isControlArgument('_kyaos')).toBe(true);
    expect(isControlArgument('_kyaosX')).toBe(true);
    expect(isControlArgument('kyaos')).toBe(false);
    expect(isControlArgument('_meta')).toBe(false);
    expect(stripControlArguments({ a: 1, _kyaos_session: 'kyaos_x', _kyaos_proof: {}, _other: 2 })).toEqual({ a: 1, _other: 2 });
    expect(stripControlArguments({})).toEqual({});
  });
});

describe('coveredRequest / hashRequest (SPEC appendix C.1)', () => {
  it('writes the covered request as method and params minus _meta, arguments minus _kyaos*', () => {
    const input = { method: 'tools/call', params: { name: 'echo', arguments: {} } };
    expect(canonicalize(coveredRequest(input))).toBe('{"method":"tools/call","params":{"arguments":{},"name":"echo"}}');
    expect(hashRequest(input)).toBe(emptyArgs);
    expect(
      hashRequest({
        method: 'tools/call',
        params: {
          name: 'echo',
          arguments: { _kyaos_proof: { jws: '...', meta: {} } },
          _meta: { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' },
        },
      }),
    ).toBe(emptyArgs);
    expect(hashRequest({ method: 'tools/call', params: { name: 'echo' } })).toBe(emptyArgs);
    expect(hashRequest({ method: 'tools/call', params: { name: 'echo', arguments: 'not an object' as never } })).toBe(emptyArgs);
    const business = coveredRequest({
      method: 'tools/call',
      params: { name: 'echo', arguments: { msg: 'hi', _kyaos_delegation: { id: 'urn:uuid:1111-aaaa' } }, _meta: { progressToken: 7 } },
    });
    expect(canonicalize(business)).toBe('{"method":"tools/call","params":{"arguments":{"msg":"hi"},"name":"echo"}}');
    expect(hashJson(business)).toBe(msgHi);
  });

  it('leaves params out where the request has none, and leaves other methods alone', () => {
    expect(coveredRequest({ method: 'tools/call' })).toEqual({ method: 'tools/call' });
    expect(hashRequest({ method: 'tools/call' })).toBe(hashJson({ method: 'tools/call' }));
    expect(coveredRequest({ method: 'tools/list', params: { cursor: 'c', _meta: { x: 1 } } })).toEqual({ method: 'tools/list', params: { cursor: 'c' } });
  });

  it('hashes the wire form: undefined members and toJSON never reach the hash', () => {
    const date = new Date(0);
    const request = { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi', at: date, gone: undefined } } };
    expect(hashRequest(request)).toBe(hashJson({ method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi', at: date.toISOString() } } }));
    expect(() => hashJson(request)).toThrow('Cannot canonicalize');
  });
});

describe('coveredResponse / hashResponse', () => {
  const result = { content: [{ type: 'text', text: 'hi' }], isError: false, _meta: { 'org.kya-os/response-proof': { jws: 'x', meta: {} }, traceparent: 't' } };

  it('body profile: hashes the result exactly as received', () => {
    expect(coveredResponse(result)).toEqual(result);
    expect(coveredResponse(result, undefined)).toEqual(result);
    expect(hashResponse(result)).toBe(hashJson(result));
    expect(hashResponse([{ type: 'text', text: 'released r-1' }])).toBe(hashJson([{ type: 'text', text: 'released r-1' }]));
    expect(hashResponse('text')).toBe(hashJson('text'));
  });

  it('envelope profile: hashes the result minus its top-level _meta, so the proof can live inside it', () => {
    expect(RESPONSE_PROOF_ENVELOPE_PROFILE).toBe('org.kya-os/response-proof.envelope');
    const { _meta, ...rest } = result;
    expect(_meta).toBeDefined();
    expect(coveredResponse(result, RESPONSE_PROOF_ENVELOPE_PROFILE)).toEqual(rest);
    expect(hashResponse(result, RESPONSE_PROOF_ENVELOPE_PROFILE)).toBe(hashJson(rest));
    expect(hashResponse(rest, RESPONSE_PROOF_ENVELOPE_PROFILE)).toBe(hashJson(rest));
    // Only a top-level _meta is removed; nested ones are data. A non-object result has no _meta to remove.
    expect(coveredResponse({ nested: { _meta: 1 } }, RESPONSE_PROOF_ENVELOPE_PROFILE)).toEqual({ nested: { _meta: 1 } });
    expect(coveredResponse([{ _meta: 1 }], RESPONSE_PROOF_ENVELOPE_PROFILE)).toEqual([{ _meta: 1 }]);
    expect(coveredResponse(null, RESPONSE_PROOF_ENVELOPE_PROFILE)).toBeNull();
  });

  it('wireJson round-trips JSON values and leaves a value with no JSON form for the hash to refuse', () => {
    expect(wireJson({ a: undefined, b: 1 })).toEqual({ b: 1 });
    expect(wireJson(undefined)).toBeUndefined();
    expect(() => hashResponse(undefined)).toThrow('Cannot canonicalize a undefined');
    expect(() => hashResponse(() => 1)).toThrow('Cannot canonicalize a function');
  });
});
