// Copyright 2026 DgVerse LLP
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HttpAdapter } from '../../../src/http/HttpAdapter.js';

describe('HttpAdapter Branch Coverage', () => {
  let adapter: HttpAdapter;
  const baseUrl = 'http://localhost';

  beforeEach(() => {
    adapter = new HttpAdapter(baseUrl);
    vi.stubGlobal('fetch', vi.fn());
  });

  it('handles baseUrl with trailing slash', () => {
    const a2 = new HttpAdapter('http://localhost/');
    expect((a2 as any).baseUrl).toBe('http://localhost');
  });

  it('handles absolute paths in requests', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ data: 1 })
    } as any);

    await adapter.get('https://external.com/api');
    expect(fetch).toHaveBeenCalledWith('https://external.com/api', expect.anything());
  });

  it('handles body being undefined in requests', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({})
    } as any);

    await adapter.post('/test', undefined);
    expect(fetch).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      headers: {}
    }));
  });

  it('handles body being defined in requests', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({})
    } as any);

    await adapter.post('/test', { key: 'val' });
    expect(fetch).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: 'val' })
    }));
  });

  it('returns empty object for 204 No Content', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 204
    } as any);

    const res = await adapter.delete('/test');
    expect(res).toEqual({});
  });

  it('throws mapped error for non-ok responses', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 400,
      json: () => Promise.resolve({ error: { code: 'BAD_REQUEST', message: 'fail' } })
    } as any);

    await expect(adapter.get('/test')).rejects.toThrow('fail');
  });

  it('preserves onboarding API error status codes', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 404,
      json: () => Promise.resolve({
        error: {
          code: 'ENROLLMENT_TOKEN_NOT_FOUND',
          message: 'Enrollment token was not found'
        }
      })
    } as any);

    await expect(adapter.post('/v1/onboard', {
      enrollmentToken: 'enroll:missing',
      publicKeyHex: 'a'.repeat(64)
    })).rejects.toMatchObject({
      code: 'ENROLLMENT_TOKEN_NOT_FOUND',
      httpStatus: 404,
      message: 'Enrollment token was not found'
    });
  });

  it('sends the account API key as a bearer token on calls to the API', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({}) } as any);
    const enterprise = new HttpAdapter(baseUrl, { apiKey: 'hak_test' });

    await enterprise.get('/v1/audit-log');
    await enterprise.post('/v1/vp/verify', { signedVP: {} });

    expect(vi.mocked(fetch).mock.calls.map(([, init]) => init?.headers)).toEqual([
      { authorization: 'Bearer hak_test' },
      { 'content-type': 'application/json', authorization: 'Bearer hak_test' },
    ]);
  });

  it('keeps the account API key away from other hosts', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({}) } as any);

    await new HttpAdapter(baseUrl, { apiKey: 'hak_test' }).get('https://external.com/status-list/1');

    expect(fetch).toHaveBeenCalledWith('https://external.com/status-list/1', expect.objectContaining({ headers: {} }));
  });
});
