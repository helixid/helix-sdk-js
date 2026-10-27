import { HelixError } from '../errors/index.js';
import { mapApiError } from '../errors/index.js';

export class HttpAdapter {
  private readonly baseUrl: string;
  private readonly adminApiKey: string | undefined;
  private readonly apiKey: string | undefined;

  constructor(baseUrl: string, options: { adminApiKey?: string; apiKey?: string } = {}) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    this.adminApiKey = options.adminApiKey;
    this.apiKey = options.apiKey;
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  hasAdminApiKey(): boolean {
    return this.adminApiKey !== undefined && this.adminApiKey.length > 0;
  }

  hasApiKey(): boolean {
    return this.apiKey !== undefined && this.apiKey.length > 0;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    // One credential per client: an enterprise account API key is sent as
    // the bearer token on every call (enterprise has no admin key at all),
    // otherwise core's shared admin key goes in its own header.
    const auth = this.apiKey
      ? { authorization: `Bearer ${this.apiKey}` }
      : this.adminApiKey
        ? { 'x-admin-api-key': this.adminApiKey }
        : {};
    const init: RequestInit = {
      method,
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...auth,
      },
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const response = await fetch(url, init);

    if (response.status === 204) {
      return {} as T;
    }

    const data = await response.json();
    if (!response.ok) {
      throw this.mapErrorResponse(data, response.status);
    }
    return data as T;
  }

  private mapErrorResponse(data: unknown, status: number): HelixError {
    return mapApiError({ ...(typeof data === 'object' && data !== null ? data : {}), status });
  }
}
