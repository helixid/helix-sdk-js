import { AsyncLocalStorage } from 'node:async_hooks';
import { helixVPHeaders, type HelixClient } from '@helixid/sdk-js';

export interface StructuredToolLike {
  name?: string;
  _call(input: unknown, ...rest: unknown[]): unknown | Promise<unknown>;
  [key: string]: unknown;
}

export interface HelixIDToolWrapperOptions {
  /** Agent self-custody has been retired — signing happens server-side via this client, not a local wallet. */
  client: HelixClient;
  /** The agent's DID, previously implied by which wallet file was loaded. */
  agentDid: string;
  targetService: string;
  userDid?: string;
}

export type LangChainMiddlewareOptions = HelixIDToolWrapperOptions;

// The VP for the tool call in progress. It is handed to the tool out of band,
// never through the tool input, so it stays out of the model's arguments.
const currentVP = new AsyncLocalStorage<Record<string, string>>();

/**
 * The headers to send with the protected request made inside a wrapped tool:
 * `{ 'X-Helix-VP': <base64url VP> }`. Empty outside a HelixIDToolWrapper call.
 */
export function currentHelixVPHeaders(): Record<string, string> {
  return { ...(currentVP.getStore() ?? {}) };
}

/**
 * Wraps `tool` so every invocation signs a fresh VP, which the tool reads with
 * `currentHelixVPHeaders()` and sends as the X-Helix-VP header. The tool input
 * is passed through unchanged.
 */
export function HelixIDToolWrapper<T extends StructuredToolLike>(
  tool: T,
  options: LangChainMiddlewareOptions,
): T {
  return {
    ...tool,
    async _call(input: unknown, ...rest: unknown[]): Promise<unknown> {
      const vp = await options.client.signVP(options.agentDid, options.targetService, {
        ...(options.userDid !== undefined ? { userDid: options.userDid } : {}),
      });
      return currentVP.run(helixVPHeaders(vp), () => tool._call(input, ...rest));
    },
  };
}

export function encodeBase64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
