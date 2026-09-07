import type { HelixClient } from '@helixid/sdk-js';

export interface RunnableConfigLike {
  callbacks: Array<{
    handleToolStart(tool: unknown, input: unknown): Promise<void>;
  }>;
}

export interface StructuredToolLike {
  name?: string;
  _call(input: unknown, ...rest: unknown[]): unknown | Promise<unknown>;
  [key: string]: unknown;
}

export interface HelixIDMiddlewareOptions {
  /** Agent self-custody has been retired — signing happens server-side via this client, not a local wallet. */
  client: HelixClient;
  /** The agent's DID, previously implied by which wallet file was loaded. */
  agentDid: string;
  targetService: string;
  userDid?: string;
}

export type LangChainMiddlewareOptions = HelixIDMiddlewareOptions;

async function attachVP(options: LangChainMiddlewareOptions, input: unknown): Promise<void> {
  const vp = await options.client.signVP(options.agentDid, options.targetService, {
    ...(options.userDid !== undefined ? { userDid: options.userDid } : {}),
  });

  const target = ensureObjectInput(input);
  target._helixVP = encodeBase64UrlJson(vp);
}

export function HelixIDMiddleware(options: LangChainMiddlewareOptions): RunnableConfigLike {
  return {
    callbacks: [
      {
        async handleToolStart(_tool, input): Promise<void> {
          await attachVP(options, input);
        },
      },
    ],
  };
}

export function HelixIDToolWrapper<T extends StructuredToolLike>(
  tool: T,
  options: LangChainMiddlewareOptions,
): T {
  return {
    ...tool,
    async _call(input: unknown, ...rest: unknown[]): Promise<unknown> {
      await attachVP(options, input);
      return tool._call(input, ...rest);
    },
  };
}

export function ensureObjectInput(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('HelixIDMiddleware requires object tool input');
  }
  return input as Record<string, unknown>;
}

export function encodeBase64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
