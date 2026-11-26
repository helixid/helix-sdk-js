import { AsyncLocalStorage } from 'node:async_hooks';
import { kyaos } from '@helixid/sdk-js';

export interface StructuredToolLike {
  name?: string;
  _call(input: unknown, ...rest: unknown[]): unknown | Promise<unknown>;
  [key: string]: unknown;
}

export interface HelixIDToolWrapperOptions {
  /**
   * The agent's Signer (KYA-OS stories L1-A, C-C): its DID and key id, and
   * a `sign()` that keeps the private key wherever it lives. Every call is
   * signed with it; no request ever carries the key.
   */
  signer: kyaos.Signer;
  /** The service's DID, from its Entity Card: the proof's `audience`. */
  audience: string;
  /**
   * The delegation chain the agent acts under, root to leaf (§6.10 hops),
   * or a function returning the current one (for chains that renew).
   * Omitted when the agent acts on its own behalf.
   */
  chain?: readonly unknown[] | (() => readonly unknown[] | undefined | Promise<readonly unknown[] | undefined>) | undefined;
  /** The RFC 7638 thumbprint of the signing key, carried as `cnf.jkt` for the §8.6 fusion. */
  cnfJkt?: string | undefined;
}

export type LangChainMiddlewareOptions = HelixIDToolWrapperOptions;

/** Signs one outbound MCP request: the request with the proof (and chain) in `params._meta`. */
export type RequestSigner = (call: kyaos.ProofCall) => Promise<kyaos.verifier.ProofRequest>;

// The signer for the tool call in progress. It is handed to the tool out of
// band, never through the tool input, so nothing reaches the model's arguments.
const currentSigner = new AsyncLocalStorage<RequestSigner>();

/**
 * Inside a wrapped tool: signs the MCP request the tool is about to send,
 * returning it with `_meta["org.kya-os/request-proof"]` (and
 * `_meta["org.kya-os/delegation-chain"]`) set. Each request gets its own
 * proof, bound to its body and the service. Throws outside a
 * `HelixIDToolWrapper` call.
 */
export function signCurrentRequest(call: kyaos.ProofCall): Promise<kyaos.verifier.ProofRequest> {
  const sign = currentSigner.getStore();
  if (sign === undefined) return Promise.reject(new Error('signCurrentRequest: not inside a HelixIDToolWrapper call'));
  return sign(call);
}

/**
 * Wraps `tool` so the requests it sends while running can be signed with
 * `signCurrentRequest(request)`: a fresh KYA-OS request proof per request,
 * signed by the agent's own Signer, with the delegation chain attached. The
 * tool input is passed through unchanged. The Helix VP and its X-Helix-VP
 * header are gone (story C-C).
 */
export function HelixIDToolWrapper<T extends StructuredToolLike>(
  tool: T,
  options: LangChainMiddlewareOptions,
): T {
  const sign: RequestSigner = async (call) => {
    const chain = typeof options.chain === 'function' ? await options.chain() : options.chain;
    return kyaos.withRequestProof(call, options.signer, {
      audience: options.audience,
      ...(chain === undefined ? {} : { chain }),
      ...(options.cnfJkt === undefined ? {} : { cnfJkt: options.cnfJkt }),
    });
  };
  return {
    ...tool,
    async _call(input: unknown, ...rest: unknown[]): Promise<unknown> {
      return currentSigner.run(sign, () => tool._call(input, ...rest));
    },
  };
}
