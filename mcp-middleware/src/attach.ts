import { HELIX_VP_META_KEY, encodeHelixVP } from '@helixid/sdk-js';
import type { AttachHelixVPOptions, MCPToolCall } from './types.js';

/**
 * Attaches a signed VP to an outbound MCP tool call, as
 * `_meta["x-helix-vp"]` — never in the tool's arguments. Pass the result's
 * `_meta` as the request's `params._meta`. Agent self-custody has been
 * retired, so signing is a server-side call (`client.signVP()`); the server
 * picks the agent's active credentials itself.
 */
export async function attachHelixVP(
  toolCall: MCPToolCall,
  options: AttachHelixVPOptions,
): Promise<MCPToolCall> {
  const vp = await options.client.signVP(options.agentDid, options.targetService, {
    ...(options.userDid !== undefined ? { userDid: options.userDid } : {}),
  });

  return {
    ...toolCall,
    _meta: {
      ...(toolCall._meta ?? {}),
      [HELIX_VP_META_KEY]: encodeHelixVP(vp),
    },
  };
}
