import type { AttachHelixVPOptions, MCPToolCall } from './types.js';

/**
 * Attaches a signed VP to an outbound MCP tool call. Agent self-custody has
 * been retired — there is no wallet file to load and no local key to sign
 * with, so this is now a server-side call (`client.signVP()`) instead of
 * loading a wallet and signing locally. The server picks the agent's
 * active credential itself.
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
    input: {
      ...(toolCall.input ?? {}),
      _helixVP: vp,
    },
  };
}
