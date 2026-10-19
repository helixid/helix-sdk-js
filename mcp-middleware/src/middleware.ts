import { VPMissingError, VPVerificationFailedError, readHelixVPHeader, readHelixVPMeta } from '@helixid/sdk-js';
import { requireScope, verifyVP } from '@helixid/sdk-js';
import type { MCPToolCall, MCPMiddlewareOptions } from './types.js';

export function helixidMCPMiddleware(options: MCPMiddlewareOptions) {
  return async (toolCall: MCPToolCall): Promise<MCPToolCall> => {
    // The VP is read from _meta["x-helix-vp"] or the X-Helix-VP header only;
    // tool arguments are never consulted.
    const vp = readHelixVPMeta(toolCall._meta) ?? readHelixVPHeader(toolCall.headers);
    if (!vp) {
      throw new VPMissingError();
    }

    const result = await verifyVP(vp, options.client, {
      allowSelfSigned: options.allowSelfSigned ?? false,
    });

    if (!result.valid) {
      throw new VPVerificationFailedError(result.error);
    }

    for (const scope of options.requiredScopes ?? []) {
      requireScope(result, scope);
    }

    return toolCall;
  };
}
