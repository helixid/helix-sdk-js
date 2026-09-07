import type { HelixClient } from '@helixid/sdk-js';

export interface StructuredTool {
  name: string;
  metadata?: {
    requiredScope?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Agent self-custody has been retired — there is no local wallet file to
 * read `credentialSubject.privilegeScopes` from anymore. `listVCs()`
 * already returns `scopes` directly on each summary, so this is one API
 * call (no need to separately fetch and parse a full VC).
 */
export async function filterToolsByScope<T extends StructuredTool>(
  tools: T[],
  client: HelixClient,
  agentDid: string,
): Promise<T[]> {
  const activeVCs = await client.listVCs({ subjectDid: agentDid, status: 'active' });
  const active = activeVCs[0];
  if (!active) {
    throw new Error('No active credential for this agent. Run onboarding first.');
  }
  const scopes = active.scopes ?? [];

  return tools.filter((tool) => {
    const requiredScope = tool.metadata?.requiredScope;
    if (!requiredScope) {
      return true;
    }
    return scopes.includes(requiredScope) || scopes.includes(tool.name);
  });
}
