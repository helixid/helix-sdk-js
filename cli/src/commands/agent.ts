import { HelixClient } from '@helixid/sdk-js';
import { success } from '../lib/output.js';

export interface AgentOnboardOptions {
  token: string;
  apiUrl: string;
  /** Comma-separated list — matches the enrollment token's requestedDomains from `POST /v1/enrollment-tokens` / the console's Enroll page. */
  domains?: string;
}

/**
 * Completes onboarding (HelixClient.onboardAgent()) for an enrollment token
 * minted elsewhere — the console's Enroll page, or `POST /v1/enrollment-tokens`
 * directly. This does not mint its own token: the token is the operator's
 * proof that this agent is authorized to onboard with the scopes/domains it
 * was granted.
 *
 * Agent self-custody has been retired: the server generates and holds the
 * private key itself. No local keypair, no wallet file, no passphrase —
 * only `{ agentDid, vcId }` comes back. To act as this agent afterward
 * (present a VP), use HelixClient.signVP(agentDid, targetService) — also an
 * API call, since there's no local key to sign with.
 */
export async function runAgentOnboard(options: AgentOnboardOptions): Promise<void> {
  const domains = options.domains
    ? options.domains.split(',').map((domain) => domain.trim()).filter(Boolean)
    : [];

  const client = new HelixClient(options.apiUrl);
  const result = await client.onboardAgent(options.token, domains);

  success(`Agent onboarded: ${result.agentDid}`);
  console.log('');
  console.log(`VC id: ${result.vcId}`);
}
