import { HelixClient } from '@helixid/sdk-js';
import { requirePassphrase } from '../lib/env.js';
import { success } from '../lib/output.js';

export interface AgentOnboardOptions {
  token: string;
  wallet: string;
  apiUrl: string;
  /** Comma-separated list — matches the enrollment token's requestedDomains from `helix agent enroll` / the console's Enroll page. */
  domains?: string;
}

/**
 * Completes the real two-step onboarding flow (HelixClient.requestOnboardingChallenge()
 * + completeOnboarding()) for an enrollment token minted elsewhere — the
 * console's Enroll page, or `POST /v1/enrollment-tokens` directly. This
 * does not mint its own token: the token is the operator's proof that this
 * agent is authorized to onboard with the scopes/domains it was granted.
 *
 * The private key is generated locally in this process and never leaves
 * it — only a signature proving possession crosses the network. See
 * AgentWallet's save()/load() for exactly how the resulting wallet file is
 * encrypted.
 */
export async function runAgentOnboard(options: AgentOnboardOptions): Promise<void> {
  const passphrase = requirePassphrase();
  const domains = options.domains
    ? options.domains.split(',').map((domain) => domain.trim()).filter(Boolean)
    : [];

  const client = new HelixClient(options.apiUrl);
  const challenge = await client.requestOnboardingChallenge(options.token, domains);
  const result = await client.completeOnboarding(
    challenge.challengeId,
    challenge.nonce,
    passphrase,
    options.wallet,
  );

  success(`Agent onboarded: ${result.agentDid}`);
  console.log('');
  console.log(`VC id:  ${result.vcId}`);
  console.log(`Wallet: ${options.wallet}`);
}
