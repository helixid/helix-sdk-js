export function requirePassphrase(): string {
  const passphrase = process.env.HELIX_WALLET_PASSPHRASE;
  if (!passphrase) {
    throw new Error('HELIX_WALLET_PASSPHRASE environment variable is required');
  }
  return passphrase;
}

export function requireHederaOperator(): { operatorId: string; operatorKey: string } {
  const operatorId = process.env.HEDERA_OPERATOR_ID;
  const operatorKey = process.env.HEDERA_OPERATOR_KEY;
  if (!operatorId || !operatorKey) {
    throw new Error('HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY environment variables are required');
  }
  return { operatorId, operatorKey };
}
