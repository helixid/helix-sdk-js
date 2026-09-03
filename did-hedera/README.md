# @helixid/did-hedera

Optional `did:hedera` method support for HelixID: anchoring a DID to Hedera
Consensus Service (HCS), resolving one back from a mirror node, and
publishing a signed StatusList credential to HCS for an on-chain audit
trail. Not required for `did:web` or `did:key`, which are handled entirely
by `@helixid/sdk-js`/`@helixid/cli` without this package.

This is a real-money-spending dependency — every anchor and publish call
submits a paid Hedera transaction and debits the configured operator
account's HBAR balance. Install it only where Hedera support is actually
needed:

```bash
npm install @helixid/did-hedera
```

`@helixid/cli` and `@helixid/mcp-server` both declare it as an
**optional** dependency — `helix did create --method hedera` (or the
`did_create` MCP tool with `method: "hedera"`) fails with a clear
"not yet supported"-style error if it isn't installed, rather than
silently producing an unanchored wallet.

## API

```ts
import {
  anchorDidHedera,
  resolveDidHedera,
  publishStatusListToHCS,
} from '@helixid/did-hedera';
```

- **`anchorDidHedera(options: HederaAnchorOptions)`** — registers a new
  `did:hedera` identity via the Hiero DID registrar and returns
  `{ did, topicId, transactionId, didDocument }`.
  ```ts
  interface HederaAnchorOptions {
    privateKeyHex: string; // Ed25519 private key hex used to create the DID
    operatorId: string;
    operatorKey: string;
    network: 'testnet' | 'previewnet' | 'mainnet';
    topicId?: string;
  }
  ```
- **`resolveDidHedera(did: string): Promise<DIDDocument>`** (aliased as
  `resolveDid`) — resolves a `did:hedera:...` DID by reading its DID
  document back from the Hedera mirror node. No operator credentials
  needed; this is a read against public mirror data.
- **`publishStatusListToHCS(statusListVC, options)`** — publishes an
  already-signed StatusList VC to an HCS topic as an additional,
  on-chain audit trail. The HTTPS-served status list file remains the
  authoritative source for revocation checks; this is supplementary, not
  a replacement.

## Cost and network access

`anchorDidHedera` and `publishStatusListToHCS` both log a `console.warn`
before submitting anything, naming the network and that the operator
account will be debited. Both require live network access to Hedera
(via `@hashgraph/sdk`) and a funded operator account
(`HEDERA_OPERATOR_ID` / `HEDERA_OPERATOR_KEY`, read by
`@helixid/cli`/`@helixid/mcp-server` via
`requireHederaOperator()` — see their READMEs).

`resolveDidHedera` only reads from a public mirror node — no operator
credentials or HBAR spend involved.

## Testing

```bash
pnpm test:unit
```

Tests mock the Hiero SDK modules (`@hiero-did-sdk/registrar`,
`@hiero-did-sdk/resolver`, `@hiero-did-sdk/hcs`) and the Hedera mirror
node — no live network calls, no real HBAR spend.

## License

Apache-2.0
