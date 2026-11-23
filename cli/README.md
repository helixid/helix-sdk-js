# @helixid/cli

Platform Operator CLI for HelixID setup-time operations. The binary is named `helix`.

All wallet encryption uses `HELIX_WALLET_PASSPHRASE` from the environment — never pass a passphrase on the command line.

## Install

From the monorepo root:

```bash
nvm use
pnpm install
pnpm --filter @helixid/cli build
```

Run locally during development:

```bash
pnpm exec tsx src/bin/helix.ts did create --method web --domain example.com --wallet ./issuer.enc
```

## Commands

### `helix did create`

Create an encrypted wallet and DID. For `--method web`, the command also
creates the issuer's initial status list by default — one command, two
artifacts, both of which need hosting on your domain:

1. the DID document at `https://<domain>/.well-known/did.json`, and
2. the status list JSON at the `--status-list-base-url` (default
   `https://<domain>/.well-known/helix-status-list.json`).

Pick a generous `--status-list-length` (default 131072 bits; 100k+ is
recommended — unused bits are free, and grant/credential indices are assigned
randomly within the list).

```bash
export HELIX_WALLET_PASSPHRASE='your-secret'

# Issuer (did:web) — also writes status-list.json next to the wallet file
helix did create --method web --domain example.com --wallet ./issuer.enc

# Issuer without the status-list step (previous behavior)
helix did create --method web --domain example.com --wallet ./issuer.enc --no-status-list
```

Agents don't use this command — agent self-custody has been retired.
Agents onboard via the API (`POST /v1/onboard`), which generates and holds
the agent's key server-side.

Status-list flags (did:web only): `--no-status-list` to opt out,
`--status-list-length <bits>`, `--status-list-output <path>`,
`--status-list-base-url <url>`.

### `helix issuer init`

Verify an issuer wallet loads correctly.

```bash
helix issuer init --wallet ./issuer.enc
```

### `helix status-list create`

Create a signed BitstringStatusList credential file.

```bash
helix status-list create \
  --length 131072 \
  --output ./public/status/1.json \
  --base-url https://example.com/status/1 \
  --wallet ./issuer.enc
```

### `helix vc issue`

Issue a `HelixAgentCredential` and update the status list file.

```bash
helix vc issue \
  --agent-did did:key:z6Mk... \
  --scopes read:orders,write:bookings \
  --expires 90d \
  --status-list ./public/status/1.json \
  --base-url https://example.com/status/1 \
  --wallet ./issuer.enc \
  --output ./vc-agent-001.json
```

Send the output VC file to the agent out of band. The agent stores it with `wallet.addCredential(vc)`.

### `helix revoke`

Revoke a credential by flipping its status list bit.

```bash
helix revoke \
  --vc-id urn:uuid:abc-123 \
  --status-list ./public/status/1.json \
  --wallet ./issuer.enc
```

### `helix wallet inspect`

Inspect wallet metadata without printing the private key.

```bash
helix wallet inspect --wallet ./agent.enc
```

### `helix init` (self-custody onboarding)

Onboards an agent whose key stays with you (KYA-OS story F-3). Take the
enrollment token the console gives you for a self-custody agent:

```bash
helix init --token enroll:... --out ./agent --api-url https://api.example
```

The key is generated on this host. Only its public JWK and a proof of
possession are sent. `./agent` gets `did.json`, `card.json`,
`signing-key.env` (the private key, mode 0600) and `helix-agent.json`. With
Helix hosting the agent is active at once. With your own domain, publish
`did.json` and `card.json` where the output says, then:

```bash
helix activate --token enroll:... --out ./agent
```

Helix reads the documents from your domain and activates the agent only if
they list the key you registered. For a loopback test domain, set
`HELIX_OUTBOUND_DEVELOPMENT=1`.

### `helix custody take`

Moves a custodial agent, service or owner to self-custody. This is a key
rotation: the new key is generated here, both keys stay in the DID document
during the overlap, and the key Helix held is shredded.

```bash
helix custody take --did did:web:... --out ./agent --admin-key ...
```

Custodial subjects are labelled `custody: helix` and are not counted in
KYA-OS conformance claims. Their proofs still verify.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `HELIX_WALLET_PASSPHRASE` | Always | Wallet encryption passphrase |
