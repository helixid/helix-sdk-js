# Contributing to the HelixID JavaScript SDK

This repository is the JavaScript/TypeScript SDK workspace: the SDK itself,
the CLI, the LangChain and MCP middleware, the Hedera DID method, and the
browser consent widget.

This is the code that runs inside other people's agents and services — it
holds wallets and builds presentations — so correctness and clear public
APIs matter more than internal convenience.

> **New to HelixID?** Read
> [docs.helixid.dev](https://docs.helixid.dev) first — it covers the concepts
> (DIDs, verifiable credentials, the two-issuer model, delegation, revocation)
> that the rest of this document assumes. This file is the authoritative
> process for *this* repository; the docs site is the orientation.

---

## Open-Source Scope

This repository is Apache-2.0 and public. It is a pnpm + Turborepo workspace of
several independently-scoped packages.

Note that these packages are **consumed as git dependencies**, not from npm — see
[Release Process](#release-process). A change to a public API therefore reaches
consumers as soon as it lands on `main`, so treat `main` as released.

---

## Ways to Contribute

1. **Framework middleware** — integrations for additional agent frameworks.
   Follow the pattern in `langchain/` and `mcp-middleware/`.
2. **DID methods** — additional resolvers, following `did-hedera/`.
3. **Widget** — accessibility, and making sure the consent UI renders scopes
   truthfully. A widget that misstates what is being approved is a security bug,
   not a cosmetic one.
4. **Bug reports** with a minimal reproduction.

---

## Before You Start

**Open a Discussion or Issue first** for any non-trivial change. Trivial means: typos, obviously incorrect code, a missing test for existing behavior, a small doc improvement. Anything else — new features, new dependencies, API changes, performance optimizations that change behavior, new packages — needs a design sketch and sign-off from a maintainer before a PR lands.

This saves time on both sides. A rejected PR after two weeks of work is a worse outcome than a fifteen-minute design conversation.

---

## Development Setup

### Prerequisites

- Node.js `^20.19.0 || >=22.12.0` — note 20.0–20.18 will **not** work
- pnpm ≥ 9 (`corepack enable` — the repo pins `pnpm@9.15.2` via `packageManager`)
- Git

### Clone and Bootstrap

```bash
git clone https://github.com/helixid/helix-sdk-js.git
cd helix-sdk-js
pnpm install
pnpm build          # turbo run build, across every package
```

This is a **pnpm** workspace, not npm. Internal dependencies are linked with
`workspace:*`, which is what makes phantom dependencies impossible — `npm install`
here will produce a broken tree.

### Run Tests

```bash
pnpm test           # turbo run test across the workspace
pnpm test:non-live  # excludes anything needing live infrastructure
pnpm test:unit      # per-package unit suites
pnpm lint
pnpm typecheck
```

Turbo caches by package, so a second run only rebuilds what changed. To work on
one package, filter it: `pnpm --filter @helixid/widget test`.

---

## Repository Structure

A pnpm + Turborepo workspace. Each directory is its own package:

```
helix-sdk-js/
├── helix-sdk-js/     # @helixid/sdk-js — the SDK itself
├── cli/              # @helixid/cli
├── did-hedera/       # @helixid/did-hedera — Hedera DID method
├── langchain/        # @helixid/langchain — LangChain/LangGraph adapter
├── mcp-middleware/   # @helixid/mcp-middleware — MCP verification middleware
├── mcp-server/       # @helixid/mcp-server
├── widget/           # @helixid/widget — browser consent widget
└── fixtures/         # shared test fixtures
```

`helix-sdk-js/` and `widget/` are the highest-stakes: the first is the public API
every consumer builds against, the second renders what a user is consenting to.

The rest of the system lives in separate repositories — see
[Project Structure](https://docs.helixid.dev/get-started/project-structure).

---

## Branching and Commits

### Branch Names

```
<type>/<short-kebab-description>

feat/did-web-resolver
fix/statuslist-cache-invalidation
docs/delegation-tutorial
```

### Conventional Commits (required)

We use [Conventional Commits](https://www.conventionalcommits.org/). The release tooling parses commit messages to generate changelogs and bump versions.

```
<type>(<scope>): <summary>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`.

Scope is the package or area: `core`, `api`, `sdk-js`, `mcp`, `langchain`, `cli`, `docs`.

Examples:

```
feat(sdk): add did:web resolver with HTTPS pinning

fix(api): invalidate status-list cache after credential revocation

perf(sdk): avoid re-parsing JWS on repeated verification

BREAKING CHANGE: verifyPresentation now returns DelegationChain,
not string[]. Migration: use result.delegationChain.dids.
```

**Breaking changes** must include a `BREAKING CHANGE:` footer and a migration note in the PR description.

### Sign Your Commits (DCO)

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). We deliberately use DCO instead of a CLA — it's a lightweight attestation with no corporate-legal review tax. By signing off, you affirm that you have the right to submit the work under Apache 2.0.

```bash
git commit -s -m "feat(sdk): add did:web resolver"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>` line. Our CI rejects PRs missing DCO on any commit. If you forget, rebase with `git rebase --signoff`.

---

## Pull Requests

### Before Opening a PR

- [ ] Rebase on the latest `main`
- [ ] Run `pnpm lint && pnpm test && pnpm build` locally and pass
- [ ] Add or update tests — no untested code merges
- [ ] Update docs if you changed public API
- [ ] Add a changeset (`pnpm changeset`) if your change is user-visible
- [ ] Every commit is DCO-signed

### PR Description

Use this template — it mirrors what reviewers and release notes need:

```markdown
## What
<short summary of the change>

## Why
<motivation, linked issue, relevant context>

## How
<implementation approach, trade-offs considered, alternatives rejected>

## Testing
<how you verified this works — unit, integration, manual scenarios>

## Risk & Rollback
<what could break, how to revert if this ships bad>

## Breaking Changes
<none | description + migration path>

Closes #<issue>
```

### Review Expectations

- Two maintainer approvals required for changes in `helix-core` or `helix-sdk-js`
- One maintainer approval for everything else
- Reviewers respond within 3 business days — if silent longer, ping in Discussions
- We squash-merge by default; commit history on `main` is one commit per PR

### Merging

Only maintainers merge. Do not merge your own PR even if you have permissions.

---

## Coding Standards

### TypeScript

- `strict` mode. No `any` in exported signatures; justify it in a comment anywhere else.
- Every package's public surface is its `exports` map. Adding an entry point is an
  API change and belongs in the PR description.
- Prefer explicit return types on exported functions.

### Tooling

- ESLint + Prettier are enforced in CI. Run `pnpm format` before pushing.

### Cryptography and Security-Sensitive Code

- Never hand-roll primitives. Use the vetted libraries already in the dependency tree.
- Wallet code must never log, serialize, or include key material in an error path.
- Changes to verification or presentation-building require a second maintainer
  review and a threat-model note in the PR.
- Widget changes that affect how scopes are displayed need a screenshot in the PR.

### Testing

- Unit tests live beside the package they cover.
- A bug fix should come with the test that would have caught it.
- `pnpm test:non-live` must pass before you open a PR.

---

## Security Disclosure

**Do not open public issues for security vulnerabilities.** Use one of:

- Email `hello@dgverse.in`
- [GitHub Security Advisory](https://github.com/helixid/helix-sdk-js/security/advisories/new) (private)

We acknowledge within 48 hours, triage within 7 business days, and practice coordinated disclosure with a default 90-day embargo. Full scope, safe-harbor terms, and response policy: [`SECURITY.md`](SECURITY.md).

---

## Release Process

Every package in this workspace is published to npm as a **public package** and
is versioned with [changesets](https://github.com/changesets/changesets).

```bash
pnpm changeset          # describe your change; commit the generated file
pnpm changeset version  # maintainers: bump versions and write changelogs
pnpm release            # maintainers: publish
```

Publishing runs from `.github/workflows/release.yml`. Contributors only need the
first command.

Some consumers may still pin a package straight from this repository as a git
dependency (e.g. `"@helixid/sdk-js": "github:helixid/helix-sdk-js#path:helix-sdk-js"`)
instead of from npm — that keeps working, but new consumers should prefer the
published npm package.

---

## Community and Code of Conduct

- **Discussions:** [github.com/helixid/helixid/discussions](https://github.com/helixid/helixid/discussions) — design questions, use cases, show-and-tell
- **Issues:** [github.com/helixid/helixid/issues](https://github.com/helixid/helixid/issues) — bugs and concrete feature requests
- **Security:** `hello@dgverse.in`
- **General contact:** `hello@dgverse.in`

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Short version: be respectful, assume good faith, keep technical debate on technical merits, and escalate conduct concerns to `hello@dgverse.in`.

---

## Licensing of Contributions

Contributions are licensed under [Apache License 2.0](LICENSE), same as the project. DCO sign-off on each commit is the full legal attestation — no CLA, no separate agreement, no surprise relicensing. See the DCO section above.

---

## Quick Reference

| Task | Command |
|---|---|
| Install deps | `pnpm install` |
| Build all packages | `pnpm build` |
| Test | `pnpm test` |
| Test (fast loop) | `pnpm test:non-live` |
| One package | `pnpm --filter @helixid/<pkg> test` |
| Lint | `pnpm lint` |
| Typecheck | `pnpm typecheck` |
| Format | `pnpm format` |
| Add a changeset | `pnpm changeset` |
