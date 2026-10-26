# `@helixid/widget`

Consent-screen building blocks for a Service Provider issuing
`DelegationGrantCredential`s: an SP-side scope resolver and a headless
consent-selection controller.

Two entry points, deliberately separated:

| Import | Runs | Contains |
|---|---|---|
| `@helixid/widget/server` | SP backend only | `resolveConsentScopes()` — reads the agent's scopes from the HelixID API with the SP's credentials |
| `@helixid/widget` | Browser-safe | types, `DEFAULT_DURABILITY_OPTIONS`, `createConsentController()` |

The server module must never be bundled into the browser: it runs with the
SP's API credentials.

**Visual rendering is not shipped here.** This package provides the types and
the selection logic; drawing the consent screen is normal frontend work owned
by the SP.

---

## Part A — `resolveConsentScopes()`

```ts
import { HelixClient } from '@helixid/sdk-js';
import { resolveConsentScopes } from '@helixid/widget/server';

const scopeOptions = await resolveConsentScopes({
  serviceDid,
  agentDid,
  serviceScopes: [
    { scope: 'book:flights', label: 'Book flights', description: 'Buy tickets on your behalf' },
    { scope: 'modify:booking', label: 'Modify bookings' },
  ],
  client: new HelixClient({ apiUrl, apiKey }), // anything with getAgentScopes()
});
```

Output is **the service's scopes that the agent holds as itself, plus
`accept-terms`**.

1. Read the agent's own scopes with `client.getAgentScopes({ serviceDid,
   agentDid })`: the union of its active onboarding credentials. Credentials
   delegated to the agent do not count: consent given to this agent directly
   must not rest on authority another agent can withdraw.
2. Keep each `serviceScopes` entry the agent holds, in the service's order.
3. Always append `accept-terms` with `required: true` — T&C acceptance folds
   into grant scopes rather than living in a separate field.
4. A scope with an empty label falls back to `humanizeScope()`
   (`book:flights` → `book flights`). No scope is ever rendered without one.

`serviceScopes` is SP-owned: a curated list, the SP's MCP server's tool
metadata, or anything else. HelixID provides the mechanism, not the scope
strings.

Grant issuance (`POST /v1/service-delegation-grants`) refuses a scope outside
the agent's own scopes (`CONSENT_GRANT_SCOPE_NOT_ALLOWED`) and a grant of
nothing but `accept-terms` (`CONSENT_NO_GRANTABLE_SCOPES`), so the menu this
returns is exactly what issuance will accept.

### Errors — the consent screen fails closed

| Error | `code` | Means |
|---|---|---|
| `ConsentNoGrantableScopesError` | `CONSENT_NO_GRANTABLE_SCOPES` | The agent holds none of the service's scopes: a consent here would grant nothing. |
| `AgentScopesLookupError` | `AGENT_SCOPES_LOOKUP_FAILED` | The agent's scopes could not be read (unknown agent, no active credential, API unreachable). `cause` holds the underlying error. |

Neither falls back to the service's full catalog, which would offer scopes
issuance then refuses. The SP's route turns either into a non-200, and the
controller shows its error state.

---

## Part B — the SP's scope-resolution route (contract, not shipped code)

HelixID does not ship this route. The SP's routing framework and auth
middleware are SP-owned. The route must satisfy:

| | |
|---|---|
| Method | `GET` — pure resolution, no state mutation |
| Path | SP's choice; passed to the widget as `scopesEndpoint` |
| Query params | `agentDid` |
| Auth | Same authenticated session context as the consent page. No separate token scheme; reuse the session middleware already protecting that page. |
| Response | `{ "scopeOptions": ScopeOption[] }`, or a non-200 when resolution throws |

Reference implementation:

```ts
// GET /api/consent/scopes?agentDid=<did>
export async function GET(request: Request) {
  const agentDid = new URL(request.url).searchParams.get('agentDid') ?? '';
  try {
    const scopeOptions = await resolveConsentScopes({
      serviceDid: SP_DID,
      agentDid,
      serviceScopes: SP_SCOPE_CATALOG,
      client: helixClient,
    });
    return Response.json({ scopeOptions });
  } catch (error) {
    const code = (error as { code?: string }).code ?? 'SCOPE_RESOLUTION_FAILED';
    const status = code === 'CONSENT_NO_GRANTABLE_SCOPES' ? 422 : 502;
    return Response.json({ error: { code, message: (error as Error).message } }, { status });
  }
}
```

---

## Part C — the consent controller

```ts
import { createConsentController, DEFAULT_DURABILITY_OPTIONS } from '@helixid/widget';

const controller = createConsentController({
  agentDid, agentName, userIdentifier, serviceDid,
  scopesEndpoint: '/api/consent/scopes',   // or pre-resolved scopeOptions
  defaultDurability: 'standing',
  offerDelegationChoice: true,             // optional; see below
  onAccept: async ({ scopes, durability, allowDelegation }) => { /* POST to your grant route */ },
  onDecline: () => { /* close the dialog */ },
});

await controller.load();                      // mount
controller.subscribe((state) => render(state));
```

Behavior:

- Provide **one** of `scopeOptions` (pre-resolved, SSR path) or
  `scopesEndpoint` (fetched at mount). If both are given, `scopeOptions` wins
  and no fetch occurs. If neither is given, the factory throws — that is a
  caller integration error, not a state to render around.
- `userIdentifier` must be the same form (DID or email) the grant captures at
  consent time, or VP verification's user-match fails later.
- Durability is an explicit control: `defaultDurability` pre-selects one
  option, it never hides the other. `state.durabilityOptions` always holds the
  full list.
- `required: true` scopes (i.e. `accept-terms`) cannot be unchecked and appear
  in every `onAccept` payload. Decline is the way not to proceed.
- Optional scopes start checked unless the resolver sets
  `defaultChecked: false`, so `onAccept` carries every required scope plus
  whichever optional ones were left checked.
- `offerDelegationChoice: true` adds a choice, "also allow agents this agent
  delegates to". It starts unchecked and is set with
  `controller.setAllowDelegation()`; `state.delegationChoiceOffered` says
  whether to render it. The selection then carries `allowDelegation`, true or
  false. Not offered (the default), the selection carries no
  `allowDelegation`, the grant is issued without the flag, and verifiers treat
  it as allowed.

### Fetch failure

If the `scopesEndpoint` request fails — non-200, malformed JSON, or network
failure — the controller enters `status: 'error'` with `canAccept: false`.
Accept is disabled; **Decline stays available**. There is no retry.

---

## Downstream

`onAccept`'s handler is the SP's own route: it calls
`HelixClient.issueServiceDelegationGrant()` with `selection.scopes`,
`selection.durability` and, when present, `selection.allowDelegation`, and
returns the grant to the caller. HelixID holds
the service's key and signs on its behalf, so neither the browser nor the SP
process ever sees a private key.
