---
"@helixid/sdk-js": minor
---

`HelixClient`'s constructor now also accepts a single `HelixClientOptions` object with no leading URL argument (`new HelixClient({ apiKey })`), in addition to the existing `(apiUrl?)` and `(baseUrl?, options?)` forms.
