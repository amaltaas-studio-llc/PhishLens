# Local AI

What the language model is asked, what it may change, and how to turn it on. Caps and history:
[adr/0006](adr/0006-llm-cannot-outvote-checks.md),
[adr/0009](adr/0009-model-server-and-inert-cloud.md).

AI is **off** until chosen (welcome page or Settings). Default install makes no model calls.

## One interface

`ChromePromptAnalyzer` (Chrome’s built-in model), `ModelServerAnalyzer` (a server you run), and an inert
`CloudAnalyzer` share:

```ts
interface SemanticAnalyzer {
  isAvailable(): Promise<boolean>;
  analyze(email: EmailMessage, options?: { signal?: AbortSignal }): Promise<SemanticAnalysis | null>;
}
```

The model returns structured JSON only: `risk` (0–100), `categories`, up to three short `reasons`, and
`confidence`. The card names the source; scoring and UI otherwise treat all analyzers the same.

## Three guarantees

Asserted in `test/semantic.test.ts`:

1. **Cap.** The `llm` category is at most 15 of 100 points, additive. It cannot remove a finding, lower a
   score past a deterministic floor, or change a classification alone.
2. **No origination.** Without a corroborating deterministic signal, the model contributes **zero**.
3. **Separate UI.** Model output is labelled as an assessment, not a technical observation.

## What the model sees

Display name, subject, and body (body capped). **No** sending domain, Reply-To, link destinations, or
attachment types — those are checked in `analysis/rules/` from the real values. The prompt asks for the
requested action before tone; concerning reasons should quote a short excerpt from the mail (any language)
and explain in English.

Calibration also applies a dead zone (low risk scores zero) and drops routine categories from the headline
when they add nothing. Details of thresholds live next to scoring config; see
[DETECTION.md](DETECTION.md).

## Chrome’s on-device model

Implemented in `src/analysis/llm/chrome-prompt.ts` / `on-device.ts`. The Prompt API surface has moved
between builds; the code probes shapes and fails closed to “unavailable.”

- Turn on **On-device AI** in `chrome://settings/system`. Chrome may download several GB on eligible devices
  ([Google’s help](https://support.google.com/chrome/answer/16961953)).
- Opening mail never starts a download. The welcome page can, **on a click**, after you choose the local model.
- `downloadable` / `downloading` count as unavailable for analysis until ready.

### When there is no assessment

| Status | Meaning |
| --- | --- |
| `ready` | Assessment produced |
| `pending` | Inference in flight |
| `skipped` | Not asked (nothing could corroborate); card can ask anyway |
| `off` | User disabled AI |
| `unavailable` | No model / not configured |
| `no-output` | Ran but failed schema validation |
| `error` | Timeout or session failure |
| `cancelled` | Reader moved on |

By default the model is asked only when a technical check already found something. Readings are reused
while the prompt would be unchanged; cancelled or failed attempts are not cached as answers.

## Operational rules

- `temperature: 0`, `topK: 1` where supported; JSON schema constraint with unconstrained retry.
- Declare English **output**; where accepted, input languages `en`, `de`, `es`, `fr`, `ja`. Availability
  probes stay output-only.
- Malformed JSON → discard entirely (no partial salvage).
- 20 s inference timeout; one prompt at a time (queued); cancel via `AbortSignal`.
- Session lives in the **content script**; each message uses a clone (or a fresh session) so prior mail
  cannot steer later verdicts.
- Warm-up at startup never downloads a model.

## Your own model server

Settings → AI mode **Model server**. OpenAI-compatible `POST …/chat/completions`. Same 15-point cap and
corroboration rules — a larger model buys better reasons, not more weight.

- Base URL from settings; `http:` only for loopback; otherwise `https:`.
- Optional host permission requested per origin on a click from the options page.
- Endpoint never arrives in a runtime message ([adr/0009](adr/0009-model-server-and-inert-cloud.md)).

## Cloud

Designed and left inert. No default backend; not offered in options unless already stored. Do not
implement as a side effect of other work.

## Trying prompts on a real model

Unit tests use fakes. For a real comparison, `npm run eval:prompts` exports paired requests; it contacts
nothing by itself. Synthetic cases live in `test/fixtures/semantic/cases.json`. Do not claim accuracy gains
from unit tests alone.
