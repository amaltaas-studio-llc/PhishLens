# The semantic layer

What the language model is asked, what it is allowed to change, and why it is on such a short leash.
Design reasoning is in [ARCHITECTURE.md §2.2 and §4.3](ARCHITECTURE.md).

## One interface, three implementations

```ts
interface SemanticAnalyzer {
  isAvailable(): Promise<boolean>;
  analyze(email: EmailMessage, options?: { signal?: AbortSignal }): Promise<SemanticAnalysis | null>;
}
```

`ChromePromptAnalyzer` (Chrome's built-in model, shipped), `ModelServerAnalyzer` (a model server the user
runs, shipped) and `CloudAnalyzer` (designed, inert) implement the same interface, so the analysis,
scoring, and UI layers cannot tell which one produced a verdict — or whether one ran at all. The card
names the source, which is the only place the difference is visible.

The model returns structured data, never prose:

```ts
interface SemanticAnalysis {
  risk: number;                  // 0-100, advisory
  categories: SemanticCategory[]; // from a fixed enum
  reasons: string[];             // short justifications, rendered as text
  confidence: number;            // 0-1
}
```

## Three containment guarantees

These are arithmetic, not convention, and each is covered in `test/semantic.test.ts`.

1. **The cap.** The `llm` category is worth 15 of 100 points and contributes additively. A model that has
   been successfully prompt-injected into declaring a phishing email safe changes the score by at most 15
   points downward from where it would otherwise be. It cannot remove a deterministic finding, cannot
   lower the score past a deterministic floor, and cannot change the classification of a message that
   failed a technical check.
2. **No origination.** A verdict that no deterministic signal corroborates scores **zero**
   (`uncorroboratedFactor: 0`). The model may sharpen a score; it may not invent one. Dampened signals do
   not count as corroboration, so a finding deliberately softened elsewhere cannot license points here.
3. **Separation in the UI.** Model output is rendered in its own section, labelled as an assessment rather
   than an observation, with the model's own reasons shown. A reader can always tell which half of the
   card is checkable.

Suppressing an uncorroborated score costs no detection capability, which is what makes it the right call
rather than merely a cautious one: 15 points is already below the `caution` threshold of 25, so an
uncorroborated verdict could never change the classification even at full weight. All that scoring it
achieved was moving the number off zero on clean mail, which destroys the difference between "we found
nothing" and "we found something small".

## Calibration

On-device models are accurate on genuine fraud and markedly over-suspicious on legitimate mail. Gemini
Nano will rate an ordinary product announcement 95/100 at 98% confidence and give "Suspicious Sender
Email" and "Link to Unknown Domain" as its reasons — both claims about domains, which is not something it
can check and not something it was asked about. Told in the prompt not to reason about domains and shown
them regardless, it did so anyway: a genuine bank notification scored 85/100 on the reasoning that one of
its links was not specific enough to the bank's own site.

Four responses, in the order they apply:

- **The model is not given the subject matter it must not judge.** It receives the sender's display name,
  the subject and the body — nothing else. No sending domain, no Reply-To, no link destinations, no
  attachment types. An instruction it cannot follow is worth less than data it cannot see, and everything
  withheld is checked properly, from the real values, in `analysis/rules/`.
- **A dead zone.** Any verdict below `minRiskForScoring` (45/100) scores zero regardless of confidence.
  Below `routineRiskCeiling` (20/100) the finding is also *worded* as clean, because models fill the
  category slot as a matter of form: one rated an auto-reply 10/100, explained itself with "standard
  auto-reply", and tagged it `social_engineering` anyway.
- **Corroboration.** Guarantee 2 above.
- **Action-first guidance.** The prompt distinguishes reporting an event that already happened from
  asking the reader to disclose, transfer, approve, or bypass a safeguard. A routine notification can
  contain a harmful follow-up, and a familiar banking app can be used to make a fraudulent transfer.
  Neither reassuring wording nor the absence of urgency clears the request. Short contrasting examples
  cover code delivery, payment changes, banking apps, and quoted versus active prompt injection.

Concerning reasons must quote a short excerpt from the supplied message and explain its significance.
This is a prompting instruction, not an enforced guarantee that the model's quotation is accurate. The
excerpt is never a URL, an address, or a filename, since those are checked from the real values elsewhere
and quoting one would reintroduce the guessing that withholding them prevents. A concern no sentence can
be quoted for is rated in the routine band, which is the prompt's closing instruction and its default.
The response schema and score containment are unchanged. When the body exceeds 4,000 characters, a
coverage notice outside the untrusted-content block tells the model it has only an opening excerpt.
Missing context should not be invented; a visible harmful request can still support a high rating.

The verdict is displayed in full either way. It just does not always move the number.

### Comparing prompts on a real model

Unit tests exercise construction, parsing, and scoring with simulated model responses. Passing them
does **not** demonstrate an improvement in language-model accuracy. The synthetic cases in
`test/fixtures/semantic/cases.json` are a small smoke evaluation, with wording separate from the examples
in the prompt. They cover routine mail, quiet scams, ambiguous requests, and injection discussion.
They are not a representative production benchmark or permanently held-out test set once used for tuning.

Export paired requests from the working tree and an earlier Git revision:

```bash
npm run eval:prompts -- harness/.build/semantic-eval <baseline-commit>
```

The default baseline is `HEAD`, useful before committing a prompt change. The command writes
`baseline.jsonl`, `candidate.jsonl`, a separate `review.json` rubric, and metadata. It uses each revision's
prompt builder, makes no network requests, and sends no email. Do not send the review rubric to the model.

Run both request sets against the same model version, generation settings, and structured-output mode,
using a fresh conversation per request. For Chrome's model, use the same system/user separation and
response constraint as the adapter. Repeat each case at least three times and save the raw responses
alongside the model and runtime versions. Review blind to the prompt version where possible:

- Count malformed responses separately from usable assessments; do not treat an error as a benign result.
- For routine cases, count false alarms (risk above 20 or a non-benign category).
- For concerning cases, count missed concerns (risk at or below 45, or no non-benign category).
- Review ambiguous cases for qualified explanations and appropriately reduced confidence, not an exact score.
- Check quotations against the input and count invented evidence, technical speculation, and unsupported
  accusations separately. Quoting a real sentence does not by itself make the explanation correct.
- Record latency and response validity as well as false alarms and missed concerns. Keep the existing
  15-point cap and corroboration checks unchanged regardless of model performance.

These evaluation bands describe the prompt's intended outputs, not new runtime scoring constants.
Do not claim an accuracy gain until the paired results support it on the intended model and a broader,
independently labelled corpus. No real-model comparison is part of `npm run verify`.

## Chrome's Prompt API

`src/analysis/llm/chrome-prompt.ts` targets Chrome's built-in Prompt API. **That API is unstable, and
the code treats it as such.** Across versions the entry point has been `window.ai.languageModel`,
`chrome.aiOriginTrial.languageModel`, and the current bare `LanguageModel` global; availability has been
reported as `capabilities().available` (`'no'` / `'after-download'` / `'readily'`) and as `availability()`
(`'unavailable'` / `'downloadable'` / `'downloading'` / `'available'`); and it is commonly gated behind a
flag, hardware requirements, or an origin trial.

One consequence is worth stating plainly, because it is a trap: the current entry point is a **class**, so
`typeof LanguageModel === 'function'`. A probe that checks `typeof === 'object'` before reading properties
— the natural way to write a defensive one — rejects the live API on every browser that has it, fails
closed, and reports "no on-device model" with complete conviction. The fakes in
`test/chrome-prompt.test.ts` are therefore function-typed with static methods, mirroring the browser's
shape rather than merely its interface, because object-literal fakes cannot distinguish a working adapter
from a broken one.

### Trying it with a real model

Development targeted the Chrome 138+ `LanguageModel` global as the primary path, with Chrome ≥ 120 as the
manifest minimum. To exercise a real model rather than the fakes you need a build where Gemini Nano is
available, which currently means enabling `chrome://flags/#prompt-api-for-gemini-nano` and
`chrome://flags/#optimization-guide-on-device-model` and waiting for the download. Expect this to drift;
the detection code is written so that drift degrades to "unavailable" rather than to a crash.

A `downloadable` or `downloading` model is deliberately treated as **unavailable**. Opening an email
should not start a multi-hundred-megabyte download.

## When there is no model

The common case, and it is a supported one rather than a degraded one. `isAvailable()` fails closed: a
missing global, an unexpected shape, or a thrown error resolves to `false` and never propagates. The
pipeline produces a complete, correctly classified result with the `llm` category contributing exactly
zero, and the card *says* the model did not run — silence would let a reader assume the AI approved the
message.

### Seven statuses, because "no assessment" has several causes

`meta.semanticStatus` distinguishes them, and the card words each differently:

| Status | Meaning |
| --- | --- |
| `ready` | An assessment was produced. |
| `pending` | Inference is in flight; the score on screen may still change. |
| `off` | The user switched AI analysis off. |
| `unavailable` | No model in this browser, or no server/backend configured — nothing was sent. |
| `no-output` | The model ran and returned nothing that passed schema validation. |
| `error` | The model is present but this attempt failed — a timeout, or a rejected session. |
| `cancelled` | The attempt was abandoned because the reader moved on. |

The distinction between `pending` and `unavailable` is the one users notice. Inference takes a few
seconds, during which the deterministic score is already complete and on screen. Showing "unavailable in
this browser" and then replacing it with a verdict seconds later would teach a reader to disbelieve that
message in the case where it is true, so the card shows a progress indicator for that window instead.

**An interrupted assessment is retried, not remembered.** Only `ready` and `off` may be cached
(`isSemanticSettled`), because a cache hit short-circuits before the model is ever asked — so caching a
non-answer would make it permanent for the life of the tab. A cancelled attempt, a one-off timeout, and a
message read while Chrome was still downloading the model are all re-assessed on the next visit.

## Operational rules

- Deterministic settings are requested where supported (`temperature: 0`, `topK: 1`), and a JSON schema
  constraint where supported, with an unconstrained retry where it is not.
- Output must be JSON matching the schema. Validation is all-or-nothing: a malformed response yields
  `null`, never a partially salvaged object, because a model that returned a malformed object is a model
  whose values are not trustworthy either — and a hostile email may well be the reason it is malformed.
- One inference has a 20-second timeout, after which the session is discarded and rebuilt.
- **One prompt at a time.** A session rejects a second `prompt()` while the first is outstanding, and this
  adapter treats a rejected inference as a poisoned session, so two overlapping calls do not degrade to
  one winning — they both fail. This is reachable in normal use, because Gmail renders a thread in stages
  and the first message opened after a page load is reported two or three times. Model work is serialised
  through a queue and superseded messages are cancelled via `AbortSignal`.
- If the API only accepts a bare `create({})` with no system prompt, the system prompt is prepended to the
  user prompt instead, so no session is ever uncalibrated or uncontained.
- The session is built at startup (`warmUp()`) rather than on first use, so its several seconds are spent
  while the reader is still looking at their inbox. Warming never downloads a model.
- The session is cached in the **content script**, never the service worker, which MV3 may terminate at
  any moment.
- **One conversation per message.** A Prompt API session is a conversation: every prompt and every reply
  stays in its context. The cached session is therefore a template, kept pristine and never prompted, and
  each message is analysed in a `clone()` of it that is destroyed afterwards. Reusing one session would
  fill its context with mail the reader has finished with until an inference failed for length, anchor each
  verdict on its predecessor so the same message scored differently depending on what was read before it,
  and let the wording of one message reach the judgement of every message after it — a steering channel
  available to any sender. On a build with no `clone`, each message gets a whole new session and its
  replacement is built behind the queue; that is slower, and the alternative is a contaminated judgement.

## Your own model server

Chrome's built-in model is small, and its over-suspicion on ordinary mail is a consequence of that. A 7B
or larger instruction-tuned model, which most machines can now run, is markedly better at the one question
this layer asks. `aiMode: 'server'` uses one you run yourself.

**It buys better reasons, not more weight.** Every guarantee above still holds unchanged: 15 points, no
origination, the same dead zone, the same separation in the UI. A 70B model on your own GPU is bound
exactly as Gemini Nano is, and `test/semantic.test.ts` asserts it for that source specifically. If a
larger model could outvote the deterministic checks, then the checks would be the thing worth fixing.

### One request shape for every runner

They all speak OpenAI's `/chat/completions`, so there is one adapter rather than one per runner. Paste the
base URL exactly as your runner documents it; `/chat/completions` is appended.

| Runner | Base URL | Notes |
| --- | --- | --- |
| Ollama | `http://localhost:11434/v1` | Needs `OLLAMA_ORIGINS` — see below |
| LM Studio | `http://localhost:1234/v1` | Start the server from the Developer tab |
| Docker Model Runner | `http://localhost:12434/engines/v1` | Requires host-side TCP to be enabled |
| llama.cpp / vLLM / LocalAI | as configured | Anything OpenAI-compatible works |

**Ollama refuses browser-origin requests by default,** and this is the first thing that goes wrong for
everybody. It looks like this, and nothing about the address, the port or the permission grant is wrong:

```text
[PhishLens] model server refused the request (403): it is not configured to
accept requests from browser extensions.
```

Chrome attaches `Origin: chrome-extension://<id>` to every request the service worker makes and the header
cannot be suppressed, so the server has to be told to expect it. Set `OLLAMA_ORIGINS` before starting it:

```bash
# macOS / Linux
OLLAMA_ORIGINS='chrome-extension://*' ollama serve
```

```powershell
# Windows: set it for the user, then restart Ollama from the tray
setx OLLAMA_ORIGINS "chrome-extension://*"
```

LM Studio has an equivalent CORS toggle in its server settings. Naming your own extension id rather than
`chrome-extension://*` is stricter and worth doing if you keep the setting permanently.

**A reasoning model needs room to think.** Qwen3-class models and their relatives produce several hundred
tokens of reasoning before the answer, runners count those against the reply's token budget, and the result
is an assessment cut off mid-sentence and discarded — visible only as "did not return a usable assessment".
So the request asks for `reasoning_effort: none`, which Ollama honours, *and* allows enough tokens for a
model that thinks anyway, since not every runner supports the field. If you see nothing usable from a model
you know is running, a dev build's console names the shape of the reply, including whether it was truncated.

Structured output is requested as `json_schema` first, then `json_object`, then not at all, because
coverage differs by runner and version and a server that does not recognise a `response_format` rejects
the request rather than ignoring the field. Each retry is a rejected request rather than a wasted
generation, so this costs a round trip on old servers and nothing on current ones.

### What is sent, and what that costs

The prompt is **byte-for-byte the on-device prompt**: display name, subject, body excerpt. Not the link
targets, not the sending domain, not the attachment types, not the recipient address — the same
withholding described under Calibration, for the same reason. There is no `Authorization` header and no
field for a key, so this cannot be pointed at a hosted vendor and used as a key-bearing client.

Plain `http://` is accepted **only for `localhost`, `127.0.0.1` and `[::1]`**, where there is no wire to
intercept. Any other host must be `https://`: the request carries the text of the message you are reading,
and sending that in the clear across a LAN would be a worse leak than most things this extension warns
about. `test/privacy.test.ts` pins both halves of that rule, including that `http://localhost.evil.example`
is not loopback.

Access to the server is an **optional host permission**, requested for that one origin when you press
Connect, and handed back when you change the address. A default install still asks for `storage` and
`https://mail.google.com/*` and nothing else — a blanket `http://*/*` in `host_permissions` would make
every user pay a permission for a feature most will not enable.

The plaintext half of that permission is spelled out as `localhost` and `127.0.0.1` rather than as a
wildcard, which has one visible consequence: **use `127.0.0.1` rather than `[::1]`**. Chrome's match
patterns cannot express an IPv6 literal, so the address field will accept `http://[::1]:11434` and Connect
will then be unable to ask for it. Both reach the same process.

The timeout is 45 seconds, against 20 for the on-device model, because the work is happening on your
hardware and a 7B model on a CPU can take most of a minute on a long message. The card shows `pending`
throughout and the deterministic score is already on screen, so the wait costs latency on the AI section
rather than on the verdict.

## The cloud design, which is not built

Designed deliberately and left inert, and **not offered in the settings page** — the option appears only
for someone whose stored setting is already `cloud`, because a mode that returns no assessment on every
message reads as a broken AI section rather than an unfinished feature. The seam still exists —
`CloudAnalyzer` implements the same interface — so enabling it changes no analysis, scoring, or UI code.

```text
extension (content script)
  → chrome.runtime.sendMessage           # the only sender
  → service worker                       # the only egress point
  → POST https://<your-backend>/api/analyze
      { subject, bodyExcerpt, senderDomain, senderNameShape,
        replyToDomain?, linkDomains[], attachmentExtensions[], deterministicSignalIds[] }
  ← { risk, categories[], reasons[], confidence }
      → parseSemanticAnalysis()          # strict validation, all-or-nothing
      → semanticToSignals()              # capped at the llm weight, additive only
```

The properties this shape is chosen for:

- **No vendor credential in the extension, ever.** An API key shipped in an extension is a published API
  key. The backend holds it.
- **One egress point.** Only the service worker makes network requests, so there is exactly one function
  to audit. Its `fetch` uses `credentials: 'omit'` and `redirect: 'error'`, so it cannot follow a redirect
  to another origin or attach ambient cookies.
- **One redaction function, applied where the socket is.** `buildCloudPayload`
  (`src/analysis/llm/redact.ts`) decides what leaves, and `test/privacy.test.ts` asserts field by field
  what it keeps *and* what must not be present, so a field added carelessly later fails the suite. The
  builder runs in the content script, though, and the worker is handed its output over a runtime message —
  so the worker re-imposes the same contract with `sanitizeCloudPayload` before sending. Without that, the
  guarantee would hold only for callers that chose to honour it, which is not what a guarantee is.
- **Deterministic findings travel as ids**, not re-derived, so the backend never needs the data required
  to recompute them. This is also why the payload may carry `linkDomains` when the local prompt withholds
  them: they arrive next to the verdicts already reached about them, as context for a judgement rather
  than as material for a guess. A backend that instead asked its model "does this domain look right"
  would be reintroducing precisely the false alarm withholding them was meant to end.
- **HTTPS-only, validated.** `normalizeBackendUrl` accepts only an `https:` origin plus optional path
  prefix, so editing storage cannot point the adapter at `http://`, at a `javascript:` URL, or straight at
  a model vendor.
- **Opt in twice.** Cloud mode requires both an explicit mode choice and a URL, and neither has a default.
- **No fallback from local to cloud.** If the on-device model is missing, PhishLens does not quietly send
  mail to a server instead.
