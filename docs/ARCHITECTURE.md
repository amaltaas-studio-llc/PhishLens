# Architecture

PhishLens is a Chrome MV3 extension that scores the open Gmail message 0–100 for phishing risk and
explains every point. Deterministic checks own technical facts; an optional language model may add at
most 15 points and cannot originate a score.

This page is the map. Deep “why not the obvious alternative?” records live in [adr/](adr/). Agent
invariants live in [AGENTS.md](../AGENTS.md). Product detail:
[DETECTION.md](DETECTION.md), [LOCAL-AI.md](LOCAL-AI.md), [PRIVACY.md](PRIVACY.md),
[DEVELOPMENT.md](DEVELOPMENT.md).

## Where code runs

```text
Gmail tab (content script)          Service worker (stateless)
─────────────────────────          ──────────────────────────
DOM extract → analysis engine      settings read/write
badge + card (Shadow DOM)          optional model-server fetch
on-device LanguageModel session     install / welcome open
list-row triage (sender only)
```

| Area | Path | May use |
| --- | --- | --- |
| Pure engine | `src/analysis/` | No `chrome.*`, no `document`, no `fetch` |
| Shared helpers | `src/shared/` | Same purity as analysis when imported from it |
| Gmail DOM | `src/gmail/` | Selectors only in `selectors.ts` |
| UI | `src/ui/`, welcome, options, popup | `el({ text })` only — never `innerHTML` |
| Background | `src/background/` | Sole `fetch` site; URL from settings only |

The content script holds analysis state and the model session because MV3 workers die after idle
([adr/0002](adr/0002-mv3-state-in-content-script.md)).

## Pipeline

![Pipeline: extract, deterministic checks, optional model, aggregate score, badge and card](assets/pipeline.svg)

1. **Extract** the open message; if it is not scorable, show **Not checked** — never a Low Risk all-clear
   ([adr/0003](adr/0003-gmail-two-signals.md)).
2. **Deterministic rules** — identity, links, content (with language packs), attachments, authentication
   ([DETECTION.md](DETECTION.md)).
3. **Optional model** — Chrome on-device or a user-run server; capped and corroboration-gated
   ([LOCAL-AI.md](LOCAL-AI.md), [adr/0006](adr/0006-llm-cannot-outvote-checks.md)).
4. **Aggregate** — category weights sum to 100; severity floors catch single-dimension attacks
   ([adr/0004](adr/0004-scoring-floors-and-weights.md)). Numbers live in `src/analysis/scoring/config.ts`.

## Layout (contributor map)

| Want to change… | Start here |
| --- | --- |
| Scoring numbers | `src/analysis/scoring/config.ts` |
| Wording / social-engineering themes | `src/analysis/rules/content.ts`, `rules/languages/` |
| Links, identity, attachments, auth | `src/analysis/rules/*.ts` |
| Brand table / PSL / TLDs | `src/shared/brands.ts`, `public-suffix.ts`, `tlds.ts` |
| Gmail selectors | `src/gmail/selectors.ts` |
| Badge / card | `src/ui/` |
| On-device or server model | `src/analysis/llm/` |
| Permissions / egress | `src/background/`, `src/manifest.json` |
| Build / verify | `scripts/build.mjs`, [DEVELOPMENT.md](DEVELOPMENT.md) |

## Design decisions

| ADR | One line |
| --- | --- |
| [0001](adr/0001-esbuild-not-vite.md) | esbuild; zero runtime deps |
| [0002](adr/0002-mv3-state-in-content-script.md) | State and model session in the content script |
| [0003](adr/0003-gmail-two-signals.md) | Hash + DOM, cross-checked; gaps are Not checked |
| [0004](adr/0004-scoring-floors-and-weights.md) | Weights sum to 100; deterministic floors |
| [0005](adr/0005-false-positive-resistance.md) | Dampen content carefully; trust cannot silence identity |
| [0006](adr/0006-llm-cannot-outvote-checks.md) | Model ≤15 pts; cannot originate a score |
| [0007](adr/0007-list-row-sender-only.md) | List marks are warnings only |
| [0008](adr/0008-no-ui-framework-shadow-dom.md) | Hand-built Shadow DOM UI |
| [0009](adr/0009-model-server-and-inert-cloud.md) | Optional local server; cloud inert |
| [0010](adr/0010-hostile-input-posture.md) | Nothing from a message is fetched |
| [0011](adr/0011-ci-harness-no-dist-in-repo.md) | verify includes dist; no committed dist/ |

Full index: [adr/README.md](adr/README.md).

## Known limitations

- Curated public-suffix and brand tables, not exhaustive lists.
- No raw RFC 5322 headers — authentication is what Gmail shows.
- Body is `textContent` only (no OCR for image-only mail).
- Wording packs: English plus Spanish, French, German, Portuguese, Italian, Dutch, Hindi, Hinglish;
  other languages lean on identity, link and attachment checks (and the model when enabled).
- On-device AI availability depends on Chrome; absence is a first-class tested path.
