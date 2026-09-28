# CLAUDE.md

The instructions for this repository live in **[AGENTS.md](AGENTS.md)**. Read it before making changes.

This file is a pointer rather than a copy on purpose: two sets of agent instructions drift, and the day
they disagree is the day one of them is silently wrong.

Quick orientation, all of it expanded in `AGENTS.md`:

- `npm run verify` (lint, typecheck, test, build, dist check) is the definition of done.
- Never put message content into the DOM as HTML; use `el({ text })` from `src/ui/dom.ts`.
- The scoring model (weights, ceilings, floors, thresholds) belongs in `src/analysis/scoring/config.ts`,
  a finding's own points beside its wording; all Gmail selectors in `src/gmail/selectors.ts`.
- `src/analysis/` must stay free of browser and Chrome APIs so it runs under Vitest in Node.
- The language model is capped at 15 of 100 points and cannot originate a score.
- New detection behaviour needs a fixture asserted in both directions.
- `npm run harness` shows the real UI without Gmail. Use it instead of guessing.
- Structural map: `docs/ARCHITECTURE.md`; rejected alternatives: `docs/adr/`.
- Never add co-author trailers to commits.
