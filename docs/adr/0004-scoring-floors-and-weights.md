# 0004. Scoring weights sum to 100; severity floors for single-dimension attacks

**Status:** Accepted

## Context

A pure weighted sum caps an attack that is malicious in only one dimension at that category’s weight.
Business email compromise is often *only* a content finding. An early weight table also omitted
`content` and double-counted identity-family rows.

## Decision

- Category weights, severity ceilings, floors and band thresholds live only in
  `src/analysis/scoring/config.ts`. Weights sum to exactly 100.
- Aggregation: clamp each finding by severity → sum per category → cap at category weight → sum →
  clamp to `[0, 100]`.
- Floors: one deterministic `high` → ≥50; one `critical` → ≥75; `high` in two or more eligible
  categories → ≥75 (convergence).
- Floors never come from `llm`, and never from `authentication.gmail_warning` (folder-conditional).

## Consequences

- Gift-card BEC and similar single-dimension attacks can still reach Suspicious or High Risk.
- The final clamp is a safety net, not the usual path, so top-of-scale scores stay meaningful.
- Moving mail to Spam does not change the score via Gmail’s banner alone.

## Rejected alternatives

- **Inflating weights** so two mediums reach 75 → ordinary multi-medium mail over-scored.
- **Counting findings, not categories,** for convergence → one fact repeated “converges.”
- **Letting the model or Gmail’s warning set floors** → unverifiable or folder-dependent verdicts.
