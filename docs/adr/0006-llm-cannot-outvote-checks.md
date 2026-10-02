# 0006. The model is capped and cannot originate a score

**Status:** Accepted

## Context

Deterministic checks own technical facts. A language model is useful for intent and tone, but small
on-device models are over-suspicious and invent “technical” reasons they cannot verify. See also
[LOCAL-AI.md](../LOCAL-AI.md).

## Decision

- The `llm` category is additive, weighted at most 15 of 100, and shown in a separate card section.
- Score only risk above a dead zone; **uncorroborated readings contribute zero**: a deterministic signal
  must already exist.
- The model cannot remove a finding, lower a score past a deterministic floor, or change a classification
  alone. This holds for Chrome’s model and for any server the user runs.

## Consequences

- Injection or a wrong reading cannot clear a rule finding.
- Clean mail is not lifted off zero by unease with no check behind it.
- A better model buys better *explanations*, not more weight.

## Rejected alternatives

- **Subtractive or overriding semantic verdicts.**
- **Proportional discount of all risk** → residual points on every clean message blur “nothing” vs “a little.”
- **Scoring uncorroborated high confidence** → clean mail leaves zero with no deterministic signal.
