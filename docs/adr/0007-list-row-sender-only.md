# 0007. Inbox-row marks are sender-only warnings, never an all-clear

**Status:** Accepted

## Context

Inbox rows expose a sender (and maybe a snippet), not a body. The feature is highly requested and easy
to turn into false all-clears or inbox noise that gets switched off.

## Decision

- An explicit allowlist of identity rules that need only name and address; everything else is classified
  “needs more.” A test forces every identity rule into one set or the other.
- Verdicts are **warning or nothing** — never “looks fine.”
- The mark floor is `high` (stricter than what the open-message card reports).

## Consequences

- An unmarked row means unchecked, not clean.
- The feature stays leave-on-able; harness list density is the metric.
- New identity rules cannot silently enter triage.

## Rejected alternatives

- **Running the full engine on sender-only data** → confident Low Risk on unchecked mail.
- **Opening each message for its body** → privacy cost and mass loads.
- **Guessing from subject or snippet** → verdicts that change with window width.
- **Marking at `medium`** → ordinary departmental names become inbox noise.
