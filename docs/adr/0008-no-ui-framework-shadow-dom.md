# 0008. Hand-built UI in Shadow DOM; card pinned, not modal

**Status:** Accepted

## Context

The UI is a small number of elements. Message content is attacker-controlled. Gmail’s CSS is hostile.
“AI pending” is not the same as “unavailable.” There is no telemetry for selector drift.

## Decision

- Hand-built DOM via `el({ text })` / `textContent` only; no `innerHTML`. Shadow roots for badge and
  panel; styles as strings. No React or Preact.
- Badge near the header timestamp; **card pinned bottom-right**, non-modal, identifies subject/domain,
  re-renders in place.
- Distinct `semanticStatus` values so pending is not worded like unavailable.
- Popup answers “is it working?”; welcome page once on install; list marks off by default.

## Consequences

- “No HTML from mail” is structural and grepped in bundles.
- The card stays readable while scrolling the message.
- Health diagnostics can report drift without uploading mail content.

## Rejected alternatives

- **A UI framework** — supply chain and `dangerouslySetInnerHTML` temptation for a short list of nodes.
- **Card anchored to the badge** — needs scroll/resize handling; leaves the viewport when reading evidence.
- **Modal card** — dismissed before the findings are read.
- **One “no AI” string for every failure mode** — contradicts itself within seconds of a pending state.
