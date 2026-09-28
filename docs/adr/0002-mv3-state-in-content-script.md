# 0002. Analysis state and the model session live in the content script

**Status:** Accepted

## Context

MV3 service workers terminate after roughly thirty seconds idle. Creating an on-device model session
is expensive. The Prompt API accepts one prompt at a time, and overlapping calls can poison the
session so both fail. Gmail fills a view in stages, so analysis is triggered more than once by design.

## Decision

- The full analysis pipeline and the on-device model session live in the **content script**, which lasts
  as long as the tab.
- The service worker is **stateless**: settings and opt-in egress only; re-read storage on every message;
  no module-level cache (asserted by tests).
- Do not persist analysis results. Keep at most fifty prompt-keyed model readings per tab.
- Warm the session at startup; serialise prompts through a queue; abort on view change; treat cancel as
  “no answer”, not a verdict.

## Consequences

- Session create-cost is paid once per tab, not on every idle timeout.
- Stale inference does not delay or corrupt the current message.
- Settings like “ask only when a check already fired” can skip work that could not change the score.

## Rejected alternatives

- **Holding the model in the service worker.** The worker dies constantly; on-device AI becomes unusable.
- **Persisting analysis results.** Privacy cost for a re-run that is cheap.
- **Unserialised concurrent prompts.** First-message AI fails silently while later messages appear to work.
