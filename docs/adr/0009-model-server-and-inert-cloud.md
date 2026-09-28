# 0009. Optional local model server; cloud designed but not shipped

**Status:** Accepted

## Context

Chrome’s built-in model is small. Many users already run Ollama, LM Studio, or similar. Cloud analysis
was designed but must not ship as a side effect of other work. The README advertises two install
permissions.

## Decision

- One OpenAI-compatible `/chat/completions` client for user-run servers. `http:` only for loopback;
  other origins need `https:` and an optional host permission requested on a click from Settings.
- The endpoint comes from **settings**, never from a runtime message. Same 15-point cap and corroboration
  rules as the on-device path ([0006](0006-llm-cannot-outvote-checks.md)).
- Cloud adapter stays inert; options hide cloud unless already stored. Sanitize at fetch time in the
  worker, not only when building the prompt.

## Consequences

- Default install keeps two permissions.
- Larger local models improve explanations only, not weight.
- The worker cannot become a general-purpose fetcher.

## Rejected alternatives

- **Per-runner native APIs** — duplicate clients for one benefit.
- **Required `localhost` host permission** — taxes every install; breaks the two-permission claim.
- **Endpoint arriving in a message** — turns the worker into an open proxy.
- **Raising the cap for “better” models** — configuration must not weaken the invariant.
- **Shipping cloud now** — left designed and inert on purpose.
