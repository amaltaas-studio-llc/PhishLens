# 0010. Nothing from a message is fetched or executed

**Status:** Accepted

## Context

Every string in an email is attacker-controlled. Network side-effects become oracles. A language model
can be prompt-injected. This is a privacy guarantee, not only a performance choice.

## Decision

- Parse URLs with the `URL` constructor; unwrap Gmail redirects with a hop bound; **never fetch** a
  message URL, attachment, image, favicon, or DNS name.
- Attachments: filename and extension only (double extensions, RTLO); no open or download.
- Bound every loop and regex over message-derived data; truncate the body before matching.
- Delimit untrusted content for the model; schema-validate output; discard malformed responses entirely.
  Caps in [0006](0006-llm-cannot-outvote-checks.md) contain injection damage.

## Consequences

- No read-receipt oracle from analysis.
- Homoglyph hosts are handled via punycode decoding, not live lookups.
- A successful injection can only affect the capped `llm` category.

## Rejected alternatives

- **Regex-split URLs** — miss what `URL` accepts and vice versa.
- **Fetching destinations for “reputation”** — privacy break and oracle.
- **Partial trust of malformed model JSON** — hostile mail may be why it is malformed.
- **Executing any string derived from the message.**
