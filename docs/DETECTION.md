# Detection and scoring

How a message becomes a 0–100 score. Design history:
[ARCHITECTURE.md](ARCHITECTURE.md) and [adr/](adr/) (especially
[0004](adr/0004-scoring-floors-and-weights.md),
[0005](adr/0005-false-positive-resistance.md)).

## Principle

> Use deterministic checks for what a computer can know; use a language model only for intent and tone.

Facts (lookalike domains, mismatched links, executable filenames) are decided in code. Readings of
wording may use a model, capped so they cannot reverse a check. Separate detectors, a separate scoring
category, and a separate card section keep the two apart.

![Pipeline from extract through checks and optional model to badge and card](assets/pipeline.svg)

## What is checked

Detectors live under `src/analysis/rules/`. Each emits `SecuritySignal`s (id, category, severity,
explanation, evidence); none computes the final score.

| Category | File | Looks for |
| --- | --- | --- |
| Identity | `identity.ts`, `thread.ts` | Lookalikes, homoglyphs, brand-in-wrong-place, display names that do not match the domain, reply-chain impersonation |
| Links | `links.ts` | Anchor ≠ destination, brand-prefix hosts, IPs, punycode, shorteners, credential wording to unrelated hosts, public object-storage pages — on every host a click passes through |
| Content | `content.ts`, `languages/` | Credential asks, OTP solicitation, payment changes, gift cards, urgency, secrecy, process bypass, … |
| Attachments | `attachments.ts` | Executables, macros, archives, double extensions, RTLO tricks (filename only) |
| Authentication | `authentication.ts` | SPF/DKIM/DMARC and Gmail’s warning as shown in the page — no raw headers |

**Wording languages.** English patterns always run. Packs add patterns to the **same themes** for Spanish,
French, German, Portuguese, Italian, Dutch, Hindi and Hinglish (gated detection; per-language negation and
bulk vocabulary). Details: `src/analysis/rules/languages/`.

**Redirects add hosts; they never replace one.** A redirect parameter is decoded textually (up to three
hops) and each host on the path is judged — the entry host first, since it is the one an attacker cannot
dress up. Host-identity rules (lookalike, IP, punycode, brand prefix, shortener, deep subdomains) run on
every hop; rules about the page itself (sign-in wording, open storage, a prose anchor naming a brand) run
on the decoded destination. A displayed brand address reached through somebody else's redirector is
`high`. Known click trackers are matched on their own host and click path (`google.com` only for
`/url`), and excuse only their own hop: what they forward to is judged like anything else, and only a
tracker whose target cannot be decoded leaves nothing to judge. A tracker's owner publishing pages
(`docs.google.com`, `sites.google.com`, `*.substack.com`, `hs-sites.com`, `ghost.io`) is not a tracker; the
publishable ones are open hosting, where brand ownership of the domain says nothing about the page.

**What counts as the message.** Quoted replies are left out of the wording checks so a thread is not
re-judged on what earlier messages said — but a quote is only a class name, which a sender can write, so
two things do not depend on it. Every link is read, quoted or not, and a body with nothing outside its
quotes (a bare forward, or a lure wrapped in a fake quote) is read from the quotes. Text hidden with
`font-size: 0`, `visibility: hidden`, `display: none`, off-screen positioning or near-zero opacity is
removed before scoring and reported once it is long enough to matter; clipping only counts when the
shape is unambiguously empty, so a rectangle starting at zero does not erase visible content; a child escapes a hidden container
only with an absolute size or its own `visibility: visible`, and the container's own text stays hidden.

**OTP vs code delivery.** Asking the reader to share a one-time code is the attack; delivering a code is
ordinary mail. Rules key on solicitation verbs, and a surrounding negation (“never share…”, including
after-verb forms in other languages) reverses a match. Conditionals like “if you do not send…” stay
reportable. Fixtures: `legitimate-verification-code`, `northwind-*-verification-code`.

## The score

Every weight, ceiling, floor and band threshold lives in `src/analysis/scoring/config.ts`.

| Category | Weight |
| --- | --- |
| Links | 25 |
| Identity | 21 |
| Content | 15 |
| Semantic (AI) | 15 |
| Authentication | 14 |
| Attachments | 10 |

Aggregation (`scoring/aggregate.ts`):

1. Cap each finding by severity (`info` 5 … `critical` 100).
2. Sum per category; cap at the category weight.
3. Sum categories; clamp to `[0, 100]`.
4. **Floors (deterministic only):** one `high` → ≥50; one `critical` → ≥75; `high` in two or more
   categories → ≥75. Never from `llm` or `authentication.gmail_warning`.

Bands: low &lt; 25 ≤ caution &lt; 50 ≤ suspicious &lt; 75 ≤ high-risk.

Floors exist so single-dimension attacks (plain-text gift-card BEC) cannot top out at the content weight
alone. Legitimate fixtures must not produce `high`/`critical` deterministic findings — that assumption is
tested.

## Holding down false positives

Full reasoning: [adr/0005](adr/0005-false-positive-resistance.md). In short:

- **Dampening** — soften `content` when a claimed brand’s domain is proven by Gmail and every link host
  stays inside it; never dampen identity/link; never high/critical. The one exception is the fake-page
  combinations (`DAMPENING.refutableCombinations`: urgent or threatened sign-in, billing update under
  threat), which a verified brand with aligned links refutes and which are zeroed; money-movement
  combinations keep full weight, since a compromised genuine mailbox sends exactly those.
- **Bulk mail** — suppress marketing-prone content themes when unsubscribe language is present and there
  is no credential ask (per language). Combinations are built from the surviving themes only.
- **Sender click-trackers** — mismatch rules skip the sender’s own domain unless the anchor impersonates a brand.
- **Trust list** — same proof gate; dampens `content` only, never a high/critical finding; findings stay
  visible. Shared ticketing/tenant platforms (`zendesk.com`, `freshdesk.com`, `onmicrosoft.com`,
  `atlassian.net`) are trusted per tenant host, never as the platform.
- **Authentication** — an SPF/DKIM failure beside a DMARC pass is `low` (forwarding, mailing lists); a
  failure without one stays `high`.
- **Brand-independent identity** — shared-name / institutional checks that need no brand table.

## List rows

Inbox marks use an allowlist of sender-only identity rules; unmarked means unchecked, never “looks fine.”
See [adr/0007](adr/0007-list-row-sender-only.md).

## Limitations

- Brand and public-suffix tables are curated subsets.
- No raw mail headers; authentication is best-effort from Gmail’s UI.
- Body is `textContent` only (no OCR).
- Wording packs cover eight languages besides English; others lean on identity, links and attachments.
- No reputation feeds; analysis is textual only ([adr/0010](adr/0010-hostile-input-posture.md)).
