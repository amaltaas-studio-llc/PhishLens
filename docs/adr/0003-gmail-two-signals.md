# 0003. Gmail view changes from hash and DOM, cross-checked

**Status:** Accepted

## Context

Gmail is a hash-routed SPA: the route changes before the DOM swaps. MutationObserver fires constantly,
including same-thread re-renders. Evidence arrives late (Reply-To, mailed-by, attachments). The user’s
own reply can become the “last expanded” message. A message with no readable sender must never become
a confident Low Risk score.

## Decision

- Combine **hash/popstate** (expected route plus a short reconciliation poll) with a **debounced
  MutationObserver** over a view signature of route plus a hash of the extracted message.
- Assess the last expanded message that is not written by the user (from the account *and* addressed to
  someone else). Headers only for that judgement.
- All Gmail selectors live in `src/gmail/selectors.ts`. `extract()` reports gaps; `isScorable()` decides
  honesty. Unscorable mail shows **Not checked** — the badge stays.

## Consequences

- Late evidence re-runs checks without treating every mutation as a new message.
- Own replies are not scored as phishing; account-takeover forgeries that look like “from me” to someone
  else still are.
- Gaps are visible UI, not a green all-clear.

## Rejected alternatives

- **Hash alone** → analysis of the previous thread. **Observer alone** → flicker and redundant work.
- **Narrow fingerprints** (subject length, link counts) → stale verdicts when content changes without counts.
- **Scoring when the sender is missing** → confident Low Risk when almost nothing was checked.
- **Removing the badge for unscorable mail** → indistinguishable from clean mail when low badges are hidden.
