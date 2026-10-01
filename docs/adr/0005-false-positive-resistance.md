# 0005. Dampen content carefully; never silence identity via trust

**Status:** Accepted

## Context

Keyword checks flag real password resets and newsletters. A curated brand table cannot cover every
organisation. Normalisation erases filter-evasion evidence. A trust list is an attractive spoofing hole.
Sender click-trackers look like URL mismatches.

## Decision

- **Sender alignment:** dampen `content` one severity step only when a claimed brand’s domain is
  *proven* by Gmail’s authentication summary, and never when medium-or-higher identity or link findings
  are present. Never dampen technical categories, and never a `high` or `critical` finding — apart from
  the fake-sign-in-page combinations listed in `scoring/config.ts`, which describe the brand's own
  notifications. A request to move money keeps its full weight even from a proven brand, since a genuine
  brand service is what an attacker abuses to send one.
- **Bulk-mail shape:** suppress content themes that marketing trivially trips when unsubscribe language
  is present and there is no credential ask (per-language vocabulary in wording packs).
- **Click tracking:** skip mismatch rules when the entry host is the sender’s registrable domain; still
  fire if the anchor impersonates a brand.
- **Brand-independent identity:** shared-name and institutional-marker checks that need no brand table.
- **Raw fields:** keep pre-normalised forms for formatting detectors only; never compare raw values to
  domains or brands.
- **Trust list:** dampen only `content`, only when Gmail proves the sender domain, never a `high` or
  `critical` finding; dampened findings stay visible and reversible. On shared sending platforms
  (helpdesk and tenant domains) an entry names the tenant's host, not the platform.

## Consequences

- Proven legitimate resets stay low; forged famous From lines making illicit asks do not.
- Newsletters do not floor at 50 from tracker mismatches.
- Trusting `paypal.com` cannot quieten `paypa1.com`.

## Rejected alternatives

- **Dampening without authentication proof** → rewards a forged display name.
- **Identity only via the brand table** → miss every unlisted bank or insurer.
- **Trust that dampens identity or removes findings** → spoofing hole or silent suppressions.
- **Comparing raw strings for equality** → reintroduces the bugs normalisation exists to prevent.
