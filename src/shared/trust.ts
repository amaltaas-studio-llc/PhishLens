/**
 * Senders the user has said they trust.
 *
 * An allowlist is the most dangerous feature a phishing tool can have (the whole point of the attack is
 * to look like someone you trust), so the shape of this one is defensive by construction. Three rules,
 * each enforced here or by the single caller in `rules/index.ts` rather than by convention:
 *
 *  1. **Trust needs proof.** An entry only applies to a message Gmail could cryptographically tie to that
 *     domain (`isSenderProven`). Spoofing a trusted From address gains nothing, because the spoof is
 *     exactly what fails the check. Trust with no proof is reported, and ignored.
 *  2. **Trust never silences.** It feeds the existing dampening stage, which lowers the weight of
 *     *wording* findings and leaves every finding visible. It cannot remove a finding, and any real
 *     technical finding cancels it outright.
 *  3. **Trust is as narrow as the sender is.** A domain nobody in particular controls (Gmail, Outlook,
 *     a disposable mailbox) cannot be trusted as a domain at all, only as one address, because trusting
 *     `gmail.com` would mean trusting everybody.
 *
 * Pure, and importable from both the analysis engine and the UI: deciding whether to *offer* trust is a
 * UI question, deciding whether it *applies* is an analysis question, and both need the same answers.
 */
import { DISPOSABLE_DOMAINS, FREEMAIL_DOMAINS } from './public-suffix.js';
import { MAX_ENTRY_CHARS, MAX_TRUSTED_SENDERS, normalizeTrustList } from './settings.js';
import type { Classification, EmailAuthInfo } from './types.js';
import { addressDomain, registrableDomain, sameRegistrableDomain, normalizeDomain } from './url.js';

/**
 * What the user would be trusting for a given sender, or `null` when there is nothing safe to offer.
 *
 * A shared mailbox host gives an address; anything else gives the registrable domain, which is the unit a
 * single organisation actually controls. Deliberately *not* the full sending domain: mail from a real
 * organisation moves between `email.`, `mail.` and `notifications.` subdomains, and an entry that breaks
 * when it does would train the user to add three.
 */
export function trustEntryFor(senderEmail: string): string | null {
  const address = senderEmail.trim().toLowerCase();
  if (address === '' || !address.includes('@')) return null;
  if (address.length > MAX_ENTRY_CHARS) return null;

  const registrable = registrableDomain(addressDomain(address));
  if (registrable === '') return null;
  // A disposable-mailbox address is not a stable identity, so neither form of entry means anything.
  if (DISPOSABLE_DOMAINS.has(registrable)) return null;
  if (FREEMAIL_DOMAINS.has(registrable)) return address;
  return SHARED_SENDER_PLATFORMS.has(registrable) ? normalizeDomain(addressDomain(address)) : registrable;
}

/**
 * Platforms that send every customer's mail from a subdomain of one domain: `acme.zendesk.com` is
 * Acme's help desk, and `northwind.zendesk.com` is anybody who signed up yesterday. The registrable
 * domain names the platform, so trusting it would trust every tenant (the `gmail.com` problem again),
 * and the entry is the tenant's full host instead.
 *
 * A short list on purpose, of platforms whose tenant subdomain *is* the sending address. Bulk senders
 * that send from the customer's own domain (SendGrid, Mailchimp) do not belong here; their mail is
 * already keyed to that domain.
 */
const SHARED_SENDER_PLATFORMS: ReadonlySet<string> = new Set([
  'zendesk.com',
  'freshdesk.com',
  'onmicrosoft.com',
  'atlassian.net',
]);

/** The entry that covers this sender, or `undefined`. Matching is exact; there are no wildcards. */
export function matchingTrustEntry(
  trusted: readonly string[],
  senderEmail: string,
): string | undefined {
  const address = senderEmail.trim().toLowerCase();
  if (address === '') return undefined;
  const host = normalizeDomain(addressDomain(address));
  const registrable = registrableDomain(host);
  const unit = SHARED_SENDER_PLATFORMS.has(registrable) ? host : registrable;

  return trusted.find((entry) =>
    entry.includes('@') ? entry === address : entry !== '' && entry === unit,
  );
}

/**
 * Whether Gmail's own surfaces prove this message came from the sender's domain.
 *
 * Strict about *what* counts. DMARC passing means the message aligned with the From domain under a policy
 * that domain published, and an aligned DKIM signature means the domain signed the message itself. SPF
 * alone is never accepted: it authenticates the envelope rather than the From header, so it passes for
 * mail that merely *claims* the From address, the one case this function exists to exclude. A `?` avatar
 * means Gmail could not verify the sender at all, which overrides anything else read from the page.
 *
 * Liberal about *where* the evidence comes from, which it has to be. Named verdicts (`dkim: pass`) are
 * only ever scraped from a tooltip that most Gmail builds do not have, so requiring one would make
 * this function return `false` for every message and the trust feature unreachable. An aligned `signed-by`
 * row is the same proof by another route: Gmail renders it with the DKIM `d=` domain of a signature it
 * verified, and omits it entirely when there is no valid signature. Presence *is* the verdict.
 *
 * Still best-effort, because a content script reads rendered HTML rather than headers, and the rows live
 * behind Gmail's "show details" toggle. No evidence returns `false` and trust does not apply: the safe
 * direction, since the cost is a false positive the user has already seen and the alternative is an
 * allowlist that works on unauthenticated mail.
 */
export function isSenderProven(auth: EmailAuthInfo | undefined, senderDomain: string): boolean {
  if (auth === undefined || senderDomain === '') return false;
  if (auth.spf === 'fail' || auth.dkim === 'fail' || auth.dmarc === 'fail') return false;
  if (auth.unauthenticatedIndicator === true) return false;
  if (auth.dmarc === 'pass') return true;
  if (auth.dkim !== undefined && auth.dkim !== 'pass') return false;

  const signedBy = normalizeDomain(auth.signedBy ?? '');
  return signedBy !== '' && sameRegistrableDomain(signedBy, senderDomain);
}

/**
 * What the card says about trust for the message on screen.
 *
 * `offer` is withheld above `caution` deliberately: the moment to add a sender to an allowlist is not
 * while looking at a message the tool has just called suspicious, and a button there would be the one
 * click an attacker most wants.
 */
export type TrustState =
  /** Trusted, and Gmail proved this message really came from that sender. */
  | { kind: 'trusted'; entry: string }
  /** Trusted, but nothing proved this message's origin, so the trust was not applied to this score. */
  | { kind: 'unproven'; entry: string }
  | { kind: 'offer'; entry: string }
  | { kind: 'none' };

export function trustState(
  trusted: readonly string[],
  senderEmail: string,
  auth: EmailAuthInfo | undefined,
  classification: Classification,
): TrustState {
  const existing = matchingTrustEntry(trusted, senderEmail);
  const proven = isSenderProven(auth, addressDomain(senderEmail));

  if (existing !== undefined) {
    return proven ? { kind: 'trusted', entry: existing } : { kind: 'unproven', entry: existing };
  }

  if (!proven) return { kind: 'none' };
  if (classification !== 'low' && classification !== 'caution') return { kind: 'none' };
  if (trusted.length >= MAX_TRUSTED_SENDERS) return { kind: 'none' };

  const entry = trustEntryFor(senderEmail);
  return entry === null ? { kind: 'none' } : { kind: 'offer', entry };
}

/** Adds an entry, keeping the list normalised and bounded. Returns the list unchanged if it is full. */
export function withTrustedSender(trusted: readonly string[], entry: string): string[] {
  return normalizeTrustList([...trusted, entry]);
}

export function withoutTrustedSender(trusted: readonly string[], entry: string): string[] {
  const target = entry.trim().toLowerCase();
  return trusted.filter((existing) => existing !== target);
}
