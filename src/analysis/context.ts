/**
 * Normalises an `EmailMessage` exactly once into an `AnalysisContext` that every detector reads.
 *
 * Two reasons this exists rather than each detector parsing what it needs:
 *  1. **Correctness.** Comparing a link to a sender domain is only meaningful if both went through
 *     the same normalisation — same parser, same redirect unwrapping, same registrable-domain rule.
 *     Doing it per-detector guarantees they eventually diverge.
 *  2. **Cost.** URL parsing and confusable folding are the expensive parts. Hostile input can
 *     contain hundreds of links; each is parsed once.
 *
 * Detectors become pure functions of this structure, which is what makes them trivially testable.
 */
import { BRANDS, brandOwningDomain, brandOwns, type Brand } from '../shared/brands.js';
import { DISPOSABLE_DOMAINS, FREEMAIL_DOMAINS } from '../shared/public-suffix.js';
import { isSenderProven, matchingTrustEntry } from '../shared/trust.js';
import {
  MAX_BODY_CHARS,
  emailLocalPart,
  emailLocalPartPreservingCase,
  fileExtension,
  fileExtensionChain,
  normalizeForMatching,
  truncate,
} from '../shared/text.js';
import type {
  EmailAttachment,
  EmailLink,
  EmailMessage,
  ThreadParticipant,
} from '../shared/types.js';
import {
  addressDomain,
  countSubdomainLabels,
  hasPunycode,
  hasRedirectParam,
  isDangerousScheme,
  isIpHost,
  isKnownTrackingRedirector,
  isMalformedHost,
  isNonNavigationScheme,
  isShortener,
  isWebUrl,
  normalizeDomain,
  openHostingSuffix,
  parseDisplayedUrl,
  parseUrl,
  registrableDomain,
  subdomainOf,
  tldOf,
  unwrapRedirects,
} from '../shared/url.js';
import { decodeIdnHost, hasBidiOrInvisible, skeleton } from '../shared/unicode.js';

export interface LinkAnalysis {
  index: number;
  link: EmailLink;
  /** Parsed `href`, or `null` when it is not an absolute URL. */
  raw: URL | null;
  /** Destination after peeling redirect wrappers. Equals `raw` when there were none. */
  target: URL | null;
  redirectHops: number;
  redirectChain: string[];
  /** A redirect parameter was present but its destination is not visible to us. */
  opaqueRedirect: boolean;
  /** The URL carries a redirect-style parameter, whether or not we could resolve its target. */
  redirectShaped: boolean;
  /**
   * The href's own host is a recognised mail-tracking redirector (SendGrid, Mailchimp, Outlook Safe
   * Links, Proofpoint, …).
   *
   * Checked on the *entry* host regardless of whether the wrapped target was resolvable, because
   * these services routinely encode the destination in a form we cannot decode. Without this, every
   * ESP-sent newsletter looks like an anchor/href mismatch: the anchor still reads
   * `example.com` while the href has been rewritten to `ct.sendgrid.net/ls/click?upn=…`.
   */
  wrappedByKnownTracker: boolean;
  /**
   * The href's own host is on the **sender's own registrable domain** — the sender is routing clicks
   * through its own infrastructure.
   *
   * Complements `wrappedByKnownTracker`, which can only recognise redirectors we have listed. This
   * catches the same behaviour structurally: every newsletter platform rewrites outbound links to a
   * host it controls (`substack.com/redirect/…`, `link.mail.beehiiv.com/…`,
   * `click.convertkit-mail.com/…`), and on those platforms the sending address is on that same domain.
   *
   * It licenses suppression rather than merely explaining it, because a rewrite to the sender's own
   * domain transfers no trust: the sender already chose every link in the message, so routing one
   * through itself gives it no capability it did not have. The deceptions these rules exist to catch —
   * borrowing a *third party's* recognisable domain — are unaffected. Checked on the entry host, like
   * `wrappedByKnownTracker`, because that is the host the reader's click actually reaches.
   */
  onSenderDomain: boolean;
  hostname: string;
  registrable: string;
  subdomain: string;
  tld: string;
  /** Rendered (Unicode) form of the hostname, for display and for brand comparison. */
  displayHost: string;
  subdomainLabelCount: number;
  isIp: boolean;
  isPunycode: boolean;
  isShortener: boolean;
  isMalformed: boolean;
  isWeb: boolean;
  isDangerousScheme: boolean;
  isNonNavigation: boolean;
  isHttps: boolean;
  openHosting: string | null;
  /** Anchor text interpreted as a URL, when a reader would read it as one. */
  displayed: URL | null;
  displayedRegistrable: string;
  /** Anchor text, normalised for keyword matching. */
  anchorText: string;
}

export interface AttachmentAnalysis {
  index: number;
  attachment: EmailAttachment;
  filename: string;
  extension: string;
  extensionChain: string[];
  hasDoubleExtension: boolean;
  hasBidiTrick: boolean;
}

/**
 * A party already in the conversation, normalised the same way the sender is.
 *
 * `nameKey` is confusable-folded so `Maria Delgado` and `Мaria Delgado` compare equal — the point of
 * reusing a name is that it looks identical to a reader, not that it is byte-identical.
 */
export interface ThreadParty {
  email: string;
  domain: string;
  registrable: string;
  /** Display name as shown, kept for evidence. */
  name: string;
  /** Folded display name, for comparison. `''` when there was no usable name. */
  nameKey: string;
}

/** A brand the message *claims* to be from, and where that claim was found. */
export interface BrandClaim {
  brand: Brand;
  source: 'sender-name' | 'sender-local-part' | 'subject' | 'body';
  matchedKeyword: string;
  /** Where the keyword was found in its folded source, which orders two claims from the same place. */
  position: number;
}

export interface AnalysisContext {
  email: EmailMessage;

  senderName: string;
  /**
   * The display name folded for keyword matching, with decorative letterforms flattened to ASCII and
   * `.`/`_` treated as the separators they are.
   *
   * Rules that ask *what a name claims* must read this and not `senderName`, which is kept verbatim for
   * evidence. A name spelled `𝗣aym𝗲nt_Declin𝗲d` claims exactly what `payment declined` claims, and the
   * whole reason it is spelled that way is that a pattern written in ASCII does not match it.
   */
  senderNameMatch: string;
  senderEmail: string;
  senderDomain: string;
  senderRegistrable: string;
  senderLocalPart: string;
  senderIsFreemail: boolean;
  senderIsDisposable: boolean;
  /** The brand that legitimately owns the sender's domain, if any. */
  senderOwnedByBrand: Brand | undefined;

  replyToEmail: string;
  replyToDomain: string;
  replyToRegistrable: string;
  hasReplyTo: boolean;

  /** Registrable domain of the delivered-to mailbox, or `''` when the client did not expose one. */
  recipientRegistrable: string;

  subject: string;
  bodyText: string;
  /**
   * The sender's local part with its original case, and the subject with its original whitespace.
   *
   * For detectors that examine **formatting** only — randomised capitalisation, padding. Never compare
   * these to anything: two spellings of one address are not equal, which is the whole reason the
   * normalised fields exist. Both fall back to the normalised value when the client gave us no raw
   * form, so a detector reading them still works, it just sees nothing anomalous.
   */
  rawSenderLocalPart: string;
  rawSubject: string;
  /** Lowercased, whitespace-collapsed subject + body. What content rules match against. */
  matchText: string;

  links: LinkAnalysis[];
  webLinks: LinkAnalysis[];
  attachments: AttachmentAnalysis[];

  /** Distinct registrable domains across all resolved link targets. */
  linkRegistrables: Set<string>;

  /**
   * Parties that sent a message earlier in this conversation, excluding any whose address matches the
   * sender's own, oldest first.
   *
   * Empty both when the message opens a thread and when the client could not tell us — the detectors
   * treat those identically, since neither is evidence of anything.
   */
  priorParties: ThreadParty[];
  /** Registrable domains already established in the conversation. */
  priorRegistrables: Set<string>;
  /** True when there is a conversation history to compare this message against. */
  inThread: boolean;

  claims: BrandClaim[];
  /**
   * The brand the message *presents itself as*.
   *
   * Restricted to claims found in the display name, the sender's local part, or the subject. A brand
   * named only in the body is deliberately excluded: a coffee shop's newsletter linking to its
   * Instagram, or an invoice saying "pay by card or PayPal", mentions a brand without claiming to be
   * it, and treating that as an identity claim produced false positives across every rule that
   * consumes this field.
   */
  primaryClaim: BrandClaim | undefined;
  /**
   * True when the message claims a brand and the sender's own domain is one that brand legitimately
   * owns — the condition under which content heuristics get dampened.
   */
  senderAlignedWithClaim: boolean;

  /**
   * The user's trust entry covering this sender, if any — set whether or not the message's origin could
   * be proved, so the card can distinguish "trusted" from "trusted, but this message was not verified".
   */
  trustedEntry: string | undefined;
  /** Gmail's surfaces tie this message to the sender's domain. See `isSenderProven`. */
  senderProven: boolean;
  /**
   * The only field the rules may read to decide that trust applies: an entry the user added *and*
   * proof that the message came from where it says. Neither half is sufficient.
   */
  senderTrusted: boolean;
}

export interface ContextOptions {
  /**
   * Senders the user trusts. Passed in rather than read from storage because `analysis/` may not touch
   * `chrome.*` — which also means the engine's behaviour stays a function of its arguments, and a test
   * can exercise trust without a browser.
   */
  trustedSenders?: readonly string[];
}

export function buildContext(email: EmailMessage, options: ContextOptions = {}): AnalysisContext {
  const senderName = (email.senderName ?? '').trim();
  const senderEmail = (email.senderEmail ?? '').trim().toLowerCase();
  const senderDomain = addressDomain(senderEmail);
  const senderRegistrable = registrableDomain(senderDomain);

  const replyToEmail = (email.replyTo ?? '').trim().toLowerCase();
  const replyToDomain = addressDomain(replyToEmail);

  const subject = truncate((email.subject ?? '').trim(), 998);
  const bodyText = truncate(email.bodyText, MAX_BODY_CHARS);
  const matchText = normalizeForMatching(`${subject}\n${bodyText}`);

  const links = email.links.map((link, index) => analyzeLink(link, index, senderRegistrable));
  const attachments = email.attachments.map((attachment, index) => analyzeAttachment(attachment, index));

  const webLinks = links.filter((l) => l.isWeb);
  const linkRegistrables = new Set(
    webLinks.map((l) => l.registrable).filter((d) => d !== ''),
  );

  const senderLocalPart = emailLocalPart(senderEmail);
  const claims = detectBrandClaims(
    [
      claimSource('sender-name', senderName),
      claimSource('sender-local-part', senderLocalPart),
      claimSource('subject', subject),
      claimSource('body', matchText),
    ],
    senderRegistrable,
  );
  const primaryClaim = choosePrimaryClaim(claims);
  const senderOwnedByBrand = brandOwningDomain(senderRegistrable);

  const senderAlignedWithClaim =
    primaryClaim !== undefined && brandOwns(primaryClaim.brand, senderRegistrable);

  const priorParties = normalizeThreadParties(email.thread?.priorSenders ?? [], senderEmail);

  const trustedEntry = matchingTrustEntry(options.trustedSenders ?? [], senderEmail);
  const senderProven = isSenderProven(email.auth, senderDomain);

  return {
    email,
    senderName,
    // Separators become spaces before folding, so a word can still be required to stand alone: `\b`
    // treats `_` as part of a word, which is enough to hide `payment` inside `payment_declined`.
    senderNameMatch: normalizeForMatching(senderName.replace(/[._]+/gu, ' ')),
    senderEmail,
    senderDomain,
    senderRegistrable,
    senderLocalPart,
    senderIsFreemail: FREEMAIL_DOMAINS.has(senderRegistrable),
    senderIsDisposable: DISPOSABLE_DOMAINS.has(senderRegistrable),
    senderOwnedByBrand,
    replyToEmail,
    replyToDomain,
    replyToRegistrable: registrableDomain(replyToDomain),
    hasReplyTo: replyToEmail !== '',
    recipientRegistrable: registrableDomain(addressDomain(email.recipientEmail)),
    subject,
    bodyText,
    rawSenderLocalPart: emailLocalPartPreservingCase(email.raw?.senderEmail ?? senderEmail),
    rawSubject: truncate(email.raw?.subject ?? subject, 998),
    matchText,
    links,
    webLinks,
    attachments,
    linkRegistrables,
    priorParties,
    priorRegistrables: new Set(priorParties.map((p) => p.registrable).filter((d) => d !== '')),
    inThread: priorParties.length > 0,
    claims,
    primaryClaim,
    senderAlignedWithClaim,
    trustedEntry,
    senderProven,
    senderTrusted: trustedEntry !== undefined && senderProven,
  };
}

function analyzeLink(link: EmailLink, index: number, senderRegistrable: string): LinkAnalysis {
  const raw = parseUrl(link.href);
  const unwrapped = raw === null ? null : unwrapRedirects(raw);
  const target = unwrapped?.url ?? raw;

  const hostname = target === null ? '' : normalizeDomain(target.hostname);
  const entryRegistrable = raw === null ? '' : registrableDomain(normalizeDomain(raw.hostname));
  const displayed = parseDisplayedUrl(link.text);

  return {
    index,
    link,
    raw,
    target,
    redirectHops: unwrapped?.hops ?? 0,
    redirectChain: unwrapped?.chain ?? [],
    opaqueRedirect: unwrapped?.opaqueRedirect ?? false,
    redirectShaped: raw !== null && hasRedirectParam(raw),
    wrappedByKnownTracker: raw !== null && isKnownTrackingRedirector(raw.hostname),
    onSenderDomain: entryRegistrable !== '' && entryRegistrable === senderRegistrable,
    hostname,
    registrable: registrableDomain(hostname),
    subdomain: subdomainOf(hostname),
    tld: tldOf(hostname),
    displayHost: decodeIdnHost(hostname),
    subdomainLabelCount: countSubdomainLabels(hostname),
    isIp: hostname !== '' && isIpHost(hostname),
    isPunycode: hasPunycode(hostname),
    isShortener: hostname !== '' && isShortener(hostname),
    isMalformed: raw === null || (target !== null && isWebUrl(target) && isMalformedHost(hostname)),
    isWeb: target !== null && isWebUrl(target),
    isDangerousScheme: raw !== null && isDangerousScheme(raw),
    isNonNavigation: raw !== null && isNonNavigationScheme(raw),
    isHttps: target !== null && target.protocol === 'https:',
    openHosting: hostname === '' ? null : openHostingSuffix(hostname),
    displayed,
    displayedRegistrable: displayed === null ? '' : registrableDomain(displayed.hostname),
    anchorText: normalizeForMatching(link.text).slice(0, 300),
  };
}

/**
 * Normalises the conversation history and drops the sender's own earlier messages.
 *
 * Dropping them matters: a genuine correspondent replying twice would otherwise be compared against
 * themselves, and every long thread would be full of self-matches for the name rules to trip over.
 * De-duplicated by address so a ten-message thread between two people yields two parties, and bounded
 * so a thread built to be enormous costs a fixed amount.
 */
function normalizeThreadParties(
  priorSenders: readonly ThreadParticipant[],
  senderEmail: string,
): ThreadParty[] {
  const parties: ThreadParty[] = [];
  const seen = new Set<string>();

  for (const participant of priorSenders.slice(0, MAX_THREAD_PARTIES)) {
    const email = participant.email.trim().toLowerCase();
    const name = participant.name.trim();
    if (email === '' && name === '') continue;
    if (email !== '' && email === senderEmail) continue;

    const key = `${email}\u0000${name.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const domain = addressDomain(email);
    parties.push({
      email,
      domain,
      registrable: registrableDomain(domain),
      name: truncate(name, 300),
      // A name that folds to almost nothing (`.`, `--`) is not a name; treat it as absent so the
      // reuse rule cannot match two participants on emptiness.
      nameKey: skeleton(name).length >= 2 ? skeleton(name) : '',
    });
  }

  return parties;
}

/** Upper bound on conversation history examined. A thread can be arbitrarily long. */
const MAX_THREAD_PARTIES = 60;

function analyzeAttachment(attachment: EmailAttachment, index: number): AttachmentAnalysis {
  const filename = attachment.filename.trim();
  const chain = fileExtensionChain(filename);
  return {
    index,
    attachment,
    filename,
    extension: attachment.extension !== '' ? attachment.extension.toLowerCase() : fileExtension(filename),
    extensionChain: chain,
    hasDoubleExtension: chain.length >= 2,
    hasBidiTrick: hasBidiOrInvisible(filename),
  };
}

// ---------------------------------------------------------------------------
// Brand claim detection
// ---------------------------------------------------------------------------

/** Shortest keyword trusted to match anywhere inside folded text; below this it must stand alone. */
const MIN_UNANCHORED_KEYWORD = 6;

/** One place a brand can be named, pre-folded both ways. */
interface ClaimSource {
  origin: BrandClaim['source'];
  /** The folded words run together, so `p a y p a l` reads as `paypal`. */
  joined: string;
  /** Where each word begins in `joined`. */
  wordStarts: ReadonlySet<number>;
  /** Folded word by word, so a short keyword can be required to be a word of its own. */
  words: readonly string[];
}

function claimSource(origin: BrandClaim['source'], text: string): ClaimSource {
  const words = text.split(/\s+/u).map((word) => skeleton(word));
  const wordStarts = new Set<number>();
  let offset = 0;
  for (const word of words) {
    wordStarts.add(offset);
    offset += word.length;
  }
  return { origin, joined: words.join(''), wordStarts, words };
}

/** How many occurrences of one keyword to try before concluding none begins a word. */
const MAX_KEYWORD_OCCURRENCES = 16;

/**
 * Whether a long keyword appears either inside one word, or spread over several starting at the first.
 *
 * Running the words together is what reads `p a y p a l` and `Micro Soft` as the brands they spell, but
 * a match allowed to *start* mid-word reads names that spell nothing: "Miriam Stearns" folds (`rn`→`m`)
 * and joins to `mlrlamsteams`, which contains `msteams`, and a list regular was reported at `high` as
 * Microsoft impersonation. Spacing a brand out starts it at a word; a person's name that happens to
 * straddle one does not. Inside a single word anything goes, because `SecurePayPal` is a claim.
 */
function containsKeyword(source: ClaimSource, folded: string): boolean {
  if (source.words.some((word) => word.includes(folded))) return true;
  let from = 0;
  for (let seen = 0; seen < MAX_KEYWORD_OCCURRENCES; seen++) {
    const at = source.joined.indexOf(folded, from);
    if (at === -1) return false;
    if (source.wordStarts.has(at)) return true;
    from = at + 1;
  }
  return false;
}

/**
 * Finds which brands the message presents itself as, in order of how strongly each place claims one.
 *
 * Matching is on confusable-folded text, so `PayPaI`, `p-a-y-p-a-l` and `pаypal` all resolve to the
 * same claim. Since folding strips separators, a match is a substring match (one that may not begin
 * mid-word, see `containsKeyword`) — safe for a long keyword and wrong for a short one, because `irs` sits inside "first" and "chairs" and `aws` inside "lawsuit".
 * Short keywords therefore have to be a whole folded word. The cost is missing `I.R.S.`, which no rule
 * relies on; the benefit is that ordinary prose no longer claims to be a tax authority.
 */
function detectBrandClaims(
  sources: readonly ClaimSource[],
  senderRegistrable: string,
): BrandClaim[] {
  const claims: BrandClaim[] = [];
  for (const brand of BRANDS) {
    const claim = strongestClaim(brand, sources);
    if (claim !== undefined) claims.push(claim);
  }
  return orderClaims(claims, senderRegistrable);
}

/**
 * Which claim a reader would say the message is making, when it names more than one brand.
 *
 * Ordering matters because the impersonation rules read the first claim, and a display name naming two
 * brands is not unusual: a product can carry one brand's word inside its own name. A name like `Amazon
 * Appstore Team` claims Amazon and, through the `appstore` keyword, Apple — so with the table's own order
 * as the only tiebreak, mail from a domain Amazon owns was reported as Apple impersonation at `high`,
 * with a correlation on top of it. Nothing about such a message is wrong; the answer to "which brand is
 * this?" was decided by which entry happens to be written first in `brands.ts`, which is not a fact
 * about the message at all.
 *
 * So, after the source that named it: a brand that owns the sending domain wins, because a message from
 * `amazon.com` naming Amazon *is* Amazon and the second name is a product word. Failing that, the
 * earliest mention wins, which reads a name left to right the way a person does — and keeps the wording
 * right on the phishing version of the same name, where no claimed brand owns the domain and the finding
 * should say Amazon rather than Apple.
 */
function orderClaims(claims: BrandClaim[], senderRegistrable: string): BrandClaim[] {
  const ownsSender = (claim: BrandClaim): number => (brandOwns(claim.brand, senderRegistrable) ? 1 : 0);

  return [...claims].sort((a, b) => {
    const bySource = CLAIM_SOURCE_PRIORITY[b.source] - CLAIM_SOURCE_PRIORITY[a.source];
    if (bySource !== 0) return bySource;
    const byOwnership = ownsSender(b) - ownsSender(a);
    if (byOwnership !== 0) return byOwnership;
    return a.position - b.position;
  });
}

/**
 * The claim from the most authoritative source that names this brand.
 *
 * Sources are ordered, so a keyword in the display name outranks a different keyword of the same brand
 * appearing in the body — a message from "PayPal Service" claims to be PayPal even if its body merely
 * mentions receipts.
 */
function strongestClaim(brand: Brand, sources: readonly ClaimSource[]): BrandClaim | undefined {
  for (const source of sources) {
    for (const keyword of brand.keywords) {
      const folded = skeleton(keyword);
      if (folded.length < 3) continue;

      const found =
        folded.length >= MIN_UNANCHORED_KEYWORD
          ? containsKeyword(source, folded)
          : source.words.includes(folded);

      if (found) {
        return {
          brand,
          source: source.origin,
          matchedKeyword: keyword,
          // Found by the word list for a short keyword, but located in the stripped text either way: the
          // two agree on which mention comes first, and only the ordering uses this.
          position: Math.max(source.joined.indexOf(folded), 0),
        };
      }
    }
  }
  return undefined;
}

const CLAIM_SOURCE_PRIORITY: Readonly<Record<BrandClaim['source'], number>> = {
  'sender-name': 3,
  'sender-local-part': 2,
  subject: 1,
  body: 0,
};

/** Sources strong enough to mean "this message is presenting itself as that brand". */
const IDENTITY_CLAIM_SOURCES: readonly BrandClaim['source'][] = [
  'sender-name',
  'sender-local-part',
  'subject',
];

/** The first claim from a source strong enough to count, `orderClaims` having settled what "first" means. */
function choosePrimaryClaim(claims: readonly BrandClaim[]): BrandClaim | undefined {
  return claims.find((c) => IDENTITY_CLAIM_SOURCES.includes(c.source));
}
