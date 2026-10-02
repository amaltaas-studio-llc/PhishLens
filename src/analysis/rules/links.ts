/**
 * Link detectors.
 *
 * Everything here compares *what the user sees* against *where the click goes*. That comparison is
 * only sound because `buildContext` already normalised both sides through the platform URL parser
 * and unwrapped redirect wrappers; a raw string comparison would be trivially defeated by
 * `HTTPS://EVIL.EXAMPLE./x` versus `https://evil.example/x`.
 *
 * No detector in this file resolves DNS, issues a request, or follows a redirect over the network.
 * All redirect analysis is textual.
 */
import { brandOwningDomain, brandOwns, BRANDS } from '../../shared/brands.js';
import { normalizeForMatching } from '../../shared/text.js';
import type { SecuritySignal } from '../../shared/types.js';
import { describeUrl, isPrivateIpHost, openHostingSuffix, registrableDomain } from '../../shared/url.js';
import { decodeIdnHost, hasSuspiciousScriptMixing, scriptsUsed, skeleton } from '../../shared/unicode.js';
import type { AnalysisContext, LinkAnalysis, LinkHost } from '../context.js';
import { displayKey } from '../scoring/aggregate.js';
import { DETECTION_TUNING } from '../scoring/config.js';
import { brandNamingDomain, findLookalike } from './identity.js';
import { signal } from './types.js';
import type { Detect } from './types.js';

/** Words that mean "this link leads to a login form". */
const CREDENTIAL_LINK_TERMS =
  // No `portal`: it names an intranet's front page as often as a sign-in form, and plain-HTTP intranet
  // portals made a `high` of ordinary internal mail. A portal's sign-in page still says `login`.
  /\b(sign\s?in|signon|log\s?in|logon|log-on|password|passwd|credential|authenticate|authentication|verify|verification|validate|confirm|secure\s?access|account\s?access|mfa|2fa|otp|sso|webmail|owa|unlock|reactivate|re-?activate)\b/u;

/**
 * TLDs whose registry admits only vetted government registrants. `.edu` is absent on purpose: it is
 * restricted too, but compromised university sites host phishing pages often enough that a `.edu`
 * destination proves nothing about the page.
 */
const VETTED_TLDS: ReadonlySet<string> = new Set(['gov', 'mil']);

/** Link wording that acts on something a brand holds for the reader, which a headline does not. */
const ANCHOR_ACTION_TERMS =
  /\b(sign\s?in|log\s?in|logon|verify|confirm|update|review|view|open|access|download|reset|unlock|restore|secure|pay|payment|claim|activate|reactivate|validate|manage|accept|recover|account|password|document|file|invoice|voicemail|shared?|get started|start|join|continue|click|chat)\b/u;

function anchorWordCount(text: string): number {
  return text.split(/[^\p{L}\p{N}]+/u).filter((word) => word !== '').length;
}

/**
 * The brand table's strings, confusable-folded once. They are constants, and folding them inside the
 * per-link loops repeats the same work for every link × brand on a link-heavy newsletter.
 */
const FOLDED_BRANDS = BRANDS.map((brand) => ({
  brand,
  keywords: brand.keywords.map((keyword) => skeleton(keyword)),
  domains: brand.domains.map((domain) => skeleton(domain)),
  targetCores: brand.lookalikeTargets.map((target) => skeleton(target.split('.')[0] ?? '')),
}));

/**
 * Take only the first N of a repeated finding so one hostile message cannot flood the panel, after
 * saying how many links each finding applies to.
 *
 * Three links to pages in one storage bucket produce three findings that read identically, and the panel
 * shows such a finding once (`distinctForDisplay`). The count is written here rather than there because
 * only here is it true: the list is about to be capped, and a panel counting what survived the cap would
 * report three of fifteen links. The cap and the scores are otherwise untouched: how much a repeated
 * finding is worth is a scoring question, and collapsing a list for display is not the place to answer it.
 */
function limit(findings: SecuritySignal[]): SecuritySignal[] {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const key = displayKey(finding);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return findings.slice(0, DETECTION_TUNING.maxLinkSignalsPerRule).map((finding) => {
    const count = counts.get(displayKey(finding)) ?? 1;
    return count === 1
      ? finding
      : { ...finding, description: `${finding.description} This applies to ${String(count)} links in the message.` };
  });
}

/**
 * The hosts of a link a rule should judge: every one the click passes through, entry included, except a
 * recognised click tracker's own hop.
 *
 * Mail platforms rewrite hrefs to their own tracking host while the anchor still reads as the sender
 * wrote it, so the tracker's host disagreeing with the anchor is the expected state, not a finding. That
 * excuses the tracker and nothing behind it: when the destination could be decoded it is judged like any
 * other host, and when it could not, nothing is left to judge, which is the only case in which a tracker
 * should silence a rule.
 */
function judgedHosts(link: LinkAnalysis): LinkHost[] {
  return link.hosts.filter((host) => !host.knownTracker && host.registrable !== '');
}

/** A host's pathname and query, which is where a sign-in page announces itself. */
function pathAndQuery(host: LinkHost): string {
  return `${host.url.pathname} ${host.url.search}`;
}

/**
 * The anchor text reads as one URL, the href goes somewhere else.
 *
 * The highest-confidence link signal there is, and the reason the product exists: nothing about a
 * legitimate message needs the visible URL to disagree with the destination.
 */
function displayedUrlMismatch(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.links) {
    const { displayed } = link;
    if (displayed === null || link.displayedRegistrable === '') continue;

    const displayedHost = decodeIdnHost(displayed.hostname);
    const brand = brandOwningDomain(link.displayedRegistrable);
    const impersonatesBrand = brand !== undefined;

    // One of a brand's own names linking to another of them. A footer reading "report a suspicious email
    // at brand.com/phishing" whose href is a short name under the brand's own TLD is the brand's own
    // redirector, and the anti-phishing advice in genuine mail is where that shape appears most, so the
    // rule was at its most confident, `critical`, on the one sentence written to prevent the attack.
    //
    // Scoped to the brand the *displayed* domain names, not to any brand, so it cannot launder a claim:
    // showing one brand's domain while linking to a different brand's is still a mismatch. The
    // destination is checked with `brandOwns`, which counts the brand's top-level domains; comparing
    // against `domains` alone is what left the gap, since no list of second-level names covers a TLD
    // whose every registration is the brand's by registry agreement.
    const agrees = (host: LinkHost): boolean =>
      host.registrable === link.displayedRegistrable || (brand !== undefined && brandOwns(brand, host.registrable));
    const hosts = judgedHosts(link);
    const destination = hosts.at(-1);
    if (destination === undefined) continue;

    if (agrees(destination)) {
      // The click does reach the address shown, by way of a host that is not it. A mail platform we
      // have not listed does exactly this, so on an ordinary address it is left to `redirect_chain`.
      // Showing a *brand's* address while routing through somebody else is the laundering shape (an
      // open redirect behind `paypal.com` lands wherever its owner likes next week) and is reported,
      // one step below a destination that plainly disagrees. The sender's own redirector is excused for
      // the reason given below.
      const via = hosts.find((host) => !agrees(host) && host.registrable !== context.senderRegistrable);
      if (via === undefined || !impersonatesBrand) continue;
      findings.push(
        signal({
          id: `link.displayed_url_mismatch.${String(link.index)}`,
          category: 'link',
          severity: 'high',
          score: 32,
          title: 'Displayed link address is reached through a different domain',
          description: `The link is shown as "${displayedHost}", which belongs to ${brand.label}, but clicking it goes first to ${via.hostname}, which does not. Whoever controls ${via.hostname} decides where the click finally lands.`,
          evidence: {
            text: link.link.text,
            url: link.link.href,
            value: `shown: ${displayedHost} → via: ${via.hostname}`,
          },
        }),
      );
      continue;
    }

    // The same rewrite, done by a platform we have not listed: the href points back at the sender's
    // own domain. Newsletter platforms (Substack, beehiiv, Kit) send from and redirect through one
    // domain, so every outbound link in a newsletter reads as a mismatch: the observed false
    // positive this guard exists to remove.
    //
    // Suppressed rather than downgraded because there is nothing here to report: the sender is not
    // borrowing anyone's reputation, only its own. When the anchor text *is* a brand's domain the
    // borrowing is real and the finding stands, which is why this yields to `impersonatesBrand`.
    if (link.onSenderDomain && !impersonatesBrand) continue;

    // The sender showing its own address while the href goes through its email provider's tracker, which
    // is how most bulk mail is sent. Authentication is what makes this safe to excuse: a
    // spoof of the sender's domain fails it, and a sender proven to own a domain borrows nothing by
    // displaying it. Without the proof this is exactly the phish, so it stays reported. A brand in the
    // table is held to more, since its address is the one worth borrowing from a compromised account:
    // its own link hosts belong in its `domains`, where they are recognised without excusing a stranger.
    // A tracker is a plain host with an opaque path; a destination dressed in the sender's own name, or
    // asking for a sign-in, is the compromised-account shape and is never excused.
    const trackerShaped =
      !destination.hostname.includes(link.displayedRegistrable) &&
      !CREDENTIAL_LINK_TERMS.test(pathAndQuery(destination).toLowerCase());
    if (
      !impersonatesBrand &&
      link.displayedRegistrable === context.senderRegistrable &&
      context.senderProven &&
      !context.senderIsFreemail &&
      trackerShaped
    ) {
      continue;
    }
    // The converse: a proven sender showing some other ordinary address (a former name, a sister
    // brand) whose link lands on the sender's own site. Nobody's reputation is borrowed.
    if (!impersonatesBrand && context.senderProven && destination.registrable === context.senderRegistrable) {
      continue;
    }

    // Two names under a TLD whose registry vets every registrant (`.gov`, `.mil`): an agency showing its
    // short name and linking its long one. Neither end can be an attacker's registration, so the
    // mismatch is reported without the floor a stranger's destination earns.
    const vetted =
      !impersonatesBrand && VETTED_TLDS.has(displayed.hostname.split('.').at(-1) ?? '') && VETTED_TLDS.has(destination.tld);
    // An ordinary address shown through an opaque link service, from a proven sender of its own domain.
    // Most bulk mail is sent through a provider whose tracker nobody can list, and its customers show
    // their partners' and their own other addresses through it. The destination behind it cannot be
    // seen, so this is reported rather than excused; a brand's address, a visible stranger destination,
    // a sign-in path, or a sender on open hosting each keep it `high`. So do the reader's own domain on
    // display, which is the reputation a mailbox lure borrows, and a subject asking for a sign-in, since
    // a proven sender is only proven to own a domain, and phishers register those.
    const opaqueService =
      !impersonatesBrand &&
      link.displayedRegistrable !== context.recipientRegistrable &&
      !CREDENTIAL_LINK_TERMS.test(normalizeForMatching(context.subject)) &&
      context.senderProven &&
      !context.senderIsFreemail &&
      openHostingSuffix(context.senderDomain) === null &&
      destination.openHosting === null &&
      link.redirectHops === 0 &&
      trackerShaped &&
      destination.url.pathname.length > 1;
    if (vetted || opaqueService) {
      findings.push(
        signal({
          id: `link.displayed_url_mismatch.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 16,
          title: vetted
            ? 'Displayed government address links to another government address'
            : 'Displayed address goes through a link service',
          description: vetted
            ? `The link is shown as "${displayedHost}" but goes to ${destination.hostname}. Both are under a registry that vets every registrant, so this is one agency's names, not a stranger's, but the address shown is still not where the click goes.`
            : `The link is shown as "${displayedHost}" but goes to ${destination.hostname}, a link service whose final destination is not visible. Bulk mail is routinely sent this way; check where it lands before entering anything.`,
          evidence: {
            text: link.link.text,
            url: link.link.href,
            value: `shown: ${displayedHost} → actual: ${destination.hostname}`,
          },
        }),
      );
      continue;
    }

    // A brand in the table, proven, showing another brand's address through its own click host, as a
    // co-marketing offer does. Still reported (the displayed address is not where the click goes), but
    // not at the severity of a stranger doing it. Only a table brand qualifies, because a phisher can
    // authenticate a domain of their own in minutes and point a brand's address at it; what they cannot
    // do is be proven as a brand the table lists.
    const ownLinkService =
      impersonatesBrand &&
      link.onSenderDomain &&
      context.senderProven &&
      context.senderOwnedByBrand !== undefined &&
      context.senderOwnedByBrand.id !== brand.id &&
      context.primaryClaim?.brand.id !== brand.id;
    if (ownLinkService) {
      findings.push(
        signal({
          id: `link.displayed_url_mismatch.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 16,
          title: "Displayed address goes through the sender's own link service",
          description: `The link is shown as "${displayedHost}", which belongs to ${brand.label}, but clicking it goes to ${destination.hostname}, the sender's own domain, which decides where the click finally lands.`,
          evidence: {
            text: link.link.text,
            url: link.link.href,
            value: `shown: ${displayedHost} → actual: ${destination.hostname}`,
          },
        }),
      );
      continue;
    }

    findings.push(
      signal({
        id: `link.displayed_url_mismatch.${String(link.index)}`,
        category: 'link',
        severity: impersonatesBrand ? 'critical' : 'high',
        score: impersonatesBrand ? 45 : 32,
        title: 'Displayed link address differs from its actual destination',
        description: `The link is shown as "${displayedHost}" but clicking it goes to ${describeUrl(destination.url)}.${impersonatesBrand ? ` The displayed address belongs to ${brand.label}; ${destination.hostname} does not.` : ''}`,
        evidence: {
          text: link.link.text,
          url: link.link.href,
          value: `shown: ${displayedHost} → actual: ${destination.hostname}`,
        },
      }),
    );
  }

  return findings;
}

/**
 * The link text names a brand (not as a URL) while the destination is unrelated:
 * `<a href="https://evil.example">Microsoft 365 sign-in</a>`.
 *
 * Separate from `displayedUrlMismatch` because the anchor text here is prose, not a URL, so it needs
 * brand-claim logic rather than URL comparison.
 */
function anchorTextBrandMismatch(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.displayed !== null) continue; // handled by displayedUrlMismatch
    // The destination only. Prose names a brand far more loosely than a displayed URL does, and an
    // unlisted mail platform's hop in front of the brand's real page is ordinary; a hop whose own name
    // deceives is reported by the host rules, which judge every hop.
    const destination = judgedHosts(link).at(-1);
    if (destination === undefined) continue;

    const folded = skeleton(link.anchorText);
    if (folded.length < 4) continue;
    const words = new Set(link.anchorText.split(/[^\p{L}\p{N}]+/u).map((word) => skeleton(word)));

    for (const { brand, keywords } of FOLDED_BRANDS) {
      const named = keywords.some((f) =>
        f.length >= DETECTION_TUNING.minAnchorSubstringKeywordChars
          ? folded.includes(f)
          : f.length >= 5 && words.has(f),
      );
      if (!named) continue;
      // Brand-scoped, because a domain two brands both list resolves to whichever the table names first.
      if (brandOwns(brand, destination.registrable)) break;
      // Bulk senders rewrite every href through their own click-tracking host, so a footer that links
      // its social profiles by name ("LinkedIn", "Instagram", "YouTube") has an anchor naming a brand
      // and a destination that is not that brand's. That is what a social footer *is*. The sender is
      // borrowing nobody's reputation, only routing through itself, which is the whole point of
      // `onSenderDomain`.
      //
      // Yields when the message claims to be this brand, where the label is bait rather than a profile
      // link: a message presenting itself as LinkedIn, with a "LinkedIn" link to its own domain, is the
      // deception this rule exists for.
      if (link.onSenderDomain && context.primaryClaim?.brand.id !== brand.id) break;
      // The same footer behind an email provider's tracker: the entry host is the provider's, and the
      // destination the sender's own site. Only for a proven sender, since the tracker hop is a stranger.
      if (
        context.senderProven &&
        destination.registrable === context.senderRegistrable &&
        context.primaryClaim?.brand.id !== brand.id
      ) {
        break;
      }
      // A newsletter's headline names brands in passing ("Norway cancels Microsoft contract") and links
      // to the article, wherever it is hosted. Bait reads differently: it is the brand as a label, or an
      // action on something the brand holds, or it comes from a message presenting itself as the brand.
      if (
        context.primaryClaim?.brand.id !== brand.id &&
        anchorWordCount(link.anchorText) > DETECTION_TUNING.maxBrandLabelWords &&
        !ANCHOR_ACTION_TERMS.test(link.anchorText.toLowerCase())
      ) {
        break;
      }

      // A proven sender naming another brand as a bare label ("Follow on Instagram", a product it sells,
      // "Outlook for iOS" in a signature) through a host of its own or its provider's is a mention, not
      // bait: it neither claims to be the brand nor asks for anything the brand holds. The table brand
      // itself, proven, linking a host the table does not list is the table's gap, not a deception.
      // Both stay reported at `medium`; a phisher authenticating a domain of their own still meets the
      // action wording, the claim, or the identity rules, any of which keeps this `high`. A sender on
      // open hosting is proven only as one of its anonymous tenants, which proves nothing about them.
      const lower = link.anchorText.toLowerCase();
      const mention =
        context.senderProven &&
        ((context.senderOwnedByBrand?.id === brand.id) ||
          (!context.senderIsFreemail &&
            openHostingSuffix(context.senderDomain) === null &&
            context.primaryClaim?.brand.id !== brand.id &&
            !ANCHOR_ACTION_TERMS.test(lower) &&
            !CREDENTIAL_LINK_TERMS.test(lower)));

      findings.push(
        signal({
          id: `link.anchor_brand_mismatch.${String(link.index)}`,
          category: 'link',
          severity: mention ? 'medium' : 'high',
          score: mention ? 14 : 28,
          title: `Link labelled as ${brand.label} points to an unrelated domain`,
          description: `The link text refers to ${brand.label}, but the link goes to ${destination.hostname}, which ${brand.label} does not own.`,
          evidence: { text: link.link.text, url: link.link.href, value: destination.hostname },
        }),
      );
      break;
    }
  }
  return findings;
}

/**
 * A destination that is a raw IP address. Effectively never legitimate in commercial mail.
 *
 * A private address is the exception, and not a milder form of the same finding: nobody outside the
 * reader's network can serve a page from `192.168.x.x`, so it cannot be where an attacker's page lives. It
 * is what an internal tool or a device on the reader's own network looks like, which is why colleagues
 * paste them. Reported, because it is still a link that names no host, but at a severity that sets no floor.
 */
function ipAddressLinks(context: AnalysisContext): SecuritySignal[] {
  const publicLinks = firstHostPerLink(context, (h) => h.isIp && !isPrivateIpHost(h.hostname));
  const [first] = publicLinks;
  if (first === undefined) {
    const ipLinks = firstHostPerLink(context, (h) => h.isIp);
    const [local] = ipLinks;
    if (local === undefined) return [];
    return [
      signal({
        id: 'link.private_ip_url',
        category: 'link',
        severity: 'low',
        score: 8,
        title: 'Link points to an address on a private network',
        description: `${ipLinks.length === 1 ? 'A link goes' : `${String(ipLinks.length)} links go`} to ${local.host.hostname}, a private network address. It only works from inside that network, so it cannot lead to a page on the internet; it is how internal tools and home devices are reached.`,
        evidence: { url: local.link.link.href, value: local.host.hostname },
      }),
    ];
  }
  return [
    signal({
      id: 'link.ip_address_url',
      category: 'link',
      severity: 'critical',
      score: 40,
      title: 'Link points directly to an IP address',
      description: `${publicLinks.length === 1 ? 'A link goes' : `${String(publicLinks.length)} links go`} to the bare address ${first.host.hostname} instead of a domain name. Legitimate services publish hostnames; bare IPs are used to avoid registering a domain that could be taken down.`,
      evidence: { url: first.link.link.href, value: first.host.hostname },
    }),
  ];
}

/** For each web link, the first host on its path satisfying `test`, for rules reporting once per link. */
function firstHostPerLink(
  context: AnalysisContext,
  test: (host: LinkHost, link: LinkAnalysis) => boolean,
): { link: LinkAnalysis; host: LinkHost }[] {
  return context.webLinks.flatMap((link) => {
    const host = judgedHosts(link).find((candidate) => test(candidate, link));
    return host === undefined ? [] : [{ link, host }];
  });
}

/** Four octets spelled into a subdomain label, dashed or dotted: `203-0-113-7.` or `ip-203.0.113.7.`. */
const IP_IN_LABELS = /(?:^|[.-])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?=$|[.-])/u;

/**
 * A host named after its own IP address: the name a hosting provider gives every server it rents out.
 *
 * It is the bare-IP link with a domain in front, and it serves the same purpose: a page on a rented
 * machine that nobody registered a name for, so there is nothing to take down but the machine. Ordinary
 * senders link to their own names, not to a server's provider-assigned one. `medium` rather than
 * `critical`, because a provider name is also what a developer's notification about their own cloud
 * instance links to, and one on the sender's own domain is the sender's infrastructure, not a disguise.
 */
function ipNamedHostLinks(context: AnalysisContext): SecuritySignal[] {
  const named = firstHostPerLink(context, (h, link) => {
    if (h.isIp || link.onSenderDomain || h.subdomain === '') return false;
    if (h.registrable === context.senderRegistrable) return false;
    const octets = IP_IN_LABELS.exec(h.subdomain);
    return octets?.slice(1, 5).every((octet) => Number(octet) <= 255) === true;
  });
  const [first] = named;
  if (first === undefined) return [];
  return [
    signal({
      id: 'link.ip_named_host',
      category: 'link',
      severity: 'medium',
      score: 16,
      title: 'Link points to a server named after its IP address',
      description: `${named.length === 1 ? 'A link goes' : `${String(named.length)} links go`} to ${first.host.hostname}, the name a hosting provider gives a rented server rather than one anybody registered. It is a bare IP address with a domain in front.`,
      evidence: { url: first.link.link.href, value: first.host.hostname },
    }),
  ];
}

/** Punycode / mixed-script hostnames in link destinations. */
function unicodeSpoofedLinks(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const { link, host } of firstHostPerLink(context, (h) => h.isPunycode)) {
    const rendered = host.displayHost;
    const labels = rendered.split('.');
    const mixed = labels.some((l) => hasSuspiciousScriptMixing(l));
    const imitates = findLookalike(host.registrable);

    findings.push(
      signal({
        id: `link.punycode_domain.${String(link.index)}`,
        category: 'link',
        severity: mixed || imitates !== null ? 'critical' : 'medium',
        score: mixed || imitates !== null ? 40 : 18,
        title: 'Link uses an internationalised domain that renders as familiar text',
        description: imitates !== null
          ? `The link's host is ${host.hostname}, which renders as "${rendered}", visually indistinguishable from ${imitates.target}, but a different domain entirely.`
          : mixed
            ? `The link's host is ${host.hostname}, which renders as "${rendered}" using a mix of ${scriptsUsed(rendered).join(' and ')} characters. Mixed scripts inside one name are how a domain is made to look like something it is not.`
            : `The link's host is ${host.hostname}, which renders as "${rendered}". Internationalised domains are legitimate but are commonly used to imitate familiar names.`,
        evidence: { url: link.link.href, value: `${rendered} (${host.hostname})` },
      }),
    );
  }
  return findings;
}

/** A link destination that imitates a brand domain without being one. */
function lookalikeLinkDomains(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  // Every domain checked, not only those reported: a newsletter routes hundreds of links through one
  // tracking host, and the answer for a domain does not change between its links.
  const checked = new Set<string>();

  for (const link of context.webLinks) {
    for (const host of judgedHosts(link)) {
      if (checked.has(host.registrable)) continue;
      if (host.isPunycode) continue; // reported by unicodeSpoofedLinks with better wording
      checked.add(host.registrable);
      const match = findLookalike(host.registrable);
      if (match === null) continue;

      findings.push(
        signal({
          id: `link.lookalike_domain.${String(link.index)}`,
          category: 'link',
          severity: 'critical',
          score: 40,
          title: `Link destination imitates ${match.brandLabel}`,
          description: `The link goes to ${host.registrable}, a near-identical imitation of ${match.target}. It is not operated by ${match.brandLabel}.`,
          evidence: { url: link.link.href, value: `${host.registrable} vs ${match.target}` },
        }),
      );
      break;
    }
  }
  return findings;
}

/**
 * A brand's real domain appearing as a *prefix* of an unrelated domain:
 * `microsoft.com.evil-example.com`, `paypal.security-login.example`.
 *
 * A reader scanning left to right sees the brand and stops. The registrable domain is what matters.
 */
function misleadingDomainComposition(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  const reported = new Set<string>();

  for (const link of context.webLinks) {
    // One finding per link, from the first host on its path that earns one.
    for (const host of judgedHosts(link)) {
      if (misleadingComposition(context, link, host, reported, findings)) break;
    }
  }
  return findings;
}

function misleadingComposition(
  context: AnalysisContext,
  link: LinkAnalysis,
  host: LinkHost,
  reported: Set<string>,
  findings: SecuritySignal[],
): boolean {
  if (reported.has(host.hostname)) return false;
  // A brand's own domain may name its subdomains as it likes, unless it is one where anybody can
  // rent a subdomain or a bucket, where the label was chosen by the tenant and not by the brand.
  if (brandOwningDomain(host.registrable) !== undefined && host.openHosting === null) return false;

  const beforeRegistrable = host.subdomain;
  if (beforeRegistrable === '') return false;
  const foldedPrefix = skeleton(beforeRegistrable);
  const foldedTokens = beforeRegistrable.split(/[.\-_]+/u).map((token) => skeleton(token));
  const onSenderDomain = host.registrable === context.senderRegistrable;

  for (const { brand, domains, targetCores } of FOLDED_BRANDS) {
    // Match a full brand domain in the subdomain (`microsoft.com.evil.example`) or a distinctive
    // brand token (`paypal.security-login.example`). A short core has to *begin* a token, since an
    // English compound ends in one far more often than a phishing host does: `gmail` ends `bigmail`,
    // `chase` ends `purchase`, `apple` ends `pineapple`, and names like these were `critical` on
    // ordinary mail. What phishing hosts do is lead with the brand (`chasesecure.`, `apple7.`),
    // and that stays reported. The cost is a short brand fused after a word (`securechase.`); the
    // hyphenated form is still caught. A long core may appear anywhere (`securepaypal.example`).
    const domainHit = domains.some((f) => f.length >= 6 && foldedPrefix.includes(f));
    const tokenHit =
      !domainHit &&
      targetCores.some((core) => {
        if (core.length < 5) return false;
        return core.length >= 6
          ? foldedPrefix.includes(core)
          : foldedTokens.some((token) => token.startsWith(core));
      });

    if (!domainHit && !tokenHit) continue;
    // A section of the sender's own site named after a subject it covers (a news site's `apple.`
    // section) borrows nobody's reputation but its own, as a social footer on the sender's tracker
    // does in `anchorTextBrandMismatch`. It yields in the same place: a message presenting itself as
    // this brand, where a brand-named host on the sender's domain is the disguise.
    if (!domainHit && onSenderDomain && context.primaryClaim?.brand.id !== brand.id) return false;
    reported.add(host.hostname);

    findings.push(
      signal({
        id: `link.misleading_domain.${String(link.index)}`,
        category: 'link',
        severity: 'critical',
        score: 42,
        title: `Link places ${brand.label}'s name in front of an unrelated domain`,
        description: `The link reads as ${brand.label} at a glance, but the part of the address that determines where it actually goes is ${host.registrable}. Everything to the left of that, including "${beforeRegistrable}", is chosen freely by whoever controls ${host.registrable}.`,
        evidence: { url: link.link.href, value: host.hostname },
      }),
    );
    return true;
  }
  return false;
}

/** URL shorteners hide the destination, so the mismatch checks above cannot run at all. */
function shortenedLinks(context: AnalysisContext): SecuritySignal[] {
  const shortened = firstHostPerLink(context, (h) => h.isShortener);
  const [first] = shortened;
  if (first === undefined) return [];
  const credentialContext = CREDENTIAL_LINK_TERMS.test(context.matchText);

  return [
    signal({
      id: 'link.url_shortener',
      category: 'link',
      severity: credentialContext ? 'medium' : 'low',
      score: credentialContext ? 20 : 10,
      title: 'Link is hidden behind a URL shortener',
      description: `${shortened.length === 1 ? 'A link uses' : `${String(shortened.length)} links use`} the shortener ${first.host.registrable}, so the real destination cannot be seen before clicking.${credentialContext ? ' The message also asks the recipient to sign in or verify something, which is when a concealed destination matters most.' : ''}`,
      evidence: { url: first.link.link.href, value: first.host.registrable },
    }),
  ];
}

/**
 * Redirect-shaped links whose destination we cannot see, and redirect chains through hosts that are
 * not known mail trackers.
 */
function suspiciousRedirects(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    // A known tracker's hop is infrastructure; what it forwards to is judged by every host rule above,
    // which walk the whole path, so reporting the hop itself would only describe how mail is sent.
    if (link.wrappedByKnownTracker) continue;
    // A redirector on the sender's own domain is not laundering a destination behind a domain the
    // recipient recognises, which is the deception described below: it *is* the domain that sent the
    // mail. Click tracking is built this way, so flagging it reports infrastructure, not intent.
    if (link.onSenderDomain) continue;

    if (link.opaqueRedirect) {
      findings.push(
        signal({
          id: `link.opaque_redirect.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 20,
          title: 'Link is built as a redirector with a hidden target',
          description: `The link to ${link.hostname} carries a redirect parameter whose destination is encoded so that it cannot be read. Redirect chains are used to launder a malicious destination behind a domain the recipient recognises.`,
          evidence: { url: link.link.href, value: link.hostname },
        }),
      );
      continue;
    }

    if (link.redirectHops > 0 && link.redirectChain.length > 1) {
      const entry = link.redirectChain[0] ?? '';
      const exit = link.registrable;
      if (registrableDomain(entry) === exit) continue;

      findings.push(
        signal({
          id: `link.redirect_chain.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 18,
          title: 'Link redirects through one domain to reach another',
          description: `The link starts at ${entry} but redirects to ${exit}. The domain the recipient sees is not the domain that serves the page.`,
          evidence: { url: link.link.href, value: link.redirectChain.join(' → ') },
        }),
      );
    }
  }
  return findings;
}

/** Non-HTTPS destination for a page that will ask for credentials. */
function insecureCredentialLinks(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.isHttps) continue;
    const looksLikeLogin =
      CREDENTIAL_LINK_TERMS.test(link.anchorText) ||
      CREDENTIAL_LINK_TERMS.test(`${link.target?.pathname ?? ''} ${link.target?.search ?? ''}`);

    findings.push(
      signal({
        id: `link.insecure_${looksLikeLogin ? 'login' : 'http'}.${String(link.index)}`,
        category: 'link',
        severity: looksLikeLogin ? 'high' : 'low',
        score: looksLikeLogin ? 26 : 8,
        title: looksLikeLogin
          ? 'Sign-in link uses unencrypted HTTP'
          : 'Link uses unencrypted HTTP',
        description: looksLikeLogin
          ? `The link to ${link.hostname} appears to lead to a sign-in page but uses plain HTTP. No legitimate service accepts credentials over an unencrypted connection.`
          : `The link to ${link.hostname} uses plain HTTP rather than HTTPS.`,
        evidence: { url: link.link.href, value: link.hostname },
      }),
    );
  }
  return findings;
}

/**
 * How much harm a non-web scheme can do, which is not one answer for the whole list.
 *
 * `javascript:`, `data:` and the Windows handlers run code or open a remote resource on click, and a
 * `file:` link *to another machine* (`file://host/share`, or a UNC path, which the parser turns into a path
 * beginning `//`) makes Windows offer the reader's credentials to that machine. Those are `critical`. Two
 * are not, and both were `critical` on ordinary technical mail: `ftp:` is a file download Chrome no longer
 * handles itself (it can hand a file to another program but cannot run anything or show a sign-in page),
 * and a `file:` link with no host names a path on the reader's own disk, a pasted local path or a
 * `file:///C` left behind by a word processor, which nothing remote can be fetched through.
 */
function schemeHarm(link: LinkAnalysis): 'executes' | 'download' | 'local' {
  const raw = link.raw;
  if (raw === null) return 'executes';
  if (raw.protocol === 'ftp:') return 'download';
  if (raw.protocol === 'file:') {
    const host = raw.hostname.toLowerCase();
    const remote = (host !== '' && host !== 'localhost') || raw.pathname.startsWith('//');
    return remote ? 'executes' : 'local';
  }
  return 'executes';
}

const SCHEME_RANK = { executes: 2, download: 1, local: 0 } as const;

/** `javascript:`, `data:`, and other schemes that should never appear as a link in mail. */
function dangerousSchemeLinks(context: AnalysisContext): SecuritySignal[] {
  const dangerous = context.links.filter((l) => l.isDangerousScheme);
  if (dangerous.length === 0) return [];
  const first = dangerous.reduce((worst, l) => (SCHEME_RANK[schemeHarm(l)] > SCHEME_RANK[schemeHarm(worst)] ? l : worst));
  const scheme = first.raw?.protocol ?? '';
  const harm = schemeHarm(first);

  if (harm === 'download') {
    return [
      signal({
        id: 'link.ftp_link',
        category: 'link',
        severity: 'medium',
        score: 18,
        title: 'Link uses the ftp: scheme',
        description: 'A link uses "ftp:" rather than http or https. Browsers no longer open FTP themselves, so clicking it hands a file download to another program, outside the browser\'s protections. It cannot run code or show a sign-in page, but anything it downloads deserves the same caution as an attachment.',
        evidence: { value: scheme, url: first.link.href },
      }),
    ];
  }
  if (harm === 'local') {
    return [
      signal({
        id: 'link.local_file_link',
        category: 'link',
        severity: 'low',
        score: 8,
        title: 'Link points to a file on your own computer',
        description: 'A link uses "file:" with no host, so it names a path on the reader\'s own disk rather than anything on the internet. It is usually a local path pasted into the message, and cannot fetch anything from elsewhere.',
        evidence: { value: scheme, url: first.link.href },
      }),
    ];
  }

  return [
    signal({
      id: 'link.dangerous_scheme',
      category: 'link',
      severity: 'critical',
      score: 45,
      title: `Link uses the ${scheme} scheme`,
      description: `A link uses "${scheme}" rather than http or https. Schemes like this execute code or open local resources instead of loading a web page, and have no legitimate use in an email link.`,
      evidence: { value: scheme, url: first.link.href },
    }),
  ];
}

/** Malformed hosts, and hrefs that are not absolute URLs at all. */
function malformedLinks(context: AnalysisContext): SecuritySignal[] {
  const malformed = context.links.filter(
    (l) => l.isMalformed && !l.isNonNavigation && !l.isDangerousScheme && l.link.href.trim() !== '',
  );
  const [first] = malformed;
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.malformed_url',
      category: 'link',
      severity: 'low',
      score: 10,
      title: 'Message contains a malformed link',
      description: `${malformed.length === 1 ? 'A link' : `${String(malformed.length)} links`} could not be resolved to a valid web address. This is often a broken phishing template, and occasionally a parser-confusion attempt.`,
      evidence: { value: first.link.href.slice(0, 120) },
    }),
  ];
}

/** Excessive subdomain nesting used to push recognisable words into view. */
function excessiveSubdomains(context: AnalysisContext): SecuritySignal[] {
  const [first] = firstHostPerLink(
    context,
    (h) => h.subdomainLabelCount > DETECTION_TUNING.maxReasonableSubdomainLabels && !h.isIp,
  );
  if (first === undefined) return [];
  const { link, host } = first;

  return [
    signal({
      id: 'link.excessive_subdomains',
      category: 'link',
      severity: 'medium',
      score: 16,
      title: 'Link host has an unusually deep subdomain structure',
      description: `The link's host has ${String(host.subdomainLabelCount)} subdomain levels beneath ${host.registrable}. Long chains of labels are used to fill the visible part of an address with reassuring words while the controlling domain stays out of sight.`,
      evidence: { url: link.link.href, value: host.hostname },
    }),
  ];
}

/**
 * A credential-related destination on a domain that has nothing to do with the claimed brand: the
 * cross-signal case the brief calls out: "credentials/login terminology combined with unrelated
 * domains".
 */
function credentialTermsOnUnrelatedDomain(context: AnalysisContext): SecuritySignal[] {
  const claim = context.primaryClaim;
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    // The page that asks for the password is the one the click lands on, so that is the host judged,
    // including when a tracker had to be peeled to find it.
    const destination = judgedHosts(link).at(-1);
    if (destination === undefined) continue;
    const loginish =
      CREDENTIAL_LINK_TERMS.test(link.anchorText) || CREDENTIAL_LINK_TERMS.test(pathAndQuery(destination));
    if (!loginish) continue;

    const finding = credentialHostFinding(link, destination, claim);
    if (finding !== null) findings.push(finding);
  }
  return findings;
}

function credentialHostFinding(
  link: LinkAnalysis,
  host: LinkHost,
  claim: AnalysisContext['primaryClaim'],
): SecuritySignal | null {
  const openHosting = host.openHosting;
  // Ownership excuses a host only where the owner chose what is published on it. A brand that rents out
  // subdomains or buckets (Google's storage, Amazon's S3) owns the domain and none of the pages, so
  // "the brand owns this" says nothing about who wrote a sign-in page served from it.
  if (openHosting === null) {
    if (claim !== undefined && brandOwns(claim.brand, host.registrable)) return null;
    /*
     * A destination carrying the claimed brand's own name under a suffix the table does not list:
     * `paypal.it` on mail presenting itself as PayPal. Saying credentials entered there "would go to
     * whoever controls that domain" is true of every sign-in page and worthless unless the domain is
     * plainly not the brand's, which is exactly what cannot be established here. The sender-side finding
     * `identity.unverified_brand_domain` states the uncertainty once, rather than every link restating it
     * as a certainty.
     */
    if (claim !== undefined && brandNamingDomain(host.registrable)?.id === claim.brand.id) return null;
  }

  if (claim !== undefined && brandOwningDomain(host.registrable) === undefined) {
    return signal({
      id: `link.credential_link_unrelated_domain.${String(link.index)}`,
      category: 'link',
      severity: 'high',
      score: 30,
      title: `Sign-in link for ${claim.brand.label} leads to a domain ${claim.brand.label} does not own`,
      description: `The message presents itself as ${claim.brand.label} and the link leads to a sign-in or verification page, but the page is hosted at ${host.registrable}. Credentials entered there would go to whoever controls that domain.`,
      evidence: { url: link.link.href, value: host.registrable, text: link.link.text },
    });
  }

  if (openHosting === null) return null;
  return signal({
    id: `link.credential_link_open_hosting.${String(link.index)}`,
    category: 'link',
    severity: 'high',
    score: 26,
    title: 'Sign-in link is hosted on a free hosting service',
    description: `The link leads to a sign-in or verification page ${describeOpenHost(host.hostname, openHosting)}. Anyone can publish there in seconds, so the address carries no indication of who is actually behind the page.`,
    evidence: { url: link.link.href, value: host.hostname },
  });
}

/**
 * Wording for an open host, which is either a tenant subdomain or the storage service itself.
 *
 * Worth branching on: calling `storage.googleapis.com` "a subdomain of storage.googleapis.com" is the
 * kind of sentence that makes a reader stop trusting the whole explanation.
 */
function describeOpenHost(hostname: string, openHosting: string): string {
  return hostname === openHosting
    ? `on ${openHosting}, where the page is stored as a file`
    : `at ${hostname}, a subdomain of ${openHosting}`;
}

/**
 * The link opens a web page that is a **file in a public storage bucket** rather than a page on
 * anybody's website.
 *
 * This is the shape that defeats every other link rule at once, and it is now the common one. The
 * destination is `storage.googleapis.com`, `s3.amazonaws.com` or a sibling: a real domain, owned by
 * Google or Amazon, with valid HTTPS and no lookalike spelling, no shortener, no redirect and no
 * punycode. Nothing about the *host* is wrong. What is wrong is that the host identifies the storage
 * provider and not the author: anyone with an account can upload `page.html` and serve it from an
 * address that reads as impeccable, which is precisely why phishing kits are hosted this way.
 *
 * Two conditions keep it off ordinary mail. The path must name an **HTML document**, because that is what
 * separates a page pretending to be a website from the legitimate uses of object storage, which are
 * images, PDFs and downloads. And the escalation to `high` requires the *message* to be asking for
 * something (a sign-in, an unlock, a renewal, a payment), since a bare link to a hosted document is
 * unremarkable while the same link under "your account will be deleted" is the whole attack.
 */
function pageServedFromOpenStorage(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  const asking =
    CREDENTIAL_LINK_TERMS.test(context.matchText) || ACCOUNT_ACTION_TERMS.test(context.matchText);

  for (const link of context.webLinks) {
    const stored = judgedHosts(link).at(-1);
    const openHosting = stored?.openHosting ?? null;
    if (stored === undefined || openHosting === null) continue;
    if (stored.registrable === context.senderRegistrable) continue;
    if (!HTML_DOCUMENT_PATH.test(stored.url.pathname)) continue;

    // A sign-in page on an open host is the same link described better by
    // `credentialTermsOnUnrelatedDomain`, which can say what the page asks for. Two findings about one
    // link, differing only in wording, spend the reader's attention twice for one fact.
    if (CREDENTIAL_LINK_TERMS.test(link.anchorText) || CREDENTIAL_LINK_TERMS.test(pathAndQuery(stored))) {
      continue;
    }

    findings.push(
      signal({
        id: `link.page_in_open_storage.${String(link.index)}`,
        category: 'link',
        severity: asking ? 'high' : 'medium',
        score: asking ? 26 : 16,
        title: 'Link opens a page stored as a file on a public hosting service',
        description: `The link goes to a web page held as a file on ${openHosting}. The address belongs to the storage provider, not to whoever wrote the page: anyone with an account can upload a file there and it will be served from that domain. A real organisation publishes pages on its own site${asking ? ', and this message is asking you to act on one' : ''}.`,
        evidence: { url: link.link.href, value: stored.hostname, text: link.link.text },
      }),
    );
  }
  return findings;
}

/** A path whose last segment is an HTML document, i.e. a page rather than an asset or a download. */
const HTML_DOCUMENT_PATH = /\.(html?|shtml|xhtml|php|asp|aspx|jsp)$/iu;

/**
 * Wording that makes a message a demand for action on an account, beyond the credential vocabulary in
 * `CREDENTIAL_LINK_TERMS`. Subscription and billing language belongs here rather than there: "renew your
 * subscription" is not a sign-in request, and it puts the same pressure behind the same click.
 */
const ACCOUNT_ACTION_TERMS =
  /\b(renew|renewal|reactivate|upgrade|subscription|billing|invoice|payment (declined|failed|method)|past due|storage (is )?(full|limit)|out of (storage|space)|will be (deleted|removed|suspended|closed)|update your (payment|billing|card))\b/u;

/**
 * A destination whose TLD is also a common file extension, so the address reads as a filename.
 *
 * Reported on its own merits rather than only alongside a credential ask: the confusion is the whole
 * point of `payroll-2024.zip` being a *website*, and a reader who mistakes it for an attachment has
 * already been deceived regardless of what the page then asks for.
 */
function filenameLookalikeTldLinks(context: AnalysisContext): SecuritySignal[] {
  const [first] = firstHostPerLink(
    context,
    (h) => (h.tld === 'zip' || h.tld === 'mov') && brandOwningDomain(h.registrable) === undefined,
  );
  if (first === undefined) return [];
  const { link, host } = first;

  return [
    signal({
      id: 'link.filename_lookalike_tld',
      category: 'link',
      severity: 'medium',
      score: 16,
      title: `Link uses the .${host.tld} top-level domain, which looks like a filename`,
      description: `The link goes to ${host.hostname}. Because ".${host.tld}" is also a common file extension, text like this is frequently mistaken for an attachment name rather than a web address.`,
      evidence: { url: link.link.href, value: host.hostname },
    }),
  ];
}

/**
 * Link text written as an attachment's filename, so it reads as a file in the message.
 *
 * Bounded to a single name of a few words ending in a document, archive or image extension, which is
 * what an attachment chip shows; a sentence that ends in ".pdf" is not one.
 */
const FILE_LABEL =
  /^(?:[^\s/\\<>:"|?*]+ ){0,8}[^\s/\\<>:"|?*]+\.(pdf|docx?|docm|xlsx?|xlsm|pptx?|csv|txt|rtf|odt|ods|eml|msg|zip|rar|7z|png|jpe?g|heic|tiff?)$/iu;

/**
 * Whether an address carries the labelled filename, as a hosted help desk's attachment download does
 * (`/attachments/token/…?name=photo.jpeg`). Such a link serves the file under an opaque path, so a
 * path-extension check alone would call every help-desk reply a fake attachment.
 */
function namesFile(host: LinkHost, filename: string): boolean {
  const wanted = filename.toLowerCase();
  let address: string;
  try {
    address = decodeURIComponent(pathAndQuery(host)).toLowerCase();
  } catch {
    address = pathAndQuery(host).toLowerCase();
  }
  return address.includes(wanted) || address.includes(wanted.replaceAll(' ', '+'));
}

/**
 * A link labelled as an attached file that opens something other than that file somewhere else.
 *
 * "Annual-Leave-Compliance-Report-2024.pdf" in the body, linked to a web page on an unrelated site, is a
 * fake attachment: the reader expects a document in the message and gets a page that asks for a sign-in.
 * What a reader can check is the mismatch itself (the label names a file, and the address is not that
 * file), so that is the whole condition, and each exemption is a place where it is ordinary:
 *  - the sender's own hosts, where a support desk or document system serves its own attachments;
 *  - a brand's file service (a Drive or OneDrive chip), where a shared file is a page by design;
 *  - a destination that really is the named file, which is a download, not a disguise.
 * A tracker that hides its destination is passed over rather than judged: the mismatch is the evidence,
 * and a newsletter's tracked "Brochure.pdf" offers none a reader could check.
 */
function fakeAttachmentLinks(context: AnalysisContext): SecuritySignal[] {
  for (const link of context.webLinks) {
    if (link.onSenderDomain || link.displayed !== null || link.opaqueRedirect) continue;
    const label = FILE_LABEL.exec(link.link.text.trim());
    if (label === null) continue;

    const destination = judgedHosts(link).at(-1);
    if (destination === undefined || destination.registrable === '') continue;
    if (destination.registrable === context.senderRegistrable) continue;
    if (brandOwningDomain(destination.registrable) !== undefined && destination.openHosting === null) continue;
    const extension = (label[1] ?? '').toLowerCase();
    if (destination.url.pathname.toLowerCase().endsWith(`.${extension}`)) continue;
    if (namesFile(destination, link.link.text.trim())) continue;

    return [
      signal({
        id: `link.fake_attachment.${String(link.index)}`,
        category: 'link',
        severity: 'high',
        score: 26,
        title: 'Link is labelled as an attached file but opens a web page elsewhere',
        description: `The link reads "${link.link.text.trim()}", like an attachment, but it opens ${destination.hostname}, which is not that file and not the sender's own site. A real attachment is in the message, not on someone else's web page.`,
        evidence: { text: link.link.text, url: link.link.href, value: destination.hostname },
      }),
    ];
  }
  return [];
}

/**
 * A subject that asks the reader to act on an account, a held message, a payment or a shared document.
 *
 * Read only when the body has no words, since then the subject is the one piece of the lure that is text:
 * the rest is a picture of a sign-in notice, which nothing here reads.
 */
const SUBJECT_ACTION_TERMS =
  /\b(action required|required action|immediate action|final (reminder|notice|warning)|(messages?|emails?|mails?) (on hold|held|pending|undelivered|suspended)|incoming messages|password (expir\w*|reset)|mailbox|account (suspended|locked|disabled|on hold|verification|update)|verify your|we (still )?need (some )?information|payment (processed|received|confirmation|declined|failed)|remittance|invoice|shared (a |an )?(file|document|folder)|sent you (a |an )?(message|document|file)|documento|signature (requested|required)|review and sign|expir(es|ation|ing) (on|soon|today)|renewing)\b/u;

/**
 * Attacker-controlled destination for a message that also carries no readable text: a bare
 * "click here" body, which exists only to get the click.
 *
 * With an action-asking subject it is `medium`: an image-only lure has exactly this shape, its notice
 * drawn as a picture so no wording check can read it, and the picture linked off-site. A table brand
 * Gmail proves is exempt from the escalation, since image-heavy announcements are how some of them write.
 * It stays below a floor because a bare image newsletter is the same shape without the subject's ask.
 */
function linkOnlyBody(context: AnalysisContext): SecuritySignal[] {
  if (context.webLinks.length === 0) return [];
  const chars = context.bodyText.trim().length;
  if (chars >= DETECTION_TUNING.minimalBodyChars) return [];
  const [first] = context.webLinks.filter(
    (l) => l.registrable !== '' && l.registrable !== context.senderRegistrable,
  );
  if (first === undefined) return [];

  const ask = SUBJECT_ACTION_TERMS.exec(normalizeForMatching(context.subject));
  if (ask !== null && !(context.senderProven && context.senderOwnedByBrand !== undefined)) {
    return [
      signal({
        id: 'link.link_only_body',
        category: 'link',
        severity: 'medium',
        score: 25,
        title: 'Message asks for action but its body is only a link',
        description: `The subject asks you to act ("${ask[0]}"), but the message has almost no readable text (${String(chars)} characters) and links to ${first.registrable}. A notice drawn as a picture says nothing that can be checked, and is how a lure avoids being read.`,
        evidence: { text: context.subject, url: first.link.href },
      }),
    ];
  }

  return [
    signal({
      id: 'link.link_only_body',
      category: 'link',
      severity: 'low',
      score: 10,
      title: 'Message body is almost entirely a link',
      description: `The message contains very little readable text (${String(context.bodyText.trim().length)} characters) but does contain links to other domains. Minimal-context messages avoid saying anything that could be checked.`,
      evidence: { url: first.link.href },
    }),
  ];
}

/**
 * A `label: value` line. The label is short and holds a letter, so a clock time or a URL's scheme is not
 * a field; the colon may be full-width, as forms in Chinese and Japanese write it. The value may be empty
 * here and arrive on the lines below, which is how a form laid out as a table reads once its cells are
 * separated.
 */
const FORM_FIELD = /^([^:：\n]{0,40}\p{L}[^:：\n]{0,40}?)[:：] ?(.*)$/u;

/** A line that is a URL on its own reads as `https: //…`, and is text, not a field. */
function formField(line: string): RegExpExecArray | null {
  const match = FORM_FIELD.exec(line);
  return match === null || (match[2] ?? '').startsWith('//') ? null : match;
}

const ADDRESS_IN_TEXT = /[\p{L}\p{N}._%+-]{1,64}@[\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63}){1,8}/gu;
const URL_IN_TEXT = /\bhttps?:\/\/\S{1,2000}/giu;
const MAX_FORM_ECHO_LINES = 400;
const MAX_FORM_ECHO_LINE_CHARS = 2000;

/** Plus-tags and Gmail's ignored dots do not change whose mailbox an address is. */
function mailboxKey(address: string): string {
  const at = address.lastIndexOf('@');
  if (at <= 0) return '';
  let local = address.slice(0, at).toLowerCase().replace(/\+.*$/u, '');
  let domain = address.slice(at + 1).toLowerCase().replace(/\.$/u, '');
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./gu, '');
  return local === '' ? '' : `${local}@${domain}`;
}

interface FormField {
  line: number;
  label: string;
  /** The value with any lines that continue it, as free text does. */
  value: string;
}

/**
 * A web form's automatic reply, repeating a submission that gave the reader's address as the submitter's,
 * with a link inside what the submitter typed.
 *
 * Contact-form abuse. A spammer types a lure into a real company's contact form, puts the victim's address
 * in the email field, and the company's autoresponder mails a copy of the submission to the victim. Every
 * identity check passes, because the mail really is from the company and authenticates as it; the words
 * and the link are the spammer's, delivered with someone else's reputation. Nothing about a brand or a
 * language is needed to see it: the form names the reader as its author, and the link sits in a field
 * someone typed into.
 *
 * Each bound has a genuine message behind it:
 *  - **The reader's address must be a field's whole value**, among at least `minFormEchoFields` fields.
 *    An address in running text is a greeting or a footer, and an account notice states it on one line.
 *  - **No outside address may be a field's value.** A forwarded message quotes a header block (From,
 *    To, Date, Subject) whose To line is the reader, and its From line is what separates it from a form.
 *    The sender's own addresses do not count, because an autoresponder's signature lists them.
 *  - **The link must be inside free text**, `minFormEchoFreeTextChars` beyond its URL. An order
 *    confirmation echoes "Tracking: https://…" and a profile form "Website: https://…", which are values
 *    the reader would recognise; a link inside a paragraph is a message.
 *  - **Not the sender's domain and not the reader's**, since a company linking itself and a reader who
 *    typed their own site into the form are each what a genuine submission contains.
 *
 * `medium`, with no floor. A reader who really did fill in the form and pasted a link into it gets this
 * finding too, and the wording tells them how to check it: they know whether they wrote that message.
 */
function echoedFormSubmission(context: AnalysisContext): SecuritySignal[] {
  const reader = mailboxKey(context.email.recipientEmail ?? '');
  if (reader === '') return [];

  const lines = context.bodyText.split('\n', MAX_FORM_ECHO_LINES).map((line) => line.trim().slice(0, MAX_FORM_ECHO_LINE_CHARS));
  const fields: FormField[] = [];
  for (let i = 0; i < lines.length; i++) {
    const match = formField(lines[i] ?? '');
    if (match === null) continue;
    let value = match[2] ?? '';
    for (let next = i + 1; next < lines.length && next <= i + DETECTION_TUNING.formEchoWindowLines; next++) {
      const continuation = lines[next] ?? '';
      if (continuation === '' || formField(continuation) !== null) break;
      value += ` ${continuation}`;
    }
    value = value.trim();
    if (value !== '') fields.push({ line: i, label: (match[1] ?? '').trim(), value });
  }

  const own = fields.find((field) => mailboxKey(field.value.replace(/^<|>$/gu, '').replace(/^mailto:/iu, '')) === reader);
  if (own === undefined) return [];

  const window = DETECTION_TUNING.formEchoWindowLines;
  const form = fields.filter((field) => Math.abs(field.line - own.line) <= window);
  if (form.length < DETECTION_TUNING.minFormEchoFields) return [];
  const strangerAddress = form.some((field) =>
    [...field.value.matchAll(ADDRESS_IN_TEXT)].some(
      (found) =>
        mailboxKey(found[0]) !== reader &&
        registrableDomain(found[0].slice(found[0].lastIndexOf('@') + 1)) !== context.senderRegistrable,
    ),
  );
  if (strangerAddress) return [];

  for (const field of form) {
    if (field === own) continue;
    const prose = field.value.replace(URL_IN_TEXT, ' ');
    if (prose === field.value) continue;
    if ((prose.match(/[\p{L}\p{N}]/gu)?.length ?? 0) < DETECTION_TUNING.minFormEchoFreeTextChars) continue;
    const typed = field.value.toLowerCase();

    for (const link of context.webLinks) {
      if (!link.hosts.some((host) => typed.includes(host.hostname))) continue;
      const destination = judgedHosts(link).at(-1);
      if (destination === undefined) continue;
      if (destination.registrable === context.senderRegistrable) continue;
      if (destination.registrable === context.recipientRegistrable) continue;

      return [
        signal({
          id: `link.echoed_form_link.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 22,
          title: 'Form confirmation repeats a link submitted under your address',
          description: `This reads as a web form's automatic confirmation, and the form gives your address as the person who filled it in. The text submitted in its "${field.label}" field links to ${destination.hostname}, which is not ${context.senderRegistrable}. Spammers type other people's addresses into a company's contact form so that the company's own mail server delivers their link: the sender is genuine, but those words are not theirs. If you did not fill in this form, nothing in it came from the company.`,
          evidence: { text: field.value.slice(0, 300), url: link.link.href, value: destination.hostname },
        }),
      ];
    }
  }
  return [];
}

const linkDetectors: Detect[] = [
  displayedUrlMismatch,
  anchorTextBrandMismatch,
  ipAddressLinks,
  ipNamedHostLinks,
  unicodeSpoofedLinks,
  lookalikeLinkDomains,
  misleadingDomainComposition,
  shortenedLinks,
  suspiciousRedirects,
  insecureCredentialLinks,
  dangerousSchemeLinks,
  malformedLinks,
  excessiveSubdomains,
  credentialTermsOnUnrelatedDomain,
  pageServedFromOpenStorage,
  filenameLookalikeTldLinks,
  fakeAttachmentLinks,
  echoedFormSubmission,
  linkOnlyBody,
] as const;

/** Capped here, once, so no per-link rule can flood the panel by forgetting to cap itself. */
export function detectLinkSignals(context: AnalysisContext): SecuritySignal[] {
  return linkDetectors.flatMap((detect) => limit(detect(context)));
}
