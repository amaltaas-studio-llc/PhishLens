/**
 * Rule engine entry point: run every deterministic detector, then refine.
 *
 * "Refine" is the false-positive-resistance stage (docs/adr/0005-false-positive-resistance.md). It is a separate pass
 * rather than logic inside detectors because dampening needs to see *all* the signals to decide:
 * a content heuristic can only be safely softened once we know no link or identity rule fired.
 */
import { brandOwns } from '../../shared/brands.js';
import type { SecuritySignal } from '../../shared/types.js';
import type { AnalysisContext } from '../context.js';
import { DAMPENING } from '../scoring/config.js';
import { isAtLeast, lowerSeverity } from '../scoring/aggregate.js';
import { detectAttachmentSignals } from './attachments.js';
import { detectAuthenticationSignals } from './authentication.js';
import { detectContentSignals } from './content.js';
import { detectCorrelatedSignals } from './correlate.js';
import { detectIdentitySignals } from './identity.js';
import { detectLinkSignals } from './links.js';
import { detectThreadSignals } from './thread.js';

export function runRuleEngine(context: AnalysisContext): SecuritySignal[] {
  const perCategory = [
    ...detectAuthenticationSignals(context),
    ...detectIdentitySignals(context),
    ...detectThreadSignals(context),
    ...detectLinkSignals(context),
    ...detectAttachmentSignals(context),
    ...detectContentSignals(context),
  ];

  const correlated = detectCorrelatedSignals(perCategory, context);
  return refine([...perCategory, ...correlated], context);
}

/**
 * Softens `content` signals when the sender is provably who it claims to be and nothing technical
 * looks wrong.
 *
 * This is what separates "your PayPal password was reset" from paypal.com (score ~5) from the same
 * text from `paypal-secure.example` (score ~70). Both contain identical social-engineering keywords;
 * only one has a verifiable sender.
 *
 * There are two ways to be provably who you claim to be. The curated brand table proves it for the
 * organisations in it; a user's own trust entry proves it for the rest, but only for a message Gmail
 * could tie to that domain (`shared/trust.ts`). The second is why this stage takes the user's list at
 * all: without it, dampening is only ever available to organisations somebody thought to enumerate.
 *
 * Constraints, enforced here rather than by convention:
 *  - only categories in `DAMPENING.dampenableCategories` are ever touched (currently just `content`);
 *  - severity and score only ever move *down*, and no finding is ever removed;
 *  - a single `medium`-or-worse technical finding cancels dampening entirely;
 *  - neither proof softens a `high` or `critical` finding, because the sender being genuine is exactly
 *    the situation a compromised account produces, save the fake-sign-in combinations a verified
 *    brand with aligned links refutes (`DAMPENING.refutableCombinations`).
 */
function refine(signals: SecuritySignal[], context: AnalysisContext): SecuritySignal[] {
  const hasBlockingFinding = signals.some(
    (s) =>
      DAMPENING.blockingCategories.includes(s.category) &&
      isAtLeast(s.severity, DAMPENING.blockingMinSeverity),
  );

  /*
   * Proof of origin first, and for the same reason trust needs it: a From header is a claim, and forging a
   * famous one is the attack. Dampening on the domain alone therefore rewarded exactly the mail it should
   * punish: "send me your verification code" from a `paypal.com` address that nothing tied to PayPal came
   * out at 8/100 and Low Risk, the most reassuring thing this extension can say, about an unverified sender
   * making a request no real organisation makes. With a valid PayPal signature the same message still lands
   * in `low`, which is the half worth keeping.
   *
   * A brand-owned domain says the organisation runs the mail service. It does not say the mailbox speaks
   * for the organisation, and for a consumer mail provider it says close to the opposite: `gmail.com` is
   * Google's, so every personal Gmail account was arriving here as a verified brand and having its
   * `content` findings quartered and its combinations zeroed. "Please send me your verification code"
   * from a stranger's Gmail scored 13/100 and Low Risk; the same sentence from a domain nobody has
   * enumerated scored 50. The brand table is right to list those domains (that is what makes `gmai1.com`
   * a lookalike), so the fix belongs here, at the one place that treats ownership as authority.
   *
   * Both branches are gated, not just the claimless one: a message from a personal Gmail account that
   * *claims* to be Google is an impersonation attempt, and it would otherwise satisfy
   * `senderAlignedWithClaim` and be softened for saying so.
   */
  const senderIsVerifiedBrand =
    context.senderProven &&
    !context.senderIsFreemail &&
    (context.senderAlignedWithClaim ||
      (context.senderOwnedByBrand !== undefined && context.primaryClaim === undefined));

  // Links that resolve to the sender's own organisation or to the brand it legitimately is, at every
  // host the click passes through. A recognised tracker's own hop is excused; what it forwards to is not,
  // since a tracker on the sender's account will forward to any address the sender typed.
  const owner = context.senderOwnedByBrand;
  const allLinksAligned =
    context.webLinks.length > 0 &&
    context.webLinks.every((link) => {
      if (link.hosts.length === 0) return false;
      return link.hosts.every((host) => {
        if (host.knownTracker) return true;
        if (host.registrable === '') return false;
        if (host.registrable === context.senderRegistrable) return true;
        return owner !== undefined && brandOwns(owner, host.registrable);
      });
    });

  const brandDampens =
    senderIsVerifiedBrand && (allLinksAligned || context.webLinks.length === 0);
  /*
   * Trust does not require every link to stay inside the sender's organisation, which brand dampening
   * does. A verified brand's mail linking elsewhere is unusual enough to be worth noticing; an
   * arbitrary organisation's mail linking to its payment processor, its survey tool or its own docs
   * host is simply what mail looks like, and requiring alignment would mean the feature almost never
   * applied. What protects this is unchanged: a link worth a `medium` finding cancels dampening.
   */
  const trustDampens = context.senderTrusted;

  if (hasBlockingFinding || !(brandDampens || trustDampens)) return signals;

  const brandLabel =
    context.primaryClaim?.brand.label ?? context.senderOwnedByBrand?.label ?? context.senderRegistrable;

  const explanation = brandDampens
    ? `Weighted down because this message was sent from ${context.senderRegistrable}, a domain ${brandLabel} genuinely owns, and every link in it stays within that organisation.`
    : `Weighted down because you trust ${context.trustedEntry ?? context.senderRegistrable} and Gmail confirmed this message really came from there.`;

  return signals.map((s) => {
    if (!DAMPENING.dampenableCategories.includes(s.category)) return s;
    if (s.severity === 'info') return s;
    // Neither proof softens a `high` or `critical` finding, with one exception below. A genuine sender is
    // exactly what a compromised account looks like, and the brand's own signature on "change the
    // payee's bank details" makes that request no less dangerous to act on.
    const refutable =
      brandDampens &&
      DAMPENING.refutableCombinations.some((id) => s.id === `content.${DAMPENING.combinationIdPrefix}${id}`);
    if (isAtLeast(s.severity, 'high') && !refutable) return s;

    // Refutable combinations are zeroed rather than merely downgraded. Their entire claim is an
    // inference about *intent* drawn from two themes co-occurring ("urgency plus a credential request
    // means someone is rushing you onto a fake login page"). Once the sender is verified as the
    // organisation it claims to be and every link stays inside it, that inference has no basis; the
    // co-occurrence is just what a real password-reset notice looks like. The finding stays visible
    // for transparency, scoring nothing, instead of being deleted.
    if (refutable) {
      return {
        ...s,
        severity: 'info' as const,
        score: 0,
        dampened: true,
        description: `${s.description} ${explanation} Because the sender is verified, this combination is reported for transparency but does not affect the score.`,
      };
    }

    return {
      ...s,
      severity: lowerSeverity(s.severity, DAMPENING.alignedSenderSeverityDrop),
      score: Math.round(s.score * DAMPENING.alignedSenderScoreFactor),
      dampened: true,
      description: `${s.description} ${explanation}`,
    };
  });
}
