/**
 * End-to-end detection tests against fixtures.
 *
 * Runs the real pipeline (context building, every detector, refinement, aggregation, classification)
 * in plain Node with no Chrome and no Gmail.
 */
import { describe, expect, it } from 'vitest';
import { buildContext } from '../src/analysis/context.js';
import type { ThreadParty } from '../src/analysis/context.js';
import { analyze, analyzeDeterministic, countedFindings } from '../src/analysis/engine.js';
import { CATEGORY_WEIGHTS } from '../src/analysis/scoring/config.js';
import { findParticipantLookalike, __testables as threadTestables } from '../src/analysis/rules/thread.js';
import { __testables as contentTestables } from '../src/analysis/rules/content.js';
import { __testables as adapterTestables } from '../src/gmail/dom-adapter.js';
import {
  brandNamingDomain,
  findLookalike,
  isCaseScrambled,
  repeatedUnitCount,
} from '../src/analysis/rules/identity.js';
import { distinctForDisplay, scoreFloor, severityFloor } from '../src/analysis/scoring/aggregate.js';
import { triageSender } from '../src/analysis/triage.js';
import { BRANDS, brandOwningDomain } from '../src/shared/brands.js';
import { fileExtension, fileExtensionChain } from '../src/shared/text.js';
import { hasUnknownTld, registrableDomain } from '../src/shared/url.js';
import type {
  AnalysisResult,
  EmailMessage,
  SecuritySignal,
  SemanticAnalysis,
  SemanticAnalyzer,
} from '../src/shared/types.js';
import { loadFixture, loadAllFixtures, toEmailAttachment, toEmailLink } from './fixtures/load.js';

const LANGUAGE_IDS = ['es', 'fr', 'de', 'pt', 'it', 'nl', 'hi', 'hinglish'] as const;

const LEGITIMATE_FIXTURES = [
  'legitimate',
  'legitimate-password-reset',
  'legitimate-newsletter',
  'legitimate-substack-newsletter',
  'legitimate-institutional-newsletter',
  'legitimate-invoice',
  'legitimate-e-invoice',
  'legitimate-thread-reply',
  'legitimate-verification-code',
  'legitimate-brand-product-name',
  'legitimate-brand-tld',
  'legitimate-settlement-notice',
  'legitimate-antivirus-renewal',
  'legitimate-hosted-service-desk',
  'legitimate-help-desk-attachment',
  'legitimate-image-newsletter',
  'legitimate-drive-share',
  'legitimate-contact-form-confirmation',
  ...LANGUAGE_IDS.flatMap((id) => [
    `northwind-${id}-verification-code`,
    `northwind-${id}-newsletter`,
  ]),
];

/**
 * Genuine mail whose sender cannot be *proved* genuine from the message, which is a third outcome the
 * corpus needs a name for.
 *
 * `paypal.it` is either PayPal Italy or somebody who registered PayPal's name in Italy, and nothing in the
 * mail distinguishes them. Demanding `low` here would mean pretending the ambiguity is resolved, and
 * demanding `high` (which is what the lookalike rule did) means calling authentic mail an imitation. So
 * these are held to a different standard: no `high` or `critical` deterministic signal and no severity
 * floor, as with any legitimate fixture, but `caution` rather than `low`, carrying the finding that says
 * which part could not be confirmed.
 */
const UNVERIFIABLE_FIXTURES = ['legitimate-brand-country-domain'];

/** Everything that must never produce a `high` deterministic signal, which is what makes floors safe. */
const HONEST_FIXTURES = [...LEGITIMATE_FIXTURES, ...UNVERIFIABLE_FIXTURES];

const MALICIOUS_FIXTURES = [
  'visible-clipping-code-request',
  'sender-host-brand-domain',
  'paypal-phish',
  'microsoft-phish',
  'bec-gift-card',
  'payroll-change',
  'punycode-link',
  'ip-url',
  'executable-attachment',
  'soft-hyphen-executable',
  'mfa-code-request',
  'anchor-mismatch',
  'zip-attachment',
  'brand-spoof-leadgen',
  'thread-hijack-lookalike',
  'thread-hijack-name-reuse',
  'storage-quota-bucket-page',
  'storage-payment-bucket-page',
  'settlement-credential-phish',
  'antivirus-renewal-scam',
  'own-organisation-mailbox-phish',
  'fake-attachment-link',
  'shared-item-alert-lure',
  ...LANGUAGE_IDS.map((id) => `northwind-${id}-credential-phish`),
];

/**
 * Phishing whose evidence is too thin for `suspicious`, held to `caution` instead of being left out.
 *
 * An image-only lure's one readable part is its subject, and a floor from a subject alone would land on
 * ordinary mail. Leaving such fixtures unlisted would check them in neither direction; holding them to the
 * malicious corpus's bar would force a floor the evidence does not support.
 */
const CAUTION_ONLY_FIXTURES = ['image-only-mailbox-lure', 'echoed-form-lure'];

const FIXED_NOW = 1_760_000_000_000;

function analyzeFixture(name: string): AnalysisResult {
  return analyzeDeterministic(loadFixture(name).email, { now: FIXED_NOW });
}

function ids(result: AnalysisResult): string[] {
  return result.signals.map((s) => s.id);
}

/** Matches exact ids and the `rule.name.<index>` form the per-link rules emit. */
function hasSignal(result: AnalysisResult, id: string): boolean {
  return result.signals.some((s) => s.id === id || s.id.startsWith(`${id}.`));
}

function signalFor(result: AnalysisResult, id: string): SecuritySignal | undefined {
  return result.signals.find((s) => s.id === id || s.id.startsWith(`${id}.`));
}

// ---------------------------------------------------------------------------
// Legitimate mail
// ---------------------------------------------------------------------------

describe('legitimate email', () => {
  const result = analyzeFixture('legitimate');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('raises no identity, link, or content findings', () => {
    const scoring = result.signals.filter((s) => s.severity !== 'info');
    expect(scoring).toEqual([]);
  });

  it('still reports the positive authentication result for transparency', () => {
    expect(hasSignal(result, 'authentication.passed')).toBe(true);
    expect(signalFor(result, 'authentication.passed')?.score).toBe(0);
  });

  it('reports that the attachment is not suspicious rather than staying silent', () => {
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(true);
  });

  /**
   * Those two transparency signals are why a count of findings cannot be a count of signals. Ordinary
   * authenticated mail carries both, so counting every signal told a reader with a clean inbox that
   * ShoutPhish had found something, on the surface most likely to be read alone. The badge counted
   * correctly and the popup did not, which is how the disagreement was noticed.
   */
  it('counts none of its transparency signals as findings', () => {
    expect(result.signals.length).toBeGreaterThan(0);
    expect(countedFindings(result)).toEqual([]);
  });

  /**
   * The other direction, because scoring zero is not the test. A combination finding from a sender the
   * reader verified is zeroed and kept, and it is exactly the kind of thing they should be told about:
   * something was found, and the reason it stopped counting is one they can see and undo.
   */
  it('counts a finding that was dampened to zero', () => {
    const [note] = result.signals;
    expect(note).toBeDefined();
    if (note === undefined) return;

    const dampened = { ...result, signals: [{ ...note, score: 0, dampened: true }] };
    expect(countedFindings(dampened)).toHaveLength(1);
  });

  it('contributes nothing from the llm category', () => {
    expect(result.categoryScores.llm).toBe(0);
    expect(result.meta.semanticSource).toBe('none');
  });
});

/**
 * A court-directed notice names the defendant in its sender line and is sent by a claims administrator.
 * The display-name rule's premise, that the name claims to *be* the brand, is false for it, and at `high`
 * its floor made every genuine notice Suspicious. The pair below pins both halves: the notice loses the
 * floor but keeps a finding saying the brand did not send it, and the same sender name asking for a
 * password is as critical as any other impersonation.
 */
describe('a settlement notice that names a brand', () => {
  const notice = analyzeFixture('legitimate-settlement-notice');
  const phish = analyzeFixture('settlement-credential-phish');

  it('says the brand did not send it, without calling it impersonation', () => {
    expect(hasSignal(notice, 'identity.display_name_impersonation')).toBe(false);
    const finding = signalFor(notice, 'identity.brand_named_in_legal_notice');
    expect(finding?.severity).toBe('medium');
    expect(finding?.title).toMatch(/not from Microsoft/u);
    expect(notice.classification).toBe('low');
  });

  it('still treats the same sender name asking for a password as impersonation', () => {
    expect(hasSignal(phish, 'identity.brand_named_in_legal_notice')).toBe(true);
    expect(signalFor(phish, 'identity.impersonation_with_credential_request')?.severity).toBe(
      'critical',
    );
    expect(phish.classification).toBe('high-risk');
  });

  it('needs the role spelled out: a bare "Claims" is how a dispute phish names itself', () => {
    const disputes = analyzeDeterministic(
      {
        ...loadFixture('settlement-credential-phish').email,
        senderName: 'PayPal Claims',
      },
      { now: FIXED_NOW },
    );
    expect(hasSignal(disputes, 'identity.display_name_impersonation')).toBe(true);
    expect(hasSignal(disputes, 'identity.brand_named_in_legal_notice')).toBe(false);
  });

  it('does not soften a freemail sender, which no claims administrator uses', () => {
    const freemail = analyzeDeterministic(
      {
        ...loadFixture('legitimate-settlement-notice').email,
        senderEmail: 'settlement.admin@gmail.com',
        auth: undefined,
      },
      { now: FIXED_NOW },
    );
    expect(signalFor(freemail, 'identity.display_name_impersonation')?.severity).toBe('critical');
  });
});

describe('legitimate password reset (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-password-reset');

  it('scores low despite containing every credential-phishing keyword', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not claim impersonation, because the sender really is PayPal', () => {
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.lookalike_sender_domain')).toBe(false);
  });

  it('raises no link findings, because every link stays on paypal.com', () => {
    expect(result.categoryScores.link).toBe(0);
  });

  /**
   * The genuine notice trips no wording rule at all, including on the sentence promising never to ask
   * for credentials: "we will never ask you to confirm your details" used to be reported as a request
   * to confirm credentials, which inverted the meaning of the only sentence in the message about them.
   */
  it('raises no content findings on a real provider notice', () => {
    const content = result.signals.filter((s) => s.category === 'content' && s.severity !== 'info');
    expect(content).toEqual([]);
  });

  /**
   * Dampening on its own terms: hold the verified sender constant and give the message wording that
   * genuinely matches a heuristic. The finding must survive, weighted down; a score whose reasoning is
   * hidden is not one a user can check, so a softened finding is still shown.
   */
  it('dampens rather than deletes a wording finding from a verified sender', () => {
    const genuine = loadFixture('legitimate-password-reset').email;
    const withUrgency = {
      ...genuine,
      bodyText: `${genuine.bodyText}\n\nPlease act immediately: this request expires today.`,
    };

    const verified = signalFor(
      analyzeDeterministic(withUrgency, { now: FIXED_NOW }),
      'content.urgency',
    );
    const impostor = signalFor(
      analyzeDeterministic(
        { ...withUrgency, senderEmail: 'service@paypal-account-recovery.com' },
        { now: FIXED_NOW },
      ),
      'content.urgency',
    );

    // Present in both, so the reasoning stays visible; softened in one, so it stops driving the score.
    expect(verified).toBeDefined();
    expect(verified?.dampened).toBe(true);
    expect(verified?.description).toMatch(/[Ww]eighted down/u);
    expect(impostor?.dampened).toBeUndefined();
    expect(verified?.score).toBeLessThan(impostor?.score ?? 0);
  });

  it('scores dramatically lower than the identical wording from a lookalike domain', () => {
    // This is the real test of the dampening mechanism: hold the body constant and change only the
    // sender's domain and links. Nothing about the language differs.
    const genuine = loadFixture('legitimate-password-reset').email;
    const impostor = {
      ...genuine,
      senderEmail: 'service@paypal-account-recovery.com',
      links: genuine.links.map((l) => ({
        ...l,
        href: l.href.replace('www.paypal.com', 'paypal-account-recovery.com'),
        normalizedDomain: 'paypal-account-recovery.com',
      })),
    };
    const impostorResult = analyzeDeterministic(impostor, { now: FIXED_NOW });

    expect(impostorResult.score).toBeGreaterThan(result.score + 40);
    expect(impostorResult.categoryScores.content).toBeGreaterThan(result.categoryScores.content);
    expect(impostorResult.classification).toBe('high-risk');
  });
});

describe('legitimate newsletter with many links (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-newsletter');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not fire the urgency heuristic on "last chance" / "ends tonight" marketing copy', () => {
    expect(hasSignal(result, 'content.urgency')).toBe(false);
  });

  it('does not treat 14 links as a link finding', () => {
    expect(result.categoryScores.link).toBe(0);
  });

  it('does not penalise the legitimate ESP relay', () => {
    const via = signalFor(result, 'authentication.via_unrelated_host');
    expect(via?.severity).not.toBe('high');
  });
});

describe('legitimate invoice (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-invoice');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not flag the PDF attachment', () => {
    expect(hasSignal(result, 'attachment.executable')).toBe(false);
    expect(hasSignal(result, 'attachment.archive')).toBe(false);
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(true);
  });

  it('does not treat routine payment terms as payment fraud', () => {
    expect(hasSignal(result, 'content.payment_detail_change')).toBe(false);
    expect(hasSignal(result, 'content.wire_transfer')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Phishing
// ---------------------------------------------------------------------------

describe('obvious PayPal phishing', () => {
  const result = analyzeFixture('paypal-phish');

  it('scores high risk', () => {
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('high-risk');
  });

  it('identifies the display-name impersonation', () => {
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(true);
  });

  it('identifies the anchor text / destination mismatch', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('identifies the Reply-To mismatch', () => {
    expect(hasSignal(result, 'identity.reply_to_mismatch')).toBe(true);
  });

  it('identifies the authentication failure', () => {
    expect(hasSignal(result, 'authentication.failure')).toBe(true);
  });

  it('identifies the account threat combined with a credential request', () => {
    expect(hasSignal(result, 'content.combo.threat_and_credential_request')).toBe(true);
  });

  /** The other half of the correlation: a brand *was* identified, so the finding names it. */
  it('names the brand it found when reporting impersonation with a credential request', () => {
    const correlated = signalFor(result, 'identity.impersonation_with_credential_request');
    expect(correlated).toBeDefined();
    expect(correlated?.title).toContain('PayPal');
    expect(correlated?.description).toContain('PayPal');
    expect(correlated?.evidence?.value).toBe(loadFixture('paypal-phish').email.senderEmail);
  });

  it('reaches high risk on deterministic signals alone, with no llm contribution', () => {
    expect(result.categoryScores.llm).toBe(0);
    expect(result.classification).toBe('high-risk');
  });

  it('does not dampen anything, because technical findings are present', () => {
    for (const s of result.signals) {
      expect(s.description).not.toMatch(/[Ww]eighted down/u);
    }
  });
});

describe('Microsoft lookalike domain', () => {
  const result = analyzeFixture('microsoft-phish');

  it('scores high risk', () => {
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('high-risk');
  });

  it('recognises rnicrosoft-online.com as imitating Microsoft', () => {
    const lookalike = signalFor(result, 'identity.lookalike_sender_domain');
    expect(lookalike).toBeDefined();
    expect(lookalike?.description).toContain('microsoft');
  });

  it('recognises microsoftonline.com placed in front of an unrelated domain', () => {
    expect(hasSignal(result, 'link.misleading_domain')).toBe(true);
    const misleading = signalFor(result, 'link.misleading_domain');
    expect(misleading?.evidence?.value).toContain('session-verify-portal.net');
  });

  it('explains that the controlling domain is the registrable one', () => {
    const misleading = signalFor(result, 'link.misleading_domain');
    expect(misleading?.description).toContain('session-verify-portal.net');
  });
});

describe('mismatched anchor URL in isolation', () => {
  const result = analyzeFixture('anchor-mismatch');

  it('fires the mismatch rule', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('marks it critical because the displayed domain belongs to a real brand', () => {
    expect(signalFor(result, 'link.displayed_url_mismatch')?.severity).toBe('critical');
  });

  it('states both the shown and the actual destination', () => {
    const s = signalFor(result, 'link.displayed_url_mismatch');
    expect(s?.description).toContain('login.microsoftonline.com');
    expect(s?.description).toContain('account-verification.example');
  });

  it('carries the href as evidence so the UI can locate the link', () => {
    expect(signalFor(result, 'link.displayed_url_mismatch')?.evidence?.url).toBe(
      'https://account-verification.example/login?next=%2Fstatement',
    );
  });

  it('reaches at least suspicious on this single finding', () => {
    expect(result.score).toBeGreaterThanOrEqual(25);
  });
});

/**
 * Regression for a false positive seen in production. A Substack newsletter scored 50/100
 * "Suspicious": the platform rewrites every outbound link to its own redirector while leaving the
 * anchor text naming the destination site, which read as several `high` mismatches, maxed the link
 * category, and tripped the severity floor.
 *
 * The last test is the important one. The guard must not become a way to launder a brand claim by
 * pointing the link at your own domain, so it is asserted to yield when the *displayed* domain is a
 * brand's, the case where reputation is genuinely being borrowed.
 */
describe('click tracking on the sender own domain', () => {
  const result = analyzeFixture('legitimate-substack-newsletter');

  it('does not read the platform rewrite as a displayed/actual mismatch', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(false);
  });

  it('does not read the tracking wrapper as a concealed redirect', () => {
    expect(hasSignal(result, 'link.opaque_redirect')).toBe(false);
    expect(hasSignal(result, 'link.redirect_chain')).toBe(false);
  });

  it('stays low overall', () => {
    expect(result.classification).toBe('low');
  });

  /**
   * Isolates the guard from the tracker list. The platform here is deliberately unlisted, so the only
   * thing that can suppress the first case is `onSenderDomain`, and the second case, identical but
   * for the sender's domain, proves the rule still fires on the shape when nobody owns the redirector.
   */
  it('suppresses the rewrite only for the domain that sent the message', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const links = [
      toEmailLink({ text: 'northwind-roastery.com', href: 'https://dripmail.example/redirect/9c1d4e2a' }),
      toEmailLink({ text: 'northwind-coffee.co.uk', href: 'https://dripmail.example/redirect/3f8a1b90' }),
    ];

    const fromPlatform = analyzeDeterministic(
      { ...base, senderEmail: 'the-brew-notes@dripmail.example', links },
      { now: FIXED_NOW },
    );
    expect(hasSignal(fromPlatform, 'link.displayed_url_mismatch')).toBe(false);

    const fromElsewhere = analyzeDeterministic(
      { ...base, senderEmail: 'the-brew-notes@unrelated-sender.example', links },
      { now: FIXED_NOW },
    );
    expect(hasSignal(fromElsewhere, 'link.displayed_url_mismatch')).toBe(true);
    // Proven, through a service whose destination cannot be seen: reported without a floor.
    expect(signalFor(fromElsewhere, 'link.displayed_url_mismatch')?.severity).toBe('medium');

    const unproven = analyzeDeterministic(
      { ...base, senderEmail: 'the-brew-notes@unrelated-sender.example', links, auth: undefined },
      { now: FIXED_NOW },
    );
    expect(signalFor(unproven, 'link.displayed_url_mismatch')?.severity).toBe('high');

    const asking = analyzeDeterministic(
      { ...base, senderEmail: 'helpdesk@unrelated-sender.example', subject: 'Password reset required', links },
      { now: FIXED_NOW },
    );
    expect(signalFor(asking, 'link.displayed_url_mismatch')?.severity).toBe('high');

    const ownDomain = analyzeDeterministic(
      {
        ...base,
        senderEmail: 'notices@unrelated-sender.example',
        links: [toEmailLink({ text: 'northwind-logistics.com', href: 'https://dripmail.example/redirect/77aa' })],
      },
      { now: FIXED_NOW },
    );
    expect(signalFor(ownDomain, 'link.displayed_url_mismatch')?.severity).toBe('high');
  });

  it('keeps a visible stranger destination high even from a proven sender', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const visible = analyzeDeterministic(
      {
        ...base,
        senderEmail: 'the-brew-notes@unrelated-sender.example',
        links: [toEmailLink({ text: 'northwind-roastery.com', href: 'https://northwind-roastery-shop.example/' })],
      },
      { now: FIXED_NOW },
    );
    expect(signalFor(visible, 'link.displayed_url_mismatch')?.severity).toBe('high');
  });

  it('says nothing when a proven sender shows another name and lands on its own site', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const own = analyzeDeterministic(
      {
        ...base,
        senderEmail: 'hello@northwind-coffee.example',
        links: [toEmailLink({ text: 'northwind-roasters.example', href: 'https://www.northwind-coffee.example/' })],
      },
      { now: FIXED_NOW },
    );
    expect(hasSignal(own, 'link.displayed_url_mismatch')).toBe(false);
  });

  it('holds one government name linking to another at medium', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const agency = analyzeDeterministic(
      { ...base, links: [toEmailLink({ text: 'www.nwt.gov', href: 'https://www.northwind-transit.gov/' })] },
      { now: FIXED_NOW },
    );
    expect(signalFor(agency, 'link.displayed_url_mismatch')?.severity).toBe('medium');
  });

  it('still reports the mismatch when the displayed domain belongs to a brand', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const bait: EmailMessage = {
      ...base,
      senderName: 'Account Security',
      senderEmail: 'security@evil-example.com',
      subject: 'Unusual sign-in activity on your account',
      bodyText:
        'We detected an unusual sign-in attempt. Confirm your identity at login.microsoftonline.com within 24 hours or your account will be locked.',
      links: [
        toEmailLink({
          text: 'login.microsoftonline.com',
          href: 'https://evil-example.com/verify?id=8812',
        }),
      ],
    };

    const baited = analyzeDeterministic(bait, { now: FIXED_NOW });
    expect(hasSignal(baited, 'link.displayed_url_mismatch')).toBe(true);
    expect(signalFor(baited, 'link.displayed_url_mismatch')?.severity).toBe('critical');
  });
});

/**
 * The commonest shape in ordinary bulk mail: the footer shows the sender's own
 * address and the href goes through the email provider's tracker, a domain nobody can list in advance.
 * Excused only when authentication proves the sender, and only for a destination shaped like a tracker;
 * the rest of the block is the forgery and compromised-account cases that look the same in the footer.
 */
describe("a proven sender showing its own address through an email provider's tracker", () => {
  const base = loadFixture('legitimate-substack-newsletter').email;
  const proven = { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy: 'northwind-outfitters.com' } as const;
  const sent = (href: string, overrides: Partial<EmailMessage> = {}) =>
    analyzeDeterministic(
      {
        ...base,
        senderName: 'Northwind Outfitters',
        senderEmail: 'offers@northwind-outfitters.com',
        auth: proven,
        links: [toEmailLink({ text: 'northwind-outfitters.com', href })],
        ...overrides,
      },
      { now: FIXED_NOW },
    );

  it('does not report the tracker as a displayed/actual mismatch', () => {
    const result = sent('https://click.mailvendor.example/c/9c1d4e2a7b');
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(false);
  });

  it('still reports it when nothing proved the sender', () => {
    const result = sent('https://click.mailvendor.example/c/9c1d4e2a7b', { auth: undefined });
    expect(signalFor(result, 'link.displayed_url_mismatch')?.severity).toBe('high');
  });

  it('still reports a destination dressed in the sender own name', () => {
    const result = sent('https://northwind-outfitters.com.account-check.example/session');
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('still reports a destination that asks for a sign-in', () => {
    const result = sent('https://portal.mailvendor.example/login');
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('gives a brand in the table no such excuse, so its own link hosts must be listed instead', () => {
    const result = analyzeDeterministic(
      {
        ...base,
        senderName: 'Dropbox',
        senderEmail: 'no-reply@dropbox.com',
        auth: { ...proven, signedBy: 'dropbox.com' },
        links: [toEmailLink({ text: 'dropbox.com', href: 'https://click.mailvendor.example/c/1' })],
      },
      { now: FIXED_NOW },
    );
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });
});

/**
 * A co-marketing offer shows another brand's address and routes the click through the sender's own
 * host. The address shown is still not where the click goes, so it stays reported, but a brand in the
 * table proven as itself is not a stranger borrowing the other brand's name. Anyone else doing it is.
 */
describe("a proven brand linking another brand's address through its own host", () => {
  const base = loadFixture('legitimate-substack-newsletter').email;
  const offer = (senderEmail: string, signedBy: string) =>
    analyzeDeterministic(
      {
        ...base,
        senderName: 'Partner Offers',
        senderEmail,
        auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy },
        links: [
          toEmailLink({ text: 'paypal.com', href: `https://www.${signedBy}/offers/redirect?id=8812` }),
        ],
      },
      { now: FIXED_NOW },
    );

  it('reports it at medium for a table brand proven as itself', () => {
    const result = offer('offers@dropbox.com', 'dropbox.com');
    expect(signalFor(result, 'link.displayed_url_mismatch')?.severity).toBe('medium');
  });

  it('keeps it critical for a domain anyone could have authenticated', () => {
    const result = offer('offers@northwind-rewards.com', 'northwind-rewards.com');
    expect(signalFor(result, 'link.displayed_url_mismatch')?.severity).toBe('critical');
  });
});

/**
 * The same guard, for the rule whose anchor text is prose rather than a URL. A social footer links the
 * networks it has profiles on *by name*, through the sender's own click tracker, so every bulk sender
 * produces "anchor names a brand, destination is not that brand's", the observed false positive.
 *
 * As with its sibling, the guard must not become a way to launder a brand claim by pointing the link at
 * a domain you control, so the last test asserts it yields when the message claims to be the brand.
 */
describe('a social footer routed through the sender own tracker', () => {
  const result = analyzeFixture('legitimate-institutional-newsletter');

  it('does not read profile links named after their networks as impersonation', () => {
    expect(hasSignal(result, 'link.anchor_brand_mismatch')).toBe(false);
  });

  it('leaves the newsletter low with no high finding to floor it', () => {
    expect(result.classification).toBe('low');
  });

  it('still fires when the tracker is not the sender own domain', () => {
    const base = loadFixture('legitimate-institutional-newsletter').email;
    const elsewhere = analyzeDeterministic(
      {
        ...base,
        links: [toEmailLink({ text: 'LinkedIn', href: 'https://unrelated-redirector.example/?qs=IIJ1' })],
      },
      { now: FIXED_NOW },
    );

    expect(hasSignal(elsewhere, 'link.anchor_brand_mismatch')).toBe(true);
  });

  it('still fires when the message claims to be the brand it links to', () => {
    const base = loadFixture('legitimate-institutional-newsletter').email;
    const bait: EmailMessage = {
      ...base,
      senderName: 'LinkedIn Security',
      senderEmail: 'security@linked-in-alerts.example',
      subject: 'Your LinkedIn account requires verification',
      bodyText:
        'Your LinkedIn account has been flagged for unusual activity. Confirm your details to restore access.',
      links: [
        toEmailLink({ text: 'LinkedIn', href: 'https://linked-in-alerts.example/verify?id=3311' }),
      ],
      auth: undefined,
    };

    expect(hasSignal(analyzeDeterministic(bait, { now: FIXED_NOW }), 'link.anchor_brand_mismatch')).toBe(
      true,
    );
  });
});

/**
 * A proven sender naming another brand in passing, through a host that is not its own: an email
 * provider's tracker, a sister domain, a short link. Reported at `medium` so it sets no floor, and the
 * three things a lure needs, a claim, an ask, or an unproven sender, each keep it `high`.
 */
describe('a proven sender mentioning another brand through a host of its provider', () => {
  const base = loadFixture('legitimate-newsletter').email;
  const anchored = (text: string, href: string, overrides: Partial<EmailMessage> = {}) =>
    signalFor(
      analyzeDeterministic({ ...base, links: [toEmailLink({ text, href })], ...overrides }, { now: FIXED_NOW }),
      'link.anchor_brand_mismatch',
    );
  const tracker = 'https://t.mailvendor.example/c/7Qx2Lm9';

  it.each(['Follow on Instagram', 'LinkedIn', 'Outlook for iOS'])('holds "%s" at medium', (text) => {
    expect(anchored(text, tracker)?.severity).toBe('medium');
  });

  it('says nothing when the tracker leads to the sender own site', () => {
    const href = 'https://t.mailvendor.example/CL0/https:%2F%2Fkestrelcoffee.co.uk%2Fpages%2Fslack/1/abc';
    expect(anchored('Slack integration', href)).toBeUndefined();
  });

  it('keeps an action on the brand high', () => {
    expect(anchored('Sign in to Microsoft 365', tracker)?.severity).toBe('high');
    expect(anchored('Open in Dropbox', tracker)?.severity).toBe('high');
  });

  it('keeps it high when the sender is not proven', () => {
    expect(anchored('LinkedIn', tracker, { auth: undefined })?.severity).toBe('high');
  });

  it('keeps it high from a freemail sender', () => {
    const freemail = {
      senderEmail: 'kestrel.coffee@gmail.com',
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy: 'gmail.com', mailedBy: 'gmail.com' },
    } as const;
    expect(anchored('LinkedIn', tracker, freemail)?.severity).toBe('high');
  });

  it('keeps it high from a tenant of open hosting, which anyone can authenticate as', () => {
    const tenant = {
      senderEmail: 'noreply@kestrel-4b7db.firebaseapp.com',
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy: 'kestrel-4b7db.firebaseapp.com' },
    } as const;
    expect(anchored('LinkedIn', tracker, tenant)?.severity).toBe('high');
  });
});

describe('punycode / homoglyph URL', () => {
  const result = analyzeFixture('punycode-link');

  it('flags the punycode link', () => {
    expect(hasSignal(result, 'link.punycode_domain')).toBe(true);
  });

  it('shows the rendered form alongside the real one', () => {
    const s = signalFor(result, 'link.punycode_domain');
    expect(s?.evidence?.value).toContain('xn--pypal-4ve.com');
    // Decoded form contains the Cyrillic а.
    expect(s?.evidence?.value).toMatch(/p\u0430ypal\.com/u);
  });

  it('also flags the punycode sender domain', () => {
    expect(hasSignal(result, 'identity.sender_punycode_domain')).toBe(true);
  });

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });
});

describe('IP-address URL', () => {
  const result = analyzeFixture('ip-url');

  it('flags the bare IP destination', () => {
    expect(hasSignal(result, 'link.ip_address_url')).toBe(true);
    expect(signalFor(result, 'link.ip_address_url')?.evidence?.value).toBe('185.234.219.14');
  });

  it('flags the unencrypted sign-in link', () => {
    expect(hasSignal(result, 'link.insecure_login')).toBe(true);
  });

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });
});

/**
 * Each link rule below was `critical` or `high` on ordinary technical and corporate mail in a public
 * corpus, because it read a link by a property the attack shares with something harmless. Every case
 * pairs the harmless shape with the attack it must still catch.
 */
describe('link rules against the harmless links that share their shape', () => {
  const withLinks = (hrefs: string[], senderEmail = 'ops@northwind-logistics.com') =>
    analyzeDeterministic(
      {
        senderEmail,
        bodyText: 'The details are at the link below.',
        links: hrefs.map((href) => toEmailLink({ text: '', href })),
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  describe('a private network address', () => {
    it.each(['http://192.168.10.20/tools/', 'http://10.0.4.7:8080/status', 'http://172.20.1.1/', 'http://[fd12:3456::1]/'])(
      'is reported without a floor: %s',
      (href) => {
        const result = withLinks([href]);
        expect(hasSignal(result, 'link.ip_address_url')).toBe(false);
        expect(signalFor(result, 'link.private_ip_url')?.severity).toBe('low');
      },
    );

    it.each(['http://185.234.219.14/login', 'http://172.32.0.1/', 'http://100.128.0.1/'])(
      'leaves a public address critical: %s',
      (href) => {
        expect(signalFor(withLinks([href]), 'link.ip_address_url')?.severity).toBe('critical');
      },
    );

    it('names the public address when both kinds are present', () => {
      const result = withLinks(['http://192.168.1.1/', 'http://185.234.219.14/verify']);
      expect(signalFor(result, 'link.ip_address_url')?.evidence?.value).toBe('185.234.219.14');
    });
  });

  describe('a host named after its IP address', () => {
    it.each([
      'https://203-0-113-7.cloud.northwind-hosting.net/renew',
      'http://ip-198.51.100.20.northwind-hosting.net/',
      'https://static.198-51-100-20.northwind-hosting.net/',
    ])('is reported at medium: %s', (href) => {
      expect(signalFor(withLinks([href]), 'link.ip_named_host')?.severity).toBe('medium');
    });

    it.each([
      'https://build-2026-09-28.northwind-ci.com/',
      'https://v1.2.3.northwind-docs.com/',
      'https://300-1-1-1.northwind-hosting.net/',
      'https://203.northwind-hosting.net/',
    ])('is not read into dates, versions or numbers that are not addresses: %s', (href) => {
      expect(hasSignal(withLinks([href]), 'link.ip_named_host')).toBe(false);
    });

    it("is not reported on the sender's own domain", () => {
      const result = withLinks(['https://10-0-4-7.build.northwind-logistics.com/'], 'ci@northwind-logistics.com');
      expect(hasSignal(result, 'link.ip_named_host')).toBe(false);
    });
  });

  describe('a non-web scheme', () => {
    it('reports an ftp link as a download, not as code', () => {
      const result = withLinks(['ftp://ftp.northwind-mirror.org/pub/readme.txt']);
      expect(hasSignal(result, 'link.dangerous_scheme')).toBe(false);
      expect(signalFor(result, 'link.ftp_link')?.severity).toBe('medium');
    });

    it.each(['file:///C:/Users/reports/q3.xlsx', 'file:///home/dana/build/', 'file://localhost/etc/notes.txt'])(
      'reports a file link with no host as local: %s',
      (href) => {
        const result = withLinks([href]);
        expect(hasSignal(result, 'link.dangerous_scheme')).toBe(false);
        expect(signalFor(result, 'link.local_file_link')?.severity).toBe('low');
      },
    );

    it.each(['file://fileserver.northwind-logistics.com/share/q3.xlsx', 'file://\\\\fileserver\\share\\q3.xlsx'])(
      'keeps a file link to another machine critical: %s',
      (href) => {
        expect(signalFor(withLinks([href]), 'link.dangerous_scheme')?.severity).toBe('critical');
      },
    );

    it('keeps a code-running scheme critical, and reports it over a milder one', () => {
      const result = withLinks(['ftp://ftp.northwind-mirror.org/pub/', 'data:text/html,<p>hello</p>']);
      expect(signalFor(result, 'link.dangerous_scheme')?.severity).toBe('critical');
      expect(hasSignal(result, 'link.ftp_link')).toBe(false);
    });
  });

  describe("a brand's name in front of an unrelated domain", () => {
    it.each([
      'https://bigmail.northwind-dev.org/',
      'https://purchase.northwind-shop.com/',
      'https://pineapple.northwind-garden.com/',
    ])(
      'does not find a short brand at the end of a longer word: %s',
      (href) => {
        expect(hasSignal(withLinks([href]), 'link.misleading_domain')).toBe(false);
      },
    );

    it.each([
      'https://chase.northwind-alerts.com/',
      'https://secure-chase.northwind-alerts.com/',
      'https://chasesecure.northwind-alerts.com/',
      'https://apple7.northwind-alerts.com/',
      'https://securepaypal.northwind-alerts.com/',
    ])('still reports a brand leading a name, or a long one anywhere: %s', (href) => {
      expect(hasSignal(withLinks([href]), 'link.misleading_domain')).toBe(true);
    });

    it("does not report a section of the sender's own site", () => {
      const result = withLinks(['https://apple.northwind-news.com/story/41'], 'desk@northwind-news.com');
      expect(hasSignal(result, 'link.misleading_domain')).toBe(false);
    });

    it("still reports it when the message claims to be that brand", () => {
      const result = analyzeDeterministic(
        {
          senderName: 'Apple Support',
          senderEmail: 'desk@northwind-news.com',
          bodyText: 'Your Apple ID has been locked. Unlock it at the link below.',
          links: [toEmailLink({ text: '', href: 'https://apple.northwind-news.com/unlock' })],
          attachments: [],
        },
        { now: FIXED_NOW },
      );
      expect(hasSignal(result, 'link.misleading_domain')).toBe(true);
    });

    it("still reports a whole brand domain embedded in the sender's own", () => {
      const result = analyzeFixture('sender-host-brand-domain');
      expect(ids(result)).toContain('link.misleading_domain.0');
      expect(result.classification).toBe('high-risk');
    });
  });

  describe('an unencrypted link that may be a sign-in page', () => {
    it("does not read an intranet's front page as a sign-in form", () => {
      const result = withLinks(['http://intranet.northwind-logistics.com/portal/home']);
      expect(hasSignal(result, 'link.insecure_login')).toBe(false);
      expect(hasSignal(result, 'link.insecure_http')).toBe(true);
    });

    it("still reports a portal's sign-in page", () => {
      const result = withLinks(['http://intranet.northwind-logistics.com/portal/login']);
      expect(hasSignal(result, 'link.insecure_login')).toBe(true);
    });
  });
});

/**
 * A redirect parameter must not hide the host the click reaches first. Unwrapping a redirect adds the
 * destination to what is judged; it never replaces the entry, which is the one host the attacker
 * could not dress up as somebody else's.
 */
describe('every host a click passes through', () => {
  const linked = (
    links: { text: string; href: string }[],
    extra: Partial<EmailMessage> = {},
  ): AnalysisResult =>
    analyzeDeterministic(
      {
        senderEmail: 'news@northwind-logistics.com',
        bodyText: 'The details are at the link below.',
        links: links.map((link) => toEmailLink(link)),
        attachments: [],
        ...extra,
      },
      { now: FIXED_NOW },
    );
  const bare = (href: string) => linked([{ text: 'Open', href }]);
  const BENIGN = encodeURIComponent('https://www.northwind-traders.com/');

  describe('an entry host that deceives', () => {
    it('reports a lookalike entry that forwards somewhere harmless', () => {
      const result = bare(`https://paypa1.com/r?url=${BENIGN}`);
      expect(signalFor(result, 'link.lookalike_domain.0')?.severity).toBe('critical');
    });

    it('reports a public IP entry', () => {
      expect(signalFor(bare(`http://185.234.219.14/go?next=${BENIGN}`), 'link.ip_address_url')?.severity).toBe('critical');
    });

    it('reports a punycode entry', () => {
      expect(hasSignal(bare(`https://xn--pypal-4ve.com/r?url=${BENIGN}`), 'link.punycode_domain.0')).toBe(true);
    });

    it('reports a lookalike hidden behind a known click tracker', () => {
      const target = encodeURIComponent('https://paypa1.com/login');
      const result = bare(`https://u1.ct.sendgrid.net/ls/click?url=${target}`);
      expect(hasSignal(result, 'link.lookalike_domain.0')).toBe(true);
    });

    it("reports a brand's address shown over an attacker's redirector", () => {
      const target = encodeURIComponent('https://www.paypal.com/');
      const result = linked([{ text: 'www.paypal.com', href: `https://northwind-redirect.example/r?return=${target}` }]);
      expect(signalFor(result, 'link.displayed_url_mismatch.0')?.severity).toBe('high');
    });
  });

  describe('the harmless routes that share the shape', () => {
    it("does not report a brand's address reached through the sender's own redirector", () => {
      const target = encodeURIComponent('https://www.paypal.com/');
      const result = linked([{ text: 'www.paypal.com', href: `https://click.northwind-logistics.com/r?url=${target}` }]);
      expect(hasSignal(result, 'link.displayed_url_mismatch.0')).toBe(false);
      expect(result.classification).toBe('low');
    });

    it('leaves an ordinary address behind an unlisted mail platform to the redirect finding', () => {
      const result = linked([
        { text: 'www.northwind-traders.com', href: `https://t.northwind-mailer.example/c?url=${BENIGN}` },
      ]);
      expect(hasSignal(result, 'link.displayed_url_mismatch.0')).toBe(false);
      expect(signalFor(result, 'link.redirect_chain.0')?.severity).toBe('medium');
    });

    it('does not report a known tracker forwarding to the address it shows', () => {
      const result = linked([{ text: 'www.northwind-traders.com', href: `https://u1.ct.sendgrid.net/ls/click?url=${BENIGN}` }]);
      expect(result.signals.filter((s) => s.category === 'link' && s.severity !== 'low')).toEqual([]);
    });
  });

  describe("a tracker's owner publishing pages", () => {
    it('judges the destination a Google redirect decodes to', () => {
      const target = encodeURIComponent('https://northwind-verify.example/login');
      const result = linked([{ text: 'www.paypal.com', href: `https://www.google.com/url?q=${target}` }]);
      expect(signalFor(result, 'link.displayed_url_mismatch.0')?.severity).toBe('critical');
    });

    it('treats a Google Docs form as a page, not as a tracker hop', () => {
      const result = linked([{ text: 'www.paypal.com', href: 'https://docs.google.com/forms/d/e/1FAIpQL/viewform' }]);
      expect(signalFor(result, 'link.displayed_url_mismatch.0')?.severity).toBe('critical');
    });

    it('still lets a Google redirect to the displayed address through', () => {
      const result = linked([{ text: 'www.northwind-traders.com', href: `https://www.google.com/url?q=${BENIGN}` }]);
      expect(result.signals.filter((s) => s.category === 'link' && s.severity !== 'low')).toEqual([]);
    });
  });

  describe("a brand's own domain that anyone can publish on", () => {
    const storage = 'https://storage.googleapis.com/northwind-drive-share/signin.html';

    it('reports a sign-in page in public storage on mail claiming to be the storage owner', () => {
      const result = linked([{ text: 'Open shared file', href: storage }], { senderName: 'Google Drive', senderEmail: 'drive-share@northwind-mail.example' });
      expect(signalFor(result, 'link.credential_link_open_hosting.0')?.severity).toBe('high');
    });

    it("does not report Google's own sign-in page on mail claiming to be Google", () => {
      const result = linked(
        [{ text: 'Sign in', href: 'https://www.google.com/accounts/signin' }],
        { senderName: 'Google', senderEmail: 'no-reply@google.com', auth: { signedBy: 'google.com' } },
      );
      expect(result.signals.filter((s) => s.id.startsWith('link.credential_link'))).toEqual([]);
    });
  });
});

/**
 * Staff write from their organisation's `.net` and `.com`, and colleagues abroad from its country
 * domain, so the same name under another suffix is the same organisation, unless the suffix is the
 * reader's own with characters dropped, which is a trap and not a market.
 */
describe("a sender under another of the recipient's own suffixes", () => {
  const fromTo = (senderEmail: string, recipientEmail: string) =>
    analyzeDeterministic(
      { senderEmail, recipientEmail, bodyText: 'Notes from this morning attached.', links: [], attachments: [] },
      { now: FIXED_NOW },
    );

  it.each([
    ['ops@northwind-logistics.net', 'reader@northwind-logistics.com'],
    ['ops@northwind-logistics.fr', 'reader@northwind-logistics.de'],
    ['ops@northwind-logistics.com', 'reader@northwind-logistics.com.au'],
  ])('is not an imitation: %s to %s', (sender, recipient) => {
    expect(hasSignal(fromTo(sender, recipient), 'identity.lookalike_of_recipient_domain')).toBe(false);
  });

  it.each([
    ['ops@northwind-logistics.co', 'reader@northwind-logistics.com'],
    ['ops@northwind-logistics.cm', 'reader@northwind-logistics.com'],
    ['ops@northwind-logistlcs.com', 'reader@northwind-logistics.com'],
  ])('is still an imitation when the suffix or the name is a near-miss: %s to %s', (sender, recipient) => {
    expect(signalFor(fromTo(sender, recipient), 'identity.lookalike_of_recipient_domain')?.severity).toBe('critical');
  });
});

describe('a brand whose name is an ordinary word', () => {
  const from = (senderName: string, senderEmail: string, subject = 'Firmware update', bodyText = 'A new release is ready for your device.') =>
    analyzeDeterministic({ senderName, senderEmail, subject, bodyText, links: [], attachments: [] }, { now: FIXED_NOW });
  const claimsFor = (senderName: string, subject: string, bodyText: string): string[] =>
    buildContext({ senderName, senderEmail: 'desk@northwind-books.com', subject, bodyText, links: [], attachments: [] })
      .claims.map((claim) => claim.brand.id);

  it.each(['Ledger', 'Ledger Support', 'Exodus Wallet', 'EXODUS', 'Ledger Wallet Team'])(
    'is claimed by a display name that is the brand alone: %s',
    (name) => {
      expect(signalFor(from(name, 'notice@northwind-updates.com'), 'identity.display_name_impersonation')?.severity).toBe('high');
    },
  );

  it.each(['Trezor', 'MetaMask Security', 'Trust Wallet'])('is claimed by a distinctive wallet name: %s', (name) => {
    expect(hasSignal(from(name, 'notice@northwind-updates.com'), 'identity.display_name_impersonation')).toBe(true);
  });

  it('is not impersonation from the brand itself', () => {
    expect(hasSignal(from('Ledger', 'hello@ledger.com'), 'identity.display_name_impersonation')).toBe(false);
  });

  it.each(['Ledger Accounting Group', 'Exodus Travel Northwind', 'Sam Ledger'])(
    'is not claimed by a name that only contains the word: %s',
    (name) => {
      expect(claimsFor(name, 'Hello', 'Notes attached.')).not.toContain('ledger');
      expect(claimsFor(name, 'Hello', 'Notes attached.')).not.toContain('exodus');
    },
  );

  it('is not claimed by accounting or news wording', () => {
    expect(
      claimsFor('Dana Whitfield', 'General ledger close for Q3', 'The ledger balances. A mass exodus of staff is not expected.'),
    ).toEqual([]);
  });

  it('is still claimed by a qualified product name in the subject', () => {
    expect(claimsFor('Dana Whitfield', 'Your Ledger Live update is ready', 'Install it today.')).toContain('ledger');
  });

  it.each(['Norton', 'Norton Security Team', 'NORTON Billing'])('treats a surname brand the same way: %s', (name) => {
    expect(signalFor(from(name, 'notice@northwind-updates.com'), 'identity.display_name_impersonation')?.severity).toBe('high');
  });

  it.each(['Priya Norton', 'Norton & Hale LLP', 'Norton Street Dental'])(
    'is not claimed by a person or firm sharing the surname: %s',
    (name) => {
      expect(claimsFor(name, 'Hello', 'Notes attached.')).not.toContain('norton');
    },
  );

  it('is claimed by a Norton product name in the subject', () => {
    expect(claimsFor('Dana Whitfield', 'Your Norton 360 renewal', 'Details inside.')).toContain('norton');
  });
});

describe('security-software brands', () => {
  const from = (senderName: string, senderEmail: string) =>
    analyzeDeterministic(
      { senderName, senderEmail, subject: 'Subscription renewal', bodyText: 'Your protection renews soon.', links: [], attachments: [] },
      { now: FIXED_NOW },
    );

  it.each(['McAfee', 'McAfee Security Team', 'Avast Billing', 'Kaspersky Support'])(
    'is impersonated by its name on an unrelated domain: %s',
    (name) => {
      expect(hasSignal(from(name, 'billing@renewal-desk-7731.com'), 'identity.display_name_impersonation')).toBe(true);
    },
  );

  it.each([
    ['McAfee', 'news@mcafee.com'],
    ['Avast', 'billing@avg.com'],
    ['Norton', 'noreply@mail.norton.com'],
    ['Kaspersky', 'support@kaspersky.com'],
  ])('is not impersonation from the brand itself: %s <%s>', (name, address) => {
    expect(hasSignal(from(name, address), 'identity.display_name_impersonation')).toBe(false);
  });

  const anchored = (text: string) =>
    hasSignal(
      analyzeDeterministic(
        {
          senderName: 'Northwind Outfitters',
          senderEmail: 'news@northwind-outfitters.com',
          subject: 'New arrivals',
          bodyText: `${text} is below.`,
          links: [toEmailLink({ text, href: 'https://shop.northwind-promo.net/new' })],
          attachments: [],
        },
        { now: FIXED_NOW },
      ),
      'link.anchor_brand_mismatch',
    );

  it.each(['Browse a vast range of tents', 'Pelaa vastuullisesti', 'Pineapple recipes'])(
    'does not read a short brand name across word breaks in link text: %s',
    (text) => {
      expect(anchored(text)).toBe(false);
    },
  );

  it.each(['Renew Avast One', 'Sign in to Apple', 'Open in Gmail'])('still reads a short brand name as a word: %s', (text) => {
    expect(anchored(text)).toBe(true);
  });

  it.each([
    'Norway cancels Microsoft contract',
    'How Microsoft plans to take over your living room',
    'Gaga for Google? When results do not count',
    'Apple cider vinegar water',
  ])('does not treat a headline that mentions a brand as a brand label: %s', (text) => {
    expect(anchored(text)).toBe(false);
  });

  it.each([
    'Microsoft 365',
    'View the shared file on OneDrive',
    'Update your PayPal payment details',
    'Get started on WhatsApp today',
  ])('still reports a brand label or an action on the brand: %s', (text) => {
    expect(anchored(text)).toBe(true);
  });
});

describe('security-software renewal scam', () => {
  const result = analyzeFixture('antivirus-renewal-scam');

  it('reports the brand on a domain it does not own and the threat paired with a card request', () => {
    expect(signalFor(result, 'identity.display_name_impersonation')?.severity).toBe('high');
    expect(signalFor(result, 'content.combo.billing_update_under_threat')?.severity).toBe('high');
    expect(result.classification).toBe('high-risk');
  });

  it('leaves the genuine card-expiry notice it imitates at low', () => {
    const genuine = analyzeFixture('legitimate-antivirus-renewal');
    expect(genuine.classification).toBe('low');
    expect(hasSignal(genuine, 'content.account_threat')).toBe(false);
  });
});

/**
 * Phishing that names no brand, only the reader's own organisation. Both directions matter: the claim to
 * be the organisation's own systems is the commonest credential lure in current corpora, and the
 * organisation's helpdesk really does run on hosted services that write under its name.
 */
describe('a sender presenting itself as part of your own organisation', () => {
  const lure = analyzeFixture('own-organisation-mailbox-phish');
  const base = loadFixture('legitimate-hosted-service-desk').email;
  const named = (senderName: string, overrides: Partial<EmailMessage> = {}) =>
    analyzeDeterministic({ ...base, senderName, ...overrides }, { now: FIXED_NOW });
  const ownOrgIds = (result: AnalysisResult) =>
    result.signals.map((s) => s.id).filter((id) => id.startsWith('identity.own_'));

  it('reports the recipient domain used as a name, and pairs it with the credential ask', () => {
    expect(signalFor(lure, 'identity.own_domain_in_sender_name')?.severity).toBe('medium');
    expect(signalFor(lure, 'identity.own_domain_in_sender_name')?.description).toContain('mailbox-quota-notice.com');
    expect(hasSignal(lure, 'identity.impersonation_with_credential_request')).toBe(true);
    expect(lure.classification).toBe('high-risk');
  });

  it('reports a department of the organisation writing from outside, without a floor', () => {
    const desk = analyzeFixture('legitimate-hosted-service-desk');
    expect(signalFor(desk, 'identity.own_department_from_outside')?.severity).toBe('medium');
    expect(desk.classification).toBe('low');
  });

  it('does not let the department form make a credential request a harvesting attempt', () => {
    const reset = named('Northwind Logistics IT Service Desk', {
      bodyText: 'Your password will expire in 3 days. Sign in to the self-service portal to update your password.',
    });
    expect(hasSignal(reset, 'identity.impersonation_with_credential_request')).toBe(false);
  });

  it.each([
    'Northwind Logistics',
    'Northwind Logistics (via the project tracker)',
    'Priya at Deskworks',
  ])('says nothing of a name that is the organisation as a customer, not a department: %s', (name) => {
    expect(ownOrgIds(named(name))).toEqual([]);
  });

  it('says nothing when the organisation writes from its own domain', () => {
    expect(ownOrgIds(named('northwind-logistics.com IT Support', { senderEmail: 'it@northwind-logistics.com' }))).toEqual([]);
  });

  it('says nothing when the organisation writes from its own name under another suffix', () => {
    expect(ownOrgIds(named('northwind-logistics.com IT Support', { senderEmail: 'it@northwind-logistics.de' }))).toEqual([]);
  });

  it('says nothing for a personal mailbox, which has no organisation to impersonate', () => {
    expect(ownOrgIds(named('gmail.com Mail Admin', { recipientEmail: 'sam.okafor@gmail.com' }))).toEqual([]);
  });

  it('needs a name long enough not to be a common word', () => {
    expect(ownOrgIds(named('Ace IT Support', { recipientEmail: 'sam@acers.com' }))).toEqual([]);
  });

  it('reads the domain only as a whole token', () => {
    expect(ownOrgIds(named('Updates from northwind-logistics.com.au'))).toEqual([]);
    expect(ownOrgIds(named('Updates from sub.northwind-logistics.com'))).toEqual([]);
    expect(ownOrgIds(named('Updates from northwind-logistics.com'))).toEqual(['identity.own_domain_in_sender_name']);
  });
});

/**
 * A filename in the body that is a link, not an attachment. Both directions matter: it is the commonest
 * brand-free document lure, and help desks and file services legitimately show attachments as links.
 */
describe('a link labelled as an attached file', () => {
  const lure = analyzeFixture('fake-attachment-link');
  const base = loadFixture('fake-attachment-link').email;
  const linked = (text: string, href: string, overrides: Partial<EmailMessage> = {}) =>
    analyzeDeterministic(
      { ...base, links: [{ text, href, normalizedDomain: new URL(href).hostname }], ...overrides },
      { now: FIXED_NOW },
    );
  const fake = (result: AnalysisResult) => signalFor(result, 'link.fake_attachment');

  it('reports a filename that opens a page on an unrelated site', () => {
    expect(fake(lure)?.severity).toBe('high');
    expect(fake(lure)?.description).toContain('docs-viewer-secure.net');
    expect(fake(lure)?.evidence?.text).toBe('Annual-Leave-Compliance-Report-2026.pdf');
    expect(lure.classification).not.toBe('low');
  });

  it('says nothing of a help desk serving the attachment under a token path', () => {
    expect(fake(analyzeFixture('legitimate-help-desk-attachment'))).toBeUndefined();
  });

  it.each([
    ['the file itself on another host', 'Q3-Results.pdf', 'https://cdn.example-files.net/reports/Q3-Results.pdf'],
    ['the file on the sender\'s own site', 'Q3-Results.pdf', 'https://staff-records-portal.com/view?id=4'],
    ['a brand\'s file share', 'Q3-Results.pdf', 'https://drive.google.com/file/d/1aBcD/view'],
    ['a sentence that ends in a filename', 'Read the full terms set out in the guide at terms-and-conditions-of-sale-v2.pdf', 'https://docs-viewer-secure.net/x'],
    ['an ordinary label', 'View report', 'https://docs-viewer-secure.net/portal/view.html'],
  ])('says nothing of %s', (_case, text, href) => {
    expect(fake(linked(text, href))).toBeUndefined();
  });

  it('says nothing when a mail tracker hides where the file goes', () => {
    const hidden = linked('Statement.pdf', 'https://northwind.us1.list-manage.com/track/click?u=4f2a&id=91c0');
    expect(fake(hidden)).toBeUndefined();
  });
});

/**
 * Contact-form abuse: a genuine company's autoresponder delivering what a stranger typed into its form.
 * Both directions matter, because the same confirmation is what everyone who really fills in a form gets.
 */
describe('an automatic reply echoing a form submitted with the reader\'s address', () => {
  const lure = analyzeFixture('echoed-form-lure');
  const base = loadFixture('echoed-form-lure').email;
  const echoed = (result: AnalysisResult) => signalFor(result, 'link.echoed_form_link');
  const LURE_LINK = 'https://reward-claims-desk.net/winner/0412';
  const withBody = (bodyText: string, overrides: Partial<EmailMessage> = {}) =>
    analyzeDeterministic({ ...base, bodyText, ...overrides }, { now: FIXED_NOW });
  const form = (fields: string) =>
    `Thank you for contacting Northwind Garden Supply.\n\nYour submission:\n\n${fields}\n\n--\nNorthwind Garden Supply`;
  const PROSE = 'Your entry is approved and your place in the members programme is reserved. Follow the link to join';

  it('reports the link inside the echoed message, at medium and without a floor', () => {
    expect(echoed(lure)?.severity).toBe('medium');
    expect(echoed(lure)?.category).toBe('link');
    expect(echoed(lure)?.description).toContain('reward-claims-desk.net');
    expect(echoed(lure)?.description).toContain('"Message"');
    expect(scoreFloor(lure.signals).basis).toBeNull();
    expect(lure.classification).toBe('caution');
  });

  it('says nothing of the confirmation the reader gets for a form they filled in', () => {
    expect(echoed(analyzeFixture('legitimate-contact-form-confirmation'))).toBeUndefined();
  });

  it('needs no prize wording, and reads full-width colons and unspaced scripts', () => {
    const plain = withBody(form(`Name: R\nEmail: alex.morgan+shop@gmail.com\nPhone: 5550142\nMessage: ${PROSE}: ${LURE_LINK}`));
    expect(echoed(plain)).toBeDefined();
    const japanese = withBody(
      form(`お名前：R\nメールアドレス：alex.morgan+shop@gmail.com\n電話番号：5550142\nお問い合わせ内容：${PROSE} ${LURE_LINK}`),
    );
    expect(echoed(japanese)).toBeDefined();
  });

  it('recognises the reader under a plus-tag or Gmail\'s ignored dots', () => {
    const fields = `Name: R\nEmail: Alex.Morgan@gmail.com\nPhone: 5550142\nMessage: ${PROSE}: ${LURE_LINK}`;
    expect(echoed(withBody(form(fields), { recipientEmail: 'alexmorgan+web@googlemail.com' }))).toBeDefined();
    expect(echoed(withBody(form(fields), { recipientEmail: 'sam.okafor@gmail.com' }))).toBeUndefined();
  });

  it('reads a message field whose text is on the lines below its label', () => {
    const below = withBody(form(`Name: R\nEmail: alex.morgan+shop@gmail.com\nPhone: 5550142\nMessage:\n${PROSE}\n${LURE_LINK}`));
    expect(echoed(below)).toBeDefined();
    const continued = withBody(form(`Name: R\nEmail: alex.morgan+shop@gmail.com\nPhone: 5550142\nMessage: ${PROSE}\n${LURE_LINK}`));
    expect(echoed(continued)).toBeDefined();
  });

  it.each([
    ['a quoted header block, whose From line is someone else', `From: Jordan Reyes <jordan@northwind-traders.com>\nTo: alex.morgan+shop@gmail.com\nDate: 3 March\nSubject: ${PROSE} ${LURE_LINK}`],
    ['a bare URL a site filled in', `Name: R\nEmail: alex.morgan+shop@gmail.com\nPhone: 5550142\nTracking: ${LURE_LINK}`],
    ['the reader named in running text', `Name: R\nPhone: 5550142\nOrder: 1182\nMessage: We sent this to alex.morgan+shop@gmail.com. ${PROSE}: ${LURE_LINK}`],
    ['a form of two fields', `Email: alex.morgan+shop@gmail.com\nMessage: ${PROSE}: ${LURE_LINK}`],
    ['a link to the sender\'s own site', `Name: R\nEmail: alex.morgan+shop@gmail.com\nPhone: 5550142\nMessage: ${PROSE}: https://northwind-gardens.com/members`],
  ])('says nothing of %s', (_case, fields) => {
    const links = [...fields.matchAll(/https:\/\/\S+/gu)].map(([href]) => ({ text: href, href, normalizedDomain: new URL(href).hostname }));
    expect(echoed(withBody(form(fields), { links }))).toBeUndefined();
  });

  it('says nothing when the reader\'s address is unknown', () => {
    const { recipientEmail: _omitted, ...unaddressed } = base;
    expect(echoed(analyzeDeterministic(unaddressed, { now: FIXED_NOW }))).toBeUndefined();
  });
});

/**
 * A lure the genuine service delivers. Every sender and link check rightly passes, so the item's name is
 * the only evidence; both directions matter because the same service shares ordinary work all day.
 */
describe('a shared file named as a security alert', () => {
  const lure = analyzeFixture('shared-item-alert-lure');
  const base = loadFixture('legitimate-drive-share').email;
  const shared = (subject: string) => analyzeDeterministic({ ...base, subject }, { now: FIXED_NOW });
  const alertItem = (result: AnalysisResult) => signalFor(result, 'identity.alert_named_shared_item');

  it('reports the alert wording in the shared item, and keeps the wording undampened', () => {
    expect(alertItem(lure)?.severity).toBe('high');
    expect(alertItem(lure)?.description).toContain('Online ID Locked');
    expect(lure.signals.some((s) => s.dampened === true)).toBe(false);
    expect(lure.classification).toBe('high-risk');
  });

  it.each([
    'Item shared with you: "Suspicious Sign-In Noticed - Your Online ID Limited.pdf"',
    'Complete with Docusign: Account Suspended Due to Unusual Activity.pdf',
    'Northwind Bank shared "Security Alert - Review Immediately" with you',
    'Document shared with you: "Billing Account Locked - Unrecognized Entry Detected"',
  ])('reads an alert in: %s', (subject) => {
    expect(alertItem(shared(subject))).toBeDefined();
  });

  it('holds a name with one alert feature at medium, since documents about an alert exist', () => {
    const procedure = shared('Item shared with you: "Account locked due to inactivity - procedure.docx"');
    expect(alertItem(procedure)?.severity).toBe('medium');
    expect(procedure.classification).not.toBe('suspicious');
  });

  it('raises a name with two alert features to high', () => {
    const alert = shared('Item shared with you: "Unrecognized Log-In Noticed - Confirm Now.pdf"');
    expect(alertItem(alert)?.severity).toBe('high');
  });

  it.each([
    'Item shared with you: "Q3 Supplier Invoices - Reconciliation.xlsx"',
    'Item shared with you: "Payment remittance advice - September.pdf"',
    'Complete with Docusign: Mutual NDA - Northwind Logistics.pdf',
    'Item shared with you: "Incident review: blocked deployment pipeline"',
    'Your account was locked due to too many sign-in attempts',
  ])('says nothing of: %s', (subject) => {
    expect(alertItem(shared(subject))).toBeUndefined();
  });

  it('leaves an ordinary share at low', () => {
    expect(analyzeFixture('legitimate-drive-share').classification).toBe('low');
  });
});

/**
 * A body that is one linked picture. The picture is unread by design, so the subject is the only text;
 * both directions matter because an image newsletter has the same shape. The lure is held to `caution`
 * rather than the malicious corpus's `suspicious`: a subject alone is not evidence enough for a floor.
 */
describe('a message whose only words are its subject', () => {
  const lure = analyzeFixture('image-only-mailbox-lure');
  const base = loadFixture('image-only-mailbox-lure').email;
  const withSubject = (subject: string, overrides: Partial<EmailMessage> = {}) =>
    analyzeDeterministic({ ...base, subject, ...overrides }, { now: FIXED_NOW });
  const linkOnly = (result: AnalysisResult) => signalFor(result, 'link.link_only_body');

  it('reports the ask in the subject beside an empty body linked off-site', () => {
    expect(linkOnly(lure)?.severity).toBe('medium');
    expect(linkOnly(lure)?.description).toContain('release-queue-portal.net');
    expect(lure.classification).toBe('caution');
  });

  it('keeps an image newsletter to the low note', () => {
    const banner = analyzeFixture('legitimate-image-newsletter');
    expect(linkOnly(banner)?.severity).toBe('low');
    expect(banner.classification).toBe('low');
  });

  it.each(['Action required: confirm your details', 'Final reminder', 'Payment processed for order 4471', 'Your password expires soon'])(
    'reads an ask in: %s',
    (subject) => {
      expect(linkOnly(withSubject(subject))?.severity).toBe('medium');
    },
  );

  it('does not read the subject once the body has words of its own', () => {
    const worded = withSubject('Action required', { bodyText: 'x'.repeat(200) });
    expect(linkOnly(worded)).toBeUndefined();
  });

  it('does not escalate a table brand Gmail proves', () => {
    const brand = withSubject('Your invoice is ready', {
      senderEmail: 'billing@paypal.com',
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy: 'paypal.com', mailedBy: 'paypal.com' },
    });
    expect(linkOnly(brand)?.severity).toBe('low');
  });
});

describe('a threat to deactivate or delete the account', () => {
  const threatened = (bodyText: string) =>
    hasSignal(
      analyzeDeterministic(
        { senderName: 'Accounts', senderEmail: 'desk@northwind-updates.com', subject: 'Notice', bodyText, links: [], attachments: [] },
        { now: FIXED_NOW },
      ),
      'content.account_threat',
    );

  it.each([
    'Your account will be terminated within 24 hours.',
    'Your Norton 360 subscription is scheduled for deactivation today.',
    'Your mailbox has been deactivated.',
    'Your account will be permanently deleted on Friday.',
    'Your access has been restricted.',
  ])('is reported: %s', (text) => {
    expect(threatened(text)).toBe(true);
  });

  it.each([
    'Reply within 30 days to avoid your subscription being deleted from the list archive.',
    'At your request, the account for J. Rivera has been deactivated.',
    'You can delete your account at any time from the settings page.',
    'Deactivate your account from the privacy settings if you no longer need it.',
  ])('is not reported for list footers, admin notices or settings help: %s', (text) => {
    expect(threatened(text)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

describe('suspicious ZIP attachment', () => {
  const result = analyzeFixture('zip-attachment');

  it('reports the archive', () => {
    expect(hasSignal(result, 'attachment.archive')).toBe(true);
  });

  it('escalates because a password for the archive is supplied in the body', () => {
    const s = signalFor(result, 'attachment.archive');
    expect(s?.severity).toBe('high');
    expect(s?.title).toContain('Password-protected');
  });

  it('does not let the attachment alone exceed the attachment category weight', () => {
    expect(result.categoryScores.attachment).toBeLessThanOrEqual(10);
  });

  it('does not reach high risk on an archive alone', () => {
    // A ZIP is a signal, not a verdict. The score here comes from the surrounding pretext too.
    expect(result.categoryScores.attachment).toBeLessThan(25);
  });
});

describe('executable attachments', () => {
  const result = analyzeFixture('executable-attachment');

  it('flags the double extension', () => {
    expect(hasSignal(result, 'attachment.double_extension')).toBe(true);
    expect(signalFor(result, 'attachment.double_extension')?.description).toContain('.exe');
  });

  it('flags the direction-override filename', () => {
    expect(hasSignal(result, 'attachment.filename_direction_override')).toBe(true);
  });

  it('flags the executables themselves', () => {
    expect(hasSignal(result, 'attachment.executable')).toBe(true);
  });

  it('scores high risk overall', () => {
    expect(result.classification).toBe('high-risk');
  });

  it('does not emit the "nothing suspicious" note', () => {
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(false);
  });
});

describe('an extension split by an invisible character', () => {
  it('reads it as the extension it displays as', () => {
    const result = analyzeFixture('soft-hyphen-executable');
    expect(signalFor(result, 'attachment.executable')?.severity).toBe('critical');
    expect(signalFor(result, 'attachment.filename_hidden_characters')?.description).toContain(
      'Its actual type is .exe.',
    );
  });

  it('does not call a hidden character a direction override, which it is not', () => {
    const result = analyzeFixture('soft-hyphen-executable');
    expect(hasSignal(result, 'attachment.filename_direction_override')).toBe(false);
  });

  it('keeps a reversed name critical whatever type it hides', () => {
    const result = analyzeDeterministic(
      {
        senderEmail: 'billing@northwind-traders.com',
        bodyText: 'Statement attached.',
        links: [],
        attachments: [toEmailAttachment({ filename: 'statement_\u202efdp.txt' })],
      },
      { now: FIXED_NOW },
    );
    expect(signalFor(result, 'attachment.filename_direction_override')?.severity).toBe('critical');
    expect(hasSignal(result, 'attachment.filename_hidden_characters')).toBe(false);
  });

  it('does not turn a document into a program', () => {
    expect(fileExtension('annual\u00ad_report.pdf')).toBe('pdf');
    expect(fileExtensionChain('annual_report\u00ad.pdf')).toEqual(['pdf']);
  });
});

// ---------------------------------------------------------------------------
// Social engineering
// ---------------------------------------------------------------------------

describe('executive gift-card scam', () => {
  const result = analyzeFixture('bec-gift-card');

  it('scores at least suspicious with no links and no attachments at all', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.categoryScores.link).toBe(0);
    expect(result.categoryScores.attachment).toBe(0);
  });

  it('recognises the gift-card request', () => {
    expect(hasSignal(result, 'content.gift_card')).toBe(true);
  });

  it('recognises the secrecy request', () => {
    expect(hasSignal(result, 'content.secrecy')).toBe(true);
  });

  it('recognises the combination as a single explained finding', () => {
    expect(hasSignal(result, 'content.combo.gift_card_with_secrecy')).toBe(true);
  });

  it('recognises the external executive claim', () => {
    expect(hasSignal(result, 'identity.external_executive_claim')).toBe(true);
  });

  it('recognises the availability probe and the channel steering', () => {
    expect(hasSignal(result, 'content.unusual_request_shape')).toBe(true);
    expect(hasSignal(result, 'content.process_bypass')).toBe(true);
  });
});

describe('fake payroll-change email', () => {
  const result = analyzeFixture('payroll-change');

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });

  it('recognises the payroll change request', () => {
    expect(hasSignal(result, 'content.payroll_change')).toBe(true);
  });

  it('recognises the request to change banking details', () => {
    expect(hasSignal(result, 'content.payment_detail_change')).toBe(true);
  });

  it('recognises the steer away from the HR portal', () => {
    expect(hasSignal(result, 'content.process_bypass')).toBe(true);
  });
});

/**
 * Both directions of the one distinction this rule rests on: a message that *contains* a code is
 * delivering one, and a message that asks the reader to hand a code over is the attack. The wording
 * overlaps almost entirely, which is why a pattern matching "your verification code is 123456" scored
 * every OTP notification ever sent at 50/100. From a domain with no dampening available, precision in
 * the rule is the only thing standing between ordinary mail and a Suspicious verdict.
 */
describe('a verification code being delivered rather than solicited', () => {
  const result = analyzeFixture('legitimate-verification-code');

  it('raises no request-for-a-code finding', () => {
    expect(hasSignal(result, 'content.mfa_request')).toBe(false);
  });

  it('scores low despite containing the phrase a code phish contains', () => {
    expect(result.classification).toBe('low');
    expect(result.score).toBeLessThan(25);
  });

  it('is not rescued by dampening, because none is available to it', () => {
    const dampened = result.signals.filter((s) => s.dampened === true);
    expect(dampened).toEqual([]);
  });
});

/**
 * The second half of the same distinction, and the reason the first fix was not enough: dropping the
 * pattern for "your verification code is 123456" left the one for "share your verification code", which
 * the safety advice sitting beside every genuine code matches word for word. Every case here is a real
 * sentence from transactional mail or a real phish; the point of the group is that the two populations are
 * separated by what the negation attaches to, and nothing else.
 */
describe('a warning not to share a code, and the request that quotes it', () => {
  const base = loadFixture('legitimate-verification-code').email;
  const withBody = (bodyText: string): AnalysisResult =>
    analyzeDeterministic({ ...base, bodyText }, { now: FIXED_NOW });

  it('reads advice that names the code as advice, not as a request for it', () => {
    const result = withBody(
      'Your verification code is 482915. Never share your verification code with anyone.',
    );

    expect(hasSignal(result, 'content.mfa_request')).toBe(false);
    expect(result.classification).toBe('low');
  });

  it.each([
    'We will never ask you to send us your verification code.',
    'Nobody from our support team will ever ask you to read out your verification code.',
    'Do not share your verification code with anyone, including our own staff.',
    "Don't forward your verification code to anyone who asks you for it.",
    'You should never give your verification code to a caller.',
    'We cannot ask you to provide your verification code, and we never will.',
    'Never ever share your verification code, even with us.',
  ])('reads each ordinary phrasing of that advice the same way: %s', (advice) => {
    const result = withBody(`Your verification code is 482915. ${advice}`);

    expect(hasSignal(result, 'content.mfa_request')).toBe(false);
  });

  /**
   * The evasion the suppression must not open. Quoting the provider's own warning costs an attacker one
   * sentence, so a negation anywhere in the body cannot be allowed to stand for the whole message.
   */
  it('still reports a request that follows the advice', () => {
    const result = withBody(
      'Never share your verification code with anyone. To confirm this sign-in, reply to this email with the verification code shown above.',
    );

    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
    expect(signalFor(result, 'content.mfa_request')?.severity).toBe('high');
  });

  it('still reports a request the negated match swallowed into its own span', () => {
    const result = withBody("Don't share this with anyone, just send me the verification code.");

    expect(signalFor(result, 'content.mfa_request')?.severity).toBe('high');
  });

  it('still reports a request with the advice appended to the same sentence', () => {
    const result = withBody('Please send me your verification code, and never share it with anyone else.');

    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
  });

  /**
   * A negation inside a demand is not advice against it. This is the sentence that makes the suppression
   * conditional on what the negator is attached to rather than on its presence.
   */
  it.each([
    'If you do not send us the verification code within ten minutes your account will be closed.',
    'Unless you forward the verification code to this address, the transfer cannot be released.',
    'Failure to provide the security code will result in your account being suspended.',
  ])('still reports the demand that contains a negation: %s', (demand) => {
    const result = withBody(demand);

    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
  });

  /**
   * A negation that governs some other verb entirely. "Do not" belongs to "hesitate" here, and what
   * follows is as plain a request as the rule ever sees, which is why what may stand between a negation
   * and the verb it suppresses is enumerated rather than merely bounded in length.
   */
  it.each([
    'Do not hesitate to send me your verification code.',
    'Do not wait to send us the verification code from your phone.',
    'Please do not forget to read me the security code when we speak.',
  ])('still reports a request the negation does not reach: %s', (request) => {
    const result = withBody(request);

    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
    expect(signalFor(result, 'content.mfa_request')?.severity).toBe('high');
  });
});

/**
 * "Enter the verification code" ends every genuine code delivery, with the code a line away, and opens
 * the lure that sends the reader to a page harvesting the one their provider just texted them. What
 * separates them is whether the message carries a code, and only one sitting against the word naming it
 * counts: an order or phone number elsewhere in a lure must not pass for one.
 */
describe('an instruction to enter a code the message delivers, and a request to enter one', () => {
  const base = loadFixture('legitimate-verification-code').email;
  const withBody = (bodyText: string): AnalysisResult =>
    analyzeDeterministic({ ...base, bodyText }, { now: FIXED_NOW });

  it.each([
    'Your sign-in code is 482 910. Enter the verification code on the page where you started.',
    '482910 is your verification code. Enter this verification code to finish signing in.',
    'Use the security code below.\n730215\nEnter the security code in the app to continue.',
  ])('reads the instruction beside a delivered code as delivery: %s', (body) => {
    const result = withBody(body);

    expect(hasSignal(result, 'content.mfa_request')).toBe(false);
    expect(result.classification).toBe('low');
  });

  it.each([
    'Enter the verification code we texted you on the page below to keep your account open.',
    'Enter the verification code sent to your phone ending 4471 at the link below.',
    'Order 55821 is on hold. Enter the verification code at the link below to release it.',
  ])('still reports a request to enter a code the message does not carry: %s', (body) => {
    const result = withBody(body);

    expect(signalFor(result, 'content.mfa_request')?.severity).toBe('high');
  });

  it('still reports a request to share the code it delivers', () => {
    const result = withBody('Your verification code is 482915. Reply to this email with the verification code.');

    expect(signalFor(result, 'content.mfa_request')?.severity).toBe('high');
  });
});

describe('MFA code request', () => {
  const result = analyzeFixture('mfa-code-request');

  it('recognises the request for a verification code', () => {
    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
  });

  it('recognises the pairing with a claimed security incident', () => {
    expect(hasSignal(result, 'content.combo.mfa_and_threat')).toBe(true);
  });

  it('recognises the sender domain as imitating the recipient’s own domain', () => {
    expect(hasSignal(result, 'identity.lookalike_of_recipient_domain')).toBe(true);
  });

  /**
   * The correlation that makes this more than a code request, and the case that exposed its wording. The
   * impersonation here is of the reader's own employer, which no brand table contains, so a description
   * built from `primaryClaim` called it "a known organisation" and named nothing the reader could check.
   */
  it('describes the impersonation it actually found, without inventing an organisation', () => {
    const correlated = signalFor(result, 'identity.impersonation_with_credential_request');
    expect(correlated).toBeDefined();
    expect(correlated?.description).toMatch(/imitates the recipient/iu);
    expect(correlated?.description).not.toMatch(/a known organisation/iu);
    expect(correlated?.title).not.toMatch(/a known organisation/iu);
  });

  it('scores high risk', () => {
    expect(result.classification).toBe('high-risk');
  });
});

// ---------------------------------------------------------------------------
// Impersonation of organisations that are not in the brand table
// ---------------------------------------------------------------------------

/**
 * The regression this suite exists for.
 *
 * A real message impersonating a life insurer scored 24/100 (one point below `caution`) because every
 * identity detector was gated on the enumerated `BRANDS` table and the insurer is not in it. No table
 * ever contains every insurer, bank, utility and agency, so identity detection cannot depend on one
 * being complete.
 */
describe('brand impersonation with no brand-table entry', () => {
  const result = analyzeFixture('brand-spoof-leadgen');

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(['suspicious', 'high-risk']).toContain(result.classification);
  });

  it('contributes identity findings without any brand-table entry', () => {
    expect(result.categoryScores.identity).toBeGreaterThan(0);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(true);
  });

  it('explains the mismatch in terms of the name and the domain', () => {
    const s = signalFor(result, 'identity.unsupported_org_claim');
    expect(s?.description).toContain('Northwind Life Offer');
    expect(s?.description).toContain('kv38mailer.com');
  });

  it('flags the repeated fragment in the sender address', () => {
    expect(hasSignal(result, 'identity.implausible_local_part')).toBe(true);
    expect(signalFor(result, 'identity.implausible_local_part')?.description).toContain('4 times');
  });

  it('flags the evasion-formatted subject', () => {
    expect(hasSignal(result, 'content.subject_obfuscation')).toBe(true);
  });

  it('still reports the unencrypted links', () => {
    expect(hasSignal(result, 'link.insecure_http')).toBe(true);
  });

  /**
   * The score must come from more than one dimension. A single saturated category was exactly the
   * original failure: links alone reached 24/25 while everything else contributed nothing.
   */
  it('draws its score from identity and content, not links alone', () => {
    expect(result.categoryScores.link).toBeGreaterThan(0);
    expect(result.categoryScores.identity).toBeGreaterThan(0);
    expect(result.categoryScores.content).toBeGreaterThan(0);
    expect(result.score - result.categoryScores.link).toBeGreaterThanOrEqual(25);
  });
});

/**
 * Reply-chain hijacking, which is invisible to every rule that judges a message alone: the quoted
 * history is real, the subject is a genuine `Re:`, authentication passes because the attacker owns the
 * domain they are sending from, and the imitated party is not in any brand table because it is whoever
 * this reader does business with.
 */
describe('reply-chain hijack by a lookalike domain', () => {
  const result = analyzeFixture('thread-hijack-lookalike');

  it('scores high risk on a message with no links, no attachments and passing authentication', () => {
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('high-risk');
    expect(result.categoryScores.link).toBe(0);
    expect(result.categoryScores.attachment).toBe(0);
  });

  it('names the participant being imitated, not a brand', () => {
    const s = signalFor(result, 'identity.thread_lookalike_participant');
    expect(s?.description).toContain('northwind-supply.com');
    expect(s?.description).toContain('northwlnd-supply.com');
    expect(s?.evidence?.value).toBe('northwlnd-supply.com vs northwind-supply.com');
  });

  it('reaches its verdict without the brand table and without the llm', () => {
    expect(hasSignal(result, 'identity.lookalike_sender_domain')).toBe(false);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(result.categoryScores.llm).toBe(0);
  });

  /**
   * The same message without the conversation is the control. Its wording still reaches `suspicious`
   * on the content rules alone (asking for bank details to be changed is not innocent language), but
   * only the thread comparison turns that into a verdict, which is the capability being added.
   */
  it('needs the conversation to reach high risk', () => {
    const { thread: _thread, ...withoutHistory } = loadFixture('thread-hijack-lookalike').email;
    const blind = analyzeDeterministic(withoutHistory, { now: FIXED_NOW });

    expect(blind.classification).not.toBe('high-risk');
    expect(result.score).toBeGreaterThan(blind.score);
    expect(hasSignal(blind, 'identity.thread_lookalike_participant')).toBe(false);
  });
});

describe('reply-chain hijack reusing a participant name', () => {
  const result = analyzeFixture('thread-hijack-name-reuse');

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(['suspicious', 'high-risk']).toContain(result.classification);
  });

  it('reports the reused name with both addresses so the reader can check it', () => {
    const s = signalFor(result, 'identity.thread_participant_name_reuse');
    expect(s?.description).toContain('Priya Raman');
    expect(s?.evidence?.value).toBe(
      'priya.raman.northwind@gmail.com vs priya.raman@northwind-supply.com',
    );
  });

  it('does not claim a lookalike domain, because no domain here resembles another', () => {
    expect(hasSignal(result, 'identity.thread_lookalike_participant')).toBe(false);
  });

  /** One attack, so one finding. The domain comparison is the more checkable of the two. */
  it('reports the lookalike domain alone when both would apply', () => {
    const both = analyzeFixture('thread-hijack-lookalike');
    expect(hasSignal(both, 'identity.thread_lookalike_participant')).toBe(true);
    expect(hasSignal(both, 'identity.thread_participant_name_reuse')).toBe(false);
  });
});

/**
 * `confirm`/`update` near `details`/`information` is most of ordinary business correspondence. Matching
 * it reported those messages under a title asserting they asked for a credential, which is both wrong
 * and unverifiable: the reader looks for the request and there is none.
 */
describe('credential wording versus ordinary business wording', () => {
  const fires = (bodyText: string): boolean =>
    hasSignal(
      analyzeDeterministic(
        { senderEmail: 'anna@harbourline-freight.com', bodyText, links: [], attachments: [] },
        { now: FIXED_NOW },
      ),
      'content.credential_verification',
    );

  it.each([
    'Could you confirm once the payment details are updated on your side?',
    'Please confirm the delivery details for Thursday.',
    'We have updated our contact information on the portal.',
    'Can you confirm your travel details before I book?',
    'We will never ask you to confirm your details by replying to an email.',
  ])('stays silent on %s', (text) => {
    expect(fires(text)).toBe(false);
  });

  it.each([
    'Please verify your account to continue.',
    'You must confirm your password before Friday.',
    'Update your login information using the link below.',
    'Re-enter your credentials to restore access.',
    'Confirm your security information to avoid interruption.',
  ])('still fires on %s', (text) => {
    expect(fires(text)).toBe(true);
  });
});

/**
 * "Closed" is the one consequence verb that also describes a *bank* account, and payment-diversion mail
 * leans on it: "my old account is being closed, use these details instead". Reported as a threat to
 * account access, it sends the reader hunting for a warning about their login the message never made,
 * while the real problem, a changed payee, is reported by the payment rules with the right words.
 */
describe('threats to account access versus a sender closing an account', () => {
  const fires = (bodyText: string): boolean =>
    hasSignal(
      analyzeDeterministic(
        { senderEmail: 'anna@harbourline-freight.com', bodyText, links: [], attachments: [] },
        { now: FIXED_NOW },
      ),
      'content.account_threat',
    );

  it.each([
    'My old account is being closed at the end of the week, so use the details below.',
    'The old account is being closed and anything sent there will bounce back.',
    'Our receiving account is being closed as part of the group restructure.',
  ])('stays silent on %s', (text) => {
    expect(fires(text)).toBe(false);
  });

  it.each([
    'Your account will be closed on Friday unless you act.',
    'We will close your account if this is not resolved.',
    'Your account has been suspended pending review.',
    // No possessive at all, and still unmistakably about the reader's access.
    'If we do not hear from you the account will remain locked.',
  ])('still fires on %s', (text) => {
    expect(fires(text)).toBe(true);
  });
});

/**
 * The `high` wording rules each set a severity floor on their own, so a pattern that reads an ordinary
 * sentence as the attack puts honest mail at Suspicious with nothing else wrong. Every silent case below
 * is the shape of a sentence that did exactly that in a corpus of genuine mailing-list, corporate and
 * newsletter mail; every firing case is the attack the rule exists for, worded as it is sent.
 */
describe('severe wording rules against the ordinary sentences that share their words', () => {
  const fires = (bodyText: string, id: string): boolean =>
    hasSignal(
      analyzeDeterministic(
        { senderEmail: 'anna@harbourline-freight.com', bodyText, links: [], attachments: [] },
        { now: FIXED_NOW },
      ),
      id,
    );

  describe('sextortion', () => {
    it.each([
      'I have installed the updated package on the build server and the tests pass.',
      'I have captured the network trace from the router, attached.',
      'The tool tells me the passphrase is correct but the key still will not import.',
      'I have been filming the conference talks all week.',
      "I've installed the updated package on the build server.",
      "I've recorded the demo for the team channel.",
      'Pay the 2.50 deposit or we will release the booking to the next guest.',
    ])('stays silent on %s', (text) => {
      expect(fires(text, 'content.sextortion')).toBe(false);
    });

    it.each([
      "I've recorded you through your webcam while you were browsing.",
      "I've installed a trojan on your computer and I see everything.",
      "Pay 0.1 BTC within 48 hours or I'll send the video to your contacts.",
      'I have recorded you through your webcam while you were browsing.',
      'I have installed a trojan on your computer and I see everything.',
      'I have full control of your device.',
      'I know your password and I know what you have been doing.',
      'swordfish41 is one of your passwords.',
    ])('still fires on %s', (text) => {
      expect(fires(text, 'content.sextortion')).toBe(true);
    });
  });

  describe('crypto_demand', () => {
    it.each([
      'Checksum 3f2a9b1c4d4e5f62718293a4b5c6d7e8 for the tarball.',
      'Message-ID 1a2b3c4d5e6f7a8b9c9d1e2f3a4b5c6d.',
      'Ticket 1234567891234567891234567891 has been closed.',
      'Track it at https://shop.northwind-retail.com/gp/o/1rkwtzqpmd58hcvxsn7gjey3dfb26ku-7bnnpc8w52jr today.',
      'boundary="3kqvwrtnmhyzpdsxgle4bnjuftcaw-8rq2-71k"',
      'iD8DBQBHqk2+3rt7wmzpkv5TYnaqLKjvdhgs5e6hhxq/k8PN5bwyoe3cqDfHrk',
    ])('does not read a hash or an identifier as a wallet: %s', (text) => {
      expect(fires(text, 'content.crypto_demand')).toBe(false);
    });

    it.each([
      'Payment address: 1NwKq7rTmYp3ZbV8xJcF2hDsGe9LuA4Wo6',
      'Payment address: 3Hk8mPq2WnRt7YvB5xZcJ4dFgL9sA6eUo1',
      'Payment address: bc1qx9t2l7wz8m4k3r5y6p0s9u2n7h4j8c3v5d6gf',
      'Send it to 1NwKq7rTmYp3ZbV8xJcF2hDsGe9LuA4Wo6. You have 48 hours.',
    ])('still recognises a wallet address: %s', (text) => {
      expect(fires(text, 'content.crypto_demand')).toBe(true);
    });

    it('reads a decimal amount between the verb and the coin as one demand', () => {
      expect(fires('You must send 0.05 BTC to settle this.', 'content.crypto_demand')).toBe(true);
    });

    it('does not let the decimal allowance run past the end of a sentence', () => {
      expect(fires('Please send the agenda. Bitcoin is on the list of topics.', 'content.crypto_demand')).toBe(
        false,
      );
    });

    it.each([
      'You should never send bitcoin to a caller who claims to be from Northwind Bank.',
      'If a stranger messages you about an investment, do not transfer USDT to them.',
    ])('reads the scam warning as advice: %s', (text) => {
      expect(fires(text, 'content.crypto_demand')).toBe(false);
    });

    it('still fires on a demand after the warning it quotes', () => {
      const quoted = 'Never send crypto to strangers. Send 0.05 BTC to settle the invoice today.';
      expect(fires(quoted, 'content.crypto_demand')).toBe(true);
    });

    const newsletter = loadFixture('legitimate-newsletter').email;
    const inBulk = (bodyText: string) =>
      hasSignal(
        analyzeDeterministic(
          { ...newsletter, bodyText: `${bodyText}\n\nYou are receiving this because you signed up. Unsubscribe at any time.` },
          { now: FIXED_NOW },
        ),
        'content.crypto_demand',
      );

    it("drops an exchange's transfer-in offer from bulk mail", () => {
      const offer = 'Transfer your bitcoin from any other exchange before June and we add 1% on top.';
      expect(fires(offer, 'content.crypto_demand')).toBe(true);
      expect(inBulk(offer)).toBe(false);
    });

    it('keeps a wallet address in bulk mail', () => {
      expect(inBulk('Send 0.05 BTC to 1NwKq7rTmYp3ZbV8xJcF2hDsGe9LuA4Wo6 within 48 hours.')).toBe(true);
    });
  });

  describe('payment_detail_change', () => {
    it.each([
      'Open a new savings deposit account online in minutes and earn a higher rate.',
      'Opening a new bank account with us takes five minutes.',
    ])('stays silent on a bank inviting the reader to open an account: %s', (text) => {
      expect(fires(text, 'content.payment_detail_change')).toBe(false);
    });

    it.each([
      'We have opened a new bank account, so please send future payments to the new deposit account below.',
      'Please update the bank account on file before paying our next invoice.',
      'We need to open a new account, so please use the new bank details below for this invoice.',
    ])('still fires on a payee announcing where to pay: %s', (text) => {
      expect(fires(text, 'content.payment_detail_change')).toBe(true);
    });
  });

  describe('gift_card', () => {
    it.each([
      'Spend $50 this weekend and get a $10 gift certificate.',
      'Why not buy a gift voucher for someone special this year?',
      'Every new member receives a prepaid card valued at $75.',
    ])('stays silent on a shop offering one: %s', (text) => {
      expect(fires(text, 'content.gift_card')).toBe(false);
    });

    it.each([
      'Can you buy some gift cards for the client event today?',
      'I need you to purchase Apple gift cards for me.',
      'Please pick up 6 Steam gift cards on your way in.',
      'Get 5 gift cards at 100 each and send me the codes.',
    ])('still fires on a request to buy them: %s', (text) => {
      expect(fires(text, 'content.gift_card')).toBe(true);
    });
  });

  describe('payroll_change', () => {
    it.each([
      'You can now view your payroll information online through the portal.',
      'Notification of a change of payroll status for exempt staff.',
      'To change the mailstop your paycheck goes to, contact the payroll office.',
      'Direct deposit account information is on the back of the form.',
    ])('stays silent on a payroll announcement: %s', (text) => {
      expect(fires(text, 'content.payroll_change')).toBe(false);
    });

    it.each([
      'I need to update my direct deposit details before the next run.',
      'Please change my payroll deposit to the new account below.',
      'Could you switch my salary to a different bank?',
      'My new account should be used for my salary from this month.',
    ])('still fires on an employee asking to redirect their pay: %s', (text) => {
      expect(fires(text, 'content.payroll_change')).toBe(true);
    });
  });

  /** Together these make a `critical` combination, so each half is tested where it used to misread. */
  describe('the halves of a transfer that bypasses approval', () => {
    it.each(['Spot volumes for Swift Harbour Gas are revised below.', 'Keynote by Professor Dana Swift.'])(
      'does not read a name as a banking term: %s',
      (text) => {
        expect(fires(text, 'content.wire_transfer')).toBe(false);
      },
    );

    it('does not read "a swift response" as a banking term', () => {
      expect(fires('Thank you for your swift response to the survey.', 'content.wire_transfer')).toBe(false);
    });

    it.each([
      'The SWIFT code is on the attached letter.',
      'The funds will arrive by swift transfer within two days.',
      'Bank: Northwind Trust, SWIFT: NWTRGB2LXXX',
    ])('still recognises SWIFT as a banking term: %s', (text) => {
      expect(fires(text, 'content.wire_transfer')).toBe(true);
    });

    it.each([
      "The script throws an error: can't call method on an undefined value.",
      'I cannot speak for the others, but the prices look fair to me.',
    ])('does not read a failed call or an idiom as avoiding contact: %s', (text) => {
      expect(fires(text, 'content.process_bypass')).toBe(false);
    });

    it.each([
      "I'm in a meeting with the board and cannot take calls.",
      "I can't talk right now, just email me.",
      "I won't be able to answer my phone today.",
    ])('still fires on a sender making themselves unreachable: %s', (text) => {
      expect(fires(text, 'content.process_bypass')).toBe(true);
    });
  });
});

/**
 * The counterweight. New senders appear in threads constantly for innocent reasons, so the rules key on
 * *resemblance* to an established party rather than unfamiliarity. This fixture contains three new
 * senders at once and must stay silent on all of them.
 */
describe('ordinary changes of cast within a thread', () => {
  const result = analyzeFixture('legitimate-thread-reply');

  it('stays low', () => {
    expect(result.classification).toBe('low');
  });

  it('raises no thread findings for an unfamiliar sender', () => {
    expect(hasSignal(result, 'identity.thread_lookalike_participant')).toBe(false);
    expect(hasSignal(result, 'identity.thread_participant_name_reuse')).toBe(false);
  });

  /**
   * `northwind-supply.de` against `northwind-supply.com` is the case that decides whether this rule is
   * usable. The names are identical and only the suffix differs, which is overwhelmingly one company
   * rather than an imitation (companies reply from country domains every day), so it is deliberately
   * not reported, unlike the brand rule where the real domains are enumerated.
   */
  it('treats the same name under a different suffix as the same organisation', () => {
    const parties = buildContext(loadFixture('legitimate-thread-reply').email).priorParties;
    expect(findParticipantLookalike('northwind-supply.de', parties)).toBeNull();
  });
});

describe('participant lookalike comparison', () => {
  const party = (email: string, name = 'Sam Reeve'): ThreadParty[] =>
    buildContext({
      senderEmail: 'reader@example.org',
      bodyText: '',
      links: [],
      attachments: [],
      thread: { priorSenders: [{ email, name }] },
    }).priorParties;

  it('catches a homoglyph substitution as conclusive', () => {
    const match = findParticipantLookalike('nоrthwind-supply.com', party('ap@northwind-supply.com'));
    expect(match?.kind).toBe('confusable');
  });

  /**
   * `i` for `l` folds to the same skeleton, so the substitution attackers most often reach for is
   * caught as visually identical rather than as an edit. Asserted so the stronger classification is not
   * lost by a change to the confusable table.
   */
  it('treats an i-for-l substitution as visually identical', () => {
    const match = findParticipantLookalike('northwlnd-supply.com', party('ap@northwind-supply.com'));
    expect(match?.kind).toBe('confusable');
  });

  it('catches a dropped character as an edit', () => {
    const match = findParticipantLookalike('northwind-suply.com', party('ap@northwind-supply.com'));
    expect(match?.kind).toBe('edit-distance');
    expect(match?.distance).toBe(1);
  });

  it('ignores unrelated domains', () => {
    expect(findParticipantLookalike('harbourline-freight.com', party('ap@northwind-supply.com'))).toBeNull();
  });

  /** On a short name an edit of one is as likely to be two unrelated companies as an imitation. */
  it('will not compare names too short to be distinctive', () => {
    expect(findParticipantLookalike('acme.com', party('ap@acne.com'))).toBeNull();
  });

  it('says nothing about a sender already established in the conversation', () => {
    expect(findParticipantLookalike('northwind-supply.com', party('ap@northwind-supply.com'))).toBeNull();
  });
});

/**
 * Brand keywords are matched on separator-stripped text so `p-a-y-p-a-l` still reads as PayPal. The
 * cost is that a short keyword can hide inside an ordinary word once the spaces are gone: `irs` sits
 * in "first", `aws` in "laws". A claim invented that way is not cosmetic: it decides whether the
 * message is treated as presenting itself as that organisation.
 */
describe('short brand keywords inside ordinary words', () => {
  const claimsFor = (subject: string, bodyText: string, senderName = 'Dana Whitfield'): string[] =>
    buildContext({
      senderName,
      senderEmail: 'dana.whitfield@northwind-logistics.com',
      subject,
      bodyText,
      links: [],
      attachments: [],
    }).claims.map((claim) => claim.brand.id);

  it('does not read "first" in a subject as a claim to be the IRS', () => {
    expect(claimsFor('First quarter results', 'Figures for the first quarter are attached.')).toEqual(
      [],
    );
  });

  it('does not read "lawsuit" in a body as a claim to be AWS', () => {
    expect(claimsFor('Update', 'Counsel advised us on the lawsuit and its timeline.')).toEqual([]);
  });

  it('does not read "chairs" or "repairs" as an IRS mention', () => {
    expect(claimsFor('Office', 'The chairs need repairs before the stairs are refitted.')).toEqual([]);
  });

  it('still recognises a short keyword standing on its own', () => {
    expect(claimsFor('IRS notice CP2000', 'Reply with the details requested.')).toContain('irs');
  });

  it('still recognises a long keyword broken up with separators', () => {
    expect(claimsFor('Account review', 'Confirm your p-a-y-p-a-l details.')).toContain('paypal');
  });

  /**
   * A person's name can fold into a brand keyword across the space between its words: `rn` folds to
   * `m`, so "Miriam Stearns" runs together as `mlrlamsteams`, which contains `msteams`. A match has to
   * begin where a word does to span more than one.
   */
  it('does not assemble a keyword from the end of one word and the start of the next', () => {
    expect(claimsFor('Lunch', 'See you there.', 'Miriam Stearns')).toEqual([]);
  });

  it('still recognises a brand spaced out from the start of a word', () => {
    expect(claimsFor('Lunch', 'See you there.', 'Micro Soft Account Team')).toContain('microsoft');
    expect(claimsFor('Lunch', 'See you there.', 'P a y P a l')).toContain('paypal');
  });

  it('still recognises a brand fused into a longer word', () => {
    expect(claimsFor('Lunch', 'See you there.', 'SecurePayPal Team')).toContain('paypal');
  });

  it('records a keyword in the display name as an identity claim, not a body mention', () => {
    const context = buildContext({
      senderName: 'PayPal Service',
      senderEmail: 'billing@kv38mailer.com',
      subject: 'Invoice',
      bodyText: 'Paypal receipts are attached.',
      links: [],
      attachments: [],
    });
    expect(context.primaryClaim?.source).toBe('sender-name');
  });
});

/**
 * A government newsletter platform is the one shared sender allowed to stand for a brand, because it
 * accepts only government bodies. The same name from anywhere else is still the claim it looks like.
 */
describe('a tax authority newsletter from its government sending platform', () => {
  const analyzeFrom = (senderEmail: string) =>
    analyzeDeterministic(
      {
        senderName: 'IRS e-News for Small Businesses',
        senderEmail,
        subject: 'IRS e-News for Small Businesses',
        bodyText: 'This issue covers the new filing season. Log in to your account to review your details.',
        links: [],
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  it('is not reported as impersonation from the platform', () => {
    const result = analyzeFrom('irs@service.govdelivery.com');
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.impersonation_with_credential_request')).toBe(false);
  });

  it('is still reported from a domain the IRS does not send from', () => {
    const result = analyzeFrom('irs@service.northwind-notices.com');
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(true);
  });
});

/**
 * A display name can name two brands honestly, because a product name can contain another brand's word:
 * `Amazon Appstore Team` claims Amazon, and `appstore` is one of Apple's keywords. Both claims are real,
 * so the question is not which to keep but which the message is *making*, and that used to be answered
 * by whichever brand appeared earlier in `brands.ts`, which is a fact about the table and not about the
 * message. Apple precedes Amazon there, so authenticated mail from a domain Amazon owns was reported as
 * Apple impersonation at `high`, correlated with the verification wording into a `critical`, 75/100.
 *
 * Both halves matter. Resolving the tie by ownership has to leave the phishing version of the same name
 * flagged, and has to make its finding name the brand a reader would say was being imitated.
 */
describe('a display name that names two brands', () => {
  const genuine = loadFixture('legitimate-brand-product-name').email;

  const claimsOf = (email: EmailMessage): string[] =>
    buildContext(email).claims.map((claim) => claim.brand.label);

  it('sees both brands in the name, since both are really there', () => {
    expect(claimsOf(genuine)).toEqual(['Amazon', 'Apple']);
  });

  it('reads the message as claiming the brand that owns the sending domain', () => {
    expect(buildContext(genuine).primaryClaim?.brand.label).toBe('Amazon');
  });

  it('raises no impersonation finding against mail from that brand own domain', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.impersonation_with_credential_request')).toBe(false);
    expect(result.categoryScores.identity).toBe(0);
    expect(result.classification).toBe('low');
  });

  /**
   * The same name from a domain neither brand owns. Ownership cannot break this tie, so the earliest
   * mention does, which is what a reader does with a name, and it keeps the sentence checkable: the
   * name says Amazon, so the finding has to say Amazon.
   */
  it('still flags the same name sent from an unrelated domain, and names the brand the name claims', () => {
    const result = analyzeDeterministic(
      { ...genuine, senderEmail: 'no-reply@appstore-amazon-developer.com', auth: undefined },
      { now: FIXED_NOW },
    );

    const s = signalFor(result, 'identity.display_name_impersonation');
    expect(s?.title).toContain('Amazon');
    expect(s?.title).not.toContain('Apple');
    expect(s?.severity).toBe('high');
  });

  /**
   * The case the rule exists for, kept here so the ownership tiebreak cannot be widened into silence:
   * a domain whose owner is no brand at all suppresses nothing.
   */
  /**
   * The links of the same message, in the form its sending platform writes them: the destination sits in
   * the tracker's path with its separators percent-encoded. `URL` leaves those encoded, so a pattern
   * written for the literal form reads the tracker as the destination, and a verification button that
   * the brand's own console serves became a sign-in link the brand supposedly sent to a domain it does
   * not own, three times over, saturating the link category on its own.
   */
  it('reads a tracker-wrapped destination as the brand own domain, not as the tracker', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'link.credential_link_unrelated_domain')).toBe(false);
    expect(result.categoryScores.link).toBe(0);
  });

  /**
   * And the reverse, which is what makes reading the wrapper better than ignoring it: the same tracker
   * around a destination the brand does not own is still reported, and the finding names the destination
   * rather than the tracker that carried it.
   */
  it('still flags a credential destination hidden inside the same wrapper', () => {
    const result = analyzeDeterministic(
      {
        ...genuine,
        links: [
          {
            text: 'Start identity verification',
            href: 'https://a1b2c3d.r.us-east-1.awstrack.me/L0/https:%2F%2Fappstore-developer-verify.com%2Fsignin/1/0100abcdef',
            normalizedDomain: 'awstrack.me',
          },
        ],
      },
      { now: FIXED_NOW },
    );

    const s = signalFor(result, 'link.credential_link_unrelated_domain');
    expect(s?.description).toContain('appstore-developer-verify.com');
    expect(s?.description).not.toContain('awstrack.me');
  });

  it('still flags a name claiming a brand from a domain no brand owns', () => {
    const result = analyzeDeterministic(
      {
        senderName: 'Microsoft Account Team',
        senderEmail: 'security@notify-ms-alerts.com',
        subject: 'Unusual sign-in activity',
        bodyText: 'We noticed a sign-in from a new device. Review the activity on your account.',
        links: [],
        attachments: [],
      },
      { now: FIXED_NOW },
    );

    expect(signalFor(result, 'identity.display_name_impersonation')?.title).toContain('Microsoft');
  });
});

/**
 * A brand that operates its own top-level domain, where the brand table's question ("is this one of the
 * domains we list?") has the wrong shape. ICANN's Specification 13 restricts registrations in a brand TLD
 * to the operator, its affiliates and its trademark licensees, so a name under `.apple` is Apple's by the
 * registry agreement rather than by appearing in a list, and no list of second-level names can keep up
 * with one. Until the TLD itself counted as ownership, an authenticated notice from Apple's own TLD with a
 * display name saying Apple was Apple impersonation at `high`: 50/100, Suspicious, and a marker on the
 * inbox row for good measure.
 */
describe("a sender on a brand's own top-level domain", () => {
  const genuine = loadFixture('legitimate-brand-tld').email;

  it('still reads the display name as claiming the brand', () => {
    expect(buildContext(genuine).primaryClaim?.brand.label).toBe('Apple');
  });

  it("treats every name under the brand TLD as the brand's own", () => {
    expect(brandOwningDomain('notices.apple')?.label).toBe('Apple');
    expect(brandOwningDomain('anything-at-all.apple')?.label).toBe('Apple');
  });

  it('raises no impersonation finding and scores nothing', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(result.categoryScores.identity).toBe(0);
    expect(result.classification).toBe('low');
  });

  it('puts no marker on the inbox row', () => {
    expect(
      triageSender({ senderName: 'Apple Savings Support', senderEmail: 'no_reply@post.notices.apple' }),
    ).toBeNull();
  });

  /**
   * Ownership asked once. Five rules compared a claim against `brand.domains` directly instead of asking
   * the function that knows about brand TLDs, so they disagreed with it about who owns a name under
   * `.apple`: the message was excluded from the alignment that dampens content heuristics, its own links
   * read as pointing outside the organisation, and a relay on its own TLD read as a service the brand does
   * not use. One question answered in five places produces unrelated symptoms in unrelated files.
   */
  it('counts the brand TLD as alignment, so the dampening a verified brand earns applies', () => {
    expect(buildContext(genuine).senderAlignedWithClaim).toBe(true);
  });

  it('reads a sign-in link on the brand TLD as the brand own', () => {
    const result = analyzeDeterministic(
      {
        ...genuine,
        links: [
          {
            text: 'Verify your account',
            href: 'https://notices.apple/account/verify',
            normalizedDomain: 'notices.apple',
          },
        ],
      },
      { now: FIXED_NOW },
    );

    expect(result.categoryScores.link).toBe(0);
  });

  /**
   * The displayed/actual mismatch rule, asked the same ownership question about the *destination*. It
   * matched a brand on the anchor text and then said "the real destination does not [belong to it]"
   * without ever checking, so a brand's own short-link domain was somewhere the brand was not: 45 points,
   * `critical`, and the sentence that earned it was the footer telling the reader where to report a
   * phishing email. Both directions matter here, because the anchor text naming a brand's domain is also
   * the strongest link signal there is when the destination really is elsewhere.
   */
  it('does not read a brand own short-link domain as a mismatch with its own address', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(false);
    expect(result.categoryScores.link).toBe(0);
    expect(result.classification).toBe('low');
  });

  it('still reports that address shown against a destination the brand does not own', () => {
    const result = analyzeDeterministic(
      {
        ...genuine,
        links: [toEmailLink({ text: 'apple.com/security', href: 'https://apple-id-security.example/verify' })],
      },
      { now: FIXED_NOW },
    );

    expect(signalFor(result, 'link.displayed_url_mismatch.0')?.severity).toBe('critical');
  });

  /**
   * Scoped to the brand the anchor text names, not to whether *some* brand owns the destination;
   * otherwise showing one brand's address while linking to another's would suppress itself, and every
   * brand in the table would be a usable disguise for every other.
   */
  it('still reports one brand address shown against another brand destination', () => {
    const result = analyzeDeterministic(
      { ...genuine, links: [toEmailLink({ text: 'apple.com/security', href: 'https://microsoft.com/verify' })] },
      { now: FIXED_NOW },
    );

    expect(signalFor(result, 'link.displayed_url_mismatch.0')?.severity).toBe('critical');
  });

  it('still flags the same claim from a domain outside that TLD', () => {
    const result = analyzeDeterministic(
      { ...genuine, senderEmail: 'no-reply@apple-savings-notice.com', auth: undefined },
      { now: FIXED_NOW },
    );
    expect(signalFor(result, 'identity.display_name_impersonation')?.title).toContain('Apple');
  });

  /**
   * The mistake this must never become. A brand TLD carries its guarantee because nobody else can register
   * under it; a TLD that anyone can buy a name in carries none, and treating one as a brand's would hand
   * the brand's identity to every registrant. Both of these are in Apple's and Microsoft's `domains` as
   * second-level names (`me.com`, `live.com`), which is exactly as far as it goes.
   */
  it.each(['phish-support.me', 'account-verify.live', 'secure-login.app', 'apple-id.dev'])(
    'claims no ownership of %s, whose TLD is open to anyone',
    (domain) => {
      expect(brandOwningDomain(domain)).toBeUndefined();
    },
  );

  /** A typo in the list is silent otherwise: a TLD that does not exist can never match a real sender. */
  it('lists only top-level domains IANA has delegated', () => {
    for (const brand of BRANDS) {
      for (const tld of brand.tlds ?? []) {
        expect(hasUnknownTld(`example.${tld}`), `${brand.id}: ${tld}`).toBe(false);
        expect(tld, `${brand.id}: ${tld}`).toBe(tld.toLowerCase());
        expect(tld.includes('.'), `${brand.id}: ${tld}`).toBe(false);
      }
    }
  });
});

/**
 * The same open-world problem as the brand TLD, in its most expensive form. A brand runs one name across
 * every market it sells in, the table lists a few of those domains, and the lookalike rule read every other
 * one as a `critical` imitation of the `.com`: 45 points and a severity floor, so authentic mail from
 * `hsbc.fr` was High Risk. Thirty-odd brands against two hundred country suffixes is not a list anyone
 * finishes, so the question is answered structurally: a name that is literally the brand's, under a suffix
 * that misspells none of the brand's own, is reported as unverifiable rather than judged as imitation.
 */
describe("a brand's own name under a suffix the table does not list", () => {
  const genuine = loadFixture('legitimate-brand-country-domain').email;

  it('is not called an imitation of the domain it shares a name with', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'identity.lookalike_sender_domain')).toBe(false);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
  });

  it('says what cannot be confirmed, without a severity floor', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    const finding = signalFor(result, 'identity.unverified_brand_domain');

    expect(finding?.severity).toBe('medium');
    expect(finding?.title).toContain('paypal.it');
    expect(finding?.description).toContain('every market');
    expect(result.classification).not.toBe('high');
  });

  /** The reader has to be told which links were left unjudged for the same reason, and not told twice. */
  it('does not also report every link to that domain as credential harvesting', () => {
    const result = analyzeDeterministic(genuine, { now: FIXED_NOW });
    expect(hasSignal(result, 'link.credential_link_unrelated_domain.0')).toBe(false);
    expect(result.categoryScores.link).toBe(0);
  });

  /**
   * What must not be softened with it. A suffix that is the brand's own with characters dropped is a typo
   * trap, not a market (`.co`, `.cm` and `.om` are the reason anyone registers them), and a name that is
   * only *confusably* the brand's is a homoglyph domain, which is the lookalike rule's entire purpose.
   */
  it.each([
    ['paypal.co', 'PayPal'],
    ['microsoft.cm', 'Microsoft'],
    ['раypal.com', 'PayPal'],
    ['paypa1.com', 'PayPal'],
  ])('still reports %s as an imitation', (domain, label) => {
    expect(brandNamingDomain(domain)).toBeUndefined();
    expect(findLookalike(domain)?.brandLabel).toBe(label);
  });

  it('claims nothing for a name that merely contains a brand', () => {
    for (const domain of ['paypal-security.com', 'secure-hsbc.net', 'appleid-verify.co']) {
      expect(brandNamingDomain(domain), domain).toBeUndefined();
    }
  });

  /** A short core collides with ordinary words, so the rule stays out of names it cannot be sure about. */
  it('claims nothing for a core too short to be distinctive', () => {
    expect(brandNamingDomain('me.tv')).toBeUndefined();
    expect(brandNamingDomain('ups.io')).toBeUndefined();
  });
});

/**
 * DKIM signatures from a sending platform are the norm for commercial mail. What matters is whether the
 * From domain is the brand's own: if it is, the mismatch says nothing, and reporting it at `medium` was
 * enough to suppress the dampening that keeps legitimate brand mail out of "caution".
 */
describe('confirmation wording that is not a credential ask', () => {
  const body = (bodyText: string): AnalysisResult =>
    analyzeDeterministic(
      {
        senderName: 'Harbour Coffee',
        senderEmail: 'orders@harbour-coffee-roasters.com',
        subject: 'Your order',
        bodyText,
        links: [],
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  it('ignores a customer-service question phrased as a confirmation', () => {
    const result = body('Please confirm you are happy with your order and we will ship it today.');
    expect(hasSignal(result, 'content.credential_verification')).toBe(false);
  });

  it('still catches a confirmation of identity', () => {
    const result = body('Confirm this is really you to keep your account active.');
    expect(hasSignal(result, 'content.credential_verification')).toBe(true);
  });
});

describe('signatures from a sending platform', () => {
  const signedBy = (senderEmail: string, signer: string): AnalysisResult =>
    analyzeDeterministic(
      {
        senderName: 'PayPal',
        senderEmail,
        subject: 'Your password was changed',
        bodyText: 'You recently changed the password on your account. Sign in if this was not you.',
        links: [],
        attachments: [],
        auth: { spf: 'pass', dkim: 'pass', signedBy: signer },
      },
      { now: FIXED_NOW },
    );

  it('stays quiet when a brand own domain signs through a known platform', () => {
    const result = signedBy('service@paypal.com', 'sendgrid.net');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(false);
  });

  it('still reports it when the From domain is not the brand at all', () => {
    const result = signedBy('service@paypal-secure-billing.com', 'sendgrid.net');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(true);
  });

  it('still reports a signer that is neither the sender nor a known platform', () => {
    const result = signedBy('service@paypal.com', 'kv38mailer.com');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(true);
  });
});

describe('organisational-claim detector boundaries', () => {
  const base = loadFixture('brand-spoof-leadgen').email;

  const withSender = (name: string, email: string): AnalysisResult =>
    analyzeDeterministic({ ...base, senderName: name, senderEmail: email }, { now: FIXED_NOW });

  it('stays quiet when the display name shares a word with the domain', () => {
    const result = withSender('Kestrel Insurance Group', 'quotes@kestrelinsurance.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet when the domain merely adds a suffix to the name', () => {
    const result = withSender('Northwind Benefits Team', 'no-reply@mail.northwind-hr.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet for a personal name, which claims no institution', () => {
    const result = withSender('Priya Raman', 'priya@kv38mailer.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet for a recognised third-party sending service', () => {
    const result = withSender('Acme Payroll Support', 'no-reply@sendgrid.net');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('escalates when an institution claims to write from a consumer mailbox', () => {
    const result = withSender('Meridian Bank Security Team', 'meridian.alerts@gmail.com');
    expect(signalFor(result, 'identity.unsupported_org_claim')?.severity).toBe('high');
  });

  it('defers to the brand table when the claimed brand is a known one', () => {
    const result = withSender('PayPal Billing Team', 'service@kv38mailer.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(true);
  });
});

describe('repeated-fragment local parts', () => {
  it('counts separator-delimited repetition', () => {
    expect(repeatedUnitCount('donot.reply.donot.reply.donot.reply.donot.reply')).toBe(4);
  });

  it('counts unseparated repetition', () => {
    expect(repeatedUnitCount('donotreplydonotreplydonotreply')).toBe(3);
  });

  it('does not count an ordinary mailbox name', () => {
    expect(repeatedUnitCount('sam.okafor')).toBe(0);
    expect(repeatedUnitCount('first.last.first')).toBe(0);
  });

  /** ESP bounce addresses are long and opaque but not repetitive; length alone must not trigger. */
  it('does not count a long opaque ESP bounce address', () => {
    expect(repeatedUnitCount('bounces+124987-abcd-user=example.com')).toBe(0);
    expect(repeatedUnitCount('bounce-md_39481726.f8a2c410')).toBe(0);
  });
});

/**
 * Randomised case and subject padding are both destroyed by normalisation: the adapter case-folds the
 * address and collapses the subject's whitespace, because every comparison downstream depends on it.
 * `EmailMessage.raw` carries the originals so formatting detectors can still see them.
 */
describe('signals that survive only in the raw fields', () => {
  const fixture = loadFixture('brand-spoof-leadgen');

  it('carries the raw forms alongside the normalised ones', () => {
    expect(fixture.email.senderEmail).toBe('donot.reply.donot.reply.donot.reply.donot.reply@kv38mailer.com');
    expect(fixture.email.raw?.senderEmail).toContain('DoNoT');
    expect(fixture.email.subject).not.toMatch(/ {2}/u);
    expect(fixture.email.raw?.subject).toMatch(/ {24}/u);
  });

  it('detects the randomised capitalisation', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    expect(hasSignal(result, 'identity.randomised_address_case')).toBe(true);
  });

  it('detects the padded subject', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    const s = signalFor(result, 'content.subject_padding');
    expect(s).toBeDefined();
    expect(s?.description).toMatch(/run of \d+ consecutive spaces/u);
  });

  it('reports nothing when the client gave no raw form', () => {
    const { raw: _raw, ...withoutRaw } = fixture.email;
    const result = analyzeDeterministic(withoutRaw, { now: FIXED_NOW });

    expect(hasSignal(result, 'identity.randomised_address_case')).toBe(false);
    expect(hasSignal(result, 'content.subject_padding')).toBe(false);
    // The brand-independent identity findings do not depend on raw fields, so they still stand.
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(true);
  });

  it('does not let the padded subject leak into the evidence shown to the user', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    for (const s of result.signals) {
      expect(s.evidence?.text ?? '').not.toMatch(/ {4}/u);
      expect(s.evidence?.value ?? '').not.toMatch(/ {4}/u);
    }
  });
});

describe('case-scrambling detection', () => {
  it('recognises alternating case', () => {
    expect(isCaseScrambled('DoNoT')).toBe(true);
    expect(isCaseScrambled('rEpLy')).toBe(true);
    expect(isCaseScrambled('aCcOuNt')).toBe(true);
  });

  /** Run length, not capital count, is what separates these from evasion. */
  it('does not flag CamelCase mailbox names', () => {
    expect(isCaseScrambled('JohnSmith')).toBe(false);
    expect(isCaseScrambled('MyCompanyName')).toBe(false);
    expect(isCaseScrambled('McDonald')).toBe(false);
    expect(isCaseScrambled('iPhoneSupport')).toBe(false);
  });

  it('does not flag single-case words', () => {
    expect(isCaseScrambled('donotreply')).toBe(false);
    expect(isCaseScrambled('NEWSLETTER')).toBe(false);
  });
});

describe('subject padding boundaries', () => {
  const base = loadFixture('legitimate-invoice').email;

  const withRawSubject = (subject: string): AnalysisResult =>
    analyzeDeterministic(
      { ...base, subject: subject.replace(/\s+/gu, ' ').trim(), raw: { subject } },
      { now: FIXED_NOW },
    );

  it('ignores ordinary double spaces', () => {
    expect(hasSignal(withRawSubject('Invoice 4471  attached'), 'content.subject_padding')).toBe(false);
  });

  it('ignores incidental whitespace from element boundaries', () => {
    expect(hasSignal(withRawSubject('Invoice 4471       attached'), 'content.subject_padding')).toBe(false);
  });

  it('flags a long padding run', () => {
    const padded = `Invoice 4471 attached${' '.repeat(40)}`;
    expect(hasSignal(withRawSubject(padded), 'content.subject_padding')).toBe(true);
  });

  it('does not treat newlines as padding', () => {
    expect(hasSignal(withRawSubject(`Invoice 4471\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nattached`), 'content.subject_padding')).toBe(false);
  });
});

describe('subject formatting markers', () => {
  const { repeatedDecorativeChar } = contentTestables;

  it('treats a repeated dingbat as an ornament', () => {
    expect(repeatedDecorativeChar('WELCOME ❋ TO YOUR ❋ QUOTE')).toBe('❋');
  });

  it('does not treat bullet or dash separators as ornaments', () => {
    expect(repeatedDecorativeChar('News • Sports • Weather')).toBeNull();
    expect(repeatedDecorativeChar('Report – Q3 – Final')).toBeNull();
  });

  it('does not treat a single emoji as an ornament', () => {
    expect(repeatedDecorativeChar('🎉 Your order has shipped')).toBeNull();
    expect(repeatedDecorativeChar('✅ Payment received, thank you')).toBeNull();
  });

  it('needs more than one marker before reporting anything', () => {
    const base = loadFixture('legitimate-newsletter').email;
    const shouting = analyzeDeterministic(
      { ...base, subject: 'LAST CHANCE: 20% OFF SINGLE ORIGINS ENDS TONIGHT' },
      { now: FIXED_NOW },
    );
    expect(hasSignal(shouting, 'content.subject_obfuscation')).toBe(false);
  });
});

/**
 * A phish built so that every individual check has an innocent answer.
 *
 * Worth a section of its own because it is the case the engine was worst at, and because each finding
 * below is paired with the reason the corresponding *legitimate* shape stays quiet. The whole design of
 * this message is that no single field is wrong: the sending domain resolves nowhere but is spelled
 * plausibly, the destination host belongs to Google, the display name reads as English, and the body
 * carries a working unsubscribe line. It originally scored 30/100 on one content finding.
 */
/**
 * A phish that leaves identity and authentication empty on purpose: no brand to impersonate, and a
 * throwaway domain whose own SPF and DKIM pass. Everything it does wrong lands in links and wording, whose
 * weights sum to 40, so the additive score alone could not express how sure the findings are.
 */
describe('severe findings from the two categories a phish could not avoid', () => {
  const result = analyzeFixture('storage-payment-bucket-page');

  it('leaves identity and authentication with nothing to score', () => {
    expect(result.categoryScores.identity).toBe(0);
    expect(result.categoryScores.authentication).toBe(0);
  });

  it('reaches high risk on the checks alone, because links and wording converge', () => {
    const sum = Object.values(result.categoryScores).reduce((a, b) => a + b, 0);

    expect(sum).toBeLessThan(75);
    expect(scoreFloor(result.signals)).toEqual({
      floor: 75,
      basis: 'convergence',
      categories: ['link', 'content'],
    });
    expect(result.classification).toBe('high-risk');
    expect(result.categoryScores.llm).toBe(0);
  });

  it('shows the storage-bucket finding once, saying how many links it covers', () => {
    const shown = distinctForDisplay(result.signals).filter((s) => s.id.startsWith('link.page_in_open_storage'));

    expect(shown).toHaveLength(1);
    expect(shown[0]?.description).toContain('This applies to 3 links in the message.');
  });

  it('keeps every copy for scoring, so the collapse changes what is shown and nothing else', () => {
    expect(result.signals.filter((s) => s.id.startsWith('link.page_in_open_storage'))).toHaveLength(3);
  });

  it('does not add a count to a finding about one link', () => {
    const single = analyzeDeterministic({
      ...loadFixture('storage-payment-bucket-page').email,
      links: [
        toEmailLink({
          text: 'UPDATE MY PAYMENT DETAILS',
          href: 'https://storage.googleapis.com/nw-bucket-41c/cloud_v2.html',
        }),
      ],
    });
    expect(signalFor(single, 'link.page_in_open_storage')?.description).not.toContain('This applies to');
  });
});

describe('phishing that is innocent one field at a time', () => {
  const result = analyzeFixture('storage-quota-bucket-page');
  const base = loadFixture('storage-quota-bucket-page').email;

  /** A plausible on-device reading of this message: confident, and naming concerns the checks also found. */
  const MODEL_VERDICT: SemanticAnalysis = {
    risk: 80,
    confidence: 0.9,
    categories: ['credential_phishing', 'social_engineering'],
    reasons: ['Threatens deletion of personal files unless a subscription is renewed immediately.'],
    source: 'local',
  };

  const fixedAnalyzer = (analysis: SemanticAnalysis): SemanticAnalyzer => ({
    id: 'fixed',
    isAvailable: () => Promise.resolve(true),
    analyze: () => Promise.resolve(analysis),
  });

  /**
   * Three categories are saturated at their weights, so the additive sum stops in the suspicious band
   * however much more is wrong. What carries it to high risk is that the severe findings are independent:
   * each category is a different way for the message to be wrong. The checks reach the verdict themselves;
   * the model is not what gets a message like this over the line.
   */
  it('reaches high risk on deterministic findings alone, because severe findings converge', () => {
    const sum = Object.values(result.categoryScores).reduce((a, b) => a + b, 0);
    const floor = scoreFloor(result.signals);

    expect(sum).toBeLessThan(75);
    expect(floor.basis).toBe('convergence');
    expect(floor.categories.length).toBeGreaterThanOrEqual(2);
    expect(result.score).toBe(75);
    expect(result.classification).toBe('high-risk');
    expect(result.categoryScores.llm).toBe(0);
  });

  it('still takes the capped points from a corroborated model verdict, as a refinement', async () => {
    const withModel = await analyze(base, fixedAnalyzer(MODEL_VERDICT), { now: FIXED_NOW });

    expect(withModel.categoryScores.llm).toBe(CATEGORY_WEIGHTS.llm);
    expect(withModel.classification).toBe('high-risk');
    expect(withModel.score).toBeGreaterThan(result.score);
  });

  describe('a From domain under a TLD that does not exist', () => {
    it('is reported as fabricated rather than merely odd', () => {
      const finding = signalFor(result, 'identity.nonexistent_sender_tld');
      expect(finding?.description).toContain('never been assigned');
    });

    /**
     * Deliberately `high` and not `critical`, and the reason is about the list rather than the message.
     * The observation is conclusive, but it is only as current as the committed IANA snapshot, and
     * `critical` floors the score at high risk, which would let one aging file hand a high-risk verdict
     * to a legitimate sender under a newly delegated TLD with nothing else wrong. At `high` that same
     * staleness tops out at suspicious.
     */
    it('cannot on its own produce a high-risk verdict, because the list ages', () => {
      const onlyFinding = analyzeDeterministic({
        senderName: 'Accounts',
        senderEmail: 'noreply@northwind-supply.ldk',
        subject: 'Your statement is ready',
        bodyText: 'Your monthly statement is attached to your account area, as usual. Thank you.',
        links: [],
        attachments: [],
      });

      expect(ids(onlyFinding)).toEqual(['identity.nonexistent_sender_tld']);
      expect(onlyFinding.classification).toBe('suspicious');
      expect(severityFloor(onlyFinding.signals)).toBeLessThan(75);
    });

    it('says nothing about a domain under a real TLD, however obscure', () => {
      for (const domain of ['qmbvx.ldk', 'example.museum', 'shop.co.za', 'mail.xn--p1ai']) {
        const scored = analyzeDeterministic({ ...base, senderEmail: `alert@${domain}` });
        expect(hasSignal(scored, 'identity.nonexistent_sender_tld')).toBe(domain === 'qmbvx.ldk');
      }
    });

    /**
     * `.local` and friends are undelegated *by design*, so their absence from the snapshot is not
     * evidence of anything. Mail from one is an internal appliance using its own hostname far more often
     * than it is an attack, and reporting that as a fabricated sender would be both wrong and, at
     * `critical`, loud.
     */
    it('treats a private-use name as misconfiguration, not fabrication', () => {
      const internal = analyzeDeterministic({ ...base, senderEmail: 'backup@fileserver.local' });

      expect(hasSignal(internal, 'identity.nonexistent_sender_tld')).toBe(false);
      expect(signalFor(internal, 'identity.private_use_sender_tld')?.severity).toBe('medium');
    });
  });

  describe('a display name spelled in mathematical letterforms', () => {
    it('is reported, and explains that it defeats checking rather than reading', () => {
      const finding = signalFor(result, 'identity.styled_display_name');
      expect(finding?.severity).toBe('medium');
      expect(finding?.description).toContain('avoid being checked');
    });

    it('is not claimed for ordinary names, accents, or emoji', () => {
      for (const name of ['Payment Declined', 'Zoë Müller', 'Kestrel Coffee ☕', 'ACME™ Billing']) {
        const scored = analyzeDeterministic({ ...base, senderName: name });
        expect(hasSignal(scored, 'identity.styled_display_name')).toBe(false);
      }
    });

    /**
     * The consequence, not just the observation. Folding the name for *matching* is what lets the
     * brand-independent organisational-claim rule see `payment declined` at all; spelled in the
     * mathematical alphabet it matched no pattern, which is the entire reason it is spelled that way.
     */
    it('still reads what the name claims, through the substitution', () => {
      expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(true);
    });
  });

  describe('a payload page held in a public storage bucket', () => {
    it('is reported even though the host is Google and the URL is flawless', () => {
      const finding = signalFor(result, 'link.page_in_open_storage');
      expect(finding?.severity).toBe('high');
      expect(finding?.evidence?.value).toBe('storage.googleapis.com');
      expect(finding?.description).toContain('not to whoever wrote the page');
    });

    it('says nothing about assets and downloads, which is what object storage is for', () => {
      for (const path of ['/bucket/logo.png', '/bucket/invoice-4471.pdf', '/bucket/app-1.2.zip']) {
        const scored = analyzeDeterministic({
          ...base,
          links: [toEmailLink({ text: 'Download', href: `https://storage.googleapis.com${path}` })],
        });
        expect(hasSignal(scored, 'link.page_in_open_storage')).toBe(false);
      }
    });

    it('leaves a sign-in page to the rule that can say what it asks for', () => {
      const login = analyzeDeterministic({
        ...base,
        links: [
          toEmailLink({
            text: 'Sign in to continue',
            href: 'https://storage.googleapis.com/strdrv-9f2/signin.html',
          }),
        ],
      });

      expect(hasSignal(login, 'link.page_in_open_storage')).toBe(false);
      expect(hasSignal(login, 'link.credential_link_open_hosting')).toBe(true);
    });

    it('softens to medium when the message is not asking the reader to act', () => {
      const quiet = analyzeDeterministic({
        ...base,
        subject: 'Notes from Thursday',
        bodyText: 'Here is the write-up we discussed. Nothing urgent, have a look when you get a chance.',
      });
      expect(signalFor(quiet, 'link.page_in_open_storage')?.severity).toBe('medium');
    });
  });

  describe('a body that vouches for itself', () => {
    it('reports the forged notice and names who such notices come from', () => {
      const finding = signalFor(result, 'content.forged_trust_assurance');
      expect(finding?.description).toContain('come from your mail provider');
    });

    it('does not fire on ordinary uses of "trust" and "verified"', () => {
      for (const line of [
        'Thank you for trusting us with your order. Your account is verified for two-factor sign-in.',
        'Our verified partners can be found in the directory.',
        'We take your trust seriously and never share your data.',
      ]) {
        const scored = analyzeDeterministic({ ...base, bodyText: line });
        expect(hasSignal(scored, 'content.forged_trust_assurance')).toBe(false);
      }
    });

    /**
     * The footers a mail gateway staples onto outbound business mail, and the notice a bank's secure
     * portal sends. Logically these are the same move (a claim inside a message about that message), but
     * the population carrying them is overwhelmingly honest, so matching them would put 22 points on
     * ordinary correspondence from any organisation with a scanning appliance.
     */
    it('leaves scanning footers and secure-portal notices alone', () => {
      for (const line of [
        'This email has been scanned for viruses by our mail gateway.',
        'This message has been checked by antivirus software and no threats were found.',
        'This is a secure message from your bank. Sign in to the portal to read it.',
        'This email was scanned by Barracuda Email Security.',
        'No virus found in this message.',
      ]) {
        const scored = analyzeDeterministic({ ...base, bodyText: line });
        expect(hasSignal(scored, 'content.forged_trust_assurance'), line).toBe(false);
      }
    });
  });

  describe('prose hidden with CSS to dilute the wording', () => {
    it('is reported by volume, with the technique named', () => {
      const finding = signalFor(result, 'content.hidden_body_text');
      expect(finding?.description).toContain('display:none');
      expect(finding?.description).toContain('2784');
    });

    it('ignores a preheader, which is what nearly every sender hides', () => {
      const preheader = analyzeDeterministic({
        ...base,
        hiddenText: { chars: 120, techniques: ['display:none'] },
      });
      expect(hasSignal(preheader, 'content.hidden_body_text')).toBe(false);
    });

    /**
     * The suppression this message bought for the price of an unsubscribe link. Bulk-mail shape exists to
     * keep marketing wording out of the score, and concealed filler is not marketing, so the message that
     * pads itself no longer gets the benefit of the doubt it was engineered to claim.
     */
    it('withdraws the bulk-mail suppression that concealment was buying', () => {
      const withoutFiller = analyzeDeterministic({ ...base, hiddenText: { chars: 0, techniques: [] } });

      expect(hasSignal(result, 'content.invoice_fraud')).toBe(true);
      expect(hasSignal(withoutFiller, 'content.invoice_fraud')).toBe(false);
    });

    it('still recognises a genuine newsletter as bulk mail', () => {
      const newsletter = analyzeFixture('legitimate-newsletter');
      expect(newsletter.classification).toBe('low');
    });
  });

  /**
   * The extraction bug this fixture also documents: Gmail printed `via <host>` in the header the whole
   * time, and `readVia` looked for it inside the sender element, which holds the display name and nothing
   * else. The rule was written long before it ever ran.
   */
  it('reads the via annotation Gmail showed all along', () => {
    expect(hasSignal(result, 'authentication.via_unrelated_host')).toBe(true);
  });
});

/**
 * The regression that followed from fixing that extraction: a rule which had never run in production
 * started running everywhere.
 *
 * Gmail prints `via` whenever the authenticated sending domain differs from the From domain, which is the
 * ordinary consequence of sending through any third-party service. It appears on a large share of real
 * commercial mail, so a few points for it lifts most of an inbox at once, and a signal equally present in
 * the honest and the dishonest population is not evidence, however irregular the relay host looks.
 */
describe('a relay host is context, not a finding', () => {
  it('costs nothing on legitimate mail sent through a platform', () => {
    const invoice = analyzeFixture('legitimate-invoice');
    const finding = signalFor(invoice, 'authentication.via_unrelated_host');

    expect(finding?.severity).toBe('info');
    expect(finding?.score).toBe(0);
    expect(invoice.categoryScores.authentication).toBe(0);
    expect(invoice.classification).toBe('low');
  });

  it('still explains where the message came from, since the reader may want to know', () => {
    const finding = signalFor(analyzeFixture('legitimate-invoice'), 'authentication.via_unrelated_host');

    expect(finding?.evidence?.value).toBe('ledgerworks-billing.com');
    expect(finding?.description).toContain('does not affect the score');
  });

  /**
   * The one configuration where a relay is evidence: it contradicts a specific claim. A message calling
   * itself Microsoft and arriving through someone else's platform is not describing how Microsoft sends
   * mail, and unlike the plain case, that conclusion needs no reputation data about the relay.
   */
  it('scores when the relay contradicts a brand the message claims to be', () => {
    const spoof = analyzeDeterministic({
      ...loadFixture('microsoft-phish').email,
      auth: { via: 'mail.ledgerworks-billing.com' },
    });
    const finding = signalFor(spoof, 'authentication.via_unrelated_host');

    expect(finding?.severity).toBe('medium');
    expect(finding?.score).toBeGreaterThan(0);
  });

  it('says nothing at all when the relay is the sender or a recognised platform', () => {
    const legitimate = loadFixture('legitimate').email;
    const own = analyzeDeterministic({
      ...legitimate,
      auth: { via: `mail.${(legitimate.senderEmail ?? '').split('@')[1] ?? ''}` },
    });
    const esp = analyzeDeterministic({
      ...loadFixture('legitimate-newsletter').email,
      auth: { via: 'sendgrid.net' },
    });

    expect(hasSignal(own, 'authentication.via_unrelated_host')).toBe(false);
    expect(hasSignal(esp, 'authentication.via_unrelated_host')).toBe(false);
  });
});

/**
 * A message's score must be a property of the message, not of where it is filed.
 *
 * Moving mail to Spam made Gmail render a banner, which the extractor read as a security verdict, which
 * (being `high` and in a floor-eligible category) dragged any message to at least 50. Two independent
 * corrections: placement notices are no longer read as verdicts, and Gmail's warning may no longer
 * establish a floor because it is not a finding this extension established.
 */
describe('Gmail banner: verdicts versus placement notices', () => {
  const { readGmailWarning } = adapterTestables;

  it('reads a genuine inbox warning as a verdict', () => {
    expect(
      readGmailWarning(
        "Be careful with this message. It contains content that's typically used to steal personal information.",
      ),
    ).toContain('Be careful');
    expect(readGmailWarning('This message seems dangerous. Many people marked similar messages as phishing scams.')).toBeDefined();
  });

  it('ignores the spam-folder placement notice', () => {
    expect(
      readGmailWarning(
        "Why is this message in spam? It's similar to messages that were detected by our spam filters.",
      ),
    ).toBeUndefined();
  });

  /** The frame matters: inside "why is this in spam", security wording is a filing rationale. */
  it('ignores a placement notice even when it contains security wording', () => {
    expect(
      readGmailWarning(
        "Why is this message in spam? It contains content that's typically used to steal personal information.",
      ),
    ).toBeUndefined();
  });

  it('ignores a notice reflecting the user’s own action', () => {
    expect(readGmailWarning('You marked this message as spam.')).toBeUndefined();
    expect(readGmailWarning('This message is in Spam. Not spam')).toBeUndefined();
  });

  it('ignores benign notices with no security wording', () => {
    expect(readGmailWarning('Images are not displayed. Display images below')).toBeUndefined();
    expect(readGmailWarning('')).toBeUndefined();
  });

  it('does not let Gmail’s warning alone establish a floor', () => {
    const warned: SecuritySignal[] = [
      {
        id: 'authentication.gmail_warning',
        category: 'authentication',
        severity: 'high',
        score: 30,
        title: 'Gmail displayed its own warning banner for this message',
        description: 'x',
      },
    ];
    expect(severityFloor(warned)).toBe(0);
  });

  it('still lets our own high-severity findings establish a floor', () => {
    const ours: SecuritySignal[] = [
      {
        id: 'identity.sender_ip_domain',
        category: 'authentication',
        severity: 'high',
        score: 28,
        title: 'x',
        description: 'x',
      },
    ];
    expect(severityFloor(ours)).toBe(50);
  });

  /** End to end: the same message must score the same with and without Gmail's banner attached. */
  it('keeps a legitimate message low when Gmail annotates it', () => {
    const base = loadFixture('legitimate').email;
    const plain = analyzeDeterministic(base, { now: FIXED_NOW });
    const annotated = analyzeDeterministic(
      {
        ...base,
        auth: {
          ...base.auth,
          gmailWarning: 'Be careful with this message. It looks suspicious.',
        },
      },
      { now: FIXED_NOW },
    );

    expect(plain.classification).toBe('low');
    // The warning is reported and adds weight, but cannot on its own make a clean message suspicious.
    expect(hasSignal(annotated, 'authentication.gmail_warning')).toBe(true);
    expect(annotated.score).toBeLessThan(50);
    expect(annotated.classification).not.toBe('suspicious');
  });
});

/**
 * Which message in a thread gets assessed.
 *
 * Taking the last expanded message assessed the user's own reply once they had replied to something,
 * scoring their own writing while the inbound message they might need warning about sat collapsed above
 * it. Skipping their own messages fixes that, but the obvious form of the skip ("ignore anything from my
 * address") would hand a free pass to mail forged to look like it came from the reader, which is a scam
 * genre in its own right and arrives in the inbox looking exactly like a sent message. The tests below
 * pin both halves: the reply is skipped, the forgery is not.
 */
describe('choosing the message to assess', () => {
  const { isOutboundMessage, selectReadableMessage, isOutboundLabel, accountAddressFromTitle } =
    adapterTestables;

  const ME = 'sam.okafor@northwind-logistics.com';
  const received = { sender: 'accounts@supplier.example', audience: [ME] };
  const myReply = { sender: ME, audience: ['accounts@supplier.example'] };

  describe('recognising a message the user sent', () => {
    it('treats a message from the account addressed to someone else as sent', () => {
      expect(isOutboundMessage(myReply, ME)).toBe(true);
    });

    it('does not treat inbound mail as sent', () => {
      expect(isOutboundMessage(received, ME)).toBe(false);
    });

    it('still assesses a forgery from the reader’s own address back to themselves', () => {
      // "I have access to your account" mail spoofs the recipient's own address. Suppressing on the
      // From address alone would exempt the entire genre.
      expect(isOutboundMessage({ sender: ME, audience: [ME] }, ME)).toBe(false);
    });

    it('still assesses a forgery that also copies in a third party', () => {
      // The account remaining among the recipients is what gives this away, which is why an
      // account-equal address in the audience must not be filtered out as redundant.
      expect(isOutboundMessage({ sender: ME, audience: [ME, 'attacker@evil.example'] }, ME)).toBe(
        false,
      );
    });

    it('assesses the message when the recipient row has not rendered', () => {
      // Unknown is not "nobody": failing towards assessing is the safe direction.
      expect(isOutboundMessage({ sender: ME, audience: null }, ME)).toBe(false);
      expect(isOutboundMessage({ sender: ME, audience: [] }, ME)).toBe(false);
    });

    it('assesses everything when the account address could not be read', () => {
      expect(isOutboundMessage(myReply, '')).toBe(false);
    });

    it('is unaffected by a sender that merely resembles the account', () => {
      expect(isOutboundMessage({ sender: 'sam.okafor@northwind.example', audience: ['x@y.example'] }, ME)).toBe(false);
    });
  });

  describe('selecting within a thread', () => {
    it('skips the user’s reply and lands on the message it answers', () => {
      expect(selectReadableMessage([received, myReply], ME, false)).toBe(0);
    });

    it('takes the newest inbound message when several are expanded', () => {
      const older = { sender: 'first@supplier.example', audience: [ME] };
      expect(selectReadableMessage([older, received, myReply], ME, false)).toBe(1);
    });

    it('takes the last message when none of them are the user’s', () => {
      expect(selectReadableMessage([received, received], ME, false)).toBe(1);
    });

    it('reports nothing to assess when the thread is only the user’s own mail', () => {
      expect(selectReadableMessage([myReply], ME, false)).toBeNull();
      expect(selectReadableMessage([], ME, false)).toBeNull();
    });

    it('reports nothing in Sent, whatever the headers say', () => {
      // The route is the one signal here a sender cannot influence: nothing a phisher does files their
      // message under `#sent`, so this may suppress unconditionally.
      expect(selectReadableMessage([received], ME, true)).toBeNull();
    });
  });

  describe('reading the route label', () => {
    it.each([
      ['#sent/FMfcgzQbcd1234567890', true],
      ['#drafts?compose=new', true],
      ['#sent', true],
      ['#inbox/FMfcgzQbcd1234567890', false],
      ['#label/Suppliers/FMfcgzQbcd1234567890', false],
      ['#search/sent/FMfcgzQbcd1234567890', false],
      ['', false],
    ])('%s → outbound view: %s', (hash, expected) => {
      expect(isOutboundLabel(hash)).toBe(expected);
    });
  });

  describe('reading the account address from the title', () => {
    it('takes the account segment, not the first address in the string', () => {
      // A subject can contain an address; taking the first match would read the wrong mailbox and make
      // the reader's own replies look like someone else's mail.
      expect(accountAddressFromTitle('Re: invoice from billing@supplier.example - sam@northwind.example - Gmail'))
        .toBe('sam@northwind.example');
    });

    it('handles a subject containing the separator', () => {
      expect(accountAddressFromTitle('Q3 - final - sam@northwind.example - Gmail')).toBe(
        'sam@northwind.example',
      );
    });

    it('returns nothing rather than guessing', () => {
      expect(accountAddressFromTitle('Gmail')).toBeUndefined();
      expect(accountAddressFromTitle('Inbox - Gmail')).toBeUndefined();
      expect(accountAddressFromTitle('')).toBeUndefined();
    });
  });
});

describe('combinations in bulk mail', () => {
  const offer =
    'Treat someone this season: buy 3 gift cards worth $25 each and get a bonus card. Order immediately, the offer expires within 24 hours!';
  const send = (bodyText: string, links: { text: string; href: string }[]) =>
    analyzeDeterministic(
      {
        senderName: 'Kestrel Coffee Roasters',
        senderEmail: 'hello@kestrelcoffee.co.uk',
        subject: 'Our winter gift guide',
        bodyText,
        links: links.map((link) => toEmailLink(link)),
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  it('does not rebuild a combination from a theme bulk mail had withdrawn', () => {
    const result = send(`${offer} You are receiving this because you subscribed. Unsubscribe.`, [
      { text: 'Unsubscribe', href: 'https://kestrelcoffee.co.uk/unsubscribe' },
    ]);
    expect(hasSignal(result, 'content.urgency')).toBe(false);
    expect(hasSignal(result, 'content.combo.urgent_gift_card_request')).toBe(false);
  });

  it('still combines the same themes in a message that is not bulk', () => {
    const result = send(offer, []);
    expect(hasSignal(result, 'content.combo.urgent_gift_card_request')).toBe(true);
  });
});

describe('a brand name under a suffix that is not a market', () => {
  it.each(['paypal.it', 'paypal.com.br', 'paypal.co.za'])('reads a country suffix as perhaps the brand: %s', (domain) => {
    expect(brandNamingDomain(domain)?.id).toBe('paypal');
  });

  it.each(['paypal.support', 'paypal.secure', 'paypal.online'])('reads a generic suffix as an imitation: %s', (domain) => {
    expect(brandNamingDomain(domain)).toBeUndefined();
    const result = analyzeDeterministic(
      { senderName: 'PayPal', senderEmail: `service@${domain}`, bodyText: 'Your statement is ready.', links: [], attachments: [] },
      { now: FIXED_NOW },
    );
    expect(hasSignal(result, 'identity.unverified_brand_domain')).toBe(false);
    expect(signalFor(result, 'identity.lookalike_sender_domain')?.severity).toBe('critical');
  });
});

describe('an executive title the writer gives themselves', () => {
  const send = (overrides: Partial<EmailMessage>) =>
    analyzeDeterministic(
      {
        senderName: 'Jo Hartley',
        senderEmail: 'jo.hartley@outlook.com',
        recipientEmail: 'sam.okafor@northwind-logistics.com',
        subject: 'Quick one',
        bodyText: 'Are you at your desk? I need a favour handled discreetly.',
        links: [],
        attachments: [],
        ...overrides,
      },
      { now: FIXED_NOW },
    );

  it.each([
    'This is your CEO. Are you at your desk? I need a favour handled discreetly.',
    "I'm the managing director and I need a favour handled discreetly today.",
    'Are you at your desk? I need a favour handled discreetly. Regards, Jo Hartley, CEO',
  ])('reports it in the body: %s', (bodyText) => {
    expect(signalFor(send({ bodyText }), 'identity.external_executive_claim')?.severity).toBe('high');
  });

  it('reports it in the display name', () => {
    expect(hasSignal(send({ senderName: 'Jo Hartley (CEO)' }), 'identity.external_executive_claim')).toBe(true);
  });

  it('does not read a title the message only mentions', () => {
    const result = send({ bodyText: 'Our president announced the new office at the all-hands. Are you going to the party?' });
    expect(hasSignal(result, 'identity.external_executive_claim')).toBe(false);
  });

  it('does not apply between two personal mailboxes, where there is no organisation to impersonate', () => {
    const result = send({
      recipientEmail: 'sam.okafor@gmail.com',
      bodyText: "Hi! I'm the founder of a small bakery now, come visit sometime.",
    });
    expect(hasSignal(result, 'identity.external_executive_claim')).toBe(false);
  });
});

describe('an organisation claim that is only generous', () => {
  const send = (senderName: string, senderEmail: string) =>
    analyzeDeterministic(
      {
        senderName,
        senderEmail,
        recipientEmail: 'sam.okafor@northwind-logistics.com',
        bodyText: 'Please confirm your account to continue your application.',
        links: [],
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  it('does not make a platform writing for a customer into credential harvesting', () => {
    const result = send('Contoso Recruiting Team', 'no-reply@northwind-hireflow.com');
    expect(signalFor(result, 'identity.unsupported_org_claim')?.severity).toBe('medium');
    expect(hasSignal(result, 'identity.impersonation_with_credential_request')).toBe(false);
  });

  it('still pairs an institutional claim from a personal mailbox with the request', () => {
    const result = send('Northwind Bank Security', 'northwind.bank.alerts@gmail.com');
    expect(signalFor(result, 'identity.unsupported_org_claim')?.severity).toBe('high');
    expect(signalFor(result, 'identity.impersonation_with_credential_request')?.severity).toBe('critical');
  });
});

describe('structured invoices', () => {
  it('does not read an XML invoice as a web page', () => {
    const result = analyzeFixture('legitimate-e-invoice');
    expect(hasSignal(result, 'attachment.script_container')).toBe(false);
    expect(hasSignal(result, 'attachment.executable_with_document_pretext')).toBe(false);
    expect(result.classification).toBe('low');
  });

  it('still reads an HTML file sent as an invoice as one', () => {
    const base = loadFixture('legitimate-e-invoice').email;
    const result = analyzeDeterministic(
      { ...base, attachments: [toEmailAttachment({ filename: 'Invoice-118-2026.html' })] },
      { now: FIXED_NOW },
    );
    expect(signalFor(result, 'attachment.script_container')?.severity).toBe('high');
  });
});

describe('payment wording: where money goes versus how the reader pays', () => {
  const withBody = (bodyText: string) =>
    analyzeDeterministic(
      { senderEmail: 'billing@northwind-streaming.com', bodyText, links: [], attachments: [] },
      { now: FIXED_NOW },
    );

  it.each([
    'Your card was declined. Please update your payment information to keep your subscription.',
    'Update your account information in settings at any time.',
    'Your card expires next month; you can update your payment method in your profile.',
  ])('does not read a card on file as a payee change: %s', (bodyText) => {
    const result = withBody(bodyText);
    expect(hasSignal(result, 'content.payment_detail_change')).toBe(false);
    expect(result.classification).toBe('low');
  });

  it.each([
    'Please note our bank details have changed; update the remittance details before the next run.',
    'Kindly update the payee account number on file to the one below.',
    'Please use the new bank account for all future invoices.',
  ])('still reads a payee change: %s', (bodyText) => {
    expect(signalFor(withBody(bodyText), 'content.payment_detail_change')?.severity).toBe('high');
  });

  it('reports a billing update demanded under a threat', () => {
    const result = withBody('Your account has been blocked. Update your payment details to keep your photos.');
    expect(signalFor(result, 'content.combo.billing_update_under_threat')?.severity).toBe('high');
  });
});

describe('a verified brand asking to move money', () => {
  const PROVEN = { spf: 'pass', dkim: 'pass', dmarc: 'pass', signedBy: 'paypal.com' } as const;

  it('keeps a money-movement combination at full weight', () => {
    const result = analyzeDeterministic(
      {
        senderName: 'PayPal',
        senderEmail: 'service@paypal.com',
        bodyText: 'Please wire the funds to the account below today. Keep this confidential and do not discuss it with anyone.',
        links: [],
        attachments: [],
        auth: PROVEN,
      },
      { now: FIXED_NOW },
    );
    const combo = signalFor(result, 'content.combo.bec_wire_secrecy');
    expect(combo?.severity).toBe('critical');
    expect(combo?.dampened).toBeUndefined();
    expect(result.classification).not.toBe('low');
  });

  it('still zeroes the fake-sign-in combination on a genuine security notice', () => {
    const result = analyzeFixture('legitimate-password-reset');
    expect(result.signals.filter((s) => s.id.startsWith('content.combo.') && s.score > 0)).toEqual([]);
    expect(result.classification).toBe('low');
  });
});

describe('role names in a thread', () => {
  it.each(['Info', 'Billing', 'Admin', 'IT', 'Northwind Billing'])('treats %s as a desk, not a person', (name) => {
    expect(threadTestables.isRoleName(name)).toBe(true);
  });

  it('still treats a person as a person', () => {
    expect(threadTestables.isRoleName('Dana Whitfield')).toBe(false);
  });
});

describe('authentication failures that DMARC overruled', () => {
  const withAuth = (auth: EmailMessage['auth']) =>
    analyzeDeterministic(
      { senderEmail: 'dana@northwind-logistics.com', bodyText: 'Lunch on Friday?', links: [], attachments: [], ...(auth === undefined ? {} : { auth }) },
      { now: FIXED_NOW },
    );

  it('reports a softfail beside a DMARC pass as low', () => {
    const result = withAuth({ spf: 'softfail', dkim: 'pass', dmarc: 'pass' });
    expect(hasSignal(result, 'authentication.failure')).toBe(false);
    expect(signalFor(result, 'authentication.partial_failure')?.severity).toBe('low');
    expect(result.classification).toBe('low');
  });

  it('keeps a failure with no DMARC pass high', () => {
    expect(signalFor(withAuth({ spf: 'softfail', dkim: 'pass' }), 'authentication.failure')?.severity).toBe('high');
    expect(signalFor(withAuth({ spf: 'pass', dkim: 'fail', dmarc: 'fail' }), 'authentication.failure')?.severity).toBe('high');
  });
});

describe('brand table domains', () => {
  it('lists no host beneath a registrable domain, which ownership checks could never match', () => {
    for (const brand of BRANDS) {
      for (const domain of brand.domains) {
        const registrable = registrableDomain(domain);
        expect(registrable === '' || registrable === domain, `${brand.id}: ${domain}`).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Invariants that must hold for every fixture
// ---------------------------------------------------------------------------

describe('invariants across all fixtures', () => {
  const fixtures = loadAllFixtures();

  // A fixture in neither list is asserted in neither direction, which is how a malicious case can stop
  // being checked for detection, or a legitimate one for staying out of the severity floors.
  it('classifies every fixture on disk as honest or malicious, exactly once', () => {
    const listed = [...HONEST_FIXTURES, ...MALICIOUS_FIXTURES, ...CAUTION_ONLY_FIXTURES];
    expect(new Set(listed).size).toBe(listed.length);
    expect(fixtures.map((f) => f.name).sort()).toEqual([...listed].sort());
  });

  it.each(CAUTION_ONLY_FIXTURES)('raises %s above low', (name) => {
    expect(analyzeFixture(name).classification).not.toBe('low');
  });

  for (const fixture of fixtures) {
    describe(fixture.name, () => {
      const result = analyzeDeterministic(fixture.email, { now: FIXED_NOW });

      it('produces an integer score in [0, 100]', () => {
        expect(Number.isInteger(result.score)).toBe(true);
        expect(result.score).toBeGreaterThanOrEqual(0);
        expect(result.score).toBeLessThanOrEqual(100);
      });

      it('score is the additive subtotal raised to any applicable severity floor', () => {
        const sum = Math.min(100, Math.round(Object.values(result.categoryScores).reduce((a, b) => a + b, 0)));
        const floor = severityFloor(result.signals);
        expect(result.score).toBe(Math.max(sum, floor));
        expect(result.score).toBeGreaterThanOrEqual(sum);
      });

      it('emits no duplicate signal ids', () => {
        const seen = ids(result);
        expect(new Set(seen).size).toBe(seen.length);
      });

      it('gives every signal a non-empty title and description', () => {
        for (const s of result.signals) {
          expect(s.title.length).toBeGreaterThan(0);
          expect(s.description.length).toBeGreaterThan(0);
        }
      });

      it('bounds every piece of evidence', () => {
        for (const s of result.signals) {
          expect(s.evidence?.text?.length ?? 0).toBeLessThanOrEqual(161);
          expect(s.evidence?.value?.length ?? 0).toBeLessThanOrEqual(161);
          expect(s.evidence?.url?.length ?? 0).toBeLessThanOrEqual(2048);
        }
      });

      it('contributes zero from the llm category when no analyzer ran', () => {
        expect(result.categoryScores.llm).toBe(0);
      });

      it('is deterministic: identical input gives an identical result', () => {
        const again = analyzeDeterministic(fixture.email, { now: FIXED_NOW });
        expect(JSON.stringify(again.signals)).toBe(JSON.stringify(result.signals));
        expect(again.score).toBe(result.score);
      });

      it('does not mutate the input message', () => {
        const before = JSON.stringify(fixture.email);
        analyzeDeterministic(fixture.email, { now: FIXED_NOW });
        expect(JSON.stringify(fixture.email)).toBe(before);
      });
    });
  }
});

describe('ranking sanity: phishing must outscore legitimate mail', () => {
  const score = (name: string): number => analyzeFixture(name).score;

  it('every malicious fixture outscores every legitimate fixture', () => {
    const legitimate = HONEST_FIXTURES.map(score);
    const malicious = MALICIOUS_FIXTURES.map(score);
    expect(Math.max(...legitimate)).toBeLessThan(Math.min(...malicious));
  });

  it('every legitimate fixture classifies as low', () => {
    for (const name of LEGITIMATE_FIXTURES) {
      expect(analyzeFixture(name).classification, name).toBe('low');
    }
  });

  /** The ambiguity is reported, and reported as ambiguity: never an all-clear, never an accusation. */
  it('every unverifiable fixture stops at caution and says what it could not verify', () => {
    for (const name of UNVERIFIABLE_FIXTURES) {
      const result = analyzeFixture(name);
      expect(result.classification, name).toBe('caution');
      expect(
        result.signals.some((s) => s.id === 'identity.unverified_brand_domain'),
        name,
      ).toBe(true);
    }
  });

  it('every malicious fixture classifies at least as suspicious', () => {
    for (const name of MALICIOUS_FIXTURES) {
      const result = analyzeFixture(name);
      expect(['suspicious', 'high-risk'], name).toContain(result.classification);
    }
  });
});

/**
 * The severity floors in `scoring/config.ts` are only safe if legitimate mail never produces a `high`
 * or `critical` deterministic signal. That is a load-bearing assumption, so it is asserted directly
 * rather than left implicit: if a future detector starts flagging real mail as `high`, this fails
 * here rather than silently marking every newsletter as suspicious in production.
 */
describe('severity floor safety', () => {
  for (const name of HONEST_FIXTURES) {
    it(`${name} produces no high or critical deterministic signal`, () => {
      const result = analyzeFixture(name);
      const offenders = result.signals.filter(
        (s) => s.category !== 'llm' && (s.severity === 'high' || s.severity === 'critical') && s.score > 0,
      );
      expect(offenders.map((s) => `${s.id} (${s.severity})`)).toEqual([]);
      expect(severityFloor(result.signals)).toBe(0);
      // Implied by the line above, and stated anyway: this is the assumption the convergence floor rests on.
      expect(scoreFloor(result.signals).basis).toBeNull();
    });
  }

  it('an informational signal never establishes a floor', () => {
    const result = analyzeFixture('legitimate');
    expect(result.signals.some((s) => s.severity === 'info')).toBe(true);
    expect(severityFloor(result.signals)).toBe(0);
  });
});

/**
 * Language packs feed the existing content themes. Each language has a credential lure that must fire,
 * and a code-delivery and newsletter that must stay honest, the same both-directions contract as the
 * English fixtures, so a pack cannot buy coverage by over-firing on ordinary mail.
 */
describe('multilingual wording packs', () => {
  for (const id of LANGUAGE_IDS) {
    describe(id, () => {
      it('reports a credential ask on the phishing lure', () => {
        const result = analyzeFixture(`northwind-${id}-credential-phish`);
        expect(hasSignal(result, 'content.credential_verification')).toBe(true);
        expect(result.classification === 'low').toBe(false);
      });

      it('keeps a one-time-code delivery low', () => {
        const result = analyzeFixture(`northwind-${id}-verification-code`);
        expect(result.classification).toBe('low');
        expect(hasSignal(result, 'content.mfa_request')).toBe(false);
      });

      it('keeps a newsletter low despite urgency language', () => {
        const result = analyzeFixture(`northwind-${id}-newsletter`);
        expect(result.classification).toBe('low');
        expect(
          result.signals.some(
            (s) => s.category === 'content' && (s.severity === 'high' || s.severity === 'critical'),
          ),
        ).toBe(false);
      });
    });
  }
});
