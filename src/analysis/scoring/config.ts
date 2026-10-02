import type { Classification, Severity, SignalCategory } from '../../shared/types.js';
export type { Severity, SignalCategory };

/**
 * The *only* place scoring numbers live.
 *
 * Nothing else in the codebase may contain a category weight, a severity ceiling, or a
 * classification threshold. Detectors emit a severity and a raw score; this module decides what
 * those are worth. Tuning the product means editing this file.
 */

/** Maximum a single signal may contribute, by severity. */
export type SeverityCeilings = Readonly<Record<Severity, number>>;

/** Maximum a whole category may contribute to the 0–100 total. */
export type CategoryWeights = Readonly<Record<SignalCategory, number>>;

export interface ScoringConfig {
  severityCeilings: SeverityCeilings;
  categoryWeights: CategoryWeights;
  /** Lower bound (inclusive) of each classification band, ordered ascending. */
  thresholds: readonly { min: number; classification: Classification }[];
}

export const SEVERITY_CEILINGS: SeverityCeilings = Object.freeze({
  info: 5,
  low: 15,
  medium: 35,
  high: 65,
  critical: 100,
});

/**
 * Category weights.
 *
 * These deviate from the brief's table in a documented way (docs/adr/0004-scoring-floors-and-weights.md): the table
 * had no row for `content`, and split identity across two overlapping rows ("Authentication /
 * identity 30" + "Sender/domain 15" = 45). Here that 45 becomes `identity: 21` + `authentication:
 * 14` = 35, `content` gets the 15 it needs, `link` and `attachment` are unchanged at 25 and 10, and
 * `llm` drops from 20 to 15 so the weights sum to exactly 100.
 *
 * Summing to exactly 100 matters: if the weights summed to more, the final clamp would fire on
 * ordinary suspicious mail, compressing the top of the scale until 80 and 100 meant the same thing.
 */
export const CATEGORY_WEIGHTS: CategoryWeights = Object.freeze({
  authentication: 14,
  identity: 21,
  link: 25,
  content: 15,
  attachment: 10,
  llm: 15,
});

/**
 * Severity floors: a conclusive deterministic finding establishes a minimum score.
 *
 * **Why this exists.** Pure "sum of capped category subtotals" has a structural blind spot: an attack
 * that is malicious in only *one* dimension can never score above that dimension's weight. Business
 * email compromise is the clearest case: a payroll-diversion or gift-card email has no links, no
 * attachments, no lookalike domain, and often passes authentication, because it is a plain text
 * message from a real mailbox. It is *entirely* a `content` finding, so with `content: 15` it would
 * top out at 15/100 and be reported as low risk. The same applies to a disguised `.pdf.exe`, which is
 * conclusive on its own but lives in a category weighted at 10.
 *
 * So the model is: **additive score, with floors for individually-conclusive findings.** The additive
 * part still does the work of ordering messages within a band; the floor stops a single-dimension
 * attack from being diluted by the categories it happens not to touch.
 *
 * Constraints that keep this honest, all tested:
 *  - Floors are driven **only by deterministic signals**. `llm` signals are excluded, so the semantic
 *    layer cannot trigger one, and the "the model can never produce high risk on its own" guarantee is
 *    unaffected.
 *  - `critical` severity is reserved for findings that are conclusive in isolation. An authentication
 *    failure looks conclusive and is not (forwarding breaks SPF, lists break DKIM), so it is held at
 *    `high`, and at `low` when DMARC passed anyway (see `authentication.ts`). No legitimate-mail fixture
 *    produces a `high` or `critical` deterministic signal. That is asserted directly by the test suite, which is what makes
 *    a floor of 50 for `high` safe rather than merely plausible.
 *  - A floor only ever raises the score; it never lowers a higher additive total.
 */
export interface ScoreFloorConfig {
  /** Categories whose signals may establish a floor. Deliberately excludes `llm`. */
  readonly eligibleCategories: readonly SignalCategory[];
  /** Minimum total score a single signal of this severity establishes. */
  readonly bySeverity: Readonly<Partial<Record<Severity, number>>>;
  /**
   * Signals that never establish a floor regardless of severity, because they are **not findings this
   * extension established**. They may still be reported at their real severity and still contribute
   * additively; they just may not set the verdict on their own.
   */
  readonly excludedSignalIds: readonly string[];
  /**
   * The floor established by severe findings in several categories at once, none of which is
   * conclusive alone. The same eligibility rules apply to each finding as to a single-finding floor.
   */
  readonly convergence: {
    readonly minCategories: number;
    readonly minSeverity: Severity;
    readonly floor: number;
  };
}

const FLOOR_ELIGIBLE_CATEGORIES: readonly SignalCategory[] = Object.freeze([
  'authentication',
  'identity',
  'link',
  'content',
  'attachment',
]);

/**
 * Gmail's own warning banner is reported and scored, but may not establish a floor.
 *
 * It is an assertion by another system, not an observation of ours: we cannot show the reasoning behind
 * it, and it is *rendered conditionally on the folder being viewed*: Gmail annotates messages in the
 * spam folder in ways it does not in the inbox. A floor here made the headline verdict a function of
 * where the user happened to be looking rather than of the message, and would have let a manual "mark
 * as spam" turn into PhishLens confirming the user's own action.
 */
const FLOOR_EXCLUDED_SIGNAL_IDS: readonly string[] = Object.freeze(['authentication.gmail_warning']);

/**
 * Severe findings in two independent categories are conclusive together, though neither is alone.
 *
 * The single-finding floor closes the one-dimension gap; this closes the one it leaves. A phish that
 * invents no brand and sends from a throwaway domain that passes its own SPF and DKIM leaves identity
 * and authentication (35 of the 100 points) with nothing to find. Everything it does wrong then lands
 * in links and wording, whose weights sum to 40, so with the model's 15 on top it stops at 55: a page
 * served from a storage bucket, a demand to change payment details and a threat to delete the account,
 * all at `high`, reported as merely Suspicious. The additive sum cannot express that the findings are
 * *independent*: each category is a different way of being wrong, and two at once is what an attack
 * looks like and what ordinary mail does not.
 *
 * It needs a floor rather than a larger weight because any weight large enough to reach 75 from two
 * categories would also inflate ordinary mail with medium findings in both. `high` is the threshold for
 * the same reason the single-finding floor is safe: no legitimate fixture produces a `high` finding in
 * *any* category, so none can produce one in two. Counting categories rather than findings is what
 * stops one fact (three links to the same page) from converging with itself.
 */
const CONVERGENCE_FLOOR: ScoreFloorConfig['convergence'] = Object.freeze({
  minCategories: 2,
  minSeverity: 'high',
  floor: 75,
});

export const SCORE_FLOORS: ScoreFloorConfig = Object.freeze({
  eligibleCategories: FLOOR_ELIGIBLE_CATEGORIES,
  bySeverity: Object.freeze({
    critical: 75,
    high: 50,
  }),
  excludedSignalIds: FLOOR_EXCLUDED_SIGNAL_IDS,
  convergence: CONVERGENCE_FLOOR,
});

/**
 * Classification bands. `high-risk` starting at 75 is above the sum of any two categories the LLM
 * can influence, which is what makes the "LLM can never produce high-risk on its own" property in
 * docs/adr/0006-llm-cannot-outvote-checks.md holds arithmetically rather than by convention.
 */
export const CLASSIFICATION_THRESHOLDS: readonly { min: number; classification: Classification }[] =
  Object.freeze([
    { min: 75, classification: 'high-risk' },
    { min: 50, classification: 'suspicious' },
    { min: 25, classification: 'caution' },
    { min: 0, classification: 'low' },
  ]);

export const DEFAULT_SCORING_CONFIG: ScoringConfig = Object.freeze({
  severityCeilings: SEVERITY_CEILINGS,
  categoryWeights: CATEGORY_WEIGHTS,
  thresholds: CLASSIFICATION_THRESHOLDS,
});

export const ALL_CATEGORIES: readonly SignalCategory[] = Object.freeze([
  'authentication',
  'identity',
  'link',
  'content',
  'attachment',
  'llm',
]);

/** Ascending. The single definition of severity ordering; `aggregate.ts` compares against it. */
export const SEVERITY_ORDER: readonly Severity[] = Object.freeze([
  'info',
  'low',
  'medium',
  'high',
  'critical',
]);

/** Sanity check used by tests: the weights must sum to 100. */
export function totalWeight(weights: CategoryWeights = CATEGORY_WEIGHTS): number {
  return ALL_CATEGORIES.reduce((sum, c) => sum + weights[c], 0);
}

// ---------------------------------------------------------------------------
// Detector tuning knobs
// ---------------------------------------------------------------------------

/**
 * Thresholds used by detectors. Here rather than inline so that "how many links counts as a lot"
 * is a product decision recorded in one place.
 */
export const DETECTION_TUNING = Object.freeze({
  /** Edit distance at or below which a domain counts as a lookalike of a brand domain. */
  lookalikeMaxEditDistance: 2,
  /**
   * Shortest domain name compared against other participants in a conversation.
   *
   * Higher than the brand comparison's floor because there is no curated list to anchor it: a thread
   * can contain any two short domains, and on four characters an edit of one is as likely to be two
   * unrelated companies as an imitation.
   */
  minThreadDomainCoreChars: 5,
  /**
   * Shortest display name that may be reported as reused by another participant.
   *
   * Short names collide innocently, and the attack this catches depends on the name being recognisable
   * enough for a reader to trust it.
   */
  minThreadNameChars: 5,
  /**
   * Shortest organisation name (the recipient's domain without its suffix) that may be read as claimed
   * by a display name. Below this the name is a common word or an initialism, and "Ace IT" says nothing
   * about a reader at `ace.com`.
   */
  minOwnOrganisationNameChars: 5,
  /**
   * Shortest brand keyword that may match inside a word of link text. Shorter ones must be a whole word,
   * since folding joins the words up and a five-letter name is found inside ordinary phrases: "a vast
   * range" reads as Avast, "pineapple" as Apple.
   */
  minAnchorSubstringKeywordChars: 6,
  /**
   * Longest link text, in words, that reads as a label for a brand ("Microsoft 365", "Open in OneDrive")
   * rather than a sentence mentioning one. Longer text is a headline unless it asks for an action.
   */
  maxBrandLabelWords: 3,
  /** Subdomain label count above which the structure itself is suspicious. */
  maxReasonableSubdomainLabels: 4,
  /** Number of links above which a message is bulk-mail shaped. */
  bulkMailLinkCount: 12,
  /** Body length below which "no text, only links/images" is suspicious. */
  minimalBodyChars: 140,
  /** Maximum number of link signals reported per rule, to keep the panel readable. */
  maxLinkSignalsPerRule: 3,
  /**
   * How many repetitions of the same fragment in a sender's local part count as implausible.
   * Three, because two (`first.last.first`) occurs by accident and three does not.
   */
  minRepeatedLocalPartUnits: 3,
  /** Proportion of letters in upper case above which a subject counts as shouting. */
  subjectCapsRatio: 0.6,
  /** Below this many letters, a caps ratio is meaningless (`RE: FYI`). */
  subjectCapsMinLetters: 15,
  /** Uses of the same decorative symbol that make it an ornament rather than punctuation. */
  minDecorativeRepeats: 2,
  /**
   * Subject-formatting markers that must coincide before anything is reported. Individually all of
   * them occur in legitimate marketing, so one is never enough.
   */
  minSubjectObfuscationMarkers: 2,
  /**
   * Consecutive spaces in a subject that count as padding.
   *
   * Set well above anything typed by accident, because the string is read from the DOM: a nested
   * element boundary can contribute a little incidental whitespace, but not 24 spaces.
   */
  minSubjectPaddingRun: 24,
  /**
   * Words with alternating capitalisation needed before an address counts as case-randomised. Two,
   * because a single odd word (`McDonald`, a deliberate stylisation) is not a pattern.
   */
  minScrambledCaseTokens: 2,
  /**
   * Characters of CSS-hidden body text that stop being a preheader and become concealment.
   *
   * Set by what legitimate senders do, not by what attackers do. Every mail platform hides a preheader
   * line to control the inbox preview, and those run to a couple of hundred characters at most, spacer
   * padding excluded, so 600 sits far above ordinary practice while remaining far below the thousands of
   * characters of filler prose that make the technique worth using.
   */
  minHiddenBodyChars: 600,
  /**
   * Distinct function-word markers a language pack needs in the gating window before its patterns run.
   *
   * Three, because one or two words collide across Romance languages (`de`, `la`, `en`) and would run
   * every pack on every English message; three is enough that a real message in that language qualifies
   * and a padded English one does not.
   */
  languageMarkerMinDistinct: 3,
  /** Characters of match text considered when counting language-pack markers. */
  languageMarkerWindowChars: 2000,
  /**
   * Share of letters that must be Devanagari before the Hindi pack runs.
   *
   * Hinglish (Hindi typed in Latin letters) is gated by markers instead; this threshold is only for
   * Devanagari script, where function-word lists are less reliable than the script itself.
   */
  devanagariLetterShare: 0.12,
  /**
   * `label: value` lines, the reader's own address among them, that make a block of text an echoed form.
   * Three, because an address on its own line under "Email:" is also how an account notice states whom it
   * was sent to; a name, an address and a message is the smallest form anyone builds.
   */
  minFormEchoFields: 3,
  /** Lines either side of the reader's address searched for the rest of the form. */
  formEchoWindowLines: 8,
  /**
   * Letters and digits a field value needs, its URLs excluded, to be free text someone typed rather than a
   * value the site filled in. Counted in characters so that unspaced scripts qualify; a tracking number,
   * an order reference or a bare "Website:" URL stays well below it.
   */
  minFormEchoFreeTextChars: 40,
});

/**
 * False-positive dampening (docs/adr/0005-false-positive-resistance.md).
 *
 * Dampening only ever applies to the `content` category, and only downward. Provable technical
 * findings in `link`/`identity`/`attachment`/`authentication` are never softened.
 */
export interface DampeningConfig {
  readonly dampenableCategories: readonly SignalCategory[];
  readonly alignedSenderSeverityDrop: number;
  readonly combinationIdPrefix: string;
  readonly refutableCombinations: readonly string[];
  readonly alignedSenderScoreFactor: number;
  readonly blockingCategories: readonly SignalCategory[];
  readonly blockingMinSeverity: Severity;
}

const DAMPENABLE_CATEGORIES: readonly SignalCategory[] = Object.freeze(['content']);

/** A `medium`-or-higher signal in one of these cancels dampening. */
const DAMPENING_BLOCKERS: readonly SignalCategory[] = Object.freeze([
  'identity',
  'link',
  'attachment',
  'authentication',
]);

export const DAMPENING: DampeningConfig = Object.freeze({
  /** Categories whose signals may be dampened. */
  dampenableCategories: DAMPENABLE_CATEGORIES,
  /** How many severity steps to drop when the sender is aligned with the brand it claims. */
  alignedSenderSeverityDrop: 1,
  /** Signal-id prefix identifying cross-theme combination findings. */
  combinationIdPrefix: 'combo.',
  /**
   * The combinations a verified sender with aligned links refutes, and so the only `high` findings
   * brand dampening may touch, which it zeroes rather than lowers.
   *
   * Their whole claim is "you are being rushed onto a fake sign-in or billing page"; once every link stays
   * inside the organisation the mail provably came from, there is no fake page, and a genuine
   * password-reset or expired-card notice is what remains. The money-movement combinations are
   * deliberately absent: a gift-card, wire, payee or payroll request is exactly what a compromised account
   * sends, and the account being genuine makes acting on it no safer: the reason trust never softens
   * `high`, applied to brands too.
   */
  refutableCombinations: Object.freeze([
    'urgent_credential_request',
    'threat_and_credential_request',
    'billing_update_under_threat',
  ]),
  /**
   * Multiplier applied to a dampened signal's raw score.
   *
   * Low enough that a fully-loaded content category on genuine, sender-aligned mail lands well below
   * the category weight. At 0.4 a real password-reset notice still saturated `content` and scored 15
   * on the strength of its wording alone, which is not what "we verified this sender" should mean.
   */
  alignedSenderScoreFactor: 0.25,
  /**
   * A `medium`-or-higher signal in one of these categories cancels dampening: if there is real
   * technical evidence of a problem, the tone heuristics should not be softened.
   */
  blockingCategories: DAMPENING_BLOCKERS,
  blockingMinSeverity: 'medium',
});

/**
 * Caps on how much the semantic layer may claim, before category capping.
 *
 * **Why there is a dead zone.** An on-device model is not calibrated. Observed behaviour is that it is
 * accurate on genuinely fraudulent mail and systematically over-suspicious on legitimate mail, where
 * it will rate an ordinary product announcement 50-60/100 with high confidence. Scoring a proportional
 * share of that produced a steady few points on every clean message, which is worse than useless: it
 * removes the difference between "nothing found" and "something found", and a tool whose floor is
 * never zero teaches users that its numbers mean nothing.
 *
 * So the semantic score is not proportional to risk, it is proportional to *risk above a threshold*,
 * rescaled so the remaining band still discriminates. The threshold sits at the boundary above which the
 * prompt asks for social-engineering structure it can support from the wording, so the model has to claim
 * structure, not unease, before it counts for anything.
 */
export const SEMANTIC_SCORING = Object.freeze({
  /**
   * Raw semantic score = (risk − `minRiskForScoring`) / (100 − `minRiskForScoring`) × confidence ×
   * this. Capped again by the `llm` category weight, so this being larger than the weight only
   * affects how quickly the LLM saturates its share.
   */
  maxRawScore: 30,
  /** Below this confidence the semantic verdict is reported as informational only. */
  minConfidenceForScoring: 0.35,
  /**
   * Risk below this contributes exactly zero, and is reported as informational.
   *
   * 45 is the top of the band the prompt reserves for an ambiguous request with a plausible ordinary
   * explanation. Everything the model rates at or under it is, by its own instructions, mail it cannot
   * point at a concrete problem in.
   */
  minRiskForScoring: 45,
  /**
   * Top of the prompt's routine band (no concerning request the wording supports) and the point below
   * which a named category is disregarded when wording the finding.
   *
   * Models fill the `categories` slot as a matter of form. One rated an auto-reply 10/100 and explained
   * itself with "standard auto-reply", having tagged it `social_engineering` anyway, which the panel
   * then headlined as wording that resembled social engineering. The rating is the judgement (it is the
   * number the prompt defines bands for and the number that is scored), so below this the finding reads
   * as clean regardless of the tag.
   */
  routineRiskCeiling: 20,
  /**
   * Multiplier applied when no deterministic signal scored anything. Zero: the semantic layer may
   * refine a score, never originate one.
   *
   * This costs no detection capability, which is what makes it the right call rather than merely a
   * cautious one. The `llm` weight (15) is already below the `caution` threshold (25), so a verdict
   * with nothing else supporting it could never change the classification even at full weight; the
   * message reads "Low Risk" either way. All that scoring it achieved was moving the number off zero
   * on clean mail, destroying the difference between "we found nothing" and "we found something
   * small". The verdict is still shown in full, with the model's reasons, as an informational finding.
   *
   * Note that corroboration is cheap to obtain for the attacks this would otherwise miss: content-only
   * fraud (payroll diversion, gift cards) trips the `content` detectors, which then corroborate.
   */
  uncorroboratedFactor: 0,
  /** Risk at or above this is reported as a `high` severity semantic signal. */
  highRiskThreshold: 70,
  /** Raised to sit inside the scoring band, since nothing below `minRiskForScoring` scores at all. */
  mediumRiskThreshold: 55,
  /**
   * Maximum reasons rendered, to bound panel size and prompt-injection payload visibility. The prompt asks
   * for the same number, since on-device decoding time grows with every reason the model writes.
   */
  maxReasons: 3,
  /**
   * Words the prompt allows each reason, so a reason reads as one line on the card rather than a
   * paragraph: the quoted excerpt is what the reader checks, and the explanation only needs to say why
   * it matters.
   */
  reasonWords: 15,
  /**
   * Words a reason may actually have before it is cut. Above `reasonWords` on purpose: small models
   * count words loosely, and cutting at exactly the requested number would truncate most of the reasons
   * that overshoot by a word or two, which costs more legibility than the extra words do.
   */
  maxReasonWords: 20,
});
