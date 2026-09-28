/**
 * Wording that is derived rather than looked up. The fixed names live in `labels.ts`.
 *
 * Wording is a security control here, not decoration: **observations and assessments must read
 * differently.** Deterministic findings state what was measured; semantic ones are framed as opinion, so
 * a model's guess never looks like a proven fact.
 */
import { REASONING_PREFIX } from '../analysis/llm/semantic-signals.js';
import { scoreFloor } from '../analysis/scoring/aggregate.js';
import type {
  AiMode,
  AnalysisResult,
  AnalysisTiming,
  Classification,
  EmailMessage,
  MessagePart,
  SecuritySignal,
  SemanticStatus,
  SignalCategory,
} from '../shared/types.js';
import { normalizeDomain } from '../shared/url.js';
import { CATEGORY_LABELS, CLASSIFICATION_LABELS } from './labels.js';

export function ariaLabel(classification: Classification, score: number, findings: number): string {
  const noun = findings === 1 ? 'finding' : 'findings';
  return `PhishLens: ${CLASSIFICATION_LABELS[classification]}, ${String(score)} out of 100, ${String(findings)} ${noun}. Activate for details.`;
}

// ---------------------------------------------------------------------------
// When the message could not be read
// ---------------------------------------------------------------------------

/**
 * What each unread part cost, in terms of what the extension can no longer say.
 *
 * A `Record` so a new `MessagePart` cannot be added without wording, and phrased as a consequence
 * rather than a cause: "could not read the sender" is a fact about the extension, and what a reader
 * needs is why that means the absence of a warning tells them nothing.
 */
const UNREADABLE_CAUSES: Readonly<Record<MessagePart, string>> = {
  sender:
    'PhishLens could not read who this message is from. Most of what it checks — whether the sending domain imitates a brand, whether it matches the display name, whether it belongs in this conversation — depends on that, so it has not produced a score.',
  body: 'PhishLens could not read the text of this message, so it has not checked its links, wording, or attachments.',
  subject: 'PhishLens could not read the subject of this message.',
};

/**
 * One paragraph of the card's explanation. `emphatic` travels with the text rather than being inferred
 * from position, because the number of preceding paragraphs depends on how many parts were unread — and
 * the paragraph that must not be skimmed past would have moved.
 */
export interface UnreadableNote {
  text: string;
  emphatic: boolean;
}

/**
 * The card's explanation.
 *
 * The emphatic paragraph is the one that matters and is why this is not simply an error message. A
 * security indicator that disappears teaches the reader that no badge means nothing found; when the
 * indicator is the thing that broke, that lesson is actively dangerous, so the card says outright that
 * this is not a clean bill of health.
 */
export function unreadableNotes(missing: readonly MessagePart[]): UnreadableNote[] {
  const causes = missing.map((part) => UNREADABLE_CAUSES[part]);
  if (causes.length === 0) {
    causes.push('PhishLens could not read this message, so it has not produced a score.');
  }

  return [
    ...causes.map((text) => ({ text, emphatic: false })),
    {
      text: 'This is not a judgement that the message is safe. Nothing was checked, so treat it with the caution you would use if PhishLens were not installed.',
      emphatic: true,
    },
    {
      text: 'The usual cause is that Gmail changed the structure of its pages and PhishLens needs updating. The report below names the parts it could not find; it contains no part of your mail, and you can read it before sending it anywhere.',
      emphatic: false,
    },
  ];
}

/**
 * The one-line identification of the message an assessment belongs to.
 *
 * The sending domain is shown in full rather than reduced to its registrable form, because a
 * subdomain is frequently the whole point of the deception (`paypal.com.secure-login.example`).
 */
export function messageReference(email: EmailMessage): { sender: string; subject: string } {
  const address = email.senderEmail ?? '';
  const at = address.lastIndexOf('@');
  const parts = [
    (email.senderName ?? '').trim(),
    at < 0 ? '' : normalizeDomain(address.slice(at + 1)),
  ].filter((part) => part !== '');

  const subject = (email.subject ?? '').trim();
  return {
    sender: parts.length === 0 ? 'Unknown sender' : parts.join(' · '),
    subject: subject === '' ? '(no subject)' : subject,
  };
}

/** A signal is locatable when the UI can point at the thing in the message it refers to. */
export function isLocatable(signal: SecuritySignal): boolean {
  if (signal.category === 'llm') return false;
  return (
    (signal.evidence?.url !== undefined && signal.evidence.url !== '') ||
    (signal.evidence?.text !== undefined && signal.evidence.text.length >= 12)
  );
}

/**
 * The evidence block: what kind of thing it is, a label, and the value beneath it.
 *
 * One function so the three cannot disagree. Label and body were separate, with opposite precedence, so
 * a signal carrying both a URL and a value showed the value under the heading for a link.
 *
 * The kind is what the card styles by, and the distinction is one a reader needs: `quote` is words the
 * sender wrote, while `value` and `url` are things PhishLens measured — a domain, a filename, where a
 * link actually goes — and are drawn as code so they are never mistaken for prose.
 */
export interface Evidence {
  kind: 'value' | 'url' | 'quote';
  label: string;
  body: string;
}

export function evidenceOf(signal: SecuritySignal): Evidence | null {
  const evidence = signal.evidence;
  if (evidence === undefined) return null;
  if (evidence.value !== undefined && evidence.value !== '') {
    return { kind: 'value', label: 'Observed', body: evidence.value };
  }
  if (evidence.url !== undefined && evidence.url !== '') {
    return { kind: 'url', label: 'Link goes to', body: evidence.url };
  }
  if (evidence.text !== undefined && evidence.text !== '') {
    return { kind: 'quote', label: 'From the email', body: evidence.text };
  }
  return null;
}

// ---------------------------------------------------------------------------
// The score, summarised
// ---------------------------------------------------------------------------

/** Categories that added to the score, largest first — the order the ring and the breakdown share. */
export function contributions(
  result: Pick<AnalysisResult, 'categoryScores'>,
): [SignalCategory, number][] {
  return (Object.entries(result.categoryScores) as [SignalCategory, number][])
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1]);
}

/** "Links", "Links and Sender", "Links, Sender and Wording". */
export function joinCategories(categories: readonly SignalCategory[]): string {
  const names = categories.map((c) => CATEGORY_LABELS[c]);
  const last = names.pop();
  if (last === undefined) return '';
  return names.length === 0 ? last : `${names.join(', ')} and ${last}`;
}

/**
 * One line under the verdict saying where the number came from.
 *
 * Two categories at most, because this is the sentence read at a glance; the breakdown lower down has
 * every one. A score raised to a minimum says so here too, since that is the case where the categories
 * alone would not explain the number.
 */
export function scoreSummary(
  result: Pick<AnalysisResult, 'score' | 'categoryScores' | 'signals'>,
): string {
  const parts = contributions(result);
  if (parts.length === 0) return 'Nothing the checks found added to the score.';

  if (result.score > addedUp(result)) {
    const floor = scoreFloor(result.signals);
    return floor.basis === 'convergence'
      ? `Raised to a minimum by severe findings in ${joinCategories(floor.categories)}.`
      : 'Raised to a minimum by one severe finding.';
  }
  const leading = parts.slice(0, 2).map(([category]) => category);
  if (parts.length === 1) return `All from ${joinCategories(leading)}.`;
  return `Mostly from ${joinCategories(leading)}.`;
}

/** What the categories sum to, which is below the score only when a floor applied. */
export function addedUp(result: Pick<AnalysisResult, 'categoryScores'>): number {
  return contributions(result).reduce((sum, [, value]) => sum + value, 0);
}

// ---------------------------------------------------------------------------
// The AI assessment, laid out
// ---------------------------------------------------------------------------

/**
 * The assessment's explanation without the reasons at its end, which the card lists separately.
 *
 * Split at the first occurrence of the prefix, which `semanticToSignals` places after its own sentences
 * and before the model's words — so nothing the model wrote can move the split earlier.
 */
export function assessmentExplanation(description: string): string {
  const at = description.indexOf(` ${REASONING_PREFIX}`);
  return at < 0 ? description : description.slice(0, at);
}

/**
 * A reason, split so the excerpt it quotes can be set apart from the model's comment on it.
 *
 * The prompt asks every concerning reason to quote the email, and a quotation rendered like the prose
 * around it is the one thing a reader most wants to check and cannot find. Straight and curly double
 * quotes both, bounded so a reason full of stray quote marks costs nothing.
 */
export interface ReasonPart {
  text: string;
  quoted: boolean;
}

const QUOTED = /“[^”]{1,240}”|"[^"]{1,240}"/gu;
const MAX_REASON_PARTS = 12;

export function reasonParts(reason: string): ReasonPart[] {
  const parts: ReasonPart[] = [];
  let last = 0;
  for (const match of reason.matchAll(QUOTED)) {
    if (parts.length >= MAX_REASON_PARTS) break;
    const start = match.index;
    if (start > last) parts.push({ text: reason.slice(last, start), quoted: false });
    parts.push({ text: match[0].slice(1, -1), quoted: true });
    last = start + match[0].length;
  }
  if (last < reason.length) parts.push({ text: reason.slice(last), quoted: false });
  return parts;
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/** "<1 ms", "14 ms", "4.8 s". Tenths of a second above one, because that is what a reader can feel. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 1) return '<1 ms';
  if (ms < 1000) return `${String(Math.round(ms))} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/**
 * The footer's account of how long this took, or `null` when there is nothing honest to say.
 *
 * Present so a slow card has an explanation the reader can see: the checks are milliseconds and the
 * model is seconds, and without the two numbers side by side every delay looks like PhishLens itself.
 */
export function timingLine(
  timing: AnalysisTiming | null,
  status: SemanticStatus,
  aiMode: AiMode,
): string | null {
  if (timing === null) return null;
  const parts = [`Checks ${formatDuration(timing.checksMs)}`];
  if (aiMode === 'off' || status === 'off') parts.push('AI off');
  else if (status === 'skipped') parts.push('AI not asked');
  else if (timing.aiReused) parts.push('AI reading reused');
  else if (timing.aiMs !== undefined) parts.push(`AI reading ${formatDuration(timing.aiMs)}`);
  return parts.join(' · ');
}

/** Shown when there *is* an assessment: what the AI section is and is not. */
export const AI_DISCLAIMER =
  'The findings above are technical observations. The assessment below is a language model’s reading of the message’s intent — informed, but not proof.';

/**
 * Why there is no assessment, keyed by how the semantic stage ended. `null` means there is one.
 *
 * Worded so no two can be mistaken for each other: `unavailable` describes the browser and is
 * permanent, the rest describe this one attempt and say nothing about the next. A `Record` rather than a
 * switch so adding a status cannot compile until it has been given wording. Each entry names whatever
 * was going to do the reading, because "the on-device model" is a lie in cloud mode.
 */
const AI_ABSENCE_NOTES: Readonly<Record<SemanticStatus, ((source: string) => string) | null>> = {
  ready: null,
  pending: () => 'The score above may change when this finishes. Technical checks are already complete.',
  off: () => 'AI analysis is switched off, so this score is based entirely on technical checks.',
  /*
   * Not an all-clear, and worded so it cannot be read as one: the model was not asked, so it has said
   * nothing about the message. The reason is given because it is also why the reading would not have
   * counted, and the offer is there for mail whose wording worries a reader in a way no check can see.
   */
  skipped: (source) =>
    `${source} was not asked, to save time: the technical checks found nothing for its reading to weigh, and on its own that reading cannot change the score. This is not a judgement that the message is safe. If the wording seems off to you, ask for a reading.`,
  unavailable: (source) =>
    `${source} is unavailable, so this score is based entirely on technical checks. No message content left this browser.`,
  'no-output': (source) =>
    `${source} did not return a usable assessment for this message. The score is based entirely on technical checks.`,
  // `cancelled` belongs to a message no longer on screen and should not reach the card; worded as the
  // unfinished attempt it is, rather than implying the model looked and found nothing.
  error: (source) =>
    `${source} could not finish assessing this message. The score is based entirely on technical checks.`,
  cancelled: (source) =>
    `${source} could not finish assessing this message. The score is based entirely on technical checks.`,
};

/**
 * Sentence-initial name for whichever analyzer the current mode uses. Naming it matters because the
 * modes differ in where the message went, and a note that says "the on-device model" while a server was
 * doing the reading misleads about exactly the thing a privacy-conscious reader is checking.
 *
 * The `off` entry is never rendered — that note takes no source — but a `Record` costs nothing and means
 * a fifth mode cannot be added without wording.
 */
const ANALYZER_NAMES: Readonly<Record<AiMode, string>> = {
  off: 'The on-device model',
  local: 'The on-device model',
  cloud: 'The analysis service',
  server: 'Your model server',
};

/** Why there is no assessment, or `null` when there is one. */
export function aiAbsenceNote(status: SemanticStatus, aiMode: AiMode): string | null {
  return AI_ABSENCE_NOTES[status]?.(ANALYZER_NAMES[aiMode]) ?? null;
}

const PENDING_LABELS: Readonly<Record<AiMode, string>> = {
  off: 'Reading the message on-device…',
  local: 'Reading the message on-device…',
  cloud: 'Sending for analysis…',
  server: 'Waiting for your model server…',
};

export function pendingLabel(aiMode: AiMode): string {
  return PENDING_LABELS[aiMode];
}
