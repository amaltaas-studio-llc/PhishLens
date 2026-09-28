/**
 * The explanation card: a notification-style card pinned to the bottom-right corner.
 *
 * Two properties this file exists to hold:
 *
 *  - **Observed** and **AI assessment** are separate sections and are never merged, so a user can tell
 *    "these two domains differ" (a checkable fact) from "this wording resembles phishing" (an opinion).
 *  - Every message-derived string reaches the DOM through `el({ text })`, i.e. `textContent`. No
 *    message content is ever parsed as HTML.
 *
 * The card reads top to bottom in the order a reader asks their questions: how bad (the ring and the
 * verdict), why (the findings, grouped by what they are about), what the model thought (kept apart),
 * and how the number was reached (the breakdown). Three kinds of text are drawn three ways so they
 * cannot be confused — PhishLens's own statements in plain prose, words from the email as quotations,
 * and measured values (domains, destinations, filenames) as code.
 *
 * All geometry is in `PANEL_CSS`; this file positions nothing. See docs/ARCHITECTURE.md §5.1.
 */
import { assessmentSignals, observedSignals } from '../analysis/engine.js';
import { distinctForDisplay, scoreFloor } from '../analysis/scoring/aggregate.js';
import { ALL_CATEGORIES, CATEGORY_WEIGHTS } from '../analysis/scoring/config.js';
import { truncate } from '../shared/text.js';
import type {
  AnalysisResult,
  AnalysisTiming,
  AiMode,
  EmailMessage,
  MessagePart,
  SecuritySignal,
  SemanticAnalysis,
  SemanticStatus,
  SignalCategory,
} from '../shared/types.js';
import type { TrustState } from '../shared/trust.js';
import { createShadowHost, el, svg } from './dom.js';
import {
  AI_DISCLAIMER,
  addedUp,
  aiAbsenceNote,
  assessmentExplanation,
  contributions,
  evidenceOf,
  formatDuration,
  isLocatable,
  joinCategories,
  messageReference,
  pendingLabel,
  reasonParts,
  scoreSummary,
  timingLine,
  unreadableNotes,
} from './format.js';
import {
  CATEGORY_LABELS,
  CLASSIFICATION_LABELS,
  SEVERITY_LABELS,
  UNREADABLE_LABEL,
} from './labels.js';
import { PANEL_CSS } from './styles.js';

const HOST_ID = 'phishlens-panel-host';

/** How often the running counter beside a pending reading is redrawn. */
const ELAPSED_TICK_MS = 200;

/** Ring geometry, in the SVG's own units. The rendered size is set in `PANEL_CSS`. */
const RING = { size: 72, radius: 30, stroke: 8, gap: 1.6 } as const;

/**
 * What trust means, at the moment the user is deciding.
 *
 * Each says what is weighted down *and* what is not, because the honest summary of this feature is that
 * it makes ordinary mail quieter and changes nothing about a message that is actually wrong. A `Record`
 * keyed on the state so a new one cannot be added without wording.
 */
const TRUST_NOTES: Readonly<Record<Exclude<TrustState['kind'], 'none'>, (entry: string) => string>> = {
  offer: (entry) =>
    `If you get mail from ${entry} often, PhishLens can weight down findings about its wording — only its wording, and only while Gmail can confirm a message really came from there. Links, attachments and identity are always scored in full, and nothing is ever hidden from this card.`,
  trusted: (entry) =>
    `You trust ${entry}, and Gmail confirmed this message came from there, so findings about its wording are weighted down. Anything found in its links, attachments, or identity is scored in full.`,
  unproven: (entry) =>
    `You trust ${entry}, but Gmail could not confirm that this message actually came from there — so that trust was not applied, and this score is exactly what it would be for any other sender.`,
};

/** The on-demand button, named for whatever would do the reading. */
const ASK_LABELS: Readonly<Record<AiMode, string>> = {
  off: 'Ask the on-device model',
  local: 'Ask the on-device model',
  cloud: 'Ask the analysis service',
  server: 'Ask your model server',
};

export interface PanelCallbacks {
  /** Hover/focus a finding: highlight the corresponding item in the message. */
  onFocusSignal: (signal: SecuritySignal) => void;
  onBlurSignal: () => void;
  onClose: () => void;
  /** Add or remove a trust entry. The card only ever offers the entry it was given. */
  onTrustChange: (entry: string, trusted: boolean) => void;
  /** The reader asked for the AI reading the default settings skipped. */
  onRunAssessment: () => void;
}

/**
 * Everything the card renders, as one value.
 *
 * Grouped rather than passed positionally because the card is repainted from three places — first
 * paint, model refinement, cache hit — and a call site that updated the result but forgot the status
 * would claim the model is unavailable while it is still running.
 */
export interface ResultView {
  kind: 'result';
  result: AnalysisResult;
  aiMode: AiMode;
  email: EmailMessage;
  semantic: SemanticStatus;
  /** How long the checks and the model took for this view, or `null` where nothing was measured. */
  timing: AnalysisTiming | null;
  /** Whether this sender is trusted, could be, or neither. See `shared/trust.ts`. */
  trust: TrustState;
}

/**
 * The message could not be read, so there is no score to explain — only why not.
 *
 * A separate shape rather than a flag on `ResultView`, because there is no `AnalysisResult` to supply
 * and inventing a zero-scored one is precisely the failure this card exists to prevent: it would
 * classify as `low`, colour the strip green, and read as an all-clear everywhere except the paragraph
 * saying otherwise.
 */
export interface UnreadableView {
  kind: 'unreadable';
  email: EmailMessage;
  missing: readonly MessagePart[];
  /** Built by the caller, which is the layer that may touch the DOM to probe selectors. */
  diagnostic: string;
}

export type PanelView = ResultView | UnreadableView;

export class Panel {
  readonly #callbacks: PanelCallbacks;
  #host: HTMLElement | null = null;
  #root: ShadowRoot | null = null;
  #panel: HTMLElement | null = null;
  #head: HTMLElement | null = null;
  #scroll: HTMLElement | null = null;
  #open = false;
  /** Redraws the running counter while a reading is in flight. Owned here so closing stops it. */
  #ticker: ReturnType<typeof setInterval> | null = null;

  constructor(callbacks: PanelCallbacks) {
    this.#callbacks = callbacks;
  }

  get isOpen(): boolean {
    return this.#open;
  }

  toggle(view: PanelView): void {
    if (this.#open) {
      this.close();
      return;
    }
    this.open(view);
  }

  /**
   * Shows the card, or updates it in place if already showing.
   *
   * In place because the controller paints the deterministic result and then repaints with the refined
   * one; rebuilding would replay the entrance animation and lose the reader's scroll position.
   */
  open(view: PanelView): void {
    const created = this.#host === null;
    if (created) this.#build();
    this.#paint(view);
    this.#open = true;

    if (created) {
      document.addEventListener('keydown', this.#handleKeydown, true);
      this.#root?.querySelector<HTMLButtonElement>('.close')?.focus();
    }
  }

  close(): void {
    this.#stopTicker();
    document.removeEventListener('keydown', this.#handleKeydown, true);
    this.#callbacks.onBlurSignal();
    this.#host?.remove();
    this.#host = null;
    this.#root = null;
    this.#panel = null;
    this.#head = null;
    this.#scroll = null;
    this.#open = false;
  }

  /** Builds the empty shell once. Contents are supplied by `#paint`. */
  #build(): void {
    const { host, root } = createShadowHost(HOST_ID, PANEL_CSS);
    const head = el('div', { class: 'head' });
    const scroll = el('div', { class: 'scroll' });
    const panel = el('div', {
      class: 'panel',
      attrs: { role: 'dialog', 'aria-modal': 'false', 'aria-label': 'PhishLens security assessment' },
      children: [head, scroll],
    });

    root.append(panel);
    document.body.append(host);

    this.#host = host;
    this.#root = root;
    this.#panel = panel;
    this.#head = head;
    this.#scroll = scroll;
  }

  #paint(view: PanelView): void {
    const panel = this.#panel;
    const head = this.#head;
    const scroll = this.#scroll;
    if (panel === null || head === null || scroll === null) return;

    this.#stopTicker();
    panel.setAttribute('data-state', view.kind === 'result' ? view.result.classification : 'unreadable');

    const offset = scroll.scrollTop;
    if (view.kind === 'result') {
      head.replaceChildren(...this.#renderHead(view.result, view.email));
      const trust = this.#renderTrust(view.trust);
      scroll.replaceChildren(
        this.#renderObserved(view.result),
        this.#renderAssessment(view),
        this.#renderBreakdown(view.result),
        ...(trust === null ? [] : [trust]),
        this.#renderFoot(view),
      );
      this.#startTicker(view);
    } else {
      head.replaceChildren(...this.#renderUnreadableHead(view.email));
      scroll.replaceChildren(this.#renderUnreadable(view));
    }
    scroll.scrollTop = offset;
  }

  /**
   * Counts up beside a reading in flight, so a slow model reads as working rather than stuck.
   *
   * Driven from the start time on the view rather than from when this paint happened, so a repaint
   * mid-reading — the reader toggling the card, a trust click — carries on from the true elapsed time
   * instead of restarting from zero.
   */
  #startTicker(view: ResultView): void {
    const started = view.timing?.aiStartedAt;
    if (view.semantic !== 'pending' || started === undefined) return;
    const counter = this.#root?.querySelector<HTMLElement>('.elapsed') ?? null;
    if (counter === null) return;

    const tick = (): void => {
      counter.textContent = formatDuration(performance.now() - started);
    };
    tick();
    this.#ticker = setInterval(tick, ELAPSED_TICK_MS);
  }

  #stopTicker(): void {
    if (this.#ticker !== null) clearInterval(this.#ticker);
    this.#ticker = null;
  }

  readonly #handleKeydown = (event: KeyboardEvent): void => {
    // Capture phase so the key is seen while focus is in Gmail, but deliberately not stopped: the card
    // is not modal, and swallowing Escape would break Gmail's own dismissal of compose and dialogs.
    if (event.key === 'Escape') this.#callbacks.onClose();
  };

  // -------------------------------------------------------------------------
  // Head
  // -------------------------------------------------------------------------

  /**
   * Score, verdict, where the score came from, and which message this is about.
   *
   * The message reference is load-bearing: a card fixed in the corner is not visually attached to the
   * header it describes, so without naming the message a stale assessment looks like a current one.
   */
  #renderHead(result: AnalysisResult, email: EmailMessage): Node[] {
    const state = result.classification;

    return [
      this.#renderHeadTop(),
      el('div', {
        class: 'hero',
        children: [
          renderRing(result),
          el('div', {
            class: 'hero-text',
            children: [
              el('span', {
                class: 'verdict',
                text: CLASSIFICATION_LABELS[state],
                attrs: { 'data-state': state },
              }),
              el('p', { class: 'summary', text: scoreSummary(result) }),
            ],
          }),
        ],
      }),
      renderReference(email),
    ];
  }

  /** Brand and close button, shared by both kinds of card. */
  #renderHeadTop(): HTMLElement {
    return el('div', {
      class: 'head-top',
      children: [
        el('span', { class: 'brand', text: 'PhishLens' }),
        el('button', {
          class: 'close',
          text: '×',
          attrs: { type: 'button', 'aria-label': 'Close' },
          on: {
            click: () => {
              this.#callbacks.onClose();
            },
          },
        }),
      ],
    });
  }

  /**
   * The head of a card with no score: the verdict slot says what did not happen instead.
   *
   * No score number and no ring, rather than a zero and an empty circle. A 0/100 beside an empty ring is
   * the most reassuring thing this card could possibly display, and it would be showing it at the exact
   * moment the extension knows least about the message.
   */
  #renderUnreadableHead(email: EmailMessage): Node[] {
    return [
      this.#renderHeadTop(),
      el('div', {
        class: 'score-row',
        children: [el('span', { class: 'verdict', text: UNREADABLE_LABEL })],
      }),
      renderReference(email),
    ];
  }

  // -------------------------------------------------------------------------
  // What the checks found
  // -------------------------------------------------------------------------

  /**
   * Deterministic findings: things that were measured.
   *
   * Grouped by category, in the order the ring draws them, so the largest slice of the ring is the
   * first group a reader meets and the colour beside each group names the slice it accounts for.
   * Findings that scored nothing go last under their own heading: they are context — authentication
   * passed, a finding softened for a verified sender — and interleaving them with what raised the score
   * makes the reasons harder to find.
   */
  #renderObserved(result: AnalysisResult): HTMLElement {
    const signals = distinctForDisplay(observedSignals(result));
    const scoring = signals.filter((s) => s.score > 0);
    const notes = signals.filter((s) => s.score === 0);

    const groups = categoryOrder(result)
      .map((category) => ({ category, members: scoring.filter((s) => s.category === category) }))
      .filter((group) => group.members.length > 0);

    return el('section', {
      class: 'observed',
      children: [
        el('h3', { class: 'section-title', text: 'What the checks found' }),
        el('p', {
          class: 'section-note',
          // "Nothing of concern" is only true when the notes below are transparency — authentication
          // passed, no attachment was suspicious. A dampened finding is also scoreless, and saying nothing
          // was of concern directly above one contradicts the list a reader is looking at.
          text:
            scoring.length > 0
              ? 'Observed — technical checks on this message.'
              : notes.some((s) => s.dampened === true)
                ? 'Observed — nothing counted towards the score, for the reasons given.'
                : 'Observed — technical checks found nothing of concern.',
        }),
        ...groups.map((group) =>
          this.#renderGroup(
            CATEGORY_LABELS[group.category],
            group.category,
            `${String(result.categoryScores[group.category])} pts`,
            group.members,
          ),
        ),
        ...(notes.length > 0
          ? [this.#renderGroup(scoring.length > 0 ? 'Also noted' : 'Noted', null, null, notes)]
          : []),
        ...(signals.length === 0 ? [el('p', { class: 'empty', text: 'No findings.' })] : []),
      ],
    });
  }

  #renderGroup(
    name: string,
    category: SignalCategory | null,
    points: string | null,
    members: readonly SecuritySignal[],
  ): HTMLElement {
    return el('div', {
      class: 'group',
      children: [
        el('div', {
          class: 'group-head',
          children: [
            category === null
              ? null
              : el('span', { class: 'dot', attrs: { 'data-category': category, 'aria-hidden': 'true' } }),
            el('span', { class: 'group-name', text: name }),
            points === null ? null : el('span', { class: 'group-points', text: points }),
          ],
        }),
        el('ul', { class: 'findings', children: members.map((s) => this.#renderFinding(s)) }),
      ],
    });
  }

  #renderFinding(signal: SecuritySignal): HTMLElement {
    const locatable = isLocatable(signal);

    return el('li', {
      class: 'finding',
      attrs: {
        'data-locatable': locatable,
        'data-category': signal.category,
        tabindex: locatable ? 0 : undefined,
        role: locatable ? 'button' : undefined,
      },
      on: locatable
        ? {
            mouseenter: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            mouseleave: () => {
              this.#callbacks.onBlurSignal();
            },
            focus: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            blur: () => {
              this.#callbacks.onBlurSignal();
            },
            click: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            keydown: (event) => {
              if (event instanceof KeyboardEvent && (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                this.#callbacks.onFocusSignal(signal);
              }
            },
          }
        : {},
      children: [
        el('div', {
          class: 'finding-top',
          children: [
            el('p', { class: 'finding-title', text: signal.title }),
            el('span', {
              class: 'sev',
              text: SEVERITY_LABELS[signal.severity],
              attrs: { 'data-severity': signal.severity },
            }),
          ],
        }),
        el('p', { class: 'finding-desc', text: signal.description }),
        renderEvidence(signal),
        locatable
          ? el('p', {
              class: 'locate',
              text: 'Show in message',
              attrs: { title: 'Hover, or press Enter, to highlight this in the message' },
            })
          : null,
      ],
    });
  }

  // -------------------------------------------------------------------------
  // The AI assessment
  // -------------------------------------------------------------------------

  /**
   * The AI section. It states plainly when no model ran, because silence would let a user assume the
   * AI approved the message, and it distinguishes "no assessment" from "not one *yet*" — the two look
   * identical and mean opposite things.
   */
  #renderAssessment(view: ResultView): HTMLElement {
    const signals = assessmentSignals(view.result);
    const note = aiAbsenceNote(view.semantic, view.aiMode);

    return el('section', {
      class: 'assessment',
      children: [
        el('h3', { class: 'section-title', text: 'AI assessment' }),
        view.semantic === 'pending' ? this.#renderPending(view.aiMode) : null,
        el('p', { class: 'ai-note', text: note ?? AI_DISCLAIMER }),
        view.semantic === 'skipped' && view.aiMode !== 'off' ? this.#renderAsk(view.aiMode) : null,
        ...(signals.length > 0
          ? signals.map((s) =>
              s.id === 'llm.assessment'
                ? this.#renderReading(s, view.result.semantic, view.result.categoryScores.llm)
                : el('ul', { class: 'findings', children: [this.#renderFinding(s)] }),
            )
          : note === null
            ? [el('p', { class: 'empty', text: 'The model returned no assessment for this message.' })]
            : []),
      ],
    });
  }

  /**
   * `role="status"` on the label: the interesting moment for a screen-reader user is the transition
   * *out* of this state, and a polite live region announces the replacement without interrupting
   * whatever they are reading. The counter sits outside it, or every tick would be announced.
   */
  #renderPending(aiMode: AiMode): HTMLElement {
    return el('div', {
      class: 'pending',
      children: [
        el('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } }),
        el('span', { text: pendingLabel(aiMode), attrs: { role: 'status' } }),
        el('span', { class: 'elapsed', attrs: { 'aria-hidden': 'true' } }),
      ],
    });
  }

  #renderAsk(aiMode: AiMode): HTMLElement {
    return el('button', {
      class: 'action',
      text: ASK_LABELS[aiMode],
      attrs: { type: 'button' },
      on: {
        click: (event) => {
          const button = event.currentTarget;
          if (button instanceof HTMLButtonElement) button.disabled = true;
          this.#callbacks.onRunAssessment();
        },
      },
    });
  }

  /**
   * The model's reading, laid out as a verdict with its particulars rather than as one paragraph.
   *
   * The facts a reader weighs it by — who read it, how high it rated the message, how sure it was, what
   * it added — are chips, because they are values to compare rather than sentences to read. The
   * explanation stays prose, and the model's reasons become a list with each quoted excerpt set apart,
   * which is the part a reader can check against the message.
   */
  #renderReading(
    signal: SecuritySignal,
    analysis: SemanticAnalysis | undefined,
    points: number,
  ): HTMLElement {
    const reasons = analysis?.reasons ?? [];
    return el('div', {
      class: 'reading',
      children: [
        el('p', { class: 'reading-title', text: signal.title }),
        analysis === undefined
          ? null
          : el('div', {
              class: 'chips',
              children: [
                el('span', { class: 'chip', text: sourceChip(analysis) }),
                el('span', { class: 'chip', text: `Rated ${String(analysis.risk)}/100` }),
                el('span', {
                  class: 'chip',
                  text: `${String(Math.round(analysis.confidence * 100))}% confident`,
                }),
                el('span', {
                  class: 'chip',
                  text: points > 0 ? `+${String(points)} points` : 'No points added',
                  attrs: { 'data-scored': points > 0 },
                }),
              ],
            }),
        el('p', { class: 'finding-desc', text: assessmentExplanation(signal.description) }),
        ...(reasons.length > 0
          ? [
              el('p', { class: 'reasons-label', text: 'The model’s reasons' }),
              el('ul', {
                class: 'reasons',
                children: reasons.map((reason) =>
                  el('li', {
                    children: reasonParts(reason).map((part) =>
                      part.quoted
                        ? el('span', { class: 'quote', text: part.text })
                        : document.createTextNode(part.text),
                    ),
                  }),
                ),
              }),
            ]
          : []),
      ],
    });
  }

  // -------------------------------------------------------------------------
  // How the score adds up
  // -------------------------------------------------------------------------

  /**
   * Shows the arithmetic. A score whose derivation is hidden is a score nobody can argue with.
   *
   * Each bar is against its category's own ceiling, not against 100 — the ring already shows shares of
   * the total — so "18 of 25" says how close that category came to the most it can add. Categories that
   * added nothing share one line: listing five empty bars pushes the two that matter out of view.
   */
  #renderBreakdown(result: AnalysisResult): HTMLElement {
    const parts = contributions(result);
    const silent = ALL_CATEGORIES.filter((c) => result.categoryScores[c] === 0);
    const added = addedUp(result);

    const rows: HTMLElement[] = parts.map(([category, value]) =>
      el('li', {
        class: 'row',
        children: [
          el('span', { class: 'dot', attrs: { 'data-category': category, 'aria-hidden': 'true' } }),
          el('span', { class: 'row-name', text: CATEGORY_LABELS[category] }),
          el('span', {
            class: 'bar',
            attrs: { 'aria-hidden': 'true' },
            children: [
              el('span', {
                class: 'bar-fill',
                attrs: { 'data-category': category },
                style: { width: `${String(Math.min(100, (value / CATEGORY_WEIGHTS[category]) * 100))}%` },
              }),
            ],
          }),
          el('span', {
            class: 'row-value',
            text: `${String(value)} of ${String(CATEGORY_WEIGHTS[category])}`,
          }),
        ],
      }),
    );

    // The categories add up to the score unless a severe finding set a minimum, in which case they add
    // up to less. Saying so is the difference between a breakdown and arithmetic that looks broken.
    if (result.score > added) {
      const floor = scoreFloor(result.signals);
      rows.push(
        el('li', {
          class: 'row floor',
          children: [
            el('span', { class: 'dot hatch', attrs: { 'aria-hidden': 'true' } }),
            el('span', {
              class: 'row-name',
              text:
                floor.basis === 'convergence'
                  ? `Minimum for severe findings in ${joinCategories(floor.categories)}`
                  : 'Minimum for a severe finding',
            }),
            el('span', { class: 'row-value', text: `+${String(result.score - added)}` }),
          ],
        }),
      );
    }

    return el('section', {
      class: 'breakdown',
      children: [
        el('h3', { class: 'section-title', text: 'How the score adds up' }),
        rows.length > 0
          ? el('ul', { class: 'rows', children: rows })
          : el('p', { class: 'empty', text: 'No category added to the score.' }),
        el('div', {
          class: 'total',
          children: [
            el('span', { text: 'Score' }),
            el('span', { class: 'total-value', text: `${String(result.score)} of 100` }),
          ],
        }),
        silent.length > 0 && parts.length > 0
          ? el('p', {
              class: 'section-note silent',
              text: `Nothing from ${joinCategories(silent)}.`,
            })
          : null,
      ],
    });
  }

  /**
   * The trust control, or `null` when there is nothing to say.
   *
   * Placed after the findings rather than beside the score for a reason: the decision it invites should
   * be made after reading what was found, not instead of reading it. The wording states the limits of
   * trust in the same breath as offering it, because a control whose effect a user has to guess at is
   * how an allowlist ends up covering more than anyone intended.
   */
  #renderTrust(trust: TrustState): HTMLElement | null {
    if (trust.kind === 'none') return null;

    const note = TRUST_NOTES[trust.kind](trust.entry);
    const adding = trust.kind === 'offer';

    return el('section', {
      class: 'trust',
      children: [
        el('h3', { class: 'section-title', text: adding ? 'Frequent sender' : 'Trusted sender' }),
        el('p', { class: 'section-note', text: note }),
        el('button', {
          class: 'copy',
          text: adding ? `Trust mail from ${trust.entry}` : `Stop trusting ${trust.entry}`,
          attrs: { type: 'button' },
          on: {
            click: () => {
              this.#callbacks.onTrustChange(trust.entry, adding);
            },
          },
        }),
      ],
    });
  }

  /**
   * Why there is no score, and the report that makes it fixable.
   *
   * The report is rendered in full and selectable rather than hidden behind the copy button alone.
   * `navigator.clipboard` can refuse — an unfocused document is enough — and a user who cannot see what
   * they are about to send has no way to satisfy themselves that it holds none of their mail, which is
   * the claim the paragraph above it makes.
   */
  #renderUnreadable(view: UnreadableView): HTMLElement {
    const notes = unreadableNotes(view.missing);

    return el('section', {
      children: [
        el('h3', { class: 'section-title', text: 'Not checked' }),
        el('div', {
          class: 'notes',
          children: notes.map((note) =>
            el('p', { class: note.emphatic ? 'emphatic' : undefined, text: note.text }),
          ),
        }),
        el('details', {
          class: 'diagnostic',
          children: [
            el('summary', { text: 'Show the report' }),
            el('pre', { text: view.diagnostic }),
          ],
        }),
        el('button', {
          class: 'copy',
          text: 'Copy report',
          attrs: { type: 'button' },
          on: {
            click: (event) => {
              const button = event.currentTarget;
              if (button instanceof HTMLButtonElement) copyReport(button, view.diagnostic);
            },
          },
        }),
      ],
    });
  }

  #renderFoot(view: ResultView): HTMLElement {
    const timing = timingLine(view.timing, view.semantic, view.aiMode);
    return el('div', {
      class: 'foot',
      children: [
        timing === null ? null : el('span', { class: 'timing', text: timing }),
        el('span', {
          text: 'Advisory only. PhishLens does not block links, downloads, or replies.',
        }),
      ],
    });
  }
}

/**
 * The categories in the order the ring draws them: by points, largest first, then the fixed order for
 * ties and for categories that scored nothing.
 */
function categoryOrder(result: AnalysisResult): SignalCategory[] {
  const scored = contributions(result).map(([category]) => category);
  return [...scored, ...ALL_CATEGORIES.filter((c) => !scored.includes(c))];
}

/**
 * The score as a ring of category slices around the number.
 *
 * Each slice is that category's share of the 100 points, in the colour its group and breakdown row
 * carry, so "most of this came from the links" is visible before a word is read. A score raised to a
 * minimum draws the raised part hatched, because it came from no category — it is the floor, and the
 * breakdown row of the same pattern says so.
 *
 * Decorative by construction: `aria-hidden`, and nothing in it is text. The number in the middle and
 * every label it depends on are ordinary text beside it.
 */
function renderRing(result: AnalysisResult): HTMLElement {
  const { size, radius, stroke, gap } = RING;
  const centre = size / 2;
  const circumference = 2 * Math.PI * radius;

  const arcs: SVGElement[] = [];
  let offset = 0;
  const arc = (length: number, attrs: Record<string, string>): void => {
    if (length <= 0) return;
    const drawn = length > gap * 2 ? length - gap : length;
    arcs.push(
      svg('circle', {
        attrs: {
          cx: centre,
          cy: centre,
          r: radius,
          fill: 'none',
          'stroke-width': stroke,
          'stroke-dasharray': `${drawn.toFixed(2)} ${circumference.toFixed(2)}`,
          'stroke-dashoffset': (-offset).toFixed(2),
          ...attrs,
        },
      }),
    );
    offset += length;
  };

  for (const [category, value] of contributions(result)) {
    arc((circumference * value) / 100, { class: 'seg', 'data-category': category });
  }
  const raised = result.score - addedUp(result);
  if (raised > 0) arc((circumference * raised) / 100, { class: 'seg-floor', stroke: 'url(#phishlens-hatch)' });

  return el('div', {
    class: 'ring',
    attrs: { 'data-state': result.classification },
    children: [
      svg('svg', {
        attrs: {
          viewBox: `0 0 ${String(size)} ${String(size)}`,
          'aria-hidden': 'true',
          focusable: 'false',
        },
        children: [
          svg('defs', {
            children: [
              svg('pattern', {
                attrs: {
                  id: 'phishlens-hatch',
                  width: 4,
                  height: 4,
                  patternUnits: 'userSpaceOnUse',
                  patternTransform: 'rotate(45)',
                },
                children: [svg('rect', { attrs: { width: 2, height: 4, fill: 'currentColor' } })],
              }),
            ],
          }),
          svg('circle', {
            class: 'track',
            attrs: { cx: centre, cy: centre, r: radius, fill: 'none', 'stroke-width': stroke },
          }),
          svg('g', {
            attrs: { transform: `rotate(-90 ${String(centre)} ${String(centre)})` },
            children: arcs,
          }),
        ],
      }),
      el('div', {
        class: 'ring-label',
        children: [
          el('span', { class: 'score-value', text: String(result.score) }),
          el('span', { class: 'score-max', text: 'of 100' }),
        ],
      }),
    ],
  });
}

/**
 * The evidence under a finding, drawn by kind — see `evidenceOf`.
 *
 * Message-derived text in every branch, and set as text in every branch.
 */
function renderEvidence(signal: SecuritySignal): HTMLElement | null {
  const evidence = evidenceOf(signal);
  if (evidence === null) return null;

  if (evidence.kind === 'quote') {
    return el('figure', {
      class: 'evidence quote-block',
      children: [
        el('figcaption', { class: 'evidence-label', text: evidence.label }),
        el('blockquote', { text: evidence.body }),
      ],
    });
  }
  return el('div', {
    class: 'evidence',
    children: [
      el('span', { class: 'evidence-label', text: evidence.label }),
      el('code', { class: 'code', text: evidence.body }),
    ],
  });
}

/** Who did the reading, short enough for a chip. The name comes from settings, never the response. */
function sourceChip(analysis: SemanticAnalysis): string {
  switch (analysis.source) {
    case 'local':
      return 'On-device model';
    case 'cloud':
      return 'Analysis service';
    case 'server':
      return analysis.model === undefined || analysis.model === ''
        ? 'Your model server'
        : truncate(analysis.model, 40);
  }
}

/**
 * Subject and sender, naming the message an assessment belongs to.
 *
 * Load-bearing: a card fixed in the corner is not visually attached to the header it describes, so
 * without naming the message a stale assessment looks like a current one. Both lines are
 * message-derived and so are set as text, never parsed.
 */
function renderReference(email: EmailMessage): HTMLElement {
  const reference = messageReference(email);
  return el('div', {
    class: 'ref',
    children: [
      el('div', { class: 'ref-line ref-subject', text: reference.subject, attrs: { title: reference.subject } }),
      el('div', { class: 'ref-line ref-sender', text: reference.sender, attrs: { title: reference.sender } }),
    ],
  });
}

/** Copies the report, reporting failure in the button rather than silently doing nothing. */
function copyReport(button: HTMLButtonElement, report: string): void {
  void navigator.clipboard.writeText(report).then(
    () => {
      button.textContent = 'Copied';
    },
    () => {
      button.textContent = 'Copy failed — select the report above';
      button.disabled = true;
    },
  );
}
