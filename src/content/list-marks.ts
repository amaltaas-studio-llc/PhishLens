/**
 * Markers on inbox rows, for the decision made before a message is opened.
 *
 * What a row can support is set out in `analysis/triage.ts`: a warning about the sender, or nothing.
 * This file is the DOM half — finding rows, reading the sender line, and putting a mark beside it — and
 * it is written around the two things that make a list different from a conversation view.
 *
 * **Gmail recycles rows.** Scrolling and refreshing reuse the same `tr` elements with different mail in
 * them, so a mark can end up beside a message it was not computed for. Each row therefore records the
 * sender it was marked for, and a row whose sender has changed is re-evaluated rather than left alone.
 *
 * **A list re-renders constantly.** Every pass is debounced, bounded to the rows actually on screen, and
 * skips rows whose sender is unchanged, so the steady state costs one attribute read per row.
 *
 * The mark itself is inline-styled rather than given a stylesheet or a shadow root. Both alternatives
 * were tried: a stylesheet in the page is a global we do not want, and a shadow host per row is dozens
 * of extra roots for one glyph. Inline properties beat Gmail's own CSS without either.
 */
import { triageSender, type TriageSeverity, type TriageVerdict } from '../analysis/triage.js';
import { observeWithPath } from '../gmail/roots.js';
import { OBSERVED_ATTRIBUTES, queryFirst, SELECTORS } from '../gmail/selectors.js';
import { logger } from '../shared/logger.js';
import { el } from '../ui/dom.js';

/** Marks the row was computed for, so a recycled row is re-evaluated rather than trusted. */
const MARKED_FOR = 'data-phishlens-row';
const MARK_CLASS = 'phishlens-row-mark';

/**
 * Bounds one pass. Gmail renders about 50 rows per page and never thousands, so this is a guard against
 * a markup change matching something enormous rather than a real limit on inbox size.
 */
const MAX_ROWS = 120;

/** Quiet period after list churn. Longer than the message observer's: nothing here is time-critical. */
const DEBOUNCE_MS = 300;

/**
 * Passes spent waiting for Gmail to render the address of the signed-in account, after which it is given
 * up on rather than polled for as long as the tab is open.
 *
 * A retry is needed at all because nothing in the list changes when the address appears, and without one
 * the recipient-lookalike check would be waiting on unrelated churn to notice.
 */
const MAX_ACCOUNT_WAITS = 20;

/** The badge's glyphs, so a mark and the badge it precedes are recognisably the same vocabulary. */
const GLYPHS: Readonly<Record<TriageSeverity, string>> = {
  high: '⚠',
  critical: '⛔',
};

const COLOURS: Readonly<Record<TriageSeverity, string>> = {
  high: '#b3261e',
  critical: '#b3261e',
};

export class ListMarks {
  #observer: MutationObserver | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  /** The region being watched, so its replacement can be noticed. */
  #root: Element | null = null;
  /**
   * How to find the region to watch, asked again rather than resolved once.
   *
   * Gmail replaces its main region wholesale on a view change, and a `MutationObserver` holds the node it
   * was given. Started with an element, the marker stayed attached to a region that was no longer in the
   * document: rows kept arriving, none of them was ever looked at, and the absence of a mark is
   * indistinguishable from mail with nothing to say about it. Nothing else restarts it either — the message
   * observer's own reattachment is about the conversation pane and says nothing to this.
   */
  #resolveRoot: (() => Element) | null = null;
  /**
   * How to read the signed-in address, so the lookalike-of-your-own-domain check can run.
   *
   * A callback rather than a string because marking starts at `document_idle`, when Gmail has often not
   * rendered its account chrome yet. Reading it once at that moment gives an empty address for the life of
   * the tab, silently losing the most valuable verdict a row can carry — a domain imitating the reader's
   * own employer.
   */
  #readAccount: () => string = () => '';
  /** Cached once found. It cannot change without a reload, and the read walks Gmail's chrome. */
  #recipientEmail = '';
  #accountWaits = 0;

  start(resolveRoot: () => Element, readAccount: () => string): void {
    this.stop();
    this.#resolveRoot = resolveRoot;
    this.#readAccount = readAccount;
    this.#attach();
    this.#schedule();
  }

  stop(): void {
    this.#observer?.disconnect();
    this.#observer = null;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
    this.#accountWaits = 0;
    this.#clearAll();
    this.#root = null;
    this.#resolveRoot = null;
  }

  #attach(): void {
    const root = this.#resolveRoot?.() ?? null;
    if (root === null) return;

    this.#observer?.disconnect();
    this.#root = root;
    this.#observer = new MutationObserver(() => {
      // Before scheduling, because this may be the last mutation a detached observer ever reports.
      this.#ensureAttached();
      this.#schedule();
    });
    /*
     * Attributes and text as well as structure, because recycling a row does not have to replace anything:
     * Gmail can rewrite the sender cell's `email` and `name` in place, and then a mark computed for one
     * message sits beside another. A missing mark is a missed warning; a mark on the wrong row is a false
     * accusation, which is the more expensive of the two. Filtered to the attributes the selectors read,
     * so the cost of the wider watch is a debounced pass that reads one attribute per row and stops.
     */
    observeWithPath(this.#observer, root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: [...OBSERVED_ATTRIBUTES],
      characterData: true,
    });
    logger.debug('list marks attached');
  }

  /** Reattaches when the region being watched is no longer the region to watch. Cheap when it is. */
  #ensureAttached(): void {
    const root = this.#resolveRoot?.() ?? null;
    if (root === null) return;
    if (this.#root === root && root.isConnected) return;

    logger.debug('list region replaced, reattaching');
    this.#attach();
  }

  #schedule(): void {
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.#scan();
    }, DEBOUNCE_MS);
  }

  #scan(): void {
    // The second recovery path, and the only one that does not need a mutation to arrive: a replaced region
    // may produce no churn the detached observer can report, and the account-address retries run here.
    this.#ensureAttached();

    const root = this.#root;
    if (root === null) return;

    const recipient = this.#recipient();

    const rows = rowsIn(root);
    let addressable = 0;
    let marked = 0;
    for (const row of rows) {
      const sender = readSender(row);
      if (sender.senderEmail !== '') addressable += 1;
      /*
       * The key is everything the verdict was computed from.
       *
       * The display name, because the same address under a different name is a different claim and the
       * impersonation rules are largely about the name. And the recipient, because it arrives *late*: the
       * first passes run at `document_idle` with no account address, and `identity.lookalike_of_recipient_
       * domain` — a `high` mark on a domain imitating the reader's own employer, which is the most valuable
       * thing a row can say — cannot fire without it. Keyed on the sender alone, every row already on
       * screen when the address resolved kept its "nothing to say here" and was skipped for the life of
       * the tab, so the check only ever ran on mail that arrived later.
       */
      const key = `${recipient.recipientEmail ?? ''}|${sender.senderEmail}|${sender.senderName}`;
      if (row.getAttribute(MARKED_FOR) === key) continue;

      removeMark(row);
      row.setAttribute(MARKED_FOR, key);

      const verdict = sender.senderEmail === '' ? null : triageSender({ ...sender, ...recipient });
      if (verdict === null) continue;
      if (addMark(row, verdict)) marked += 1;
    }

    /*
     * All three counts, every pass, and not just the marks.
     *
     * An unmarked inbox is the expected result — the floor is `high`, so ordinary mail earns nothing — and
     * a stale row selector produces exactly the same silence. Logging only the marks made the two
     * indistinguishable from outside, which is the question anyone debugging this actually has: rows at
     * zero means the selectors no longer match Gmail's markup, and rows with addresses but no marks means
     * the feature is working and has nothing to say.
     */
    logger.debug('list pass', { rows: rows.length, addressable, marked });

    if (this.#recipientEmail === '' && this.#accountWaits < MAX_ACCOUNT_WAITS) {
      this.#accountWaits += 1;
      this.#schedule();
    }
  }

  /** Resolved once per pass, and retried on later passes for as long as Gmail has not exposed it. */
  #recipient(): { recipientEmail?: string } {
    if (this.#recipientEmail === '') this.#recipientEmail = this.#readAccount();
    return this.#recipientEmail === '' ? {} : { recipientEmail: this.#recipientEmail };
  }

  #clearAll(): void {
    for (const mark of document.querySelectorAll(`.${MARK_CLASS}`)) mark.remove();
    for (const row of document.querySelectorAll(`[${MARKED_FOR}]`)) row.removeAttribute(MARKED_FOR);
  }
}

function rowsIn(root: Element): Element[] {
  for (const selector of SELECTORS.listRow) {
    try {
      const found = root.querySelectorAll(selector);
      if (found.length > 0) return [...found].slice(0, MAX_ROWS);
    } catch {
      // An invalid candidate is not a match, exactly as in `queryFirst`.
    }
  }
  return [];
}

/**
 * The sender line as the row presents it.
 *
 * `[email]` is what makes triage possible from a list at all: Gmail puts the real address in that
 * attribute even though the row displays only a name. Without it there is no address, so there is no
 * verdict — which is the honest outcome rather than a guess from a display name.
 */
function readSender(row: Element): { senderName: string; senderEmail: string } {
  const element = queryFirst(row, SELECTORS.listSender);
  if (element === null) return { senderName: '', senderEmail: '' };

  return {
    senderEmail: element.getAttribute('email')?.trim() ?? '',
    // `name` carries the full display name; the row's text is often truncated to fit the column, and a
    // truncated name would make the impersonation checks see a different string than the card does.
    senderName: (element.getAttribute('name') ?? element.textContent).trim(),
  };
}

function removeMark(row: Element): void {
  row.querySelector(`.${MARK_CLASS}`)?.remove();
}

/** Returns whether the mark was placed; a row whose cells cannot be found is left alone. */
function addMark(row: Element, verdict: TriageVerdict): boolean {
  const cell = queryFirst(row, SELECTORS.listSubjectCell);
  if (cell === null) return false;

  const mark = el('span', {
    class: MARK_CLASS,
    text: GLYPHS[verdict.severity],
    attrs: {
      // The finding's own wording, as the tooltip. It comes from a message, so it arrives as text and is
      // set as an attribute value — never parsed.
      title: `PhishLens: ${verdict.title}. This message has not been opened or fully checked.`,
      'aria-label': `PhishLens warning: ${verdict.title}`,
      'data-phishlens-severity': verdict.severity,
      role: 'img',
    },
    style: {
      'margin-right': '6px',
      'font-size': '11px',
      'font-weight': '700',
      'line-height': '1',
      color: COLOURS[verdict.severity],
      // The row is a flex/table cell whose children Gmail sizes; an inline-block that cannot shrink
      // keeps the glyph from being squeezed to nothing in a narrow window.
      display: 'inline-block',
      'flex-shrink': '0',
      cursor: 'help',
    },
  });

  cell.prepend(mark);
  return true;
}
