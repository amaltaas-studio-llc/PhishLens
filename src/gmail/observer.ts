/**
 * Detects *which message the user is currently reading* in a hash-routed SPA.
 *
 * Neither available signal works alone:
 *
 *  - **`hashchange`/`popstate` alone** fires while Gmail is still showing the *previous* thread.
 *    Extracting at that moment analyses the old message and attributes the result to the new one:
 *    a stale analysis, which is worse than no analysis in a security tool.
 *  - **`MutationObserver` alone** fires dozens of times per thread open (avatars resolving, quoted
 *    text collapsing, the chat roster, ads) and also fires when Gmail re-renders the *same* thread.
 *    That produces redundant re-analysis and a flickering badge.
 *
 * So both are used, reconciled through a single **view signature**:
 *
 *     routeThreadId | domMessageId | domThreadId | sender | fingerprint(the whole extracted message)
 *
 *  - The debounced observer recomputes the signature. **Unchanged signature → no emit.** That is what
 *    stops redundant re-analysis on a same-thread re-render.
 *  - A route change records the expected thread id and starts a bounded reconciliation poll. An emit
 *    only happens once the DOM has moved on from the view we last reported. **A route change whose DOM
 *    has not caught up produces nothing, rather than a result for the previous thread.** That is what
 *    stops staleness.
 *  - If reconciliation times out, `no-message` is emitted so the UI tears the badge down instead of
 *    leaving a stale one attached to the wrong message.
 *  - A message that was reported and is then no longer readable (collapsed, or replaced by the user's own
 *    reply) is retracted the same way, after a grace period, because a brief absence is what an ordinary
 *    re-render looks like from here.
 *
 * The staleness guard compares **the DOM against itself**, never the route against the DOM. Gmail's
 * hash route carries a conversation id (`FMfcgz…`) while the subject element carries a thread perm id
 * (`thread-f:…`); they identify the same thread in two different id namespaces and are never equal, so
 * an equality test between them rejects every message forever. What is comparable is the previously
 * rendered DOM view: while it is unchanged after a route change, Gmail has not caught up yet.
 *
 * The guard is conditioned on the route having actually changed since the last emit. Re-entering the
 * same thread (open → back to the list → open again) legitimately re-renders an identical view, and
 * must not be mistaken for a DOM that has failed to catch up.
 *
 * The fingerprint component matters beyond thread identity: Gmail reuses message-id attributes when
 * expanding a collapsed message in place, and it renders the header before the body has loaded.
 * Fingerprinting everything extracted means "same thread, but the body has now actually arrived" is a
 * change, so the first emit is against a complete message rather than an empty one. See `domSignature`.
 */
import { logger } from '../shared/logger.js';
import type { EmailMessage, MessagePart } from '../shared/types.js';
import type { MailAdapter, MessageHandle } from './adapter.js';
import { VISIBILITY_ATTRIBUTES } from './hidden-text.js';
import { observeWithPath } from './roots.js';
import { OBSERVED_ATTRIBUTES } from './selectors.js';

export interface MessageOpenedEvent {
  kind: 'message';
  signature: string;
  handle: MessageHandle;
  email: EmailMessage;
  /**
   * Parts of the message the adapter could not read. Carried with the event rather than recomputed by
   * the consumer, because it describes the same extraction the `email` above came from.
   */
  missing: readonly MessagePart[];
}

export interface NoMessageEvent {
  kind: 'no-message';
  reason: 'navigated-away' | 'reconciliation-timeout' | 'no-open-message';
}

export type ObserverEvent = MessageOpenedEvent | NoMessageEvent;

export interface ObserverOptions {
  /** Quiet period after DOM churn before re-evaluating. */
  debounceMs?: number;
  /** Interval between reconciliation attempts after a route change. */
  reconcileIntervalMs?: number;
  /** Give up reconciling after this long. */
  reconcileTimeoutMs?: number;
  /** How long a body that is present but unreadable is given to become readable before it is reported. */
  unreadableGraceMs?: number;
  /** How long a reported message may be absent before its absence is reported in turn. */
  disappearanceGraceMs?: number;
}

const DEFAULTS = {
  debounceMs: 200,
  reconcileIntervalMs: 120,
  reconcileTimeoutMs: 4000,
  /*
   * Longer than the debounce, so a re-render in progress is not mistaken for a message that has gone;
   * far shorter than the reconciliation window, because unlike a route change this happens with a badge
   * already on screen making a claim about a message nobody can see.
   */
  disappearanceGraceMs: 600,
  /*
   * Gmail draws a body hidden while it is still building the view, and reporting that as unreadable would
   * flash "not checked" on ordinary mail. Long enough to outlast that; short enough that a body which
   * really does hide everything is reported while the reader is still looking at it.
   */
  unreadableGraceMs: 1500,
} as const;

export class GmailObserver {
  readonly #adapter: MailAdapter;
  readonly #onEvent: (event: ObserverEvent) => void;
  readonly #options: Required<ObserverOptions>;

  #mutationObserver: MutationObserver | null = null;
  /** The element the observer was given, so its replacement can be noticed. */
  #observedRoot: Element | null = null;
  #debounceTimer: ReturnType<typeof setTimeout> | null = null;
  #reconcileTimer: ReturnType<typeof setInterval> | null = null;
  #reconcileDeadline = 0;
  /** Grace period before a reported message's absence is treated as real. */
  #vanishTimer: ReturnType<typeof setTimeout> | null = null;
  /** The body first seen present-but-unreadable, and when, so the grace runs once per body. */
  #unreadableSince: { body: Element | null; at: number } | null = null;
  #unreadableTimer: ReturnType<typeof setTimeout> | null = null;

  /** Signature of the last emitted message. The redundancy guard, and *only* that. */
  #lastSignature = '';
  /**
   * Whether a message event is outstanding: whether the UI is, right now, asserting something about a
   * message.
   *
   * Separate from `#lastSignature` because the two answer different questions, and conflating them would
   * make the answer to this one wrong whenever the other is deliberately forgotten. Clearing the signature
   * is how a re-evaluation is forced: `refresh()` does it on a settings change, and reattaching to a
   * replaced conversation root does it because the replacement holds a render nothing has looked at. Read
   * as "there is no assertion on screen", an empty signature would cancel the retraction, so replacing the
   * root with a view whose message cannot be read would leave a badge and a card standing on the previous
   * message, which is the one thing the disappearance grace exists to prevent.
   */
  #reported = false;
  /**
   * The route and the *identity* of the last message actually emitted. The staleness guard compares the
   * rendered message against `identity` when the route has moved on from `routeThreadId`.
   */
  #lastEmit: { routeThreadId: string; identity: string } | null = null;
  /**
   * The elements the last emitted handle pointed at.
   *
   * Held because the consumer *draws into* them (the badge is injected into the header element), and a
   * signature cannot answer whether what was drawn is still on screen. Gmail redraws the message header
   * with equivalent markup, which takes the badge with it and leaves every byte of the extraction
   * identical; read as redundant, the message would spend the rest of its time on screen with no badge
   * and nothing to indicate one was ever due.
   */
  #reportedNodes: { root: Element; header: Element | null; body: Element | null } | null = null;
  /**
   * The body subtree whose inline styles are watched, kept so the watch follows the message.
   *
   * Scoped to the body rather than added to the root's filter because `style` is Gmail's most-written
   * attribute (sizing, animation, scroll position), and almost none of it is inside a message. Only there
   * does it decide what the engine reads. See `VISIBILITY_ATTRIBUTES`.
   */
  #watchedBody: Element | null = null;
  /** Thread id the *route* says should be on screen, used to detect route changes. */
  #expectedThreadId = '';
  #started = false;

  constructor(
    adapter: MailAdapter,
    onEvent: (event: ObserverEvent) => void,
    options: ObserverOptions = {},
  ) {
    this.#adapter = adapter;
    this.#onEvent = onEvent;
    this.#options = { ...DEFAULTS, ...options };
  }

  start(): void {
    if (this.#started) return;
    this.#started = true;

    window.addEventListener('hashchange', this.#handleRouteChange, { passive: true });
    window.addEventListener('popstate', this.#handleRouteChange, { passive: true });

    this.#attachMutationObserver();
    // Gmail's conversation root may not exist yet at document_idle.
    this.#handleRouteChange();
    this.#scheduleEvaluation();
  }

  stop(): void {
    if (!this.#started) return;
    this.#started = false;

    window.removeEventListener('hashchange', this.#handleRouteChange);
    window.removeEventListener('popstate', this.#handleRouteChange);
    this.#mutationObserver?.disconnect();
    this.#mutationObserver = null;
    this.#observedRoot = null;
    this.#clearDebounce();
    this.#stopReconciling();
    this.#stopConfirmingDisappearance();
    this.#clearUnreadableGrace();
    this.#lastSignature = '';
    this.#reported = false;
    this.#lastEmit = null;
    this.#reportedNodes = null;
    this.#watchedBody = null;
    this.#expectedThreadId = '';
  }

  /** Forces a re-evaluation, e.g. after a settings change. */
  refresh(): void {
    this.#lastSignature = '';
    this.#scheduleEvaluation();
  }

  #attachMutationObserver(): void {
    const root = this.#adapter.observationRoot() ?? document.body;
    this.#mutationObserver?.disconnect();
    this.#observedRoot = root;
    this.#mutationObserver = new MutationObserver(() => {
      // Before evaluating, because this may be the last mutation a detached observer ever reports.
      this.#ensureObserving();
      this.#scheduleEvaluation();
    });
    /*
     * Structure is not the only way a message changes. Gmail collapses a message by adding a class to the
     * container it already rendered, and it rewrites text in place: an attachment chip's filename, a
     * subject, a link's href. Watching `childList` alone would never re-evaluate any of that: the open
     * message could become collapsed, and unreadable, with the badge still asserting a verdict about it,
     * and `invoice.pdf` could become `invoice.exe` with no evaluation to notice. A
     * signature covering every field of the message helps only where something asks for it to be recomputed.
     *
     * Attributes are filtered to the ones the selectors actually read (`OBSERVED_ATTRIBUTES`), because the
     * unfiltered stream is mostly `style` and `jsaction` churn from hovering. Character data is not
     * filterable, so relative timestamps ticking over arrive here too; both are absorbed by the debounce
     * and then by the unchanged-signature guard, which is the cheap half of the evaluation.
     */
    // Plus the path out of the root, because Gmail replaces the conversation container rather than
    // emptying it and an observer holding the old one reports nothing again. See `roots.ts`.
    observeWithPath(this.#mutationObserver, root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: [...OBSERVED_ATTRIBUTES],
      characterData: true,
    });

    // Plus the message body, for the attributes extraction reads rather than the ones selectors match.
    const body = this.#watchedBody;
    if (body?.isConnected === true) {
      this.#mutationObserver.observe(body, {
        attributes: true,
        attributeFilter: [...VISIBILITY_ATTRIBUTES],
        subtree: true,
      });
    }

    logger.debug('mutation observer attached', { root: root.tagName });
  }

  /** Reattaches when the element being observed is no longer the one to observe. Cheap when it is. */
  #ensureObserving(): void {
    if (!this.#started) return;

    const root = this.#adapter.observationRoot() ?? document.body;
    const observed = this.#observedRoot;
    if (observed === root && observed.isConnected) return;

    logger.debug('observation root replaced, reattaching', {
      connected: observed?.isConnected ?? false,
    });
    this.#attachMutationObserver();
    // The replacement holds a different render, which nothing has looked at yet. Only the redundancy
    // guard is cleared: whatever was reported is still on screen, and stays retractable.
    this.#lastSignature = '';
  }

  readonly #handleRouteChange = (): void => {
    const threadId = this.#adapter.routeThreadId();

    if (threadId === '') {
      // Navigated to a list view; there is no open message to report on.
      this.#expectedThreadId = '';
      this.#stopReconciling();
      this.#retract('navigated-away');
      return;
    }

    if (threadId === this.#expectedThreadId) return;

    this.#expectedThreadId = threadId;
    // The previous thread's badge must go immediately; it describes a message no longer on screen.
    this.#retract('navigated-away');
    this.#startReconciling();
  };

  /**
   * Polls until the DOM catches up with the route, or the deadline passes.
   *
   * A poll rather than waiting on mutations because the render that completes a thread open does not
   * reliably produce an observable mutation inside the observed subtree on the first pass; the
   * conversation root itself is sometimes replaced, which detaches the observer.
   */
  #startReconciling(): void {
    this.#stopReconciling();
    this.#reconcileDeadline = Date.now() + this.#options.reconcileTimeoutMs;

    this.#reconcileTimer = setInterval(() => {
      if (this.#evaluate()) {
        this.#stopReconciling();
        return;
      }
      if (Date.now() > this.#reconcileDeadline) {
        this.#stopReconciling();
        logger.debug('reconciliation timed out', { expected: this.#expectedThreadId });
        // Reported unconditionally, unlike the other two: it says the route asked for a thread that never
        // arrived, which the consumer needs to hear whether or not anything was on screen before it.
        this.#lastSignature = '';
        this.#reported = false;
        this.#reportedNodes = null;
        this.#onEvent({ kind: 'no-message', reason: 'reconciliation-timeout' });
      }
    }, this.#options.reconcileIntervalMs);
  }

  #stopReconciling(): void {
    if (this.#reconcileTimer !== null) {
      clearInterval(this.#reconcileTimer);
      this.#reconcileTimer = null;
    }
  }

  #scheduleEvaluation(): void {
    this.#clearDebounce();
    this.#debounceTimer = setTimeout(() => {
      this.#debounceTimer = null;
      this.#evaluate();
    }, this.#options.debounceMs);
  }

  #clearDebounce(): void {
    if (this.#debounceTimer !== null) {
      clearTimeout(this.#debounceTimer);
      this.#debounceTimer = null;
    }
  }

  /** The open message and its extraction, or `null` when there is nothing worth reporting yet. */
  #readView(): { handle: MessageHandle; email: EmailMessage; missing: readonly MessagePart[] } | null {
    const handle = this.#adapter.currentMessage();
    this.#watchBody(handle?.bodyElement ?? null);
    if (handle === null) return null;

    const extraction = this.#adapter.extract(handle);
    const { email } = extraction;
    const empty =
      email.bodyText.trim() === '' && email.links.length === 0 && email.attachments.length === 0;
    if (!empty || !extraction.missing.includes('body')) this.#clearUnreadableGrace();
    // A header rendered before its body: wait rather than analysing an empty message.
    if (empty && !extraction.missing.includes('body')) return null;
    /*
     * Unless the adapter has said the body is there and could not be read. That is waited on too, but
     * only for a grace: waiting on it indefinitely would mean a message that never emits, and a message
     * that never emits gets no badge, which on a quiet install is exactly what a clean message looks like.
     */
    if (empty && !this.#unreadableGraceOver(handle.bodyElement)) return null;
    return { handle, email: extraction.email, missing: extraction.missing };
  }

  /** Whether this unreadable body has been given its grace, arranging a re-evaluation if not. */
  #unreadableGraceOver(body: Element | null): boolean {
    const now = Date.now();
    if (this.#unreadableSince?.body !== body) this.#unreadableSince = { body, at: now };
    const remaining = this.#unreadableSince.at + this.#options.unreadableGraceMs - now;
    if (remaining <= 0) return true;

    // Nothing may mutate in the meantime, and a body that stays hidden must still be reported.
    this.#unreadableTimer ??= setTimeout(() => {
      this.#unreadableTimer = null;
      this.#scheduleEvaluation();
    }, remaining);
    return false;
  }

  #clearUnreadableGrace(): void {
    this.#unreadableSince = null;
    if (this.#unreadableTimer !== null) {
      clearTimeout(this.#unreadableTimer);
      this.#unreadableTimer = null;
    }
  }

  /** Visibility can make the first readable extraction possible, so watch before requiring one. */
  #watchBody(body: Element | null): void {
    if (body === this.#watchedBody) return;
    this.#watchedBody = body;
    // Re-registering releases the previous body's target rather than retaining every opened message.
    this.#attachMutationObserver();
  }

  /**
   * A reported message is no longer readable. Waits, then retracts it.
   *
   * Absence has to be confirmed rather than acted on, because a momentary absence is the normal shape of
   * a Gmail re-render: the container is replaced, or the header arrives before the body, and `#readView`
   * correctly declines both. Retracting immediately would tear the badge off and rebuild it on ordinary
   * churn. Waiting *indefinitely* would be worse, though: collapsing the open message, or replying to it
   * so that the only expanded message is the user's own, would leave the badge and the popup asserting a
   * verdict about a message no longer on screen, which is a claim the reader cannot check.
   */
  #noteMessageAbsent(): void {
    if (!this.#reported) return;
    if (this.#vanishTimer !== null) return;

    this.#vanishTimer = setTimeout(() => {
      this.#vanishTimer = null;
      if (!this.#started || !this.#reported) return;
      // A list route, or a route change, is reported by the route handler with its own reason.
      if (this.#adapter.routeThreadId() === '') return;
      if (this.#readView() !== null) return;

      logger.debug('reported message is no longer in the view');
      this.#retract('no-open-message');
    }, this.#options.disappearanceGraceMs);
  }

  /**
   * Withdraws the outstanding assertion, if there is one.
   *
   * Silent when nothing is outstanding, which is what keeps a retraction from being reported twice and
   * what keeps an ordinary arrival at a list view from announcing the absence of a message nobody was
   * shown a verdict for.
   */
  #retract(reason: 'navigated-away' | 'no-open-message'): void {
    this.#lastSignature = '';
    this.#reportedNodes = null;
    if (!this.#reported) return;

    this.#reported = false;
    this.#onEvent({ kind: 'no-message', reason });
  }

  #stopConfirmingDisappearance(): void {
    if (this.#vanishTimer !== null) {
      clearTimeout(this.#vanishTimer);
      this.#vanishTimer = null;
    }
  }

  /**
   * The single decision point. Returns `true` when a message event was emitted.
   */
  #evaluate(): boolean {
    if (!this.#started) return false;

    // Navigation is where Gmail most often replaces the conversation container, and the reconciliation
    // poll is the one trigger that survives an observer left holding the old one.
    this.#ensureObserving();

    const routeThreadId = this.#adapter.routeThreadId();
    if (routeThreadId === '') {
      this.#retract('navigated-away');
      return false;
    }

    const view = this.#readView();
    if (view === null) {
      this.#noteMessageAbsent();
      return false;
    }
    this.#stopConfirmingDisappearance();
    const { handle, email, missing } = view;

    // Staleness guard. Route ids and DOM thread ids are different Gmail id namespaces (see the file
    // header), so the DOM is compared against the message we last reported instead. The *same message*
    // under a changed route means Gmail has not re-rendered yet.
    const identity = messageIdentity(handle, email);
    const lastEmit = this.#lastEmit;
    if (
      lastEmit !== null &&
      lastEmit.routeThreadId !== routeThreadId &&
      lastEmit.identity === identity
    ) {
      logger.debug('DOM has not caught up with the route yet', {
        expected: routeThreadId,
        rendered: lastEmit.routeThreadId,
      });
      return false;
    }

    // Acceptance ends reconciliation regardless of whether the interval or the debounce got here first.
    this.#stopReconciling();
    const signature = viewSignature(routeThreadId, handle, email);
    if (signature === this.#lastSignature && !this.#reportedNodesReplaced(handle)) return false;

    this.#lastSignature = signature;
    this.#reported = true;
    this.#lastEmit = { routeThreadId, identity };
    this.#reportedNodes = {
      root: handle.root,
      header: handle.headerElement,
      body: handle.bodyElement,
    };
    this.#expectedThreadId = routeThreadId;
    logger.debug('message opened', { signature });
    this.#onEvent({ kind: 'message', signature, handle, email, missing });

    return true;
  }

  /**
   * Whether the elements last reported are no longer the ones rendered.
   *
   * Compared by reference, which is the question being asked: not "does this message look the same" (the
   * signature answers that, and answers it identically for a header Gmail has redrawn from the same data)
   * but "is the element the badge was put into still the element on screen". Where the message is gone
   * rather than redrawn, `#readView` has already declined and the disappearance grace handles it.
   */
  #reportedNodesReplaced(handle: MessageHandle): boolean {
    const reported = this.#reportedNodes;
    if (reported === null) return false;

    return (
      reported.root !== handle.root ||
      reported.header !== handle.headerElement ||
      reported.body !== handle.bodyElement
    );
  }
}

/**
 * Identity of the currently-rendered view.
 *
 * Deliberately includes content-derived components, not just ids: Gmail reuses message ids when
 * expanding a collapsed message in place, and renders headers before bodies. Without the fingerprint
 * we would either miss the transition or analyse a half-rendered message.
 */
export function viewSignature(
  routeThreadId: string,
  handle: MessageHandle,
  email: EmailMessage,
): string {
  return `${routeThreadId}|${domSignature(handle, email)}`;
}

/**
 * *Which* message is rendered, and nothing about what it says.
 *
 * The staleness guard needs this rather than the signature below, and the difference between the two is
 * the difference between the two questions asked of the DOM. "Has anything changed?" must move when a
 * Reply-To line or an attachment chip arrives late, or the enrichment is dropped. "Is this still the
 * message I reported?" must *not* move when it does: the guard reads inequality as "Gmail has
 * re-rendered for the new route", so a content-derived identity would let expanding the details panel on
 * a message the reader has navigated away from emit it under the next thread's route, with its own ids
 * unchanged and every id in the comparison agreeing that it had not changed.
 *
 * Ids, the sender, and no more. The subject is left out even though it is as stable as the ids for the
 * same reason the body is: Gmail renders the thread's subject element separately from the message, so a
 * transition where it is briefly absent would read as a different message, which is the failure this is
 * guarding against. Where the ids are unreadable and the sender is the same, the guard blocks a render it
 * should have allowed and the reconciliation poll reports a timeout: silence rather than a verdict
 * attributed to the wrong thread, which is the direction this project errs in.
 */
export function messageIdentity(handle: MessageHandle, email: EmailMessage): string {
  const sender = email.senderEmail ?? '';
  /*
   * Only message-owned evidence can establish identity across a route transition.
   *
   * The thread perm id is read from the subject heading, which is not part of the message: Gmail renders it
   * separately and swaps it first, so for a moment the heading names the thread being opened while the
   * message below it is still the previous one. Counting it here would let that heading update alone
   * satisfy the guard. With no message id, two threads from the same sender remain ambiguous and time out
   * rather than letting an independently updated heading vouch for the body beneath it.
   */
  return handle.messageId === ''
    ? `sender:${sender}`
    : `message:${handle.messageId}|${sender}`;
}

/**
 * Identity of the rendered *view*, derived purely from the DOM: what is on screen, down to the evidence.
 *
 * Deliberately excludes the route, so it can answer "is Gmail still showing what it showed before?"
 * independently of what the URL now claims.
 *
 * It covers the *evidence*, not merely the message, and the difference is the whole point. Gmail reveals
 * parts of a message after it has drawn the rest: expanding the details panel adds the Reply-To line and
 * the `mailed-by` / `signed-by` rows, and attachment chips arrive late. A signature that does not move when
 * they arrive reads the enrichment as "nothing has changed" and drops it, leaving the score standing on
 * evidence that has since been superseded, and the fields most often revealed that way are the
 * authentication and Reply-To checks, which is to say the ones hardest to argue with.
 *
 * **Values, not summaries, and every field rather than a chosen list.** Counting is not enough:
 * `invoice.pdf` becoming `invoice.exe` leaves the attachment count at one, which is a score of
 * 0 becoming a score of 75 behind an identical signature, and a rewritten href or an edited sentence of the
 * same length does the same for the link and content rules. Any hand-picked list of fields is a list that
 * a field added later is left out of, so the whole extracted message is fingerprinted: everything the
 * engine is given is exactly what decides whether the engine has to run again.
 */
export function domSignature(handle: MessageHandle, email: EmailMessage): string {
  return [handle.messageId, handle.threadId, email.senderEmail ?? '', fingerprint(evidenceOf(email))].join(
    '|',
  );
}

/**
 * Everything the extraction produced, as one string to hash.
 *
 * `EmailMessage` is a plain data structure by contract (it is what crosses from the Gmail adapter into an
 * engine that may not touch the DOM), so serialising it is total, and it stays total as fields are added.
 * Bounded by extraction rather than here: the adapter truncates the body and caps links and attachments
 * before any of this is reached.
 */
function evidenceOf(email: EmailMessage): string {
  try {
    return JSON.stringify(email);
  } catch {
    /*
     * Unreachable with the types in `shared/types.ts`, which admit only strings, numbers, booleans and
     * arrays of those. Kept because this runs inside a timer callback: a throw here would stop the observer
     * for the life of the tab, and detection that has quietly stopped is the worst outcome available. The
     * fallback is deliberately coarse (like any signature built from counts, it misses a changed value)
     * because re-analysing on every mutation instead would be a different silent failure.
     */
    return `${email.subject ?? ''}|${String(email.bodyText.length)}|${String(email.links.length)}|${String(email.attachments.length)}`;
  }
}

/**
 * A cheap non-cryptographic fingerprint (FNV-1a).
 *
 * Only ever compared for equality against another fingerprint from this same function, so collision
 * resistance is irrelevant and a hash function is not a security control here.
 */
export function fingerprint(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}
