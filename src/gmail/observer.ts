/**
 * Detects *which message the user is currently reading* in a hash-routed SPA.
 *
 * Neither available signal works alone:
 *
 *  - **`hashchange`/`popstate` alone** fires while Gmail is still showing the *previous* thread.
 *    Extracting at that moment analyses the old message and attributes the result to the new one —
 *    a stale analysis, which is worse than no analysis in a security tool.
 *  - **`MutationObserver` alone** fires dozens of times per thread open (avatars resolving, quoted
 *    text collapsing, the chat roster, ads) and also fires when Gmail re-renders the *same* thread.
 *    That produces redundant re-analysis and a flickering badge.
 *
 * So both are used, reconciled through a single **view signature**:
 *
 *     routeThreadId | domMessageId | domThreadId | fingerprint(sender, subject, bodyLength)
 *
 *  - The debounced observer recomputes the signature. **Unchanged signature → no emit.** That is what
 *    stops redundant re-analysis on a same-thread re-render.
 *  - A route change records the expected thread id and starts a bounded reconciliation poll. An emit
 *    only happens once the DOM has moved on from the view we last reported. **A route change whose DOM
 *    has not caught up produces nothing, rather than a result for the previous thread.** That is what
 *    stops staleness.
 *  - If reconciliation times out, `no-message` is emitted so the UI tears the badge down instead of
 *    leaving a stale one attached to the wrong message.
 *  - A message that was reported and is then no longer readable — collapsed, or replaced by the user's own
 *    reply — is retracted the same way, after a grace period, because a brief absence is what an ordinary
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
 * Including the body length means "same thread, but the body has now actually arrived" is a change,
 * so the first emit is against a complete message rather than an empty one.
 */
import { logger } from '../shared/logger.js';
import type { EmailMessage, MessagePart } from '../shared/types.js';
import type { MailAdapter, MessageHandle } from './adapter.js';

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
  /** How long a reported message may be absent before its absence is reported in turn. */
  disappearanceGraceMs?: number;
}

/** Ancestors watched for the observed root being replaced. Enough to reach `<body>` from a Gmail pane. */
const MAX_WATCHED_ANCESTORS = 24;

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

  /** Signature of the last emitted message. The redundancy guard, and *only* that. */
  #lastSignature = '';
  /**
   * Whether a message event is outstanding — whether the UI is, right now, asserting something about a
   * message.
   *
   * Separate from `#lastSignature` because the two answer different questions, and conflating them made
   * the answer to this one wrong whenever the other was deliberately forgotten. Clearing the signature is
   * how a re-evaluation is forced: `refresh()` does it on a settings change, and reattaching to a replaced
   * conversation root does it because the replacement holds a render nothing has looked at. Read as "there
   * is no assertion on screen", an empty signature then cancelled the retraction — so replacing the root
   * with a view whose message cannot be read left a badge and a card standing on the previous message,
   * which is the one thing the disappearance grace exists to prevent.
   */
  #reported = false;
  /**
   * The route and DOM identity of the last message actually emitted. The staleness guard compares the
   * current DOM against `domSignature` when the route has moved on from `routeThreadId`.
   */
  #lastEmit: { routeThreadId: string; domSignature: string } | null = null;
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
    this.#lastSignature = '';
    this.#reported = false;
    this.#lastEmit = null;
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
    this.#mutationObserver.observe(root, {
      childList: true,
      subtree: true,
      // Attribute and character-data mutations are the noisiest and least informative: Gmail
      // constantly toggles classes and updates relative timestamps. Structural changes are what
      // indicate a different message.
      attributes: false,
      characterData: false,
    });

    /*
     * The path from the root to the document, watched for the root being swapped out rather than
     * changed. A MutationObserver holds the node it was given: when Gmail replaces the conversation
     * container — which it does on some in-place actions, not only on navigation — the observer stays
     * attached to an element no longer in the document and reports nothing ever again. Nothing else
     * notices, because every other trigger in this file is downstream of a mutation, so the extension
     * goes quiet on a page that still looks like it is working.
     *
     * `childList` without `subtree` on each ancestor is what makes that observable: replacing any node
     * on the path is a child-list change on its parent, and this is the one form of Gmail churn that
     * happens outside the observed subtree. The cost is a handful of targets that almost never fire,
     * as against watching `document.body` wholesale — which would catch it too, and would also re-run
     * extraction every time the chat roster or an advert changed.
     */
    for (const ancestor of pathToDocument(root)) {
      this.#mutationObserver.observe(ancestor, { childList: true });
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
   * reliably produce an observable mutation inside the observed subtree on the first pass — the
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
    if (handle === null) return null;

    const extraction = this.#adapter.extract(handle);
    const { email } = extraction;
    // A header rendered before its body: wait rather than analysing an empty message.
    if (email.bodyText.trim() === '' && email.links.length === 0 && email.attachments.length === 0) {
      return null;
    }
    return { handle, email: extraction.email, missing: extraction.missing };
  }

  /**
   * A reported message is no longer readable. Waits, then retracts it.
   *
   * Absence has to be confirmed rather than acted on, because a momentary absence is the normal shape of
   * a Gmail re-render: the container is replaced, or the header arrives before the body, and `#readView`
   * correctly declines both. Retracting immediately would tear the badge off and rebuild it on ordinary
   * churn. Waiting *indefinitely* is the bug this replaces, though — collapsing the open message, or
   * replying to it so that the only expanded message is the user's own, left the badge and the popup
   * asserting a verdict about a message no longer on screen, which is a claim the reader cannot check.
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
    // header), so the DOM is compared against the view we last reported instead. An unchanged view
    // under a changed route means Gmail has not re-rendered yet.
    const domSig = domSignature(handle, email);
    const lastEmit = this.#lastEmit;
    if (
      lastEmit !== null &&
      lastEmit.routeThreadId !== routeThreadId &&
      lastEmit.domSignature === domSig
    ) {
      logger.debug('DOM has not caught up with the route yet', {
        expected: routeThreadId,
        rendered: lastEmit.routeThreadId,
      });
      return false;
    }

    const signature = viewSignature(routeThreadId, handle, email);
    if (signature === this.#lastSignature) return false;

    this.#lastSignature = signature;
    this.#reported = true;
    this.#lastEmit = { routeThreadId, domSignature: domSig };
    this.#expectedThreadId = routeThreadId;
    logger.debug('message opened', { signature });
    this.#onEvent({ kind: 'message', signature, handle, email, missing });
    return true;
  }
}

/**
 * The ancestors of an element, outward to the document.
 *
 * Bounded because it is walked on every reattachment and the shape of the page is Gmail's to change; the
 * limit is generous enough to reach `<body>` from the conversation container several times over.
 */
function pathToDocument(element: Element): Element[] {
  const path: Element[] = [];
  let current: Element | null = element.parentElement ?? null;
  while (current !== null && path.length < MAX_WATCHED_ANCESTORS) {
    path.push(current);
    current = current.parentElement ?? null;
  }
  return path;
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
 * Identity of the rendered message, derived purely from the DOM.
 *
 * Deliberately excludes the route, so it can answer "is Gmail still showing what it showed before?"
 * independently of what the URL now claims.
 *
 * It covers the *evidence*, not merely the message, and the difference is the whole point. Gmail reveals
 * parts of a message after it has drawn the rest: expanding the details panel adds the Reply-To line and
 * the `mailed-by` / `signed-by` rows, and attachment chips arrive late. A signature that does not move when
 * they arrive reads the enrichment as "nothing has changed" and drops it, leaving the score standing on
 * evidence that has since been superseded — and the fields most often revealed that way are the
 * authentication and Reply-To checks, which is to say the ones hardest to argue with.
 *
 * **Values, not summaries, and every field rather than a chosen list.** Counting was tried twice and was
 * wrong twice: `invoice.pdf` becoming `invoice.exe` leaves the attachment count at one, which is a score of
 * 0 becoming a score of 75 behind an identical signature, and a rewritten href or an edited sentence of the
 * same length does the same for the link and content rules. Any hand-picked list of fields is a list that a
 * later field is left out of, so the whole extracted message is fingerprinted — everything the engine is
 * given is exactly what decides whether the engine has to run again.
 */
export function domSignature(handle: MessageHandle, email: EmailMessage): string {
  return [handle.messageId, handle.threadId, email.senderEmail ?? '', fingerprint(evidenceOf(email))].join(
    '|',
  );
}

/**
 * Everything the extraction produced, as one string to hash.
 *
 * `EmailMessage` is a plain data structure by contract — it is what crosses from the Gmail adapter into an
 * engine that may not touch the DOM — so serialising it is total, and it stays total as fields are added.
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
     * fallback is deliberately coarse — it misses a changed value, as the old signature did — because
     * re-analysing on every mutation instead would be a different silent failure.
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
