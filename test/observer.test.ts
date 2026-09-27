/**
 * Tests for the SPA message observer.
 *
 * This class decides *whether the extension does anything at all*, and every one of its negative
 * decisions is deliberately silent — a wrong `return false` produces no error, no badge, and no log in
 * a production build. That combination is why it needs direct tests rather than coverage via the
 * analysis stack.
 *
 * The regression that motivated these: the staleness guard compared the route's conversation id
 * (`FMfcgz…`) against the DOM's thread perm id (`thread-f:…`). Those are two different Gmail id
 * namespaces for the same thread, so the comparison rejected every message and the extension silently
 * never analysed anything on a real inbox.
 *
 * Runs without a DOM. The observer touches only `window` events, `MutationObserver` and timers, so
 * those are faked here rather than pulling in jsdom for one test file.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Extraction, MailAdapter, MessageHandle } from '../src/gmail/adapter.js';
import { GmailObserver, domSignature, viewSignature, type ObserverEvent } from '../src/gmail/observer.js';
import type { EmailMessage } from '../src/shared/types.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface RenderedView {
  messageId: string;
  threadId: string;
  senderEmail: string;
  subject: string;
  bodyText: string;
}

/**
 * The two properties the observer asks of an element: whether it is still in the document, and what
 * encloses it. Both exist because Gmail replaces the conversation container rather than emptying it.
 */
class FakeElement {
  isConnected = true;
  readonly parentElement: FakeElement | null;

  constructor(
    readonly tagName: string,
    parent: FakeElement | null = null,
  ) {
    this.parentElement = parent;
  }
}

/** A conversation container inside a pane inside the body, which is the shape of the path Gmail swaps. */
function conversationRoot(): FakeElement {
  return new FakeElement('DIV', new FakeElement('DIV', new FakeElement('BODY')));
}

/** A Gmail stand-in whose route and rendered DOM can be moved independently, as Gmail's really are. */
class FakeAdapter implements MailAdapter {
  readonly id = 'fake';
  route = '';
  view: RenderedView | null = null;
  rootAvailable = true;
  root = conversationRoot();

  observationRoot(): Element | null {
    return this.rootAvailable ? (this.root as unknown as Element) : null;
  }

  /** Gmail re-rendering the conversation pane: a fresh container, the old one detached. */
  replaceRoot(): void {
    this.root.isConnected = false;
    this.root = conversationRoot();
  }

  /** The observer never asks; it is on the interface for the list-row scanner. */
  accountAddress(): string {
    return '';
  }

  /**
   * Mirrors `GmailDomAdapter.routeThreadId()`, including its contract that a list route such as
   * `inbox` or `search/invoices` yields no thread id. A fake that returned the raw hash would let
   * list-view tests pass for the wrong reason.
   */
  routeThreadId(): string {
    const segments = this.route.split('/').filter((s) => s !== '');
    const last = segments[segments.length - 1] ?? '';
    return /^[A-Za-z0-9_-]{16,}$/u.test(last) ? last : '';
  }

  currentMessage(): MessageHandle | null {
    if (this.view === null) return null;
    return {
      messageId: this.view.messageId,
      threadId: this.view.threadId,
      priorSenders: [],
      headerElement: null,
      bodyElement: null,
      root: {} as Element,
    };
  }

  extract(): Extraction {
    const view = this.view;
    if (view === null) {
      return { email: { bodyText: '', links: [], attachments: [] }, missing: ['sender'] };
    }
    const email: EmailMessage = {
      senderEmail: view.senderEmail,
      subject: view.subject,
      bodyText: view.bodyText,
      links: [],
      attachments: [],
    };
    return { email, missing: view.senderEmail === '' ? ['sender'] : [] };
  }
}

class FakeMutationObserver {
  static instances: FakeMutationObserver[] = [];
  readonly callback: () => void;
  /** Recorded because *what* is watched is the whole mechanism for noticing a replaced root. */
  readonly targets: unknown[] = [];
  /**
   * And with what options, because a fake calls the callback whatever it was asked to watch. Every test
   * here drives the callback directly, so the options are the only place the real browser's answer to
   * "is this worth reporting" is visible at all.
   */
  readonly watches: { target: unknown; options: MutationObserverInit }[] = [];

  constructor(callback: () => void) {
    this.callback = callback;
    FakeMutationObserver.instances.push(this);
  }

  observe(target: unknown, options: MutationObserverInit = {}): void {
    this.targets.push(target);
    this.watches.push({ target, options });
  }

  disconnect(): void {
    // No-op.
  }
}

function latestObserver(): FakeMutationObserver {
  const observers = FakeMutationObserver.instances;
  const latest = observers[observers.length - 1];
  if (latest === undefined) throw new Error('no MutationObserver was attached');
  return latest;
}

function triggerMutation(): void {
  latestObserver().callback();
}

/**
 * A thread as Gmail actually presents it: an opaque conversation id in the hash, and an unrelated
 * `thread-f:` perm id on the subject element.
 */
function thread(name: string, permId: string): RenderedView {
  return {
    messageId: `msg-${name}`,
    threadId: `thread-f:${permId}`,
    senderEmail: `sender@${name}.example`,
    subject: `Subject ${name}`,
    bodyText: `Body of ${name}, long enough to be a real message.`,
  };
}

const THREAD_A_HASH = 'FMfcgzQhWLMhlXGCZNdTpfpfWQXRPjNz';
const THREAD_B_HASH = 'FMfcgzGxSVbKjRnQPmWdTzXvLhYcNqBt';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let adapter: FakeAdapter;
let events: ObserverEvent[];
let observer: GmailObserver;

function messageEvents(): ObserverEvent[] {
  return events.filter((e) => e.kind === 'message');
}

function noMessageReasons(): string[] {
  return events.flatMap((e) => (e.kind === 'no-message' ? [e.reason] : []));
}

/** Runs long enough for the debounce and at least one reconciliation poll to fire. */
function settle(ms = 500): void {
  vi.advanceTimersByTime(ms);
}

function navigate(hash: string): void {
  adapter.route = hash;
  window.dispatchEvent(new Event('hashchange'));
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeMutationObserver.instances = [];

  Object.defineProperty(globalThis, 'window', {
    value: new EventTarget(),
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'document', {
    value: { body: new FakeElement('BODY') },
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'MutationObserver', {
    value: FakeMutationObserver,
    configurable: true,
    writable: true,
  });

  adapter = new FakeAdapter();
  events = [];
  observer = new GmailObserver(adapter, (event) => {
    events.push(event);
  });
});

afterEach(() => {
  observer.stop();
  vi.useRealTimers();
  Reflect.deleteProperty(globalThis, 'window');
  Reflect.deleteProperty(globalThis, 'document');
  Reflect.deleteProperty(globalThis, 'MutationObserver');
});

// ---------------------------------------------------------------------------
// The regression
// ---------------------------------------------------------------------------

describe('route id and DOM thread id namespaces', () => {
  it('emits for a message whose DOM thread id shares no namespace with the route id', () => {
    // Exactly the live-Gmail shape: hash says `FMfcgz…`, the subject element says `thread-f:…`.
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1798123456789012345');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).not.toContain('reconciliation-timeout');
  });

  it('emits even when the DOM exposes no thread id at all', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = { ...thread('a', 'x'), threadId: '' };

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Redundancy
// ---------------------------------------------------------------------------

describe('redundant re-render suppression', () => {
  it('does not re-emit while the same message stays on screen', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');

    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Gmail churns the subtree constantly: avatars, timestamps, ads.
    triggerMutation();
    settle();
    triggerMutation();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });

  it('re-emits when the body arrives after the header', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = { ...thread('a', '1'), bodyText: '' };

    observer.start();
    settle();
    // An empty body is not a message worth reporting.
    expect(messageEvents()).toHaveLength(0);

    adapter.view = thread('a', '1');
    triggerMutation();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

describe('staleness guard', () => {
  it('does not attribute the previous thread to a newly routed thread', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Route moves to B while Gmail still shows A.
    navigate(THREAD_B_HASH);
    settle(300);

    // Nothing new reported: the only message event is still A's.
    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).toContain('navigated-away');
  });

  it('emits once the DOM catches up with the new route', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate(THREAD_B_HASH);
    settle(200);
    expect(messageEvents()).toHaveLength(1);

    adapter.view = thread('b', '2');
    settle();

    const emitted = messageEvents();
    expect(emitted).toHaveLength(2);
    expect(emitted[1]?.kind === 'message' && emitted[1].email.senderEmail).toBe('sender@b.example');
  });

  it('reports a timeout rather than a stale badge when the DOM never catches up', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate(THREAD_B_HASH);
    settle(5000);

    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).toContain('reconciliation-timeout');
  });

  /**
   * The guard must key on "the route changed", not merely "the DOM looks the same as last time".
   * Re-opening a thread renders a byte-identical view, and that is a legitimate emit.
   */
  it('re-emits when the same thread is re-opened from the list view', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Back to the inbox list: no thread in the route, no message rendered.
    adapter.view = null;
    navigate('inbox');
    settle();
    expect(noMessageReasons()).toContain('navigated-away');

    // Same thread re-opened; the rendered view is identical to before.
    adapter.view = thread('a', '1');
    navigate(THREAD_A_HASH);
    settle();

    expect(messageEvents()).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// List views
// ---------------------------------------------------------------------------

describe('list views', () => {
  it('reads the thread id from a full Gmail hash route', () => {
    adapter.route = `inbox/${THREAD_A_HASH}`;
    adapter.view = thread('a', '1');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });

  it('treats a non-thread route as no open message', () => {
    adapter.route = 'inbox';
    adapter.view = thread('a', '1');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(0);
  });

  it('tears down when navigating from a thread to a list', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate('search/invoices');
    settle();

    expect(noMessageReasons()).toContain('navigated-away');
  });
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

describe('lifecycle', () => {
  it('emits nothing after stop', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    const before = messageEvents().length;

    observer.stop();
    adapter.view = thread('b', '2');
    adapter.route = THREAD_B_HASH;
    settle();

    expect(messageEvents()).toHaveLength(before);
  });

  it('re-emits the current message on refresh', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    observer.refresh();
    settle();

    expect(messageEvents()).toHaveLength(2);
  });

  /**
   * A MutationObserver holds the node it was given. Gmail replaces the conversation container on some
   * in-place actions, not only on navigation, and the observer then sits on an element that is no longer
   * in the document, reporting nothing ever again — on a page that still looks like it is working, with a
   * badge still attached. Every other trigger in the observer is downstream of a mutation, so the
   * watchers on the path out of the root are the only thing that makes the replacement noticeable.
   */
  describe('when Gmail replaces the conversation root', () => {
    it('watches the path out of the root, not only the root', () => {
      adapter.route = THREAD_A_HASH;
      adapter.view = thread('a', '1');
      observer.start();

      const { targets } = latestObserver();
      expect(targets).toContain(adapter.root);
      expect(targets).toContain(adapter.root.parentElement);
      expect(targets).toContain(adapter.root.parentElement?.parentElement);
    });

    it('reattaches to the replacement', () => {
      adapter.route = THREAD_A_HASH;
      adapter.view = thread('a', '1');
      observer.start();
      settle();
      const attachments = FakeMutationObserver.instances.length;

      adapter.replaceRoot();
      // What the ancestor watchers deliver: the detached observer's last useful report.
      triggerMutation();
      settle();

      expect(FakeMutationObserver.instances.length).toBe(attachments + 1);
      expect(latestObserver().targets).toContain(adapter.root);
    });

    it('keeps reporting messages rendered into the replacement', () => {
      adapter.route = THREAD_A_HASH;
      adapter.view = thread('a', '1');
      observer.start();
      settle();

      adapter.replaceRoot();
      triggerMutation();
      settle();

      // The new container's own churn has to reach the observer, or the reattachment proved nothing.
      adapter.view = thread('a2', '1');
      triggerMutation();
      settle();

      expect(messageEvents().length).toBeGreaterThan(1);
    });
  });

  /**
   * The badge and the popup are claims about a message on screen. Collapsing the open message, or replying
   * to it so that the only expanded message is the user's own, leaves nothing readable — and the claim
   * stood, because the evaluation simply returned. Retracting it needs a delay rather than an immediate
   * teardown: a momentary absence is exactly what an ordinary Gmail re-render looks like from here.
   */
  /**
   * Gmail changes a message without changing the shape of the page: a class marks it collapsed, a text
   * node carries an attachment's filename, an attribute carries a link's target. None of that is a
   * child-list mutation, so none of it was ever looked at.
   */
  describe('what the browser is asked to report', () => {
    beforeEach(() => {
      adapter.route = THREAD_A_HASH;
      adapter.view = thread('a', '1');
      observer.start();
    });

    function rootWatch(): MutationObserverInit {
      const watch = latestObserver().watches.find((entry) => entry.target === adapter.root);
      if (watch === undefined) throw new Error('the root itself is not being watched');
      return watch.options;
    }

    it('watches text and the attributes the selectors read', () => {
      const options = rootWatch();

      expect(options.subtree).toBe(true);
      expect(options.characterData).toBe(true);
      expect(options.attributes).toBe(true);
      // `class` decides whether a message is collapsed; the id attributes decide which message it is.
      expect(options.attributeFilter).toContain('class');
      expect(options.attributeFilter).toContain('data-message-id');
      expect(options.attributeFilter).toContain('href');
    });

    /** The hover churn the filter exists to drop. Watching it would re-extract on every mouse move. */
    it('leaves the attributes nothing reads alone', () => {
      expect(rootWatch().attributeFilter).not.toContain('style');
    });

    /** Ancestors are watched for one thing only: the root being swapped out from under them. */
    it('watches ancestors for structure alone', () => {
      const ancestors = latestObserver().watches.filter((entry) => entry.target !== adapter.root);

      expect(ancestors.length).toBeGreaterThan(0);
      for (const { options } of ancestors) {
        expect(options).toEqual({ childList: true });
      }
    });
  });

  describe('when a reported message stops being readable', () => {
    beforeEach(() => {
      adapter.route = THREAD_A_HASH;
      adapter.view = thread('a', '1');
      observer.start();
      settle();
    });

    it('retracts it once the absence has lasted', () => {
      adapter.view = null;
      triggerMutation();
      settle(1000);

      expect(noMessageReasons()).toContain('no-open-message');
    });

    it('says nothing when the message comes back within the grace period', () => {
      adapter.view = null;
      triggerMutation();
      settle(300);

      adapter.view = thread('a', '1');
      triggerMutation();
      settle(1000);

      expect(noMessageReasons()).not.toContain('no-open-message');
    });

    /** A header without a body is a render in progress, and it is the common case, not the edge one. */
    it('says nothing while a body is still arriving', () => {
      adapter.view = { ...thread('a', '1'), bodyText: '' };
      triggerMutation();
      settle(300);

      adapter.view = thread('a', '1');
      triggerMutation();
      settle(1000);

      expect(noMessageReasons()).not.toContain('no-open-message');
    });

    /** Leaving for a list view is the route handler's business, and it has its own reason for it. */
    it('leaves a navigation to be reported as a navigation', () => {
      adapter.view = null;
      navigate('inbox');
      settle(1000);

      expect(noMessageReasons()).toContain('navigated-away');
      expect(noMessageReasons()).not.toContain('no-open-message');
    });

    it('retracts it only once', () => {
      adapter.view = null;
      triggerMutation();
      settle(1000);
      triggerMutation();
      settle(1000);

      expect(noMessageReasons().filter((reason) => reason === 'no-open-message')).toHaveLength(1);
    });

    /**
     * Retraction has to survive the signature being forgotten, because forgetting it is routine: it is how
     * a re-evaluation is forced. Reattaching to a replaced conversation root does it, and a replacement
     * arriving without a readable message is precisely the case the grace period was added for — Gmail
     * rebuilding the pane around the user's own reply. Reading an empty signature as "nothing was
     * asserted" cancelled the retraction there, and left the badge on the message underneath.
     */
    it('still retracts after the conversation root has been replaced', () => {
      adapter.replaceRoot();
      adapter.view = null;
      triggerMutation();
      settle(1000);

      expect(noMessageReasons()).toContain('no-open-message');
    });

    it('still retracts on navigation after the conversation root has been replaced', () => {
      adapter.view = null;
      adapter.replaceRoot();
      triggerMutation();
      // Long enough to evaluate the replacement, short of the grace period, so the retraction that
      // follows has to come from the navigation.
      settle(300);

      navigate('inbox');
      settle(1000);

      expect(noMessageReasons()).toContain('navigated-away');
    });

    /** The other half: forcing a re-evaluation must not fabricate a retraction either. */
    it('says nothing on a refresh while the message is still readable', () => {
      observer.refresh();
      settle(1000);

      expect(noMessageReasons()).toEqual([]);
    });
  });

  it('survives an observation root that is not there yet', () => {
    adapter.rootAvailable = false;
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');

    expect(() => {
      observer.start();
      settle();
    }).not.toThrow();
    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

describe('signatures', () => {
  const handle = (messageId: string, threadId: string): MessageHandle => ({
    messageId,
    threadId,
    priorSenders: [],
    headerElement: null,
    bodyElement: null,
    root: {} as Element,
  });

  const email = (overrides: Partial<EmailMessage> = {}): EmailMessage => ({
    senderEmail: 'a@example.com',
    subject: 'Hello',
    bodyText: 'Body',
    links: [],
    attachments: [],
    ...overrides,
  });

  it('separates route identity from DOM identity', () => {
    const dom = domSignature(handle('m1', 't1'), email());

    expect(viewSignature(THREAD_A_HASH, handle('m1', 't1'), email())).toBe(`${THREAD_A_HASH}|${dom}`);
    // The same rendered message under a different route has the same DOM signature.
    expect(domSignature(handle('m1', 't1'), email())).toBe(dom);
  });

  it('changes when the body length changes', () => {
    const before = domSignature(handle('m1', 't1'), email({ bodyText: 'short' }));
    const after = domSignature(handle('m1', 't1'), email({ bodyText: 'considerably longer body' }));

    expect(after).not.toBe(before);
  });

  it('changes when the sender changes under a reused message id', () => {
    const before = domSignature(handle('m1', 't1'), email({ senderEmail: 'a@example.com' }));
    const after = domSignature(handle('m1', 't1'), email({ senderEmail: 'b@example.com' }));

    expect(after).not.toBe(before);
  });

  /**
   * Gmail reveals a message in stages, and the stages that arrive late are the ones detection leans on
   * hardest. Expanding the details panel adds Reply-To and the `mailed-by` / `signed-by` rows; attachment
   * chips render after the body. A signature made only of subject, body length and link count was
   * identical before and after each of those, so the observer read new evidence as "nothing has changed"
   * and discarded it, leaving the badge standing on an analysis that could no longer be reproduced from
   * what was on screen.
   */
  describe('evidence revealed after the first render', () => {
    const base = handle('m1', 't1');
    const initial = domSignature(base, email());

    it('changes when a Reply-To appears', () => {
      expect(domSignature(base, email({ replyTo: 'billing@unrelated.example' }))).not.toBe(initial);
    });

    it('changes when Gmail exposes its authentication summary', () => {
      expect(
        domSignature(base, email({ auth: { spf: 'pass', dkim: 'pass', signedBy: 'example.com' } })),
      ).not.toBe(initial);
    });

    it('changes when an authentication verdict changes, not merely appears', () => {
      const passing = domSignature(base, email({ auth: { dmarc: 'pass' } }));
      const failing = domSignature(base, email({ auth: { dmarc: 'fail' } }));

      expect(failing).not.toBe(passing);
    });

    it('changes when Gmail raises its own warning banner', () => {
      expect(
        domSignature(base, email({ auth: { gmailWarning: 'This message seems dangerous.' } })),
      ).not.toBe(initial);
    });

    it('changes when an attachment chip arrives', () => {
      expect(
        domSignature(base, email({ attachments: [{ filename: 'invoice.pdf', extension: 'pdf' }] })),
      ).not.toBe(initial);
    });

    it('changes when hidden text is found on a later pass', () => {
      expect(
        domSignature(base, email({ hiddenText: { chars: 800, techniques: ['font-size:0'] } })),
      ).not.toBe(initial);
    });

    /** Still stable across a re-render that revealed nothing, or the badge would rebuild on every mutation. */
    it('does not change when the same evidence is read again', () => {
      const withAuth = email({ auth: { spf: 'pass', signedBy: 'example.com' }, replyTo: 'a@example.com' });
      expect(domSignature(base, withAuth)).toBe(domSignature(base, withAuth));
    });
  });

  /**
   * Counting is not reading. A count answers "has something arrived", and the signature has to answer "is
   * this the same evidence" — `invoice.pdf` becoming `invoice.exe` keeps the attachment count at one while
   * turning a score of 0 into a score of 75, and a rewritten href or an edited sentence of the same length
   * does the same for the link and content rules. Each of these is a stale verdict left standing behind a
   * signature that claims nothing has changed.
   */
  describe('evidence that changed without changing shape', () => {
    const base = handle('m1', 't1');

    const attachment = (filename: string, extension: string): EmailMessage =>
      email({ attachments: [{ filename, extension }] });

    it('changes when an attachment becomes an executable', () => {
      expect(domSignature(base, attachment('invoice.exe', 'exe'))).not.toBe(
        domSignature(base, attachment('invoice.pdf', 'pdf')),
      );
    });

    it('changes when a link points somewhere else', () => {
      const to = (href: string): EmailMessage =>
        email({ links: [{ text: 'Sign in', href, normalizedDomain: new URL(href).hostname }] });

      expect(domSignature(base, to('https://accounts.example/login'))).not.toBe(
        domSignature(base, to('https://accounts.example.attacker.test/login')),
      );
    });

    it('changes when anchor text is rewritten under the same href', () => {
      const anchor = (text: string): EmailMessage =>
        email({
          links: [{ text, href: 'https://redirect.example/c/1', normalizedDomain: 'redirect.example' }],
        });

      expect(domSignature(base, anchor('paypal.com'))).not.toBe(domSignature(base, anchor('Read more')));
    });

    it('changes when the body is edited to the same length', () => {
      expect(domSignature(base, email({ bodyText: 'Send the invoice' }))).not.toBe(
        domSignature(base, email({ bodyText: 'Send the payment' })),
      );
    });

    it('changes when the display name changes under the same address', () => {
      expect(domSignature(base, email({ senderName: 'Microsoft Account Team' }))).not.toBe(
        domSignature(base, email({ senderName: 'Accounts Payable' })),
      );
    });

    it('changes when the conversation above the message does', () => {
      const alone = email();
      const inThread = email({
        thread: { priorSenders: [{ email: 'other@example.com', name: 'Dana' }] },
      });

      expect(domSignature(base, inThread)).not.toBe(domSignature(base, alone));
    });

    it('changes when a concealment technique is found that was not there before', () => {
      expect(
        domSignature(base, email({ hiddenText: { chars: 800, techniques: ['display:none'] } })),
      ).not.toBe(domSignature(base, email({ hiddenText: { chars: 800, techniques: ['font-size:0'] } })));
    });

    it('changes when the unnormalised spelling of an address changes', () => {
      // Read only by the formatting detectors, and `DoNoT.rEpLy` is itself the evidence.
      expect(
        domSignature(base, email({ raw: { senderEmail: 'DoNoT.rEpLy@example.com' } })),
      ).not.toBe(domSignature(base, email({ raw: { senderEmail: 'donotreply@example.com' } })));
    });
  });
});
