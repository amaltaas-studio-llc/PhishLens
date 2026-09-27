/**
 * @vitest-environment jsdom
 *
 * The content script's orchestration, driven the way Gmail and Chrome drive it.
 *
 * Everything here is about *timing*, which is why it needs the real Controller rather than a test of one
 * of its parts: the observer, the model round trip and a settings write all arrive asynchronously and out
 * of order, and every failure in that space is silent. A verdict from work nobody wanted any more is
 * indistinguishable, on screen, from a verdict that is correct.
 *
 * The model runs through `aiMode: 'server'`, whose round trip is a message to the service worker. That
 * makes the inference a promise this file resolves by hand — which is the whole point, since the bug being
 * asserted lives in the window between asking a model something and no longer wanting the answer.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { Controller } from '../src/content/controller.js';
import type { Extraction, MailAdapter, MessageHandle } from '../src/gmail/adapter.js';
import type { ExtensionRequest, TabResponse, TabStatus } from '../src/shared/messaging.js';
import { DEFAULT_SETTINGS } from '../src/shared/settings.js';
import type { EmailMessage, SemanticAnalysis, Settings } from '../src/shared/types.js';

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

const THREAD_HASH = '#inbox/FMfcgzQhWLMhlXGCZNdTpfpfWQXRPjNz';

const EMAIL: EmailMessage = {
  senderName: 'Northwind Logistics',
  senderEmail: 'notifications@northwind-logistics.com',
  recipientEmail: 'reader@northwind-logistics.com',
  subject: 'Your delivery is scheduled',
  bodyText: 'Your consignment leaves the depot on Tuesday morning.',
  links: [],
  attachments: [],
};

/** A message-shaped tree, because the badge attaches to a real element and the card reads a real body. */
function drawMessage(): { root: Element; header: Element; body: Element } {
  const root = document.createElement('div');
  root.setAttribute('data-message-id', 'msg-18f2a0c');
  const header = document.createElement('div');
  const body = document.createElement('div');
  body.append(document.createTextNode(EMAIL.bodyText));
  root.append(header, body);
  document.body.append(root);
  return { root, header, body };
}

class FakeAdapter implements MailAdapter {
  readonly id = 'fake';
  #tree = drawMessage();

  /**
   * Gmail redrawing the message header from the same data, which is routine and which takes the injected
   * badge with it. Everything the extraction reads is unchanged, so nothing in the message says so.
   */
  replaceHeader(): void {
    const header = document.createElement('div');
    this.#tree.root.replaceChild(header, this.#tree.header);
    this.#tree = { ...this.#tree, header };
  }

  observationRoot(): Element | null {
    return document.body;
  }

  accountAddress(): string {
    return EMAIL.recipientEmail ?? '';
  }

  routeThreadId(): string {
    const segments = window.location.hash.replace(/^#/u, '').split('/');
    const last = segments[segments.length - 1] ?? '';
    return /^[A-Za-z0-9_-]{16,}$/u.test(last) ? last : '';
  }

  currentMessage(): MessageHandle | null {
    if (this.routeThreadId() === '') return null;
    return {
      messageId: 'msg-18f2a0c',
      threadId: 'thread-f:1798',
      priorSenders: [],
      headerElement: this.#tree.header,
      bodyElement: this.#tree.body,
      root: this.#tree.root,
    };
  }

  extract(): Extraction {
    return { email: EMAIL, missing: [] };
  }
}

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

interface PendingInference {
  resolve: (analysis: SemanticAnalysis | null) => void;
}

let stored: Settings;
let inferences: PendingInference[];
let storageListeners: ((changes: Record<string, unknown>, area: string) => void)[];
let tabListeners: ((
  message: unknown,
  sender: chrome.runtime.MessageSender,
  respond: (response: TabResponse) => void,
) => boolean)[];

function settings(over: Partial<Settings> = {}): Settings {
  return {
    ...DEFAULT_SETTINGS,
    aiMode: 'server',
    modelBaseUrl: 'http://127.0.0.1:11434/v1',
    modelName: 'northwind-small',
    ...over,
  };
}

function semantic(over: Partial<SemanticAnalysis> = {}): SemanticAnalysis {
  return {
    risk: 40,
    categories: ['unusual_request'],
    reasons: ['The message asks for an unusual action.'],
    confidence: 0.6,
    source: 'server',
    ...over,
  };
}

function installChrome(): void {
  const runtime = {
    id: 'phishlens-test',
    onMessage: {
      addListener: (listener: (typeof tabListeners)[number]) => {
        tabListeners.push(listener);
      },
      removeListener: () => undefined,
    },
    sendMessage: (request: ExtensionRequest): Promise<unknown> => {
      if (request.type === 'GET_SETTINGS') {
        return Promise.resolve({ ok: true, type: 'SETTINGS', settings: stored });
      }
      if (request.type === 'MODEL_SERVER_ANALYZE') {
        return new Promise((resolve) => {
          inferences.push({
            resolve: (analysis) => {
              resolve({ ok: true, type: 'SEMANTIC', analysis });
            },
          });
        });
      }
      return Promise.resolve(null);
    },
  };

  Object.defineProperty(globalThis, 'chrome', {
    value: {
      runtime,
      storage: {
        onChanged: {
          addListener: (listener: (typeof storageListeners)[number]) => {
            storageListeners.push(listener);
          },
          removeListener: () => undefined,
        },
      },
    },
    configurable: true,
    writable: true,
  });
}

/** What Chrome does when the options page writes a setting. */
function writeSettings(next: Settings): void {
  stored = next;
  for (const listener of storageListeners) listener({}, 'sync');
}

/** What the toolbar popup asks, through the listener the controller registers for it. */
function tabStatus(): TabStatus | null {
  const answers: TabResponse[] = [];
  for (const listener of tabListeners) {
    listener({ type: 'GET_TAB_STATUS' }, { id: 'phishlens-test' }, (response) => {
      answers.push(response);
    });
  }
  const answer = answers[0];
  if (answer === undefined || !answer.ok || answer.type !== 'TAB_STATUS') return null;
  return answer.status;
}

/** Lets every queued promise settle without advancing the clock. */
async function flush(): Promise<void> {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
}

// ---------------------------------------------------------------------------

let controller: Controller;
let adapter: FakeAdapter;

function badgeIsOnScreen(): boolean {
  return document.querySelector('#phishlens-badge-host') !== null;
}

beforeEach(async () => {
  vi.useFakeTimers();
  document.body.replaceChildren();
  window.location.hash = THREAD_HASH;
  stored = settings();
  inferences = [];
  storageListeners = [];
  tabListeners = [];
  installChrome();

  adapter = new FakeAdapter();
  controller = new Controller(adapter);
  await controller.start();
  // The observer's debounce, then the deterministic pass, then the model being asked.
  await vi.advanceTimersByTimeAsync(500);
  await flush();
});

afterEach(() => {
  controller.stop();
  vi.useRealTimers();
});

describe('a message opened with a model configured', () => {
  it('shows the deterministic verdict and asks the model once', () => {
    expect(inferences).toHaveLength(1);
    expect(tabStatus()).toMatchObject({ kind: 'scored', semantic: 'pending' });
  });

  it('applies the model’s answer when it arrives', async () => {
    inferences[0]?.resolve(semantic());
    await flush();

    expect(tabStatus()).toMatchObject({ kind: 'scored', semantic: 'ready' });
  });

  /**
   * A header Gmail has redrawn from the same data takes the badge with it, and says nothing about it: every
   * byte the extraction reads is identical, so the view signature matches and the event that would put the
   * badge back was suppressed as redundant. The message then spent the rest of its time on screen with no
   * badge — and on a `showBadgeWhenLow: false` install, no badge is also what a clean message looks like.
   *
   * The verdict must come back from the cache rather than from the model. Redrawing a header is not new
   * evidence, and a round trip per redraw would be one per scroll on a slow connection.
   */
  it('puts the badge back when Gmail redraws the header, without asking the model again', async () => {
    inferences[0]?.resolve(semantic());
    await flush();
    expect(badgeIsOnScreen()).toBe(true);

    adapter.replaceHeader();
    expect(badgeIsOnScreen()).toBe(false);

    await vi.advanceTimersByTimeAsync(500);
    await flush();

    expect(badgeIsOnScreen()).toBe(true);
    expect(inferences).toHaveLength(1);
    expect(tabStatus()).toMatchObject({ kind: 'scored', semantic: 'ready' });
  });
});

/**
 * Changing which model is asked invalidates every cached verdict, and the clear alone was not enough: an
 * inference already in flight belongs to the settings that have just been replaced. Its answer arrived
 * after the cache was emptied, wrote itself back in, and the re-evaluation that the same settings change
 * had asked for then read it as a cache hit — so the reader who changed the model watched the previous
 * model's verdict reappear, with nothing short of a tab reload able to shift it.
 */
describe('when a settings change supersedes work in flight', () => {
  it('asks the new model instead of caching the old one’s answer', async () => {
    writeSettings(settings({ modelName: 'northwind-large' }));
    await flush();

    // The answer to the question nobody is waiting for any more.
    inferences[0]?.resolve(semantic({ risk: 90 }));
    await flush();
    await vi.advanceTimersByTimeAsync(500);
    await flush();

    expect(inferences).toHaveLength(2);
  });

  it('shows no verdict from the superseded model while the new one is being asked', async () => {
    writeSettings(settings({ modelName: 'northwind-large' }));
    await flush();

    inferences[0]?.resolve(semantic({ risk: 90 }));
    await flush();
    await vi.advanceTimersByTimeAsync(500);
    await flush();

    expect(tabStatus()).toMatchObject({ semantic: 'pending' });
  });

  /**
   * The same for the trust list, which is the one a reader is most likely to change while an inference is
   * running: the button that adds an entry sits on the card of the message being analysed.
   */
  it('re-analyses after a trust change made mid-inference', async () => {
    writeSettings(settings({ trustedSenders: ['northwind-logistics.com'] }));
    await flush();

    inferences[0]?.resolve(semantic({ risk: 90 }));
    await flush();
    await vi.advanceTimersByTimeAsync(500);
    await flush();

    expect(inferences).toHaveLength(2);
  });

  /** A presentation-only change must not throw the inference away; nothing about the verdict has moved. */
  it('leaves the inference alone when only the presentation changed', async () => {
    writeSettings(settings({ showBadgeWhenLow: false }));
    await flush();

    inferences[0]?.resolve(semantic());
    await flush();

    expect(inferences).toHaveLength(1);
    expect(tabStatus()).toMatchObject({ semantic: 'ready' });
  });
});
