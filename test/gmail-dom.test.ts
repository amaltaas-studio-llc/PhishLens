/**
 * @vitest-environment jsdom
 *
 * The adapter against markup, rather than around it.
 *
 * Everything else in this suite runs in plain Node, and for the detection engine that is a feature: the
 * rules are pure, so they need no DOM and the suite stays fast enough to run on every save. But it left
 * `src/gmail/` — the layer that decides whether any of it happens at all — asserted only through helpers
 * reached via `__testables`. Two bugs walked straight through that gap:
 *
 *  - The trust gate required a named `dkim: pass`, which is only ever scraped from a tooltip most Gmail
 *    builds do not render. Every fixture supplies `auth` as a JSON block, so nothing noticed that the
 *    condition was unsatisfiable against what `extractAuth` can actually read. The feature was
 *    unreachable in production and green in CI.
 *  - `extractBody` strips quoted replies and `extractLinks` did not, because no test ever ran both over
 *    one tree. (They still disagree, now on purpose and asserted here: see "quoted content".)
 *
 * **What these tests do and do not prove.** They prove the adapter's logic: that a details table becomes
 * an `EmailAuthInfo`, that a quoted reply is excluded, that an unread part is reported as unread rather
 * than silently dropped. They do *not* prove the selectors still match Gmail, because the markup here was
 * written from the same table the code reads. Nothing in a repository can prove that — it needs the live
 * product, which is what `src/content/health.ts` and the copied diagnostic are for. The structures below
 * follow a real session diagnostic (`table.cf.gJ` for the details table, `span[email]` for the sender)
 * rather than being invented, so they are at least a record of markup that existed.
 *
 * Markup is built with `DOMParser`, not `innerHTML`: the ban on parsing HTML applies here too, and a test
 * suite is a strange place to make the one exception.
 *
 * Keep the markup *valid*. An HTML parser silently discards a `<td>` that is not inside a row, so invalid
 * fixture markup does not fail — it quietly tests a different tree than the one written here.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { analyzeDeterministic } from '../src/analysis/engine.js';
import { loadFixture } from './fixtures/load.js';

import { isScorable } from '../src/gmail/adapter.js';
import { GmailDomAdapter } from '../src/gmail/dom-adapter.js';
import { isSenderProven } from '../src/shared/trust.js';

// ---------------------------------------------------------------------------
// A Gmail-shaped page
// ---------------------------------------------------------------------------

interface PageOptions {
  /** The `mailed-by` / `signed-by` rows Gmail renders in the details table. */
  details?: Record<string, string>;
  /** Anchors in the body, as `[text, href]`. */
  links?: [string, string][];
  /** Body content quoted from an earlier message, which analysis must not read. */
  quoted?: string;
  attachments?: string[];
  senderName?: string;
  senderEmail?: string;
  subject?: string;
  body?: string;
  /** Markup for the body, for the cases where its *structure* is what is being asserted. */
  bodyHtml?: string;
  /** Gmail's own red banner, or an unrelated live region, depending on what is being asserted. */
  banner?: { text: string; role: 'warning' | 'unrelated' };
}

const DEFAULTS = {
  senderName: 'Northwind Logistics',
  senderEmail: 'notifications@northwind-logistics.com',
  subject: 'Your delivery is scheduled',
  body: 'Your consignment leaves the depot on Tuesday morning.',
};

function render(options: PageOptions = {}): void {
  const o = { ...DEFAULTS, ...options };

  const detailRows = Object.entries(o.details ?? {})
    .map(([label, value]) => `<tr><td class="gL">${label}:</td><td class="gM">${value}</td></tr>`)
    .join('');

  const anchors = (o.links ?? [])
    .map(([text, href]) => `<a href="${href}">${text}</a>`)
    .join(' ');

  const chips = (o.attachments ?? [])
    .map((filename) => `<span class="aV3">${filename}</span>`)
    .join('');

  // Both forms go *inside* the message, which is the only place `extractAuth` looks — and which the first
  // candidate for the group (`.gJ .aiG`) already implies, since `.gJ` is part of the message header. An
  // unrelated live region placed on the page outside the message would make the negative case pass for
  // the wrong reason: nothing would have been found, rather than found and judged not to be a verdict.
  const banner =
    o.banner === undefined
      ? ''
      : o.banner.role === 'warning'
        ? `<div class="gJ"><div class="aiG">${o.banner.text}</div></div>`
        : `<div role="alert">${o.banner.text}</div>`;

  // `.hP` for the subject and `div[role="main"]` for the conversation root are the page-level structures;
  // everything inside `div[data-message-id]` is the message the adapter reads.
  const html = `<!doctype html><html><body>
    <a aria-label="Northwind Mail (reader@northwind-logistics.com)" href="#"></a>
    <div role="main">
      <h2 class="hP">${o.subject}</h2>
      <div data-message-id="msg-18f2a0c" class="gs">
        ${banner}
        <div class="gE iv gt">
          <table class="cf gJ">
            <tr>
              <td><span class="gD" email="${o.senderEmail}" name="${o.senderName}">${o.senderName}</span></td>
              <td class="gH"><div class="gK">10:24</div></td>
            </tr>
            ${detailRows}
          </table>
        </div>
        <div class="ii gt">
          <div class="a3s aiL">
            ${o.bodyHtml ?? `<p>${o.body}</p>`}
            ${anchors}
            ${o.quoted === undefined ? '' : `<blockquote class="gmail_quote">${o.quoted}</blockquote>`}
          </div>
        </div>
        <div class="aQH">${chips}</div>
      </div>
    </div>
  </body></html>`;

  const parsed = new DOMParser().parseFromString(html, 'text/html');
  document.body.replaceChildren(...parsed.body.childNodes);
}

/** Extraction of whatever `render` last drew, or a failure that says which step gave up. */
function extract(): ReturnType<GmailDomAdapter['extract']> {
  const adapter = new GmailDomAdapter();
  const handle = adapter.currentMessage();
  if (handle === null) throw new Error('currentMessage() found no message in the rendered page');
  return adapter.extract(handle);
}

beforeEach(() => {
  document.body.replaceChildren();
});

// ---------------------------------------------------------------------------

describe('reading an ordinary message out of the page', () => {
  it('reads the sender, subject and body', () => {
    render();
    const { email } = extract();

    expect(email.senderEmail).toBe('notifications@northwind-logistics.com');
    expect(email.senderName).toBe('Northwind Logistics');
    expect(email.subject).toBe('Your delivery is scheduled');
    expect(email.bodyText).toContain('leaves the depot on Tuesday');
  });

  it('reads links with the href as written, not as the document would resolve it', () => {
    render({ links: [['Track your parcel', 'https://track.northwind-logistics.com/c/9f2a']] });
    const { email } = extract();

    expect(email.links).toHaveLength(1);
    expect(email.links[0]?.href).toBe('https://track.northwind-logistics.com/c/9f2a');
    expect(email.links[0]?.text).toBe('Track your parcel');
  });

  /**
   * A genuine reply: what was written is read, and what it quotes is not read as its wording. Its links
   * are read regardless — which block is "quoted" is decided by a class the sender can write, and a link
   * kept out of the analysis by one is still on screen to be clicked.
   */
  it('reads a reply’s own words, and every link including the ones it quotes', () => {
    render({
      body: 'Is this genuine? I have not clicked anything.',
      links: [['our usual portal', 'https://portal.northwind-logistics.com/login']],
      quoted:
        'From: security@northwind-alerts.example<br><a href="https://northwind-alerts.example/verify">Verify your account now</a>',
    });

    const { email, missing } = extract();
    expect(email.bodyText).toContain('Is this genuine?');
    expect(email.bodyText).not.toContain('Verify your account');
    expect(email.links.map((l) => l.href)).toEqual([
      'https://portal.northwind-logistics.com/login',
      'https://northwind-alerts.example/verify',
    ]);
    expect(missing).toEqual([]);
  });

  /**
   * `textContent` joins text nodes exactly, so a footer of two cells reads `policyunsubscribe` and every
   * rule anchored on a word boundary misses both words — the bulk-mail test among them, which is what
   * stops a newsletter's wording being read as a scam. Inline markup must not split a word the same way.
   */
  it('keeps apart text that renders on separate lines, and together text that renders as one word', () => {
    render({
      bodyHtml:
        '<table><tr><td>Privacy policy</td><td>Unsubscribe</td></tr></table>' +
        '<div>Total</div><div>Delivered</div>Line one<br>line two <p>Con<b>sign</b>ment</p>',
    });
    const { bodyText } = extract().email;

    expect(bodyText).toMatch(/policy\s+Unsubscribe/u);
    expect(bodyText).toMatch(/Total\s+Delivered/u);
    expect(bodyText).toMatch(/one\s+line two/u);
    expect(bodyText).toContain('Consignment');
  });

  it('reads attachment filenames from the footer chips', () => {
    render({ attachments: ['Consignment_4471.pdf'] });
    expect(extract().email.attachments.map((a) => a.extension)).toEqual(['pdf']);
  });

  /**
   * The badge has to land somewhere. Every candidate is a placement rather than a requirement, so the
   * assertion is not *which* element wins but that the search degrades: with the timestamp cluster gone,
   * a worse position inside the header is found, and the message is still annotated.
   */
  it('finds somewhere in the header to attach the badge, and keeps finding one as candidates vanish', () => {
    render();
    const preferred = new GmailDomAdapter().currentMessage()?.headerElement;
    expect(preferred?.className).toContain('gK');

    document.querySelector('td.gH')?.remove();
    const fallback = new GmailDomAdapter().currentMessage()?.headerElement;
    expect(fallback).not.toBeNull();
    expect(fallback?.className).toContain('gE');
  });

  /**
   * A container of `font-size:0` around a newsletter, which is how bulk mail collapses the whitespace
   * between its tags while every paragraph inside names its own size. Removing the subtree took the whole
   * body with it, and an empty body is not reported as a missing part — the element was there — so the
   * message was scored on its subject and sender alone with nothing on the card to say what had happened.
   */
  it('keeps body text whose container sets a zero font size its contents override', () => {
    render({
      bodyHtml: `<table><tr><td style="direction:ltr;font-size:0;padding:4px 8px">
        <p style="font-size:14px">Your consignment leaves the depot on Tuesday morning.</p>
      </td></tr></table>`,
    });

    const { email, missing } = extract();
    expect(email.bodyText).toContain('leaves the depot on Tuesday');
    expect(email.hiddenText).toBeUndefined();
    expect(missing).toEqual([]);
  });

  /**
   * The same failure reached from the other side. Reading an inline style cannot be exact, so the guarantee
   * is not that the scan is always right but that being wrong is *said*: a body read to nothing is reported
   * as a part that could not be read, which stops the message being scored as though its wording had been
   * examined and found unremarkable. Substituting the text that was removed would be the worse fix, because
   * Gmail renders a body hidden while it is still building the view and every such message would be accused
   * of concealing all of its words.
   */
  it('reports a body it has read to nothing as unread rather than scoring an empty one', () => {
    render({
      bodyHtml: `<div style="display:none">
        <p>Your consignment leaves the depot on Tuesday morning.</p>
        <a href="https://track.northwind-logistics.com/c/9f2a">Track your parcel</a>
      </div>`,
    });

    const { email, missing } = extract();
    expect(email.bodyText).toBe('');
    // The shape that made this worth reporting: links to judge, and no wording to judge them against.
    expect(email.links).toHaveLength(1);
    expect(email.hiddenText?.techniques).toEqual(['display:none']);
    expect(missing).toContain('body');
    expect(isScorable(missing)).toBe(false);
  });

  it('reports nothing missing, so the message is scorable', () => {
    render();
    const { missing } = extract();

    expect(missing).toEqual([]);
    expect(isScorable(missing)).toBe(true);
  });

  /** Filler beside a paragraph that sets its own size: the paragraph is read, the filler is not. */
  it('keeps an overriding paragraph in the body and counts the filler around it as hidden', () => {
    const filler = 'Pellentesque habitant morbi tristique senectus et netus. '.repeat(4);
    render({
      bodyHtml: `<div style="font-size:0">${filler}<p style="font-size:14px">Your consignment leaves the depot on Tuesday morning.</p></div>`,
    });

    const { email, missing } = extract();
    expect(email.bodyText).toContain('leaves the depot on Tuesday');
    expect(email.bodyText).not.toContain('Pellentesque');
    expect(email.hiddenText?.techniques).toEqual(['font-size:0']);
    expect(email.hiddenText?.chars).toBeGreaterThan(100);
    expect(missing).toEqual([]);
  });
});

/**
 * Quoted content, which is removed from the body text and nothing else.
 *
 * The selectors that find it are matched against markup inside the message, and the sender writes some of
 * that markup. So the property asserted is not that a quote is always recognised correctly, but that
 * recognising one wrongly can cost wording at most — never the whole message, and never its links.
 */
describe('quoted content', () => {
  /**
   * Gmail prefixes a sender's classes, so `pull-quote` arrives as `m_42pull-quote` — which a substring
   * match on "quote" still found. Wrapping a whole message in one emptied its body, the observer read the
   * empty message as one still loading, and it was never assessed at all: no score and no badge.
   */
  it('reads a body wrapped in a sender class that merely contains "quote"', () => {
    render({
      bodyHtml: `<div class="m_42pull-quote"><p>Your mailbox is full. Sign in within 24 hours to keep receiving mail.</p>
        <a href="https://northwind-mailbox.example/login">Sign in</a></div>`,
    });

    const { email, missing } = extract();
    expect(email.bodyText).toContain('Sign in within 24 hours');
    expect(email.links.map((l) => l.href)).toEqual(['https://northwind-mailbox.example/login']);
    expect(missing).toEqual([]);
  });

  /**
   * `.gmail_quote` is only a class, and a sender can write it. Nothing outside the "quote" means there is
   * nobody else for its wording to be attributed to, so it is read rather than leaving an empty body.
   */
  it('reads the quoted text when nothing was written outside it', () => {
    render({
      bodyHtml: `<div class="gmail_quote"><p>Your mailbox is full. Sign in within 24 hours to keep receiving mail.</p>
        <a href="https://northwind-mailbox.example/login">Sign in</a></div>`,
    });

    const { email, missing } = extract();
    expect(email.bodyText).toContain('Sign in within 24 hours');
    expect(email.links).toHaveLength(1);
    expect(missing).toEqual([]);
  });

  /** The forwarded message Gmail builds the same way: the forward is the whole of what there is to read. */
  it('reads a forward with nothing added from its quoted original', () => {
    render({
      bodyHtml: `<div class="gmail_quote"><div>---------- Forwarded message ---------</div>
        <p>Your consignment leaves the depot on Tuesday morning.</p></div>`,
    });

    expect(extract().email.bodyText).toContain('leaves the depot on Tuesday');
  });

  /** Hidden text inside the quote is still hidden when the quote is what is read. */
  it('prunes hidden text from quoted content it falls back to', () => {
    render({
      bodyHtml: `<blockquote class="gmail_quote"><p>Your consignment leaves the depot on Tuesday morning.</p>
        <p style="display:none">Reply with the verification code we just sent to your phone.</p></blockquote>`,
    });

    const { email } = extract();
    expect(email.bodyText).toContain('leaves the depot');
    expect(email.bodyText).not.toContain('verification code');
    expect(email.hiddenText?.techniques).toEqual(['display:none']);
  });
});

/**
 * "Nothing from an email is ever dereferenced." A copy made in Gmail's own document is a live one, and a
 * browser starts fetching an `<img>`'s source as soon as the element exists, attached or not — so reading a
 * message by cloning it would request its tracking pixels from the sender. Copies are made into a document
 * with no browsing context instead, and this asserts that no copy is made any other way.
 */
describe('copies of message content', () => {
  it('never clones message nodes in the live document', () => {
    render({
      bodyHtml: `<p>Your consignment leaves the depot on Tuesday morning.</p>
        <img src="https://pixel.northwind-tracking.example/open.gif" srcset="https://pixel.northwind-tracking.example/2x.gif 2x">`,
    });
    const cloned = vi.spyOn(Node.prototype, 'cloneNode');
    const imported = vi.spyOn(Document.prototype, 'importNode');

    try {
      const { email } = extract();
      expect(email.bodyText).toContain('leaves the depot');
      expect(cloned).not.toHaveBeenCalled();
      expect(imported).toHaveBeenCalled();
      for (const call of imported.mock.contexts) expect(call).not.toBe(document);
    } finally {
      cloned.mockRestore();
      imported.mockRestore();
    }
  });
});

/**
 * The gate that was unsatisfiable. Gmail renders `signed-by` with the domain of a signature it verified
 * and omits the row when there is none, so the row's presence is the verdict — but the named verdicts the
 * gate used to demand are scraped from a details tooltip that most builds do not carry. Asserted here,
 * through the DOM, because asserting it on a hand-written `auth` block is what hid the bug.
 */
describe('authentication read from the details table', () => {
  it('reads mailed-by and signed-by as the domains they name', () => {
    render({
      details: {
        'mailed-by': 'bounce.northwind-logistics.com',
        'signed-by': 'northwind-logistics.com',
      },
    });

    const auth = extract().email.auth;
    expect(auth?.mailedBy).toBe('bounce.northwind-logistics.com');
    expect(auth?.signedBy).toBe('northwind-logistics.com');
  });

  it('proves the sender from an aligned signed-by row alone, with no verdict anywhere', () => {
    render({ details: { 'signed-by': 'northwind-logistics.com' } });

    const auth = extract().email.auth;
    expect(auth?.dkim).toBeUndefined();
    expect(auth?.dmarc).toBeUndefined();
    expect(isSenderProven(auth, 'northwind-logistics.com')).toBe(true);
  });

  it('does not prove a sender whose signature belongs to someone else', () => {
    render({
      senderEmail: 'billing@northwind-invoices.example',
      details: { 'signed-by': 'northwind-logistics.com' },
    });

    expect(isSenderProven(extract().email.auth, 'northwind-invoices.example')).toBe(false);
  });

  it('does not prove a sender from an envelope alone', () => {
    render({ details: { 'mailed-by': 'northwind-logistics.com' } });
    expect(isSenderProven(extract().email.auth, 'northwind-logistics.com')).toBe(false);
  });
});

describe('Gmail’s own warning banner', () => {
  it('reads a banner that is a verdict about the message', () => {
    render({
      banner: { text: 'This message seems dangerous. Similar messages were used to steal people’s personal information.', role: 'warning' },
    });

    expect(extract().email.auth?.gmailWarning).toBeDefined();
  });

  /**
   * The page always holds something with `role="alert"` — Gmail's live regions carry it — which is why
   * the last candidate in that selector group is safe only because the text is judged afterwards. If a
   * stray live region could become a warning, every message would carry Gmail's own verdict.
   */
  it('reads an unrelated live region as no warning at all', () => {
    render({ banner: { text: 'Conversation marked as read.', role: 'unrelated' } });
    expect(extract().email.auth?.gmailWarning).toBeUndefined();
  });
});

/**
 * Which message in a thread gets assessed, when the candidate selectors disagree about which element is
 * a message.
 *
 * Selection asks for the *last* expanded message the user did not write, and "last" only means anything if
 * the candidates are in the order they appear on screen. The union of a prioritised selector list is not:
 * it lists every match of the first candidate, then every match of the second, so a thread whose messages
 * are marked differently arrives in an order Gmail never rendered — and one message arrives repeatedly, at
 * each depth a candidate happened to match.
 *
 * Both failures pick the wrong element silently, which is the reason to assert them here: a badge appears
 * either way, carrying a verdict on a message the reader is not looking at.
 */
describe('choosing a message when the markup is inconsistent', () => {
  const ACCOUNT = '<a aria-label="Northwind Mail (reader@northwind-logistics.com)" href="#"></a>';

  function message(attributes: string, email: string, body: string): string {
    return `<div ${attributes}>
      <div class="gE iv gt">
        <table class="cf gJ"><tr>
          <td><span class="gD" email="${email}" name="Sender">Sender</span></td>
          <td class="gH"><div class="gK">10:24</div></td>
        </tr></table>
      </div>
      <div class="ii gt"><div class="a3s aiL"><p>${body}</p></div></div>
    </div>`;
  }

  function draw(markup: string): void {
    const html = `<!doctype html><html><body>${ACCOUNT}
      <div role="main"><h2 class="hP">Invoice 4471</h2>${markup}</div>
    </body></html>`;
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    document.body.replaceChildren(...parsed.body.childNodes);
  }

  /**
   * The earlier message is the one a lower-priority selector reaches, so selector order puts it last. The
   * reader is looking at the message below it.
   */
  it('assesses the lower message when the upper one matches a later selector', () => {
    draw(
      message('class="adn ads"', 'first@northwind-suppliers.example', 'The earlier message.') +
        message('data-message-id="msg-2"', 'second@northwind-invoices.example', 'The message on top.'),
    );

    expect(extract().email.senderEmail).toBe('second@northwind-invoices.example');
  });

  /**
   * One message, matched at two depths. Choosing the inner element loses everything outside it — here the
   * header, so the sender and the authentication summary — and the message still looks readable.
   */
  it('reads a message matched at two depths from its outermost element', () => {
    draw(`<div data-message-id="msg-3">
      <div class="gE iv gt">
        <table class="cf gJ">
          <tr>
            <td><span class="gD" email="billing@northwind-invoices.example" name="Billing">Billing</span></td>
            <td class="gH"><div class="gK">09:02</div></td>
          </tr>
          <tr><td class="gL">signed-by:</td><td class="gM">northwind-invoices.example</td></tr>
        </table>
      </div>
      <div class="gs"><div class="ii gt"><div class="a3s aiL"><p>The invoice is attached.</p></div></div></div>
    </div>`);

    const { email, missing } = extract();
    expect(email.senderEmail).toBe('billing@northwind-invoices.example');
    expect(email.auth?.signedBy).toBe('northwind-invoices.example');
    expect(missing).toEqual([]);
  });

  /**
   * The thread history, read from the same rows selection is made from — and it has to be the same rows,
   * or the assessed message cannot be located among them.
   *
   * Reading them separately, from the first candidate selector that matched anything, put the two at
   * different depths: a `.adn.ads` wrapper enclosing a `[data-message-id]` element is one message twice,
   * and selection keeps the wrapper while the history listed the rows inside. Locating the wrapper among
   * those rows failed, so the history came back empty — and an empty history is indistinguishable from an
   * ordinary one-message thread, which is to say every thread-hijack rule quietly stopped firing.
   */
  describe('the thread history behind the assessed message', () => {
    const FIRST = 'enquiries@northwind-suppliers.example';
    const ASSESSED = 'accounts@northwind-invoices.example';

    /** One message matched twice: by the wrapper Gmail puts around it, and by the row inside it. */
    function wrapped(id: string, email: string, body: string): string {
      return `<div class="adn ads">${message(`data-message-id="${id}"`, email, body)}</div>`;
    }

    it('reads the senders above it when the wrapper encloses the row', () => {
      draw(
        wrapped('msg-1', FIRST, 'Could you confirm the balance on this account?') +
          wrapped('msg-2', ASSESSED, 'Attached is the statement you asked for.'),
      );

      const handle = new GmailDomAdapter().currentMessage();
      expect(handle?.priorSenders.map((party) => party.email)).toEqual([FIRST]);
    });

    it('excludes the assessed message itself and anything below it', () => {
      draw(
        wrapped('msg-1', FIRST, 'Could you confirm the balance on this account?') +
          wrapped('msg-2', ASSESSED, 'Attached is the statement you asked for.') +
          // Collapsed, so selection stays on the message above it.
          `<div class="adn ads kv">${message('data-message-id="msg-3"', 'dispatch@northwind-couriers.example', 'Later in the thread.')}</div>`,
      );

      const addresses = new GmailDomAdapter()
        .currentMessage()
        ?.priorSenders.map((party) => party.email);
      expect(addresses).toEqual([FIRST]);
    });
  });
});

/**
 * The failure the project refuses to accept is a confident all-clear on a message nobody read. It is
 * worth asserting through the DOM as well as through the rule, because the interesting half is that the
 * adapter *notices*: a sender it could not parse has to arrive as an unread part rather than as an empty
 * string that scores like ordinary mail.
 */
describe('a message the page will not give up', () => {
  it('reports an unreadable sender as unread rather than as absent', () => {
    render({ senderEmail: '', senderName: '' });
    const { email, missing } = extract();

    expect(email.senderEmail ?? '').toBe('');
    expect(missing).toContain('sender');
    expect(isScorable(missing)).toBe(false);
  });
});


describe('visible clipping', () => {
  it.each(['visible-clipping-code-request', 'legitimate'])(
    'preserves visible content and its assessment: %s',
    (name) => {
      const { email: fixture } = loadFixture(name);
      render({
        senderName: fixture.senderName,
        senderEmail: fixture.senderEmail,
        subject: fixture.subject,
        bodyHtml: '<div style="position:absolute;clip:rect(0,400px,200px,0)"></div>',
      });
      document.querySelector('.a3s div')!.textContent = fixture.bodyText;
      const { email } = extract();
      expect(email.bodyText).toContain(fixture.bodyText);
      expect(email.hiddenText).toBeUndefined();
      const result = analyzeDeterministic(email);
      if (name === 'legitimate') {
        expect(result.classification).toBe('low');
        expect(result.signals.some((s) => s.severity === 'high' || s.severity === 'critical')).toBe(false);
      } else {
        expect(result.signals.some((s) => s.id === 'content.mfa_request')).toBe(true);
      }
    },
  );
});
