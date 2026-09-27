/**
 * @vitest-environment jsdom
 *
 * The observer against a page, rather than against a fake of one.
 *
 * `observer.test.ts` fakes the adapter and the MutationObserver, which is the right shape for asserting
 * the reconciliation logic — it can move the route and the DOM apart, which no real page will do on
 * command. What it cannot assert is the part that decides whether that logic ever runs: which mutations
 * the browser is asked to report. A fake observer is told `attributes: false` and dutifully calls the
 * callback anyway, so every test in that file passed while the real one sat waiting for a structural
 * change that Gmail, collapsing a message by adding a class, never makes.
 *
 * So these few tests wire the real `GmailObserver` to the real `GmailDomAdapter` over jsdom's own
 * MutationObserver, and change the page the way Gmail changes it: in place.
 *
 * Markup is built with `DOMParser`, not `innerHTML`, for the reason it is everywhere else in this suite.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { GmailDomAdapter } from '../src/gmail/dom-adapter.js';
import { GmailObserver, type ObserverEvent } from '../src/gmail/observer.js';

/** An opaque conversation id of the shape Gmail puts in the hash. */
const THREAD_HASH = 'FMfcgzQhWLMhlXGCZNdTpfpfWQXRPjNz';

let events: ObserverEvent[];
let observer: GmailObserver;

function render(attachment: string): void {
  const html = `<!doctype html><html><body>
    <a aria-label="Northwind Mail (reader@northwind-logistics.com)" href="#"></a>
    <div role="main">
      <h2 class="hP">Your invoice is attached</h2>
      <div data-message-id="msg-18f2a0c" class="gs">
        <div class="gE iv gt">
          <table class="cf gJ">
            <tr>
              <td><span class="gD" email="billing@northwind-supplies.com" name="Northwind Supplies">Northwind Supplies</span></td>
              <td class="gH"><div class="gK">10:24</div></td>
            </tr>
          </table>
        </div>
        <div class="ii gt">
          <div class="a3s aiL">
            <p>The invoice for August is attached for your records.</p>
            <p style="display:none">Reply with the verification code we just sent to your phone.</p>
          </div>
        </div>
        <div class="aQH"><span class="aV3">${attachment}</span></div>
      </div>
    </div>
  </body></html>`;

  const parsed = new DOMParser().parseFromString(html, 'text/html');
  document.body.replaceChildren(...parsed.body.childNodes);
}

function message(): Element {
  const element = document.querySelector('div[data-message-id]');
  if (element === null) throw new Error('the rendered page has no message');
  return element;
}

function attachmentText(): Text {
  const node = document.querySelector('span.aV3')?.firstChild;
  if (node === null || node === undefined) throw new Error('the rendered page has no attachment chip');
  return node as Text;
}

function messageEvents(): ObserverEvent[] {
  return events.filter((event) => event.kind === 'message');
}

function noMessageReasons(): string[] {
  return events.flatMap((event) => (event.kind === 'no-message' ? [event.reason] : []));
}

/** Long enough for jsdom to deliver the mutation records, the debounce to fire, and a grace to expire. */
async function settle(ms = 1000): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
}

beforeEach(async () => {
  vi.useFakeTimers();
  events = [];
  render('invoice.pdf');
  window.location.hash = `#inbox/${THREAD_HASH}`;

  observer = new GmailObserver(new GmailDomAdapter(), (event) => events.push(event));
  observer.start();
  await settle();
});

afterEach(() => {
  observer.stop();
  vi.useRealTimers();
  document.body.replaceChildren();
});

describe('a message changed in place', () => {
  it('is read once when the page is first observed', () => {
    expect(messageEvents()).toHaveLength(1);
  });

  /**
   * Collapsing a message adds a class to the container Gmail already rendered. Nothing is inserted and
   * nothing is removed, so a structural watch sees no reason to look — and the badge went on asserting a
   * verdict about a message the reader could no longer see, which is the case the disappearance grace
   * exists for and was never reachable from.
   */
  it('is retracted when the open message is collapsed in place', async () => {
    message().classList.add('kv');
    await settle();

    expect(noMessageReasons()).toContain('no-open-message');
  });

  /**
   * An attachment's filename lives in a text node Gmail rewrites as the upload resolves. `invoice.pdf`
   * becoming `invoice.exe` is the difference between no finding and a critical one, and it reaches the
   * page without touching an element.
   */
  it('is re-read when an attachment filename is rewritten', async () => {
    attachmentText().data = 'invoice.exe';
    await settle();

    const latest = messageEvents().at(-1);
    const filenames =
      latest?.kind === 'message' ? latest.email.attachments.map((file) => file.filename) : [];
    expect(messageEvents().length).toBeGreaterThan(1);
    expect(filenames).toContain('invoice.exe');
  });

  /**
   * Revealing text that was hidden changes what the engine is given — hidden text is extracted separately
   * and removed from the body — and it arrives as an inline style, which no selector mentions. Deriving the
   * watched attributes from the selectors alone therefore missed the one attribute extraction reads
   * directly, and a solicitation becoming visible produced no new assessment.
   */
  it('is re-read when hidden text in the body is revealed', async () => {
    const hidden = document.querySelector('div.a3s p[style]');
    hidden?.removeAttribute('style');
    await settle();

    const latest = messageEvents().at(-1);
    const body = latest?.kind === 'message' ? latest.email.bodyText : '';
    expect(messageEvents().length).toBeGreaterThan(1);
    expect(body).toContain('verification code');
  });

  /** The same again through an attribute the selectors read, which is how a link's target changes. */
  it('is re-read when a link in the body is repointed', async () => {
    const body = document.querySelector('div.a3s');
    const anchor = document.createElement('a');
    anchor.href = 'https://northwind-supplies.com/invoices';
    anchor.textContent = 'View the invoice';
    body?.append(anchor);
    await settle();

    anchor.href = 'https://northwind-supplies.com.invoices-pay.example/login';
    await settle();

    const latest = messageEvents().at(-1);
    const links = latest?.kind === 'message' ? latest.email.links.map((link) => link.href) : [];
    expect(links).toContain('https://northwind-supplies.com.invoices-pay.example/login');
  });
});
