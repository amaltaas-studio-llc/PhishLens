/**
 * @vitest-environment jsdom
 *
 * Locating a finding's excerpt in the message, which runs on every hover and focus of a finding.
 *
 * The search used to read every element's full `textContent`, which re-reads everything beneath it: the
 * body's length times its depth, both of which the message chooses. These assert that the single-pass
 * search still finds the tightest element, that it gives up within its bounds rather than running on, and
 * that it treats quoted history the way extraction does.
 *
 * Markup is built with `DOMParser`, not `innerHTML`, as everywhere else in this suite.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import { Highlighter, findSmallestElementContaining } from '../src/ui/highlight.js';

function body(markup: string): Element {
  const parsed = new DOMParser().parseFromString(
    `<!doctype html><html><body><div class="a3s">${markup}</div></body></html>`,
    'text/html',
  );
  document.body.replaceChildren(...parsed.body.childNodes);
  const element = document.querySelector('div.a3s');
  if (element === null) throw new Error('the rendered page has no body');
  return element;
}

beforeEach(() => {
  document.body.replaceChildren();
});

describe('finding an excerpt in the message', () => {
  it('returns the deepest element holding the whole excerpt', () => {
    const root = body('<table><tr><td><p id="target">Verify your account within 24 hours.</p></td></tr></table>');
    expect(findSmallestElementContaining(root, 'verify your account within')?.id).toBe('target');
  });

  /** Evidence is captured collapsed and ellipsised; the page has neither. */
  it('matches across element boundaries and whitespace, ignoring case and ellipses', () => {
    const root = body('<p id="target">Your  <b>ACCOUNT</b>\n will be <i>suspended</i> today.</p>');
    expect(findSmallestElementContaining(root, '…your account will be suspended…')?.id).toBe('target');
  });

  /** Extraction breaks the body at blocks, so an excerpt may carry a space the text nodes do not. */
  it('matches an excerpt spanning two blocks, which the body text separates', () => {
    const cells = body('<table><tr id="row"><td>Privacy policy</td><td>Unsubscribe</td></tr></table>');
    expect(findSmallestElementContaining(cells, 'privacy policy unsubscribe')?.id).toBe('row');
    const lines = body('<p id="target">Your parcel is held<br>pending a customs fee.</p>');
    expect(findSmallestElementContaining(lines, 'is held pending a customs')?.id).toBe('target');
  });

  it('finds nothing for an excerpt that is not there', () => {
    const root = body('<p>Your consignment leaves the depot on Tuesday morning.</p>');
    expect(findSmallestElementContaining(root, 'reply with the verification code')).toBeNull();
  });

  /** A reply repeating a quoted sentence is highlighted where the reply says it, not in the quote. */
  it('prefers the text outside quoted history', () => {
    const root = body(
      '<p id="reply">Did you really mean: confirm your payment details?</p>' +
        '<div class="gmail_quote"><p id="quoted">Please confirm your payment details today.</p></div>',
    );
    expect(findSmallestElementContaining(root, 'confirm your payment details')?.id).toBe('reply');
  });

  /** Extraction reads the quotes when nothing was written outside them, so the excerpt can come from there. */
  it('looks inside quoted history when nothing outside it matches', () => {
    const root = body(
      '<p>Forwarding this.</p><div class="gmail_quote"><p id="quoted">Please confirm your payment details today.</p></div>',
    );
    expect(findSmallestElementContaining(root, 'confirm your payment details')?.id).toBe('quoted');
  });

  it('stays bounded on a body built to be enormous and deep', () => {
    let markup = '';
    for (let i = 0; i < 400; i++) markup += '<div>';
    markup += 'filler '.repeat(50);
    for (let i = 0; i < 400; i++) markup += '</div>';
    const root = body(`${markup}${'<span>filler text</span>'.repeat(8000)}<p>verify your account now</p>`);

    const started = Date.now();
    // Past the node bound, so not located, which costs a highlight and nothing else.
    expect(findSmallestElementContaining(root, 'verify your account now')).toBeNull();
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('the highlighter', () => {
  it('marks an anchor the evidence names, and removes every trace on clear', () => {
    const root = body('<p>Sign in <a id="link" href="https://northwind-mailbox.example/login">here</a>.</p>');
    const highlighter = new Highlighter();
    const shown = highlighter.show(
      {
        id: 'x',
        category: 'link',
        severity: 'medium',
        score: 10,
        title: 't',
        description: 'd',
        evidence: { url: 'https://northwind-mailbox.example/login' },
      },
      root,
    );

    expect(shown).toBe(true);
    expect(document.querySelector('#link')?.classList.contains('phishlens-highlight')).toBe(true);
    highlighter.dispose();
    expect(document.querySelector('#link')?.hasAttribute('class')).toBe(false);
  });
});
