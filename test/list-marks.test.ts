/**
 * @vitest-environment jsdom
 *
 * Markers on inbox rows, against markup rather than around it.
 *
 * The rules a row may use are asserted in `test/triage.test.ts`; what is asserted here is the half that
 * decides whether any of them run. A row remembers what it was marked for and is skipped while that is
 * unchanged, which is what keeps a constantly re-rendering list cheap — and is also the place where a
 * verdict can be lost permanently rather than merely delayed.
 *
 * Markup is built with `DOMParser`, not `innerHTML`, as everywhere else in this suite.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ListMarks } from '../src/content/list-marks.js';

const MARK = '.phishlens-row-mark';

/** An inbox of rows in Gmail's shape: the address in `email`, the display name in `name`. */
function render(rows: { email: string; name: string }[]): void {
  const markup = rows
    .map(
      ({ email, name }, index) => `<tr class="zA" id="row-${index}">
        <td class="yW"><span email="${email}" name="${name}">${name}</span></td>
        <td class="xY"><div class="y6"><span>A subject</span></div></td>
      </tr>`,
    )
    .join('');

  const parsed = new DOMParser().parseFromString(
    `<!doctype html><html><body><div role="main"><table>${markup}</table></div></body></html>`,
    'text/html',
  );
  document.body.replaceChildren(...parsed.body.childNodes);
}

/**
 * Where the marker is pointed: resolved on every call, the way the controller resolves it from the
 * adapter. Handing over a fixed element is what left the marker watching a region Gmail had replaced.
 */
function region(): Element {
  const root = document.querySelector('div[role="main"]');
  if (root === null) throw new Error('the rendered page has no main region');
  return root;
}

function marks(): string[] {
  return [...document.querySelectorAll(MARK)].map((mark) => mark.getAttribute('aria-label') ?? '');
}

/**
 * Past the 300 ms debounce. Microtasks are flushed first because a `MutationObserver` delivers its records
 * in one, and advancing a fake clock does not run them.
 */
async function settle(): Promise<void> {
  await Promise.resolve();
  vi.advanceTimersByTime(500);
  await Promise.resolve();
}

/**
 * Started markers, stopped after each test. A marker keeps asking for passes while it waits for the
 * account address, so one left running scans the *next* test's page — and with the root resolved afresh
 * each pass, it would find it.
 */
let markers: ListMarks[] = [];

function startMarking(readAccount: () => string): ListMarks {
  const marker = new ListMarks();
  markers.push(marker);
  marker.start(region, readAccount);
  return marker;
}

beforeEach(() => {
  vi.useFakeTimers();
  document.body.replaceChildren();
});

afterEach(() => {
  for (const marker of markers) marker.stop();
  markers = [];
  vi.useRealTimers();
});

describe('marking inbox rows', () => {
  it('marks a sender impersonating a known brand and leaves ordinary mail alone', async () => {
    render([
      { email: 'security@paypa1-alerts.example', name: 'PayPal Security' },
      { email: 'notifications@northwind-logistics.com', name: 'Northwind Logistics' },
    ]);

    startMarking(() => '');
    await settle();

    expect(marks()).toHaveLength(1);
    expect(document.querySelector(`#row-0 ${MARK}`)).not.toBeNull();
  });

  /**
   * The account address arrives late — the first passes run at `document_idle`, before Gmail has rendered
   * its account chrome — and `identity.lookalike_of_recipient_domain` cannot fire without it. It is the
   * most valuable thing a row can say, because no brand table contains the reader's own employer. Keyed on
   * the sender alone, every row already on screen when the address resolved kept its "nothing to say" and
   * was skipped for the life of the tab, so the check only ever ran on mail that arrived afterwards.
   */
  it('re-triages rows already on screen once the account address appears', async () => {
    render([{ email: 'accounts@northwind-Iogistics.com', name: 'Accounts' }]);

    let account = '';
    startMarking(() => account);
    await settle();
    expect(marks()).toEqual([]);

    // Nothing in the list changes when Gmail finally renders its account chrome, so the pass that picks
    // this up has to be one the marker asked for itself.
    account = 'reader@northwind-logistics.com';
    await settle();

    expect(marks()).toHaveLength(1);
    expect(marks()[0]).toContain('PhishLens warning');
  });

  it('stops looking for an account address that never arrives', async () => {
    const reads = vi.fn(() => '');
    render([{ email: 'a@b.example', name: 'Somebody' }]);
    startMarking(reads);

    for (let pass = 0; pass < 40; pass += 1) await settle();

    // Bounded: a page that never exposes the address must not be polled for as long as the tab is open.
    expect(reads.mock.calls.length).toBeLessThan(40);
  });

  /** Gmail recycles row elements, so a mark must not outlive the message it was computed for. */
  it('re-evaluates a row whose sender has been replaced', async () => {
    render([{ email: 'security@paypa1-alerts.example', name: 'PayPal Security' }]);
    startMarking(() => 'reader@northwind-logistics.com');
    await settle();
    expect(marks()).toHaveLength(1);

    const cell = document.querySelector('td.yW');
    const replacement = document.createElement('span');
    replacement.setAttribute('email', 'notifications@northwind-logistics.com');
    replacement.setAttribute('name', 'Northwind Logistics');
    cell?.replaceChildren(replacement);
    await settle();

    expect(marks()).toEqual([]);
  });

  /**
   * Gmail replaces its main region wholesale on a view change, and a `MutationObserver` holds the node it
   * was given. Pointed at an element, the marker went on watching a region that was no longer in the
   * document — rows kept arriving and none was ever looked at — and no mark is indistinguishable from mail
   * with nothing to say about it. Nothing else restarts it: the message observer reattaches for its own
   * purposes and says nothing to this.
   */
  it('keeps marking after Gmail replaces the list region', async () => {
    render([{ email: 'notifications@northwind-logistics.com', name: 'Northwind Logistics' }]);
    startMarking(() => 'reader@northwind-logistics.com');
    await settle();
    expect(marks()).toEqual([]);

    // A fresh main region in place of the old one, carrying a row that has something to say.
    render([{ email: 'security@paypa1-alerts.example', name: 'PayPal Security' }]);
    await settle();

    expect(marks()).toHaveLength(1);
  });

  it('removes everything it drew when marking is switched off', async () => {
    render([{ email: 'security@paypa1-alerts.example', name: 'PayPal Security' }]);
    const marker = startMarking(() => 'reader@northwind-logistics.com');
    await settle();

    marker.stop();

    expect(marks()).toEqual([]);
    expect(document.querySelectorAll('[data-phishlens-row]')).toHaveLength(0);
  });
});
