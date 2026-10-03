/**
 * @vitest-environment jsdom
 *
 * The assessment card, rendered.
 *
 * The card is where every string from a message reaches a reader, so the properties asserted here are the
 * ones a redesign is most likely to break without anyone noticing: message text arriving as text and never
 * as markup, the measured findings and the model's opinion staying in separate sections, colour always
 * accompanied by a word, and a skipped AI reading never reading as an all-clear.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { analyze, analyzeDeterministic, withSemanticStatus } from '../src/analysis/engine.js';
import type {
  AnalysisResult,
  AnalysisTiming,
  EmailMessage,
  SecuritySignal,
  SemanticAnalysis,
  SemanticStatus,
} from '../src/shared/types.js';
import { svg } from '../src/ui/dom.js';
import {
  aiAbsenceNote,
  assessmentExplanation,
  evidenceOf,
  formatDuration,
  reasonParts,
  scoreSummary,
  timingLine,
} from '../src/ui/format.js';
import { Panel, type ResultView } from '../src/ui/panel.js';
import { loadFixture } from './fixtures/load.js';

const PHISH = loadFixture('microsoft-phish').email;
const LEGITIMATE = loadFixture('legitimate').email;

const TIMING: AnalysisTiming = { checksMs: 12, aiMs: 4800, aiReused: false };

function reading(over: Partial<SemanticAnalysis> = {}): SemanticAnalysis {
  return {
    risk: 78,
    categories: ['credential_phishing'],
    reasons: ['"Verify your account immediately" pressures the reader to act before checking.'],
    confidence: 0.82,
    source: 'local',
    ...over,
  };
}

async function readyResult(email: EmailMessage, analysis = reading()): Promise<AnalysisResult> {
  return analyze(
    email,
    { id: 'fixed', isAvailable: () => Promise.resolve(true), analyze: () => Promise.resolve(analysis) },
    { now: 0 },
  );
}

function deterministic(email: EmailMessage, status: SemanticStatus): AnalysisResult {
  const { context: _context, ...result } = analyzeDeterministic(email, { now: 0 });
  return withSemanticStatus(result, status);
}

let clicks = 0;
const panel = new Panel({
  onFocusSignal: () => undefined,
  onBlurSignal: () => undefined,
  onClose: () => undefined,
  onTrustChange: () => undefined,
  onRunAssessment: () => {
    clicks += 1;
  },
});

function show(result: AnalysisResult, email: EmailMessage, semantic: SemanticStatus): ShadowRoot {
  const view: ResultView = {
    kind: 'result',
    result,
    aiMode: 'local',
    email,
    semantic,
    timing: TIMING,
    trust: { kind: 'none' },
  };
  panel.open(view);
  const root = document.querySelector('#shoutphish-panel-host')?.shadowRoot;
  if (root === null || root === undefined) throw new Error('the card did not render');
  return root;
}

afterEach(() => {
  panel.close();
  clicks = 0;
});

describe('the rendered card', () => {
  it('keeps measured findings and the model’s reading in separate sections', async () => {
    const root = show(await readyResult(PHISH), PHISH, 'ready');
    const observed = root.querySelector('section.observed');
    const assessment = root.querySelector('section.assessment');

    expect(observed?.querySelectorAll('li.finding[data-category="llm"]')).toHaveLength(0);
    expect(assessment?.querySelector('.reading')).not.toBeNull();
    expect(assessment?.querySelectorAll('li.finding:not([data-category="llm"])')).toHaveLength(0);
  });

  it('sets message text as text, never as markup', async () => {
    const hostile: EmailMessage = {
      ...PHISH,
      subject: '<img src=x onerror="alert(1)">Verify now',
      bodyText: `${PHISH.bodyText} <script>document.title='owned'</script>`,
    };
    const root = show(await readyResult(hostile), hostile, 'ready');

    expect(root.querySelector('img, script')).toBeNull();
    expect(root.querySelector('.ref-subject')?.textContent).toBe(hostile.subject);
  });

  it('names every category the ring colours, in words beside it', async () => {
    const result = await readyResult(PHISH);
    const root = show(result, PHISH, 'ready');
    const slices = [...root.querySelectorAll('.ring .seg')].map((s) => s.getAttribute('data-category'));
    const rows = [...root.querySelectorAll('li.row .dot')].map((d) => d.getAttribute('data-category'));

    expect(slices.length).toBeGreaterThan(0);
    expect(rows).toEqual(slices);
    expect(root.querySelector('.ring svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(root.querySelector('.ring-label .score-value')?.textContent).toBe(String(result.score));
  });

  it('lists the model’s reasons with the quoted excerpt set apart', async () => {
    const root = show(await readyResult(PHISH), PHISH, 'ready');
    const quote = root.querySelector('ul.reasons .quote');
    expect(quote?.textContent).toBe('Verify your account immediately');
    // The explanation above the list introduces the reasons without repeating them.
    expect(root.querySelector('.reading .finding-desc')?.textContent).not.toMatch(/Model's reasoning/u);
  });

  it('offers a reading the gate skipped, and never calls the message safe for skipping it', () => {
    const root = show(deterministic(LEGITIMATE, 'skipped'), LEGITIMATE, 'skipped');
    const note = root.querySelector('.ai-note')?.textContent ?? '';

    expect(note).toMatch(/not a judgement that the message is safe/u);
    const button = root.querySelector<HTMLButtonElement>('button.action');
    button?.click();
    expect(clicks).toBe(1);
    expect(button?.disabled).toBe(true);
  });

  it('shows how long the checks and the reading took', async () => {
    const root = show(await readyResult(PHISH), PHISH, 'ready');
    expect(root.querySelector('.timing')?.textContent).toBe('Checks 12 ms · AI reading 4.8 s');
  });

  it('adds the floor to the breakdown when a severe finding raised the score', async () => {
    const result = await readyResult(PHISH);
    const root = show(result, PHISH, 'ready');
    const summed = Object.values(result.categoryScores).reduce((a, b) => a + b, 0);
    expect(root.querySelector('li.row.floor') !== null).toBe(result.score > summed);
    expect(root.querySelector('.total-value')?.textContent).toBe(`${String(result.score)} of 100`);
  });
});

/**
 * The card is repainted in place (the model's reading arriving, a trust click, the ask button), and a
 * repaint replaces every node in it. A repaint that drops keyboard focus to the page takes the live region
 * with it, so a screen-reader user hears nothing when the reading lands and then has to find their way
 * back into the card from the top of Gmail.
 */
describe('the card across repaints', () => {
  function view(semantic: SemanticStatus, over: Partial<ResultView> = {}): ResultView {
    return {
      kind: 'result',
      result: deterministic(PHISH, semantic),
      aiMode: 'local',
      email: PHISH,
      semantic,
      timing: TIMING,
      trust: { kind: 'none' },
      ...over,
    };
  }

  function rootOf(): ShadowRoot {
    const root = document.querySelector('#shoutphish-panel-host')?.shadowRoot;
    if (root === null || root === undefined) throw new Error('the card did not render');
    return root;
  }

  it('keeps one live region, and gives it the new state when the reading lands', async () => {
    panel.open(view('pending'));
    const live = rootOf().querySelector('[role="status"]');
    expect(live?.textContent).toMatch(/Reading the message on-device/u);

    panel.open({ ...view('ready'), result: await readyResult(PHISH) });
    expect(rootOf().querySelectorAll('[role="status"]')).toHaveLength(1);
    expect(rootOf().querySelector('[role="status"]')).toBe(live);
    expect(live?.textContent).toMatch(/AI assessment added/u);
  });

  it('puts focus back on the equivalent control after a repaint', () => {
    panel.open(view('pending'));
    const root = rootOf();
    const close = root.querySelector<HTMLElement>('.close');
    expect(root.activeElement).toBe(close);

    panel.open(view('ready'));
    expect(root.activeElement?.matches('.close')).toBe(true);
    expect(root.activeElement).not.toBe(close);
  });

  it('keeps focus on the same finding, by position, across a repaint', () => {
    panel.open(view('pending'));
    const root = rootOf();
    const findings = [...root.querySelectorAll<HTMLElement>('li.finding[tabindex]')];
    const target = findings.at(-1);
    if (target === undefined) throw new Error('the fixture has no locatable finding');
    target.focus();

    panel.open(view('ready'));
    const after = [...root.querySelectorAll('li.finding[tabindex]')];
    expect(root.activeElement).not.toBe(target);
    expect(after.findIndex((finding) => finding === root.activeElement)).toBe(findings.length - 1);
  });

  it('keeps focus on the trust button after the click that repaints it', () => {
    const offer = { kind: 'offer', entry: 'northwind-logistics.com' } as const;
    panel.open(view('ready', { trust: offer }));
    const root = rootOf();
    root.querySelector<HTMLElement>('.trust button')?.focus();

    panel.open(view('ready', { trust: { kind: 'trusted', entry: 'northwind-logistics.com' } }));
    expect(root.activeElement?.matches('.trust button')).toBe(true);
    expect(root.activeElement?.textContent).toMatch(/Stop trusting/u);
  });

  /** The ask button is gone once the reading it asked for is under way; focus stays in the card. */
  it('moves focus to the close button when the focused control no longer exists', () => {
    panel.open(view('skipped', { result: deterministic(LEGITIMATE, 'skipped'), email: LEGITIMATE }));
    const root = rootOf();
    root.querySelector<HTMLElement>('button.action')?.focus();

    panel.open(view('pending', { result: deterministic(LEGITIMATE, 'pending'), email: LEGITIMATE }));
    expect(root.querySelector('button.action')).toBeNull();
    expect(root.activeElement?.matches('.close')).toBe(true);
  });

  /** Focus is only moved by a repaint that took it away: a reader working in Gmail is left alone. */
  it('does not take focus on a repaint when it was elsewhere', () => {
    const outside = document.createElement('button');
    document.body.append(outside);
    panel.open(view('pending'));
    outside.focus();

    panel.open(view('ready'));
    expect(document.activeElement).toBe(outside);
    expect(rootOf().activeElement).toBeNull();
    outside.remove();
  });

  it('reports whether focus was inside it when it closes', () => {
    panel.open(view('ready'));
    expect(panel.close()).toBe(true);

    const outside = document.createElement('button');
    document.body.append(outside);
    panel.open(view('ready'));
    outside.focus();
    expect(panel.close()).toBe(false);
    outside.remove();
  });
});

describe('card wording', () => {
  it('formats durations at the precision a reader can feel', () => {
    expect(formatDuration(0.2)).toBe('<1 ms');
    expect(formatDuration(12.4)).toBe('12 ms');
    expect(formatDuration(4830)).toBe('4.8 s');
    expect(formatDuration(Number.NaN)).toBe('<1 ms');
  });

  it('describes each way a view can have been timed', () => {
    expect(timingLine(null, 'ready', 'local')).toBeNull();
    expect(timingLine({ checksMs: 3, aiReused: false }, 'skipped', 'local')).toBe(
      'Checks 3 ms · AI not asked',
    );
    expect(timingLine({ checksMs: 3, aiReused: false }, 'off', 'off')).toBe(
      'Checks 3 ms · AI off',
    );
    expect(timingLine({ ...TIMING, aiReused: true }, 'ready', 'local')).toBe(
      'Checks 12 ms · AI reading reused',
    );
  });

  it('splits quoted excerpts out of a reason, in either quote style', () => {
    expect(reasonParts('“Do not call” avoids checking.')).toEqual([
      { text: 'Do not call', quoted: true },
      { text: ' avoids checking.', quoted: false },
    ]);
    expect(reasonParts('Asks to "reply with the code" today')).toEqual([
      { text: 'Asks to ', quoted: false },
      { text: 'reply with the code', quoted: true },
      { text: ' today', quoted: false },
    ]);
    expect(reasonParts('No quotation here')).toEqual([{ text: 'No quotation here', quoted: false }]);
  });

  it('bounds the work a reason full of quote marks can cause, dropping none of its text', () => {
    const reason = '"a" '.repeat(500);
    const parts = reasonParts(reason);
    expect(parts.length).toBeLessThan(16);
    // What is past the bound stays, unquoted, in the last part.
    const rebuilt = parts.map((p) => (p.quoted ? `"${p.text}"` : p.text)).join('');
    expect(rebuilt).toBe(reason);
  });

  it('ends the explanation where the model’s reasons begin', () => {
    const description =
      "This is a language assessment. It rated the message 78/100. Model's reasoning: It asks for a code.";
    expect(assessmentExplanation(description)).toBe(
      'This is a language assessment. It rated the message 78/100.',
    );
    expect(assessmentExplanation('No reasons were given.')).toBe('No reasons were given.');
  });

  it('labels a measured value, a destination and a quotation differently', () => {
    const base: SecuritySignal = {
      id: 'x',
      category: 'link',
      severity: 'medium',
      score: 10,
      title: 't',
      description: 'd',
    };
    expect(evidenceOf({ ...base, evidence: { value: 'northwind.example' } })?.kind).toBe('value');
    expect(evidenceOf({ ...base, evidence: { url: 'https://northwind.example/' } })?.label).toBe(
      'Link goes to',
    );
    expect(evidenceOf({ ...base, evidence: { text: 'act now' } })).toEqual({
      kind: 'quote',
      label: 'From the email',
      body: 'act now',
    });
  });

  it('summarises a clean score without claiming the message is safe', () => {
    const summary = scoreSummary(deterministic(LEGITIMATE, 'skipped'));
    expect(summary).toBe('Nothing the checks found added to the score.');
  });

  it('names the categories a score came from', async () => {
    expect(scoreSummary(await readyResult(PHISH))).toMatch(/^(Mostly|All) from |^Raised to a minimum/u);
  });

  it('gives the skipped state its own wording, naming what would have done the reading', () => {
    expect(aiAbsenceNote('skipped', 'server')).toMatch(/^Your model server was not asked/u);
  });
});

describe('svg()', () => {
  it('builds elements in the SVG namespace, with attributes and children only', () => {
    const circle = svg('circle', { class: 'seg', attrs: { r: 30, hidden: false } });
    const group = svg('g', { children: [circle, null, false] });

    expect(circle.namespaceURI).toBe('http://www.w3.org/2000/svg');
    expect(circle.getAttribute('class')).toBe('seg');
    expect(circle.getAttribute('r')).toBe('30');
    expect(circle.hasAttribute('hidden')).toBe(false);
    expect(group.childNodes).toHaveLength(1);
  });
});
