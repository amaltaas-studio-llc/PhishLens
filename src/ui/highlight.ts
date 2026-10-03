/**
 * Locates the thing in the message that a finding refers to.
 *
 * The constraint this file is built around: *do not break Gmail's own event handlers or markup.*
 * That rules out the obvious implementation (wrap matched text in `<mark>` elements), because
 * re-parenting a node inside a Gmail-managed subtree can detach Gmail's listeners and, for anchors,
 * change what a click does. On a security tool, breaking a link's behaviour would be worse than the
 * problem being reported.
 *
 * So highlighting only ever:
 *  - adds a class token to an element that already exists, and
 *  - removes it again.
 *
 * No wrapping, no splitting text nodes, no re-parenting, no attribute rewriting, no listener changes.
 * For text evidence, the *smallest existing element* containing the text is highlighted rather than
 * the exact character range: a slightly coarser highlight in exchange for not restructuring Gmail's
 * DOM.
 */
import { BLOCK_BOUNDARY } from '../gmail/block-text.js';
import { SELECTORS, queryAll, queryAllUnion } from '../gmail/selectors.js';
import { collapseWhitespace } from '../shared/text.js';
import type { SecuritySignal } from '../shared/types.js';
import { normalizeDomain, parseUrl, unwrapRedirects } from '../shared/url.js';
import { MIN_LOCATABLE_TEXT } from './format.js';
import { HIGHLIGHT_CSS } from './styles.js';

const HIGHLIGHT_CLASS = 'shoutphish-highlight';
const SUBTLE_CLASS = 'shoutphish-highlight-subtle';
const STYLE_ID = 'shoutphish-highlight-style';

/**
 * Bounds on one text search, which runs on every hover and focus of a finding.
 *
 * Text nodes rather than elements, because reading each element's `textContent` re-reads everything
 * beneath it: the cost of the obvious search is the body's length times its depth, and a message
 * controls both. Past either bound the excerpt is simply not located, which costs a highlight.
 */
const MAX_TEXT_NODES = 5000;
const MAX_SEARCH_CHARS = 200_000;

export class Highlighter {
  #highlighted: Element[] = [];
  #styleInjected = false;

  /**
   * Injects the highlight stylesheet into the main document.
   *
   * This is the only stylesheet ShoutPhish adds outside a shadow root, and it is necessary because the
   * highlighted elements are Gmail's. Its selectors are namespaced under `.shoutphish-` so they cannot
   * match anything Gmail styles.
   */
  #ensureStyle(): void {
    if (this.#styleInjected || document.getElementById(STYLE_ID) !== null) {
      this.#styleInjected = true;
      return;
    }
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = HIGHLIGHT_CSS;
    document.head.append(style);
    this.#styleInjected = true;
  }

  /** Highlights whatever the signal points at. Returns true if something was found. */
  show(signal: SecuritySignal, bodyElement: Element | null): boolean {
    this.clear();
    if (bodyElement === null) return false;
    this.#ensureStyle();

    const byUrl = signal.evidence?.url;
    if (byUrl !== undefined && byUrl !== '') {
      const anchors = findAnchorsForUrl(bodyElement, byUrl);
      if (anchors.length > 0) {
        for (const anchor of anchors) this.#mark(anchor, HIGHLIGHT_CLASS);
        this.#scrollTo(anchors[0]);
        return true;
      }
    }

    const byText = signal.evidence?.text;
    if (byText !== undefined && byText.length >= MIN_LOCATABLE_TEXT) {
      const element = findSmallestElementContaining(bodyElement, byText);
      if (element !== null) {
        this.#mark(element, SUBTLE_CLASS);
        this.#scrollTo(element);
        return true;
      }
    }
    return false;
  }

  clear(): void {
    for (const element of this.#highlighted) {
      element.classList.remove(HIGHLIGHT_CLASS, SUBTLE_CLASS);
      // Leave no trace: an empty class attribute we created should not persist.
      if (element.getAttribute('class') === '') element.removeAttribute('class');
    }
    this.#highlighted = [];
  }

  #mark(element: Element, className: string): void {
    element.classList.add(className);
    this.#highlighted.push(element);
  }

  #scrollTo(element: Element | undefined): void {
    if (element === undefined) return;
    try {
      element.scrollIntoView({ block: 'center', behavior: 'smooth' });
    } catch {
      // Older engines, or a detached node. Not worth reporting.
    }
  }

  dispose(): void {
    this.clear();
    document.getElementById(STYLE_ID)?.remove();
    this.#styleInjected = false;
  }
}

/**
 * Finds anchors whose destination matches the signal's evidence URL.
 *
 * Matched on the *unwrapped* destination and normalised host + path, not on raw string equality: the
 * evidence URL came from the same extraction pass, but Gmail rewrites hrefs and a raw comparison
 * would miss a redirect wrapper on one side and not the other.
 */
function findAnchorsForUrl(bodyElement: Element, evidenceUrl: string): HTMLAnchorElement[] {
  const target = resolveKey(evidenceUrl);
  if (target === null) return [];

  // Quoted anchors included, as they are in extraction: a link finding can come from either.
  const matches: HTMLAnchorElement[] = [];
  for (const anchor of queryAll(bodyElement, SELECTORS.bodyLink)) {
    if (!(anchor instanceof HTMLAnchorElement)) continue;
    const href = anchor.getAttribute('href');
    if (href === null) continue;
    if (resolveKey(href) === target) matches.push(anchor);
  }
  return matches;
}

/** `host + pathname` of the unwrapped destination, used as the comparison key. */
function resolveKey(href: string): string | null {
  const parsed = parseUrl(href);
  if (parsed === null) return null;
  const destination = unwrapRedirects(parsed).url;
  return `${normalizeDomain(destination.hostname)}${destination.pathname}`;
}

/**
 * The deepest element whose text contains the excerpt.
 *
 * Deepest rather than first so the highlight is as tight as possible without splitting text nodes: the
 * text is read once, the excerpt found in it, and the answer is the nearest element holding every text
 * node the match touches. The excerpt may have been whitespace-collapsed and ellipsised when it was
 * captured as evidence, so both sides are collapsed and the ellipses trimmed before comparing.
 *
 * Quoted history is searched only when the rest of the body does not hold the excerpt, mirroring
 * `extractBody`, which reads the quotes only when nothing was written outside them. Searching them first
 * would highlight the quoted original of a sentence the reply repeats.
 */
export function findSmallestElementContaining(root: Element, excerpt: string): Element | null {
  const needle = collapseWhitespace(excerpt.replace(/^…|…$/gu, '')).toLowerCase();
  if (needle.length < 8) return null;

  const quoted = new Set(queryAllUnion(root, SELECTORS.quotedContent));
  return (
    locate(root, needle, (element) => quoted.has(element)) ??
    (quoted.size > 0 ? locate(root, needle, () => false) : null)
  );
}

interface TextSpan {
  node: Text;
  start: number;
  end: number;
}

function locate(root: Element, needle: string, skip: (element: Element) => boolean): Element | null {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: (node) =>
      node instanceof Element && skip(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
  });

  // The body as one collapsed, lower-cased string, with each text node's range in it. A space marks
  // every block boundary, as `separateBlocks` does for the body text the excerpt was taken from;
  // without it an excerpt spanning two table cells could never be found.
  const spans: TextSpan[] = [];
  let haystack = '';
  let visited = 0;
  let previousBlock: Element | null = null;
  let breakPending = false;
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    if (node instanceof Element) {
      if (node.matches('br, hr')) breakPending = true;
      continue;
    }
    if (!(node instanceof Text)) continue;
    if (visited >= MAX_TEXT_NODES || haystack.length >= MAX_SEARCH_CHARS) break;
    visited += 1;

    const block = node.parentElement?.closest(BLOCK_BOUNDARY) ?? null;
    if ((breakPending || block !== previousBlock) && haystack !== '' && !haystack.endsWith(' ')) {
      haystack += ' ';
    }
    previousBlock = block;
    breakPending = false;

    let piece = node.data.replace(/\s+/gu, ' ').toLowerCase();
    if (piece.startsWith(' ') && (haystack === '' || haystack.endsWith(' '))) piece = piece.slice(1);
    if (piece === '') continue;
    spans.push({ node, start: haystack.length, end: haystack.length + piece.length });
    haystack += piece;
  }

  const at = haystack.indexOf(needle);
  if (at === -1) return null;
  const end = at + needle.length;

  const touched = spans.filter((span) => span.end > at && span.start < end);
  const first = touched[0]?.node.parentElement ?? null;
  return touched.reduce<Element | null>(
    (common, span) => (common === null ? null : nearestCommon(common, span.node)),
    first,
  );
}

/** The nearest ancestor of `element` (itself included) that contains `node`. */
function nearestCommon(element: Element, node: Node): Element | null {
  let candidate: Element | null = element;
  while (candidate !== null && !candidate.contains(node)) candidate = candidate.parentElement;
  return candidate;
}
