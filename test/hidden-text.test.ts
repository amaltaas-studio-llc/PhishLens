/**
 * Tests for the CSS-hidden body text scan.
 *
 * Two failure directions, and they are not symmetric. Missing concealed text lets a message dilute the
 * wording the content rules read, which is the attack this exists to stop. But *over*-reporting deletes
 * text from the visible body before anything scores it, so a rule that is too eager silently removes the
 * evidence — a worse outcome than the one it was added to prevent. Nearly every case below is therefore a
 * legitimate style attribute that must be left alone.
 *
 * The style tests need no DOM at all, which is why that decision is a separate string function. The
 * subtree walk gets a fake element rather than jsdom, following `observer.test.ts`.
 */
import { describe, expect, it } from 'vitest';

import { countContentChars, findHiddenSubtrees, hidingTechnique } from '../src/gmail/hidden-text.js';

// ---------------------------------------------------------------------------
// Fake DOM
// ---------------------------------------------------------------------------

/** The smallest element the scan uses: attributes, descendants in document order, and containment. */
class FakeElement {
  readonly children: FakeElement[] = [];
  parent: FakeElement | null = null;

  constructor(readonly attributes: Record<string, string> = {}) {}

  append(...children: FakeElement[]): this {
    for (const child of children) {
      child.parent = this;
      this.children.push(child);
    }
    return this;
  }

  getAttribute(name: string): string | null {
    return this.attributes[name] ?? null;
  }

  hasAttribute(name: string): boolean {
    return name in this.attributes;
  }

  contains(other: FakeElement): boolean {
    for (let node: FakeElement | null = other; node !== null; node = node.parent) {
      if (node === this) return true;
    }
    return false;
  }

  /** Document order, which the collapse-to-outermost rule depends on. Selector is assumed, not parsed. */
  querySelectorAll(_selector: string): FakeElement[] {
    const found: FakeElement[] = [];
    for (const child of this.children) {
      if (child.hasAttribute('style') || child.hasAttribute('hidden')) found.push(child);
      found.push(...child.querySelectorAll(_selector));
    }
    return found;
  }
}

function element(attributes: Record<string, string> = {}): FakeElement {
  return new FakeElement(attributes);
}

function scan(root: FakeElement): { roots: number; techniques: string[] } {
  const result = findHiddenSubtrees(root as unknown as Element);
  return { roots: result.roots.length, techniques: result.techniques };
}

// ---------------------------------------------------------------------------

describe('hidingTechnique', () => {
  it('recognises the declarations that remove an element from view', () => {
    expect(hidingTechnique('display:none;')).toBe('display:none');
    expect(hidingTechnique('visibility: hidden')).toBe('visibility:hidden');
    expect(hidingTechnique('opacity:0')).toBe('opacity:0');
    expect(hidingTechnique('font-size:0px;line-height:0')).toBe('font-size:0');
    expect(hidingTechnique('max-height:0px;overflow:hidden')).toBe('height:0');
    expect(hidingTechnique('text-indent:-9999px')).toBe('moved off screen');
    expect(hidingTechnique('clip:rect(0 0 0 0)')).toBe('clipped');
  });

  it('reads them however they are spelled, since real mail varies', () => {
    expect(hidingTechnique('DISPLAY : NONE')).toBe('display:none');
    expect(hidingTechnique('color:#fff;   display:none')).toBe('display:none');
    expect(hidingTechnique('opacity:0.00;')).toBe('opacity:0');
  });

  it('reports the most conclusive technique when several are combined', () => {
    const preheader =
      'display:none;font-size:1px;line-height:1px;max-height:0px;opacity:0;overflow:hidden';
    expect(hidingTechnique(preheader)).toBe('display:none');
  });

  /**
   * The whole legitimate vocabulary of inline mail styling. Anything here reading as hidden would cut
   * visible paragraphs out of the body of ordinary newsletters.
   */
  it('leaves ordinary styling alone', () => {
    for (const style of [
      'color:#333333;font-size:14px;line-height:1.5',
      'font-size:1.2em;font-weight:bold',
      'width:600px;max-width:100%',
      'margin-top:-1px;border-collapse:collapse',
      'padding:0;margin:0',
      'opacity:0.9',
      'height:100%;width:100%',
      'left:-2px;position:relative',
      'display:block',
      'font-size:10pt',
      '',
    ]) {
      expect(hidingTechnique(style), style).toBeNull();
    }
  });

  /**
   * CSS property names are suffixes of one another, and these are the pairs that matter. `line-height:0`
   * sits on ordinary text and `min-width:0` on any flexible layout, so an unanchored `height` or `width`
   * pattern would read a legitimate paragraph as concealed and remove it from the body.
   */
  it('does not mistake a longer property for the one it ends with', () => {
    for (const style of [
      'line-height:0',
      'min-height:0',
      'min-width:0;flex:1',
      'padding:0;margin:0;height:auto',
      'border-top:0',
      'font-size:14px;line-height:0',
    ]) {
      expect(hidingTechnique(style), style).toBeNull();
    }
  });

  it('still reads those properties when they are the declaration', () => {
    expect(hidingTechnique('font-size:14px;height:0;overflow:hidden')).toBe('height:0');
    expect(hidingTechnique('line-height:0;max-height:0;overflow:hidden')).toBe('height:0');
  });

  /**
   * A box with no height does not erase what is in it — the content overflows and is drawn anyway — which
   * is why the preheader idiom is `max-height:0;overflow:hidden` and never the height alone. Without the
   * pair, this read a spacer row and any `height:0` layout reset as concealment and removed the visible
   * paragraphs *inside* them.
   */
  it('does not read a zero dimension as concealment unless it is also clipped', () => {
    for (const style of [
      'height:0',
      'max-height:0px',
      'width:0',
      'max-width:0;padding:4px 8px',
      'height:0;overflow:visible',
    ]) {
      expect(hidingTechnique(style), style).toBeNull();
    }

    expect(hidingTechnique('max-height:0;overflow:hidden')).toBe('height:0');
    expect(hidingTechnique('width:0;overflow-x:hidden')).toBe('width:0');
  });

  /**
   * A value beginning `0.` is not zero, and reading it as zero costs more than a false finding: a caller
   * strips what this matches out of the body, so `font-size:0.9em` — a common way to set small print —
   * would delete a paragraph the reader can see from everything downstream of extraction.
   */
  it('does not read the leading zero of a fraction as the whole value', () => {
    for (const style of [
      'font-size:0.9em',
      'font-size:0.95rem',
      'font-size:0.8em;color:#666',
      'height:0.9em',
      'max-width:0.5in',
      'width:0.25%',
    ]) {
      expect(hidingTechnique(style), style).toBeNull();
    }
  });

  it('reads zero however CSS spells it', () => {
    for (const style of ['font-size:0', 'font-size:0.0em', 'font-size:.0px', 'font-size:00']) {
      expect(hidingTechnique(style), style).toBe('font-size:0');
    }
    expect(hidingTechnique('height:0.0;overflow:hidden')).toBe('height:0');
    expect(hidingTechnique('max-width:.0px;overflow:hidden')).toBe('width:0');
  });

  /** Below a tenth of the parent is unreadable at any body size, and `0.9em` is not. */
  it('reads a relative font size under a tenth as concealment', () => {
    expect(hidingTechnique('font-size:0.01em')).toBe('font-size:0');
    expect(hidingTechnique('font-size:.05rem')).toBe('font-size:0');
    expect(hidingTechnique('font-size:0.09%')).toBe('font-size:0');
  });

  /**
   * The point of a preheader is to survive a client that disagrees, so these declarations usually carry
   * `!important` in real mail. Matching a value to the end of its declaration has to allow for it.
   */
  it('reads a declaration the sender insisted on', () => {
    expect(hidingTechnique('max-height:0 !important;overflow:hidden')).toBe('height:0');
    expect(hidingTechnique('font-size:0px!important;color:#fff')).toBe('font-size:0');
    expect(hidingTechnique('opacity:0 ! important')).toBe('opacity:0');
    expect(hidingTechnique('width:0 !important;overflow:hidden')).toBe('width:0');
  });
});

describe('countContentChars', () => {
  it('counts letters and digits', () => {
    expect(countContentChars('Renew now: 250 GB')).toBe(13);
  });

  /**
   * Filler is measured by how much *reading* it adds, and the padding cells attackers stack between
   * paragraphs contain no reading. Counting `&nbsp;` runs would let a hundred spacer characters pass for
   * concealed prose and make the threshold meaningless.
   */
  it('does not count invisible padding as content', () => {
    expect(countContentChars('\u00a0 \u200b \u2060 \ufeff - — · ! ?')).toBe(0);
    expect(countContentChars('  \n\t  ')).toBe(0);
  });

  it('counts non-Latin scripts as content', () => {
    expect(countContentChars('Здравствуйте')).toBe(12);
    expect(countContentChars('こんにちは')).toBe(5);
  });
});

describe('findHiddenSubtrees', () => {
  it('finds a hidden element and names the technique', () => {
    const root = element().append(element({ style: 'display:none' }));
    expect(scan(root)).toEqual({ roots: 1, techniques: ['display:none'] });
  });

  it('finds the [hidden] attribute, which does hide', () => {
    const root = element().append(element({ hidden: '' }));
    expect(scan(root)).toEqual({ roots: 1, techniques: ['hidden attribute'] });
  });

  /**
   * `aria-hidden` is an instruction to screen readers about an element that is on screen. Treating it as
   * hidden would delete visible text from the body before it is scored, and hand an attacker a
   * one-attribute way to keep wording out of the analysis while still showing it to the reader.
   */
  it('ignores aria-hidden, which hides nothing from the reader', () => {
    const root = element().append(element({ 'aria-hidden': 'true' }));
    expect(scan(root)).toEqual({ roots: 0, techniques: [] });
  });

  it('collapses a hidden subtree to its outermost element', () => {
    const root = element().append(
      element({ style: 'display:none' }).append(
        element({ style: 'opacity:0' }),
        element({ style: 'font-size:1px' }).append(element({ style: 'display:none' })),
      ),
    );

    expect(scan(root)).toEqual({ roots: 1, techniques: ['display:none'] });
  });

  it('reports sibling subtrees separately, with each technique once', () => {
    const root = element().append(
      element({ style: 'display:none' }),
      element({ style: 'font-size:0' }),
      element({ style: 'display:none' }),
      element({ style: 'color:#333' }),
    );

    const result = scan(root);
    expect(result.roots).toBe(3);
    expect(result.techniques).toEqual(['display:none', 'font-size:0']);
  });

  /**
   * The bug this file existed to prevent, arriving through the one door it left open: a technique was
   * judged on an element and then applied to its whole subtree. `font-size:0` on a container is how bulk
   * mail collapses the whitespace between its tags, and every paragraph inside it names its own size and is
   * drawn at it. A genuine newsletter built that way had its entire body — a thousand characters the reader
   * was looking at — removed before scoring, which left the message scored on its subject and sender alone
   * with nothing on the card to say so.
   */
  it('leaves a zero font size alone when what is inside sets its own', () => {
    const root = element().append(
      element({ style: 'font-size:0;padding:4px 8px' }).append(
        element({ style: 'font-size:14px;color:#333' }),
      ),
    );

    expect(scan(root)).toEqual({ roots: 0, techniques: [] });
  });

  /** The concealment case is unchanged: nothing inside asks to be drawn, so nothing is. */
  it('still finds a zero font size whose subtree never overrides it', () => {
    const root = element().append(
      element({ style: 'font-size:0' }).append(element({ style: 'color:#333' })),
    );

    expect(scan(root)).toEqual({ roots: 1, techniques: ['font-size:0'] });
  });

  /** A descendant restating the property as another way of hiding is not an escape from it. */
  it('is not fooled by a descendant that hides itself differently', () => {
    const root = element().append(
      element({ style: 'font-size:0' }).append(element({ style: 'font-size:0.02em' })),
    );

    expect(scan(root)).toEqual({ roots: 1, techniques: ['font-size:0'] });
  });

  /** `visibility` is the other inherited property a child can simply switch back on. */
  it('leaves a hidden subtree alone when a child makes itself visible again', () => {
    const root = element().append(
      element({ style: 'visibility:hidden' }).append(element({ style: 'visibility:visible' })),
    );

    expect(scan(root)).toEqual({ roots: 0, techniques: [] });
  });

  /** `display:none` and `opacity:0` cannot be escaped from inside, so no descendant is consulted. */
  it('ignores what is inside a subtree that is not rendered at all', () => {
    const root = element().append(
      element({ style: 'display:none' }).append(element({ style: 'font-size:14px' })),
      element({ style: 'opacity:0' }).append(element({ style: 'opacity:1' })),
    );

    expect(scan(root)).toEqual({ roots: 2, techniques: ['display:none', 'opacity:0'] });
  });

  it('finds nothing in a body that hides nothing', () => {
    const root = element().append(
      element({ style: 'font-size:14px' }).append(element({ style: 'color:#111' })),
      element(),
    );
    expect(scan(root)).toEqual({ roots: 0, techniques: [] });
  });

  it('stays bounded on a message built to be enormous', () => {
    const root = element();
    for (let i = 0; i < 6000; i++) root.append(element({ style: 'display:none' }));

    const started = Date.now();
    const result = scan(root);
    expect(Date.now() - started).toBeLessThan(1000);
    expect(result.roots).toBeLessThanOrEqual(4000);
  });
});
