/**
 * Finding the parts of a message body that are rendered but cannot be seen.
 *
 * Split from `dom-adapter.ts` because the decision "does this style attribute hide its element" is pure
 * string work and deserves to be tested directly against the forms found in real mail, rather than only
 * through a constructed DOM.
 *
 * **Inline styles only.** Gmail rewrites message CSS heavily and a content script cannot ask it what a
 * `<style>` rule resolved to, but `getComputedStyle` on every node of a large message is a layout read
 * per element and this runs on every message open. Inline `style` is where bulk mail puts this anyway,
 * because it is the only form of CSS that survives every mail client. The consequence is a rule that
 * under-reports rather than one that guesses.
 */

/** Ceiling on elements examined. A message can contain thousands of nodes. */
const MAX_ELEMENTS_SCANNED = 4000;

/** Ceiling on the descendants examined for an override, per candidate. */
const MAX_ESCAPES_EXAMINED = 200;

/** Ceiling on the ancestors between an override and its candidate. Mail nests deeply, but not this deep. */
const MAX_ESCAPE_DEPTH = 64;

/** Ceiling on distinct techniques reported, so one message cannot fill the panel. */
const MAX_TECHNIQUES = 6;

/**
 * CSS declarations that take an element out of view, each paired with the name to report it by.
 *
 * Ordered most to least conclusive so the reported technique is the strongest one present.
 *
 * Every property is anchored to the start of a declaration, because CSS property names are suffixes of
 * one another and the difference is not cosmetic: `line-height:0` is on ordinary text, `min-width:0` is
 * on half the flexible layouts ever written, and an unanchored `height` pattern reads both as concealment
 * and deletes the paragraph they style.
 *
 * `font-size` is capped at 2px rather than 0: a one-pixel font is the standard preheader idiom and is
 * unreadable in the same way zero is. Offsets have to be large and negative — `left:-2px` is a nudge,
 * `left:-9999px` is a removal. Zero is spelled out by `ZERO` rather than matched loosely, for the reason
 * recorded there.
 */
const DECL = String.raw`(?:^|;)\s*`;

/**
 * Zero however CSS spells it — `0`, `00`, `0.0`, `.0`, `0.` — and nothing else.
 *
 * Written out because the obvious `0(\.\d+)?` reads the leading zero of `0.9em` as the whole value and
 * treats nine-tenths of the parent font as invisible. Relative units make that the common case rather than
 * a curiosity: `font-size:0.9em` is how a great deal of legitimate mail sets small print, and since a
 * caller strips what this matches, the mistake is not a spurious finding but a paragraph the reader can see
 * being removed from the analysis — the direction an attacker would choose.
 */
const ZERO = String.raw`(?:0+(?:\.0+)?|\.0+)`;

/**
 * The end of a declaration, `!important` included.
 *
 * A value has to be matched to its end rather than to a word boundary, or `0` matches the first character
 * of `0.9em` and the rest of the value is never looked at. `!important` is here because it is not an edge
 * case in mail: the whole point of a preheader is to survive a client that disagrees, so `display:none
 * !important` and `max-height:0 !important` are how these declarations are usually written.
 */
const END = String.raw`\s*(?:!\s*important\b\s*)?(?:;|$)`;

/**
 * Clipping, without which a zero dimension hides nothing.
 *
 * Content in a box with no height is not erased, it overflows and is drawn anyway — which is why the
 * preheader idiom is `max-height:0;overflow:hidden` and never `max-height:0` alone. Requiring the pair is
 * what separates concealment from the `height:0` of a spacer row or a layout reset, whose *children* hold
 * text the reader can see.
 */
const CLIPPED = new RegExp(`${DECL}overflow(-[xy])?\\s*:\\s*(hidden|clip)`, 'u');

interface HidingDeclaration {
  name: string;
  pattern: RegExp;
  /** Hides only in combination with clipping. */
  needsClipping?: boolean;
  /**
   * A descendant that can undo it, for the inherited properties.
   *
   * `display:none` and `opacity:0` cannot be escaped from inside: the subtree is not rendered, or is
   * composited at zero as a whole, whatever its children ask for. A zero font size is only the parent's
   * own, and a descendant naming a size that does not depend on the parent's is drawn at that size —
   * which is the entire purpose of `font-size:0` on a container, since it collapses the whitespace between
   * tags without touching the text inside them. Treating the container as hidden deletes a paragraph the
   * reader is looking at.
   *
   * An escape frees the descendant and nothing else: the container's own text, and every sibling that
   * did not escape, are still drawn at zero. See `findHiddenSubtrees`.
   */
  escapedBy?: RegExp;
}

/**
 * A font size that does not scale with the parent's, so a zero above it is no longer inherited.
 *
 * `em`, `%`, `ex` and `ch` are deliberately absent: each is a multiple of the inherited size, and any
 * multiple of zero is zero, so `font-size:1em` inside `font-size:0` hides exactly as well as nothing at
 * all. `rem` is present because it is the exception that looks like the rule — it resolves against the
 * root element, which here is Gmail's page, not the container. `initial` is `medium`. The values a hiding
 * declaration would itself match (`1px`, `.05rem`) are excluded where this is consulted, not here.
 */
const ABSOLUTE_FONT_SIZE = new RegExp(
  `${DECL}font-size\\s*:\\s*(?:(?:\\d+(?:\\.\\d+)?|\\.\\d+)\\s*(?:px|pt|pc|cm|mm|in|q|rem|vw|vh|vmin|vmax)|(?:xx-|x-)?small|medium|(?:x-|xx-|xxx-)?large|initial)${END}`,
  'u',
);

const HIDING_DECLARATIONS: readonly HidingDeclaration[] = [
  { name: 'display:none', pattern: new RegExp(`${DECL}display\\s*:\\s*none`, 'u') },
  {
    name: 'visibility:hidden',
    pattern: new RegExp(`${DECL}visibility\\s*:\\s*(hidden|collapse)`, 'u'),
    escapedBy: new RegExp(`${DECL}visibility\\s*:\\s*visible`, 'u'),
  },
  /*
   * Zero, or close enough that nothing is legible: `opacity:0.01` is a common way of writing it, chosen
   * because some clients drop an element whose opacity is exactly zero. Five percent is the ceiling —
   * faded secondary text sits at a half or more, never anywhere near this.
   */
  {
    name: 'opacity:0',
    pattern: new RegExp(
      `${DECL}opacity\\s*:\\s*(?:${ZERO}|0*\\.0[0-4]\\d*|0*\\.050*|(?:[0-4](?:\\.\\d+)?|5(?:\\.0+)?)%)${END}`,
      'u',
    ),
  },
  /*
   * Zero at any unit, one to two *pixels*, or under a tenth of a relative unit. Not `1em`, which is
   * ordinary body text, and not `0.9em`, which is ordinary small print.
   */
  {
    name: 'font-size:0',
    pattern: new RegExp(
      `${DECL}font-size\\s*:\\s*(?:${ZERO}\\s*[a-z%]*|[0-2](?:\\.\\d+)?\\s*(?:px|pt)|0?\\.0\\d*\\s*(?:em|rem|ex|ch|%))${END}`,
      'u',
    ),
    escapedBy: ABSOLUTE_FONT_SIZE,
  },
  {
    name: 'height:0',
    pattern: new RegExp(`${DECL}(max-)?height\\s*:\\s*${ZERO}\\s*[a-z%]*${END}`, 'u'),
    needsClipping: true,
  },
  {
    name: 'width:0',
    pattern: new RegExp(`${DECL}(max-)?width\\s*:\\s*${ZERO}\\s*[a-z%]*${END}`, 'u'),
    needsClipping: true,
  },
  {
    name: 'clipped',
    // A top edge of zero is not an empty rectangle. Only unambiguously empty shapes qualify.
    pattern: new RegExp(
      String.raw`${DECL}(?:clip\s*:\s*rect\(\s*${ZERO}(?:px)?(?:(?:\s*,\s*|\s+)${ZERO}(?:px)?){3}\s*\)|clip-path\s*:\s*inset\(\s*(?:100%|50%)\s*\))${END}`,
      'u',
    ),
  },
  {
    name: 'moved off screen',
    pattern: new RegExp(`${DECL}(text-indent|left|right|top|margin-left|margin-top)\\s*:\\s*-\\d{3,}`, 'u'),
  },
];

/**
 * The strongest hiding technique a style attribute applies, or `null` when it applies none.
 *
 * Exported for tests. Takes the attribute as written; whitespace and case vary freely in real mail.
 *
 * Answers for the element's own box only. Whether a descendant overrides an inherited property is a
 * question about a subtree, which `findHiddenSubtrees` asks.
 */
export function hidingTechnique(styleAttribute: string): string | null {
  const style = styleAttribute.toLowerCase();
  for (const { name, pattern, needsClipping } of HIDING_DECLARATIONS) {
    if (!pattern.test(style)) continue;
    if (needsClipping === true && !CLIPPED.test(style)) continue;
    return name;
  }
  return null;
}

/** The declaration a technique was named for, so the subtree rules can be read off it. */
function declarationFor(technique: string): HidingDeclaration | undefined {
  return HIDING_DECLARATIONS.find((declaration) => declaration.name === technique);
}

/**
 * The descendants drawn in spite of the ancestor's declaration, outermost only.
 *
 * Bounded like the outer scan, and inline styles only, for the same reason: a class rule Gmail rewrote is
 * not readable from here. The consequence is the safe one — a subtree whose override lives in a stylesheet
 * is still treated as hidden, which under-reports the body rather than inventing concealment.
 *
 * An override with no text in it frees nothing anyone could read. Counting it was how one empty
 * `<span style="font-size:14px">` beside a paragraph of filler exempted the filler too.
 */
function escapesFrom(element: Element, declaration: HidingDeclaration): Element[] {
  const escapedBy = declaration.escapedBy;
  if (escapedBy === undefined) return [];

  const escapes: Element[] = [];
  let examined = 0;
  for (const descendant of element.querySelectorAll('[style]')) {
    if (examined >= MAX_ESCAPES_EXAMINED) break;
    examined += 1;

    // Document order, so only the most recent escape can contain this one.
    if (escapes.at(-1)?.contains(descendant) === true) continue;

    const style = descendant.getAttribute('style')?.toLowerCase() ?? '';
    // A descendant restating the property *as another way of hiding* escapes nothing.
    if (!escapedBy.test(style) || hidingTechnique(style) !== null) continue;
    if (countContentChars(descendant.textContent) === 0) continue;
    if (hiddenBetween(descendant, element, declaration)) continue;

    escapes.push(descendant);
  }
  return escapes;
}

/**
 * Whether something between an override and its candidate hides it in a way the override does not undo.
 *
 * `font-size:14px` inside `display:none` inside `font-size:0` is not drawn, and reading it as visible put
 * text that nobody can see back into the body. A repeat of the candidate's own declaration is the one
 * thing in between that the override does undo.
 */
function hiddenBetween(descendant: Element, candidate: Element, declaration: HidingDeclaration): boolean {
  let node = descendant.parentElement;
  for (let depth = 0; node !== null && node !== candidate; depth += 1) {
    // Too deep to tell: treated as hidden, which keeps the text out of the body rather than in it.
    if (depth >= MAX_ESCAPE_DEPTH) return true;
    const technique = hidingTechnique(node.getAttribute('style') ?? '');
    if (technique !== null && technique !== declaration.name) return true;
    if (node.hasAttribute('hidden')) return true;
    node = node.parentElement;
  }
  return false;
}

/** Letters and digits only: invisible padding (`&nbsp;`, `&zwnj;`) is not content being concealed. */
export function countContentChars(text: string): number {
  return (text.match(/[\p{L}\p{N}]/gu) ?? []).length;
}

/**
 * The attributes this scan reads, named so that whatever *triggers* extraction can watch them.
 *
 * Neither appears in any selector, which is how the message observer came to ignore both: it derives the
 * attributes it watches from `selectors.ts`, and a watch list built only from what is used to *find*
 * elements misses what is used to *read* them. Removing `display:none` from a paragraph changes the
 * extracted body — the concealed text moves from `hiddenText` into it — and produced no re-assessment.
 */
export const VISIBILITY_ATTRIBUTES: readonly string[] = ['style', 'hidden'];

const HIDING_CANDIDATES = VISIBILITY_ATTRIBUTES.map((name) => `[${name}]`).join(',');

export interface HiddenSubtree {
  element: Element;
  /**
   * Descendants drawn in spite of the declaration on `element`, which belong to the visible body.
   *
   * A caller removing the subtree puts these back in its place. Nothing hidden inside them is looked
   * for, which errs towards keeping text in the body.
   */
  visible: Element[];
  /** Content characters hidden: the subtree's, less those in `visible`. */
  chars: number;
}

export interface HiddenScan {
  /** Hidden subtrees. Outermost only — a hidden child of a hidden parent is not extra. */
  roots: HiddenSubtree[];
  techniques: string[];
}

/**
 * Every hidden subtree in an element, with the techniques used.
 *
 * Nested hidden elements collapse into their outermost ancestor. Counting them separately would report
 * a hidden `<div>` of ten hidden `<span>`s as eleven findings and count its text eleven times.
 *
 * `aria-hidden="true"` is deliberately not treated as hiding. It instructs screen readers to skip an
 * element that is *on screen* — decorative arrows, icons, spacer cells — and mail uses it that way
 * constantly. Since a caller removes what this returns from the visible body, honouring it would delete
 * text the reader can see, which both loses findings and hands an attacker a one-attribute way to keep
 * wording out of the analysis while still showing it.
 */
export function findHiddenSubtrees(root: Element): HiddenScan {
  const roots: HiddenSubtree[] = [];
  const techniques = new Set<string>();
  let scanned = 0;

  for (const element of root.querySelectorAll(HIDING_CANDIDATES)) {
    if (scanned >= MAX_ELEMENTS_SCANNED) break;
    scanned += 1;

    // Document order, so an ancestor is always seen before its descendants — and since no root is
    // inside another, only the most recent one can contain this element.
    if (roots.at(-1)?.element.contains(element) === true) continue;

    const technique =
      hidingTechnique(element.getAttribute('style') ?? '') ??
      (element.hasAttribute('hidden') ? 'hidden attribute' : null);
    if (technique === null) continue;

    const declaration = declarationFor(technique);
    const visible = declaration === undefined ? [] : escapesFrom(element, declaration);
    let chars = countContentChars(element.textContent);
    for (const escape of visible) chars -= countContentChars(escape.textContent);

    /*
     * Everything readable inside escaped, which is the newsletter wrapper this exists for. Not a root, so
     * its descendants are still scanned on their own account. Only when an escape was found: a hidden
     * element with no text and nothing escaping it is still reported, as it always was.
     */
    if (visible.length > 0 && chars <= 0) continue;

    roots.push({ element, visible, chars: Math.max(0, chars) });
    if (techniques.size < MAX_TECHNIQUES) techniques.add(technique);
  }

  return { roots, techniques: [...techniques] };
}
