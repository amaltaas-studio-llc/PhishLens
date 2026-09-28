/**
 * Shared types and helpers for wording packs in languages other than English.
 *
 * Packs add patterns to the existing content themes; they do not invent findings. Theme ids, titles,
 * severities and scores stay in `content.ts`, so combinations and floors work in every language without
 * a second scoring model.
 *
 * Two helpers exist because JavaScript's regex engine is not enough on its own:
 *  - `\b` is ASCII-only even with the `u` flag, so it breaks at "é" and never matches Devanagari.
 *  - Accentless spellings ("verificacion", "securite") are common in phishing, and folding must keep
 *    match indices valid for excerpts taken from the unfolded text.
 */

/** Every content theme a pack may extend. Kept in sync with `CONTENT_PATTERNS` in `content.ts`. */
export const THEME_IDS = [
  'urgency',
  'credential_verification',
  'password_reset_pressure',
  'account_threat',
  'mfa_request',
  'wire_transfer',
  'payment_detail_change',
  'payroll_change',
  'gift_card',
  'invoice_fraud',
  'secrecy',
  'process_bypass',
  'unusual_request_shape',
  'crypto_demand',
  'sextortion',
  'prize_lure',
] as const;

export type ThemeId = (typeof THEME_IDS)[number];

export type LanguageId = 'es' | 'fr' | 'de' | 'pt' | 'it' | 'nl' | 'hi' | 'hinglish';

/**
 * Negation that reverses a solicitation theme.
 *
 * `before` covers languages that put the negation ahead of the verb ("ne partagez jamais", "nunca
 * comparta"). `after` covers those that put it after ("Teilen Sie den Code niemals", "OTP share na
 * karein"). `conditional` names the forms that look like negation but introduce a demand
 * ("si usted no…", "wenn Sie nicht…", "agar aap… nahi"), which must stay reportable.
 */
export interface PackNegation {
  readonly before?: RegExp;
  readonly after?: RegExp;
  readonly conditional?: RegExp;
}

export interface LanguagePack {
  readonly id: LanguageId;
  readonly label: string;
  readonly script: 'latin' | 'devanagari';
  /** Function words used only to decide whether this pack's patterns should run. */
  readonly markers: readonly string[];
  readonly themes: Partial<Record<ThemeId, readonly RegExp[]>>;
  readonly negation?: PackNegation;
  /** Unsubscribe / preference vocabulary that marks bulk mail in this language. */
  readonly bulk: RegExp;
  /** Credential-ask vocabulary that withdraws the bulk-mail benefit of the doubt. */
  readonly credentialAsk: RegExp;
  readonly genericSalutation?: RegExp;
}

/** Characters that count as part of a word for pack patterns. */
const WORD = String.raw`[\p{L}\p{M}\p{N}]`;

/**
 * Unicode-aware stand-in for `\b`.
 *
 * Placed wherever a pack author writes `\b`. Looking both ways matters: a trailing boundary after a
 * Devanagari word has no ASCII word-character on either side under JavaScript's own `\b`.
 */
const BOUNDARY = String.raw`(?:(?<!${WORD})(?=${WORD})|(?<=${WORD})(?!${WORD}))`;

/**
 * Compiles a pack pattern against diacritic-folded text.
 *
 * Authors write patterns with accents and with `\b` the same way the English table does. Diacritics
 * are folded here so the pattern matches the folded haystack `matchThemes` searches, and `\b` is
 * rewritten into a Unicode-aware boundary so accented Latin and Devanagari word edges still count.
 *
 * German `ß` is written as `ss` in patterns: `normalizeForMatching` runs NFKC first, which expands
 * `ß` to two characters, and a length-preserving fold cannot undo that.
 */
export function compile(source: string): RegExp {
  return new RegExp(foldLatinDiacritics(source).replace(/\\b/gu, BOUNDARY), 'u');
}

const COMBINING_MARK = /\p{M}/u;

/**
 * Maps precomposed Latin letters with diacritics onto their ASCII base, one code point to one.
 *
 * Length-preserving on purpose: pack patterns run against the folded text, and the match index is
 * then used to excerpt the *unfolded* `matchText`. NFKD would expand "é" into two code points and
 * every later index would point at the wrong character.
 *
 * Combining marks that already stand alone are left in place rather than deleted, for the same
 * reason. `normalizeForMatching` runs NFKC first, so ordinary mail reaches here precomposed.
 */
export function foldLatinDiacritics(text: string): string {
  let out = '';
  for (const char of text) {
    const nfd = char.normalize('NFD');
    const base = nfd[0];
    if (base === undefined || nfd.length === 1 || !/\p{L}/u.test(base)) {
      out += char;
      continue;
    }
    let marksOnly = true;
    for (const mark of nfd.slice(1)) {
      if (!COMBINING_MARK.test(mark)) {
        marksOnly = false;
        break;
      }
    }
    out += marksOnly ? base : char;
  }
  return out;
}
