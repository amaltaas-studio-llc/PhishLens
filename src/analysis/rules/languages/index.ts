/**
 * Language packs that extend the English content themes.
 *
 * A pack runs only when its language is detected in the message. English patterns always run; mixed
 * mail can activate several packs at once, so padding a phish with another language cannot switch a
 * check off.
 */
import { DETECTION_TUNING } from '../../scoring/config.js';
import { de } from './de.js';
import { es } from './es.js';
import { fr } from './fr.js';
import { hi } from './hi.js';
import { hinglish } from './hinglish.js';
import { it } from './it.js';
import { type LanguageId, type LanguagePack, compile } from './lexicon.js';
import { nl } from './nl.js';
import { pt } from './pt.js';

export {
  THEME_IDS,
  compile,
  foldLatinDiacritics,
  type LanguageId,
  type LanguagePack,
  type PackNegation,
  type ThemeId,
} from './lexicon.js';

export const LANGUAGE_PACKS: readonly LanguagePack[] = Object.freeze([
  es,
  fr,
  de,
  pt,
  it,
  nl,
  hi,
  hinglish,
]);

const DEVANAGARI_LETTER = /\p{Script=Devanagari}/u;
const ANY_LETTER = /\p{L}/u;

/**
 * Which packs' patterns should run against this text.
 *
 * Latin packs need several distinct function-word markers in the gating window. Hindi needs a share
 * of Devanagari letters among all letters. Markers are matched with the same Unicode boundary as
 * pack patterns, so a marker that is only a substring of an English word does not count.
 */
export function detectLanguages(text: string): readonly LanguagePack[] {
  const window = text.slice(0, DETECTION_TUNING.languageMarkerWindowChars);
  const active: LanguagePack[] = [];

  for (const pack of LANGUAGE_PACKS) {
    if (pack.script === 'devanagari') {
      if (devanagariShare(window) >= DETECTION_TUNING.devanagariLetterShare) active.push(pack);
      continue;
    }
    if (distinctMarkers(window, pack.markers) >= DETECTION_TUNING.languageMarkerMinDistinct) {
      active.push(pack);
    }
  }
  return active;
}

function distinctMarkers(text: string, markers: readonly string[]): number {
  const seen = new Set<string>();
  for (const marker of markers) {
    if (seen.has(marker)) continue;
    // Anchored per marker so a short particle cannot match inside a longer English word.
    if (compile(String.raw`\b${escapeRegExp(marker)}\b`).test(text)) seen.add(marker);
  }
  return seen.size;
}

function devanagariShare(text: string): number {
  let letters = 0;
  let devanagari = 0;
  for (const char of text) {
    if (!ANY_LETTER.test(char)) continue;
    letters += 1;
    if (DEVANAGARI_LETTER.test(char)) devanagari += 1;
  }
  return letters === 0 ? 0 : devanagari / letters;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/** Stable list of pack ids, for docs and tests. */
export const LANGUAGE_IDS: readonly LanguageId[] = LANGUAGE_PACKS.map((pack) => pack.id);
