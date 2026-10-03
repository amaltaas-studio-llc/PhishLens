/**
 * Strict validation of model output.
 *
 * The contract is all-or-nothing for what is scored: a missing or non-numeric `risk` or `confidence`,
 * or no usable reason, yields `null` and the `llm` category contributes zero, because a model that
 * returned a malformed object is a model whose *values* we have no reason to trust either, and a
 * hostile email may well be the reason the output is malformed. The lists are filtered rather than
 * rejected: a non-string reason or an unknown category is dropped, since neither can raise the score
 * and the remaining entries are still the model's own words.
 */
import { collapseWhitespace } from '../../shared/text.js';
import {
  SEMANTIC_CATEGORIES,
  type SemanticAnalysis,
  type SemanticCategory,
} from '../../shared/types.js';
import { SEMANTIC_SCORING } from '../scoring/config.js';

const CATEGORY_SET: ReadonlySet<string> = new Set(SEMANTIC_CATEGORIES);
const MAX_REASON_CHARS = 240;

/**
 * Extracts a JSON object from a model response.
 *
 * Models wrap JSON in code fences and add lead-in prose even when told not to. Tolerating that is
 * about the *envelope* only; the object inside is still validated strictly.
 */
export function extractJsonObject(raw: string): unknown {
  const text = raw.trim();
  if (text === '') return null;

  const fenced = /```(?:json)?\s*([\s\S]*?)```/iu.exec(text);
  const candidates = [fenced?.[1]?.trim(), text, sliceOutermostBraces(text)].filter(
    (c): c is string => c !== undefined && c !== '',
  );

  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

function sliceOutermostBraces(text: string): string {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  return start >= 0 && end > start ? text.slice(start, end + 1) : '';
}

/**
 * Validates and normalises a parsed object into a `SemanticAnalysis`.
 * Returns `null` if anything required is missing or the wrong type.
 */
export function parseSemanticAnalysis(
  raw: unknown,
  source: SemanticAnalysis['source'],
  model?: string,
): SemanticAnalysis | null {
  const object = typeof raw === 'string' ? extractJsonObject(raw) : raw;
  if (object === null || typeof object !== 'object' || Array.isArray(object)) return null;

  const record = object as Record<string, unknown>;

  const risk = toBoundedNumber(record['risk'], 0, 100);
  if (risk === null) return null;

  const confidence = toBoundedNumber(record['confidence'], 0, 1);
  if (confidence === null) return null;

  const reasons = toReasons(record['reasons']);
  if (reasons.length === 0) return null;

  const categories = toCategories(record['categories']);

  return {
    risk: Math.round(risk),
    categories,
    reasons,
    confidence,
    source,
    ...(model !== undefined && model !== '' ? { model } : {}),
  };
}

function toBoundedNumber(value: unknown, min: number, max: number): number | null {
  const numeric =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim() !== ''
        ? Number(value)
        : Number.NaN;
  if (!Number.isFinite(numeric)) return null;
  return Math.min(Math.max(numeric, min), max);
}

function toReasons(value: unknown): string[] {
  const list = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
  return list
    .filter((r): r is string => typeof r === 'string')
    .map((r) => boundReason(collapseWhitespace(r)))
    .filter((r) => r.length > 0)
    .slice(0, SEMANTIC_SCORING.maxReasons);
}

/**
 * A reason past the word or character cap, cut where a reader can stop.
 *
 * A hard slice would end reasons mid-word: the cut is inside a statement and looks like the model gave
 * up. Keep the words that fit, then prefer ending on the last complete sentence among
 * them (unmarked, since nothing of that sentence is missing) and otherwise end on a word with `…`.
 * Text without spaces (Japanese, a pasted token) has no words to count, so the character cap decides.
 */
function boundReason(text: string): string {
  // Bounds the work below; nothing past this could survive either cap.
  const head = text.slice(0, MAX_REASON_CHARS * 2);
  const words = head.split(' ');
  if (words.length <= SEMANTIC_SCORING.maxReasonWords && text.length <= MAX_REASON_CHARS) return text;

  const kept = codePointPrefix(
    words.slice(0, SEMANTIC_SCORING.maxReasonWords).join(' '),
    MAX_REASON_CHARS - 1,
  );

  const sentence = lastSentenceEnd(kept);
  if (sentence >= kept.length / 2) return kept.slice(0, sentence).trimEnd();

  // `kept` is a prefix of `text`, so the character after it says whether the cap split a word.
  const lastSpace = kept.lastIndexOf(' ');
  const splitWord = !/\s/u.test(text[kept.length] ?? ' ');
  const cut = splitWord && lastSpace > kept.length / 2 ? kept.slice(0, lastSpace) : kept;
  return `${cut.replace(/[\s,;:–\u2014-]+$/u, '')}…`;
}

/** The longest prefix of at most `limit` UTF-16 units that does not split a surrogate pair. */
function codePointPrefix(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const code = text.charCodeAt(limit - 1);
  return text.slice(0, code >= 0xd800 && code <= 0xdbff ? limit - 1 : limit);
}

/**
 * Index just past the last sentence end in `text`, or -1.
 *
 * Three things look like a sentence end and are not. A period inside a quotation ends the quoted
 * excerpt, not the reason: the prompt asks for an excerpt *followed by* why it matters, so cutting
 * there keeps the email's words and drops the explanation. A period followed by a lowercase word is an
 * abbreviation ("Northwind Inc. and"). And a period followed by anything but whitespace is `0.35` or
 * a domain. The CJK stops need no following space, since those scripts do not use one.
 */
function lastSentenceEnd(text: string): number {
  let end = -1;
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === '"') quoted = !quoted;
    else if (char === '“') quoted = true;
    else if (char === '”') quoted = false;
    else if (char === '。' || char === '！' || char === '？') {
      if (!quoted) end = i + 1;
    } else if ((char === '.' || char === '!' || char === '?') && !quoted) {
      const next = text[i + 1];
      if (next === undefined) end = i + 1;
      else if (/\s/u.test(next) && !/\p{Ll}/u.test(text[i + 2] ?? '')) end = i + 1;
    }
  }
  return end;
}

function toCategories(value: unknown): SemanticCategory[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<SemanticCategory>();
  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const normalized = entry.trim().toLowerCase().replace(/[\s-]+/gu, '_');
    if (CATEGORY_SET.has(normalized)) seen.add(normalized as SemanticCategory);
    if (seen.size >= 4) break;
  }
  return [...seen];
}
