/**
 * Score aggregation — pure functions, no detector knowledge, no I/O.
 *
 * This is deliberately separable from detection so the weighting rule can be retuned or replaced
 * without touching a single detector, and so it can be unit-tested on synthetic signals that no
 * detector would ever produce.
 *
 * The rule, in order:
 *   1. clamp each signal's score to `[0, ceiling(severity)]`
 *   2. sum within a category, then cap the subtotal at that category's weight
 *   3. sum the capped subtotals and clamp to `[0, 100]`
 */
import type {
  AnalysisResult,
  Classification,
  SecuritySignal,
  Severity,
  SignalCategory,
} from '../../shared/types.js';
import {
  ALL_CATEGORIES,
  CLASSIFICATION_THRESHOLDS,
  DEFAULT_SCORING_CONFIG,
  SCORE_FLOORS,
  SEVERITY_CEILINGS,
  SEVERITY_ORDER,
  type CategoryWeights,
  type ScoringConfig,
  type SeverityCeilings,
} from './config.js';

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(value, min), max);
}

/**
 * A single signal's effective contribution: its raw score clamped to its severity's ceiling.
 * A detector claiming 90 points at `low` severity gets 15.
 */
export function cappedSignalScore(
  signal: SecuritySignal,
  ceilings: SeverityCeilings = SEVERITY_CEILINGS,
): number {
  return clamp(signal.score, 0, ceilings[signal.severity]);
}

/**
 * One category's contribution to the total.
 *
 * Signals are summed after individual capping, then the subtotal is capped at `weight`, so a
 * category can never contribute more than its allotted share of 100 no matter how many signals fire.
 */
export function aggregateCategory(
  signals: SecuritySignal[],
  weight: number,
  ceilings: SeverityCeilings = SEVERITY_CEILINGS,
): number {
  const cap = Math.max(0, weight);
  let subtotal = 0;
  for (const signal of signals) {
    subtotal += cappedSignalScore(signal, ceilings);
    if (subtotal >= cap) return cap;
  }
  return clamp(subtotal, 0, cap);
}

export type SignalsByCategory = Partial<Record<SignalCategory, SecuritySignal[]>>;

export interface TotalScore {
  total: number;
  byCategory: Record<SignalCategory, number>;
}

/** Groups a flat signal list by category, always returning an entry for every category. */
export function groupByCategory(signals: readonly SecuritySignal[]): Record<SignalCategory, SecuritySignal[]> {
  const grouped = Object.fromEntries(
    ALL_CATEGORIES.map((c) => [c, [] as SecuritySignal[]]),
  ) as Record<SignalCategory, SecuritySignal[]>;

  for (const signal of signals) {
    // A signal whose category is not one we score is dropped rather than silently counted as
    // something else. The union type makes this unreachable in typed code, but the semantic layer
    // feeds in values that originated as model output, so it is checked at runtime.
    if (!ALL_CATEGORIES.includes(signal.category)) continue;
    grouped[signal.category].push(signal);
  }
  return grouped;
}

/**
 * The total score: sum of capped category subtotals, clamped to `[0, 100]`.
 *
 * With the default weights summing to exactly 100 the outer clamp is unreachable, which is
 * intentional — it is a guard against a misconfigured weight table, not part of normal operation.
 */
export function computeTotalScore(
  signalsByCategory: SignalsByCategory,
  weights: CategoryWeights = DEFAULT_SCORING_CONFIG.categoryWeights,
  ceilings: SeverityCeilings = DEFAULT_SCORING_CONFIG.severityCeilings,
): TotalScore {
  const byCategory = Object.fromEntries(
    ALL_CATEGORIES.map((category) => [
      category,
      aggregateCategory(signalsByCategory[category] ?? [], weights[category], ceilings),
    ]),
  ) as Record<SignalCategory, number>;

  const sum = ALL_CATEGORIES.reduce((acc, c) => acc + byCategory[c], 0);
  return { total: Math.round(clamp(sum, 0, 100)), byCategory };
}

/** Convenience wrapper for a flat signal list. */
export function scoreSignals(
  signals: readonly SecuritySignal[],
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
): TotalScore {
  return computeTotalScore(groupByCategory(signals), config.categoryWeights, config.severityCeilings);
}

/**
 * Categories that added to the score, largest first — the order the card's ring and breakdown share,
 * and the one the diagnostic report prints, so the two can never disagree.
 */
export function contributions(
  result: Pick<AnalysisResult, 'categoryScores'>,
): [SignalCategory, number][] {
  return (Object.entries(result.categoryScores) as [SignalCategory, number][])
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1]);
}

/** What the categories sum to, which is below the score only when a floor applied. */
export function addedUp(result: Pick<AnalysisResult, 'categoryScores'>): number {
  return contributions(result).reduce((sum, [, value]) => sum + value, 0);
}

export interface ScoreFloor {
  floor: number;
  /**
   * What established it: one conclusive finding, or severe findings converging from several
   * categories. `null` when nothing did. The panel words the two differently, because "the minimum for
   * this finding" is false when no single finding sets it.
   */
  basis: 'finding' | 'convergence' | null;
  /** The categories that converged, in `ALL_CATEGORIES` order. Empty unless `basis` is `convergence`. */
  categories: SignalCategory[];
}

/**
 * The minimum score established by *deterministic* findings, and which rule established it.
 *
 * `llm` signals are excluded by `SCORE_FLOORS.eligibleCategories`, so a semantic verdict can neither
 * raise a floor nor count towards convergence — see `config.ts` for why floors exist at all.
 */
export function scoreFloor(
  signals: readonly SecuritySignal[],
  floors: typeof SCORE_FLOORS = SCORE_FLOORS,
): ScoreFloor {
  let single = 0;
  const severe = new Set<SignalCategory>();
  for (const signal of signals) {
    if (!floors.eligibleCategories.includes(signal.category)) continue;
    // Findings borrowed from another system do not establish a floor, only our own do.
    if (floors.excludedSignalIds.includes(signal.id)) continue;
    // A signal claiming zero points is an informational note; it does not establish a floor.
    if (signal.score <= 0) continue;
    single = Math.max(single, floors.bySeverity[signal.severity] ?? 0);
    // A dampened finding is explained by a proven sender, which is the opposite of independent evidence.
    if (signal.dampened !== true && isAtLeast(signal.severity, floors.convergence.minSeverity)) {
      severe.add(signal.category);
    }
  }

  const converged = severe.size >= floors.convergence.minCategories ? floors.convergence.floor : 0;
  // A tie goes to the single finding: it is the stronger explanation, and the one a reader can check alone.
  if (converged > single) {
    return {
      floor: clamp(converged, 0, 100),
      basis: 'convergence',
      categories: ALL_CATEGORIES.filter((c) => severe.has(c)),
    };
  }
  return { floor: clamp(single, 0, 100), basis: single > 0 ? 'finding' : null, categories: [] };
}

export function severityFloor(
  signals: readonly SecuritySignal[],
  floors: typeof SCORE_FLOORS = SCORE_FLOORS,
): number {
  return scoreFloor(signals, floors).floor;
}

/** Applies the floor to an additive total. Only ever raises it. */
export function applyFloor(
  total: number,
  signals: readonly SecuritySignal[],
  floors: typeof SCORE_FLOORS = SCORE_FLOORS,
): number {
  return Math.max(clamp(total, 0, 100), severityFloor(signals, floors));
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export function classify(
  score: number,
  thresholds: readonly { min: number; classification: Classification }[] = CLASSIFICATION_THRESHOLDS,
): Classification {
  const bounded = clamp(score, 0, 100);
  // Thresholds are ordered descending by `min`; the first match wins.
  const ordered = [...thresholds].sort((a, b) => b.min - a.min);
  for (const band of ordered) {
    if (bounded >= band.min) return band.classification;
  }
  return 'low';
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

function rank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function isAtLeast(severity: Severity, minimum: Severity): boolean {
  return rank(severity) >= rank(minimum);
}

export function lowerSeverity(severity: Severity, steps: number): Severity {
  const lowered = clamp(rank(severity) - steps, 0, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[lowered] ?? 'info';
}

/**
 * Two findings read the same when everything the reader is shown matches, which leaves only where in the
 * message they point — the id's link index and the evidence URL — to differ.
 */
export function displayKey(signal: SecuritySignal): string {
  return [
    signal.category,
    signal.severity,
    signal.title,
    signal.description,
    signal.evidence?.value ?? '',
  ].join('\u0000');
}

/**
 * The first of each group of findings that read the same, in order.
 *
 * Display only. The dropped copies still scored, and still have to: `analyze()` rescores from the full
 * deterministic list when a model answers, so a collapsed list anywhere upstream of the panel would make
 * the score depend on whether a model was running.
 */
export function distinctForDisplay(signals: readonly SecuritySignal[]): SecuritySignal[] {
  const seen = new Set<string>();
  return signals.filter((signal) => {
    const key = displayKey(signal);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Sorts signals for presentation: most severe first, then by score, then stably by id. */
export function sortSignalsForDisplay(signals: readonly SecuritySignal[]): SecuritySignal[] {
  return [...signals].sort((a, b) => {
    const bySeverity = rank(b.severity) - rank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    if (b.score !== a.score) return b.score - a.score;
    return a.id.localeCompare(b.id);
  });
}
