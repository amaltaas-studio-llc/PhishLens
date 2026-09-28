/**
 * Per-tab model answers, keyed by prompt. Gmail redraws a message as its authentication and attachments
 * arrive, which the model is never shown, so a redraw joins or replays the reading instead of asking
 * again. Technical evidence is rescored on every view.
 */
import { buildUserPrompt } from '../analysis/llm/prompt.js';
import type {
  AiMode,
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzer,
} from '../shared/types.js';

/**
 * Keys are the full prompt rather than a hash of it: a collision would put one message's reading on
 * another, and fifty prompts of a few kilobytes is not memory worth a risk of that shape.
 */
const MAX_READINGS = 50;

/**
 * What the model would be shown, as a key.
 *
 * The cloud adapter also sends the deterministic signal ids, so for that mode they are part of what was
 * asked; for the others they are not, which is exactly why a late authentication result can reuse a
 * reading there.
 */
export function readingKey(
  email: EmailMessage,
  aiMode: AiMode,
  signalIds: readonly string[],
): string {
  const prompt = buildUserPrompt(email);
  return aiMode === 'cloud' ? `${prompt}\n${[...signalIds].sort().join(',')}` : prompt;
}

interface InFlight {
  key: string;
  abort: AbortController;
  promise: Promise<SemanticAnalysis | null>;
}

export interface Lookup {
  analyzer: SemanticAnalyzer;
  /** A settled reading will answer; no inference runs. */
  reused: boolean;
}

export class Readings {
  readonly #settled = new Map<string, SemanticAnalysis>();
  #inFlight: InFlight | null = null;
  #generation = 0;
  #key: string | null = null;

  /** A completed reading remains useful even when new evidence no longer calls for inference. */
  has(key: string): boolean {
    return this.#settled.has(key);
  }

  /**
   * An analyzer for `key` that answers from a settled reading, joins the one in flight, or asks
   * `resolve()`'s analyzer — built only in the last case, so a replay constructs nothing.
   *
   * The caller's abort signal is deliberately not forwarded to the shared inference. A view being
   * replaced by another view *of the same text* is the case this class exists for, and forwarding it
   * would cancel the work the replacement is about to join. The controller's token already keeps a
   * superseded view's answer off the screen; cancelling the inference itself is `cancelUnless`'s job.
   */
  lookup(key: string, resolve: () => SemanticAnalyzer | null): Lookup | null {
    this.cancelUnless(key);
    const settled = this.#settled.get(key);
    if (settled !== undefined) {
      return { analyzer: replay(Promise.resolve(settled)), reused: true };
    }

    const current = this.#inFlight;
    if (current?.key === key) return { analyzer: replay(current.promise), reused: false };

    const inner = resolve();
    if (inner === null) return null;
    return { analyzer: this.#starting(key, inner), reused: false };
  }

  /** Stops an inference in flight unless it is the one `key` would join. */
  cancelUnless(key: string | null): void {
    if (this.#key === key) return;
    this.#key = key;
    this.#generation++;
    this.#inFlight?.abort.abort();
    this.#inFlight = null;
  }

  /** Forgets everything: the readings belong to a model that is no longer the one being asked. */
  clear(): void {
    this.cancelUnless(null);
    this.#settled.clear();
  }

  /**
   * Wraps `inner` so its first `analyze()` becomes the shared inference for `key`.
   *
   * The generation is checked around `isAvailable()` as well as the inference, because the reader can
   * leave while a model is still loading; an unavailable model is still reported as one.
   */
  #starting(key: string, inner: SemanticAnalyzer): SemanticAnalyzer {
    const generation = this.#generation;
    const valid = (): boolean => generation === this.#generation;
    return {
      id: inner.id,
      isAvailable: async () => valid() && await inner.isAvailable() && valid(),
      analyze: (email) => {
        if (!valid()) return Promise.resolve(null);
        const current = this.#inFlight;
        if (current?.key === key) return current.promise;

        const abort = new AbortController();
        const promise = inner.analyze(email, { signal: abort.signal }).then((analysis) => {
          if (analysis !== null && valid() && !abort.signal.aborted) this.#remember(key, analysis);
          return analysis;
        });
        const entry: InFlight = { key, abort, promise };
        this.#inFlight = entry;

        const release = (): void => {
          if (this.#inFlight === entry) this.#inFlight = null;
        };
        promise.then(release, release);
        return promise;
      },
    };
  }

  #remember(key: string, analysis: SemanticAnalysis): void {
    this.#settled.delete(key);
    this.#settled.set(key, analysis);
    while (this.#settled.size > MAX_READINGS) {
      const oldest = this.#settled.keys().next();
      if (oldest.done === true) break;
      this.#settled.delete(oldest.value);
    }
  }
}

/** An analyzer whose answer is already decided, or already being decided elsewhere. */
function replay(answer: Promise<SemanticAnalysis | null>): SemanticAnalyzer {
  return {
    id: 'reading-cache',
    isAvailable: () => Promise.resolve(true),
    analyze: () => answer,
  };
}
