/**
 * The model's readings for this tab, keyed by exactly what the model was shown.
 *
 * The result cache in the controller is keyed by the view signature, which changes whenever Gmail
 * finishes drawing part of a message: the authentication summary and the attachment strip routinely
 * arrive a moment after the body. Each of those is a new view, and each one used to cancel the inference
 * in flight and start the same one again — on the on-device model, seconds of work thrown away per
 * message, for a question whose text had not changed. The model never sees authentication or
 * attachments (`llm/prompt.ts`), so its reading of the new view is the reading already under way.
 *
 * So a reading is found by its prompt: a settled one is replayed, and one in flight is joined rather
 * than restarted. The score around it is still rebuilt from the new view's checks every time; only the
 * model's answer is shared.
 *
 * Stateful, and therefore content-script only, for the same reason as the model session itself.
 */
import { buildUserPrompt } from '../analysis/llm/prompt.js';
import type {
  AiMode,
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzer,
} from '../shared/types.js';

/**
 * Bounded like the result cache. Keys are the full prompt rather than a hash of it: a collision would
 * put one message's reading on another, and fifty prompts of a few kilobytes is not memory worth a risk
 * of that shape.
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
    const current = this.#inFlight;
    if (current === null || current.key === key) return;
    current.abort.abort();
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
   * `isAvailable()` passes straight through, since the engine asks it before analysing and an
   * unavailable model must still be reported as one.
   */
  #starting(key: string, inner: SemanticAnalyzer): SemanticAnalyzer {
    return {
      id: inner.id,
      isAvailable: () => inner.isAvailable(),
      analyze: (email) => {
        const current = this.#inFlight;
        if (current?.key === key) return current.promise;

        const abort = new AbortController();
        const promise = inner.analyze(email, { signal: abort.signal }).then((analysis) => {
          if (analysis !== null && !abort.signal.aborted) this.#remember(key, analysis);
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
