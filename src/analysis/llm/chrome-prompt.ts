/**
 * Chrome on-device model adapter (the Prompt API / built-in AI).
 *
 * The API surface is unstable, so finding it and reading its state live in `on-device.ts`, where every
 * shape is probed rather than assumed. `analyze()` returns `null` for both "no model" and "nothing usable
 * came back", so the pipeline needs no special case for either.
 *
 * Two structural constraints shape the class:
 *  - The session is expensive, so it is cached. That is only sound in the content script, which lives
 *    as long as the tab; the service worker MV3 terminates when idle must never load this module.
 *  - A session takes one prompt at a time, so all model work is serialised through `#enqueue`.
 */
import { isAborted } from '../../shared/abort.js';
import { logger } from '../../shared/logger.js';
import type {
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzeOptions,
  SemanticAnalyzer,
} from '../../shared/types.js';
import {
  findFactory,
  fn,
  isRecord,
  OUTPUT_LANGUAGE,
  probeAvailability,
  type OnDeviceModelState,
  type UnknownRecord,
} from './on-device.js';
import { parseSemanticAnalysis } from './parse.js';
import { RESPONSE_SCHEMA, SYSTEM_PROMPT, buildUserPrompt, describePromptShape } from './prompt.js';

/** Milliseconds before a single on-device inference is abandoned. */
const INFERENCE_TIMEOUT_MS = 20_000;

/** Deterministic settings where the API supports them. */
const DETERMINISTIC_OPTIONS = { temperature: 0, topK: 1 };

/**
 * Per-prompt options, most useful first: a schema constraint that keeps the schema out of the input,
 * the constraint alone, then nothing. Each has been the only one some Chrome version accepts.
 */
const PROMPT_SHAPES: readonly (UnknownRecord | undefined)[] = [
  { responseConstraint: RESPONSE_SCHEMA, omitResponseConstraintInput: true },
  { responseConstraint: RESPONSE_SCHEMA },
  undefined,
];

interface Session {
  prompt(input: string, options?: UnknownRecord): Promise<unknown>;
  /** Branches a session from its current state. Present since early builds, but not guaranteed. */
  clone?: () => Promise<Session | null>;
  destroy?: () => void;
}

function asSession(value: unknown): Session | null {
  if (!isRecord(value)) return null;
  const prompt = fn(value, 'prompt');
  if (prompt === null) return null;
  const clone = fn(value, 'clone');
  return {
    ...(clone !== null
      ? {
          clone: async (): Promise<Session | null> => asSession(await clone.call(value)),
        }
      : {}),
    prompt: async (input: string, options?: UnknownRecord) => {
      const result: unknown = options === undefined
        ? await prompt.call(value, input)
        : await prompt.call(value, input, options);
      return result;
    },
    ...(fn(value, 'destroy') !== null
      ? {
          destroy: () => {
            try {
              fn(value, 'destroy')?.call(value);
            } catch {
              // A session that will not close is not worth reporting.
            }
          },
        }
      : {}),
  };
}

/**
 * A session branched from `template`, or `null` when this build cannot branch one.
 *
 * `clone()` exists in the Prompt API for exactly this: it copies the session's state — including the
 * system prompt, which is the part that must not be lost — without re-loading the model, so per-message
 * isolation costs almost nothing where it is supported.
 */
async function branch(template: Session): Promise<Session | null> {
  if (template.clone === undefined) return null;
  try {
    return await template.clone();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class ChromePromptAnalyzer implements SemanticAnalyzer {
  readonly id = 'chrome-on-device';

  /**
   * Cached *template* session, kept pristine and cloned per message. Valid only in a long-lived context
   * (the content script), which is why this adapter is not in the service worker.
   */
  #session: Session | null = null;
  #disposed = false;
  /**
   * Whether the cached session was created with the system prompt attached.
   *
   * False only on the last-resort bare `create({})`. Every instruction that makes the output usable
   * lives in `SYSTEM_PROMPT` — the JSON contract, the calibration against over-flagging, and the
   * framing of message text as data rather than instructions — so a session without it must be given
   * the same text inline instead. Running without it at all would quietly produce an uncalibrated,
   * injection-exposed verdict that looks exactly like a normal one.
   */
  #sessionHasSystemPrompt = false;
  #factoryLabel = '';
  /** Set once availability has been determined, to avoid re-probing on every message. */
  #availability: OnDeviceModelState | 'unknown' = 'unknown';
  /** Index into `PROMPT_SHAPES` of the options this browser last accepted, once one has been. */
  #promptShape: number | null = null;

  /**
   * Tail of the queue of pending model work. Every use of the session goes through `#enqueue`.
   *
   * A session accepts one prompt at a time and rejects a second while the first is outstanding. Since a
   * rejected inference is treated as a poisoned session and destroys it, concurrent calls do not merely
   * queue badly — they lose each other's results. Gmail renders a thread in stages and each stage looks
   * like a new message to the observer, so concurrency here is the normal case, not an edge one.
   */
  #chain: Promise<unknown> = Promise.resolve();

  async isAvailable(): Promise<boolean> {
    try {
      if (this.#availability === 'unknown') {
        const factory = findFactory();
        if (factory === null) {
          this.#availability = 'unsupported';
          logger.debug('on-device model: no factory global present');
          return false;
        }
        this.#factoryLabel = factory.label;
        this.#availability = await probeAvailability(factory.host);
        logger.debug('on-device model probe', {
          factory: factory.label,
          availability: this.#availability,
        });
      }
      // A model still to download is deliberately not available: triggering a multi-hundred-
      // megabyte download because a user opened an email would be an unacceptable surprise.
      return this.#availability === 'available';
    } catch (error) {
      // Any unexpected shape or thrown error resolves to false. Never propagate.
      this.#availability = 'unavailable';
      logger.debug('on-device model probe failed', error);
      return false;
    }
  }

  /**
   * Loads the model and builds the session ahead of first use.
   *
   * Called at content-script startup so the several seconds of session creation are spent while the
   * user is still looking at their inbox, rather than after they open the first message. Never
   * downloads: `isAvailable()` is false unless the model is already on disk, so a cold browser warms
   * nothing and costs nothing.
   */
  async warmUp(): Promise<void> {
    try {
      if (!(await this.isAvailable())) return;
      const session = await this.#enqueue(() => this.#ensureSession());
      logger.debug('on-device model warm-up', { session: session !== null });
    } catch (error) {
      logger.debug('on-device model warm-up failed', error);
    }
  }

  async analyze(
    email: EmailMessage,
    options: SemanticAnalyzeOptions = {},
  ): Promise<SemanticAnalysis | null> {
    if (!(await this.isAvailable())) return null;
    return this.#enqueue(() => this.#analyzeOne(email, options));
  }

  async #analyzeOne(
    email: EmailMessage,
    options: SemanticAnalyzeOptions,
  ): Promise<SemanticAnalysis | null> {
    // Reached the front of the queue only to find the reader has moved on. Whatever is on screen now
    // is not this message, so the cheapest correct thing is to not run at all.
    if (isAborted(options.signal)) return null;

    /*
     * Every message is analysed in a session of its own.
     *
     * A Prompt API session is a conversation: each prompt and each reply stay in its context. Reusing
     * one across messages therefore asks the model to judge this message *having just judged the last
     * one*, which is wrong in three ways of increasing seriousness. The context fills up with mail the
     * reader has finished with, until an inference fails for length on a busy morning and the failure
     * looks like an unavailable model. A verdict anchors on its predecessor, so the same message scores
     * differently depending on what was read before it — the opposite of a check you can reproduce. And
     * the wording of one message reaches the judgement of the next, which hands any message in the
     * mailbox a channel for steering the assessment of every message after it.
     */
    let working: Session | null = null;
    let spentTemplate = false;
    try {
      const template = await this.#ensureSession();
      if (template === null) return null;

      working = await branch(template);
      if (working === null) {
        // No `clone` on this build. Prompting the cached session spends it, so it is retired below.
        working = template;
        spentTemplate = true;
      }

      const user = buildUserPrompt(email);
      const prompt = this.#sessionHasSystemPrompt ? user : `${SYSTEM_PROMPT}\n\n${user}`;
      logger.debug('on-device inference starting', {
        shape: describePromptShape(email),
        cloned: !spentTemplate,
      });

      const raw = await this.#promptWithTimeout(working, prompt, options.signal);
      if (raw === null) return null;

      const analysis = parseSemanticAnalysis(raw, 'local', this.#factoryLabel);
      if (analysis === null) {
        logger.debug('on-device output rejected by schema validation');
      }
      return analysis;
    } catch (error) {
      // A failed session is assumed poisoned; the next call rebuilds it.
      this.#discardSession();
      logger.debug('on-device inference failed', error);
      return null;
    } finally {
      if (spentTemplate) this.#retireSession();
      else working?.destroy?.();
    }
  }

  /**
   * Releases a session that has now seen a message, and builds its replacement behind the queue.
   *
   * Only reached on a build without `clone`, where isolation costs a session creation per message. The
   * rebuild is queued rather than awaited so that cost is paid while the reader is still reading, which
   * is the same reason `warmUp()` exists.
   */
  #retireSession(): void {
    this.#discardSession();
    void this.#enqueue(() => this.#ensureSession()).catch(() => undefined);
  }

  /**
   * Runs `job` after all previously queued model work has finished.
   *
   * The queue tail is kept as a promise that never rejects, so one failed inference cannot break the
   * chain for every subsequent message.
   */
  #enqueue<T>(job: () => Promise<T>): Promise<T> {
    const run = this.#chain.then(job);
    this.#chain = run.catch(() => undefined);
    return run;
  }

  /**
   * Creates a session, reusing the cached one when present.
   *
   * Tries the modern `initialPrompts` system-role shape first, then the older `systemPrompt` option,
   * then a bare create — each historically valid, none guaranteed.
   */
  async #ensureSession(): Promise<Session | null> {
    // A queued rebuild can outlive teardown, and a session created after it would never be released.
    if (this.#isDisposed()) return null;
    if (this.#session !== null) return this.#session;

    const factory = findFactory();
    if (factory === null) return null;
    const create = fn(factory.host, 'create');
    if (create === null) return null;

    const attempts: { options: UnknownRecord; system: boolean }[] = [
      {
        options: {
          ...DETERMINISTIC_OPTIONS,
          initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }],
        },
        system: true,
      },
      { options: { ...DETERMINISTIC_OPTIONS, systemPrompt: SYSTEM_PROMPT }, system: true },
      { options: { initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }] }, system: true },
      { options: {}, system: false },
    ].map((attempt) => ({ ...attempt, options: { ...OUTPUT_LANGUAGE, ...attempt.options } }));

    for (const attempt of attempts) {
      try {
        const session = asSession(await create.call(factory.host, attempt.options));
        if (session !== null) {
          // Teardown can land during the seconds a creation takes, and a session stored afterwards is
          // one nothing will ever release.
          if (this.#isDisposed()) {
            session.destroy?.();
            return null;
          }
          this.#session = session;
          this.#sessionHasSystemPrompt = attempt.system;
          return session;
        }
      } catch {
        // Options rejected by this Chrome version; try the next shape.
      }
    }
    logger.debug('on-device session could not be created with any known option shape');
    return null;
  }

  /**
   * Runs one inference with a timeout, requesting a JSON-schema constraint when the version supports
   * it and retrying unconstrained when it does not.
   *
   * The retry loop is why abort needs explicit handling. Its `catch` exists to swallow "this Chrome
   * version rejected that option shape" and try the next one, and an abort arrives as a rejection too
   * — so without the check below, cancelling would silently run all three attempts instead of none.
   */
  async #promptWithTimeout(
    session: Session,
    prompt: string,
    signal?: AbortSignal,
  ): Promise<string | null> {
    for (const index of this.#shapeOrder()) {
      if (isAborted(signal)) return null;
      const options = PROMPT_SHAPES[index];
      // Passed to the API as well as checked here: the API can stop work already in progress, which
      // this loop cannot.
      const withSignal = signal === undefined ? options : { ...options, signal };

      try {
        const result = await withTimeout(session.prompt(prompt, withSignal), INFERENCE_TIMEOUT_MS);
        if (typeof result === 'string' && result.trim() !== '') {
          this.#promptShape = index;
          return result;
        }
      } catch (error) {
        if (isAborted(signal)) return null;
        if (error instanceof TimeoutError) {
          this.#discardSession();
          return null;
        }
        // Unsupported option shape; fall through to the next attempt.
      }
    }
    return null;
  }

  /**
   * The shapes to try, the one that last worked first.
   *
   * The browser does not change under a tab, so a shape it rejected once it will reject every time — and
   * a rejection is not free: an unsupported option can be refused only after the input has been read.
   * The rest of the ladder is kept behind it rather than dropped, because the remembered shape can also
   * fail for a reason that is about the message, and a fallback that has stopped existing cannot help.
   */
  #shapeOrder(): number[] {
    const all = PROMPT_SHAPES.map((_shape, index) => index);
    const known = this.#promptShape;
    return known === null ? all : [known, ...all.filter((index) => index !== known)];
  }

  /**
   * Read through a method because the flag is checked either side of an `await`, and narrowing does not
   * survive one: read directly, the second check is dead code as far as the compiler is concerned.
   */
  #isDisposed(): boolean {
    return this.#disposed;
  }

  #discardSession(): void {
    this.#session?.destroy?.();
    this.#session = null;
    this.#sessionHasSystemPrompt = false;
  }

  /** Releases the on-device session. Called when the content script tears down. */
  dispose(): void {
    this.#disposed = true;
    this.#discardSession();
  }
}

class TimeoutError extends Error {
  constructor() {
    super('inference timed out');
    this.name = 'TimeoutError';
  }
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new TimeoutError());
        }, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
