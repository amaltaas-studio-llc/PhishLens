/**
 * Finding Chrome's on-device model and asking what state it is in.
 *
 * Separate from the adapter so the welcome page can ask without bundling the prompt, the parser and the
 * analyzer it never runs. The API surface is unstable (the entry point, the availability method and its
 * values have all differed between Chrome versions), so every shape is probed rather than assumed, and
 * anything unexpected resolves to "unavailable" instead of throwing.
 */

// ---------------------------------------------------------------------------
// Structural probing (no `any`, no optimistic casts)
// ---------------------------------------------------------------------------

export type UnknownRecord = Record<string, unknown>;

/**
 * The prompt asks for English JSON, and current Chrome warns on every request that does not say so.
 * Only the output is declared: the mail being read can be in any language, and declaring English input
 * would claim otherwise. Builds that predate the option ignore it, as dictionaries ignore unknown keys.
 * Passed to `availability()` as well as `create()`, since Chrome answers availability per language.
 */
export const OUTPUT_LANGUAGE = { expectedOutputs: [{ type: 'text', languages: ['en'] }] } as const;

export function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null;
}

/**
 * Whether properties can be read off `value`.
 *
 * Broader than `isRecord` on purpose: the current entry point is a class, so it is function-typed and
 * an object-only check rejects the real API. Availability *results* still use `isRecord`, since a
 * function there would mean something is wrong.
 */
function isPropertyHost(value: unknown): value is UnknownRecord {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

export function fn(host: unknown, name: string): ((...args: unknown[]) => unknown) | null {
  if (!isPropertyHost(host)) return null;
  const candidate = host[name];
  return typeof candidate === 'function' ? (candidate as (...args: unknown[]) => unknown) : null;
}

/**
 * Locates the language-model factory across the shapes this API has shipped as.
 * Returns the object that exposes `create()`, or `null`.
 */
export function findFactory(): { host: UnknownRecord; label: string } | null {
  const g = globalThis as unknown as UnknownRecord;

  // Current: bare `LanguageModel` global (Chrome 138+ in extensions, 148+ on the web). This is a
  // class, so it is function-typed; see `isPropertyHost`.
  const bare = g['LanguageModel'];
  if (isPropertyHost(bare) && fn(bare, 'create') !== null) {
    return { host: bare, label: 'LanguageModel' };
  }

  // Earlier: `window.ai.languageModel`.
  const ai = g['ai'];
  if (isPropertyHost(ai)) {
    const languageModel = ai['languageModel'];
    if (isPropertyHost(languageModel) && fn(languageModel, 'create') !== null) {
      return { host: languageModel, label: 'window.ai.languageModel' };
    }
  }

  // Origin-trial era: `chrome.aiOriginTrial.languageModel`.
  const chromeNs = g['chrome'];
  if (isPropertyHost(chromeNs)) {
    const trial = chromeNs['aiOriginTrial'];
    if (isPropertyHost(trial)) {
      const languageModel = trial['languageModel'];
      if (isPropertyHost(languageModel) && fn(languageModel, 'create') !== null) {
        return { host: languageModel, label: 'chrome.aiOriginTrial.languageModel' };
      }
    }
  }
  return null;
}

/**
 * What Chrome says about its on-device model. `unsupported` means this build offers no Prompt API at
 * all, which a user fixes by updating Chrome; `unavailable` means it offers one but not the model, which
 * they fix (if the device qualifies) in `chrome://settings/system`.
 */
export type OnDeviceModelState =
  | 'available'
  | 'downloadable'
  | 'downloading'
  | 'unavailable'
  | 'unsupported';

/** Normalises the two historical availability reporting shapes to a single verdict. */
export async function probeAvailability(
  host: UnknownRecord,
): Promise<Exclude<OnDeviceModelState, 'unsupported'>> {
  const availability = fn(host, 'availability');
  if (availability !== null) {
    const result: unknown = await availability.call(host, OUTPUT_LANGUAGE);
    if (typeof result === 'string') {
      if (result === 'available' || result === 'downloadable' || result === 'downloading') return result;
      return 'unavailable';
    }
  }

  const capabilities = fn(host, 'capabilities');
  if (capabilities !== null) {
    const result: unknown = await capabilities.call(host);
    if (isRecord(result)) {
      const available = result['available'];
      if (available === 'readily') return 'available';
      if (available === 'after-download') return 'downloadable';
    }
    return 'unavailable';
  }

  // A factory that exposes `create()` but no availability probe at all. Assume unavailable rather
  // than triggering a model download as a side effect of a feature check.
  return 'unavailable';
}

/** The model's state as this context sees it. Never throws; anything unexpected is `unavailable`. */
export async function onDeviceModelState(): Promise<OnDeviceModelState> {
  try {
    const factory = findFactory();
    return factory === null ? 'unsupported' : await probeAvailability(factory.host);
  } catch {
    // Includes Chrome rejecting the probe when On-device AI is off (settings/system).
    return 'unavailable';
  }
}

/**
 * Chrome's message when the On-device AI user toggle (or a policy that looks like it) blocks execution.
 *
 * Calling `create()` while blocked also makes Chrome report a Mojo bad-message on the extension's
 * Errors page, so we must recognise this *before* create, not only after a rejection.
 */
export function isOnDeviceSettingDisabledError(error: unknown): boolean {
  const text =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : '';
  return (
    /feature flag gating model execution was disabled/i.test(text) ||
    /policy or user setting disabled/i.test(text)
  );
}

/** Outcome of a welcome-page download attempt. */
export type ModelDownloadOutcome =
  | { ok: true }
  | { ok: false; reason: 'unsupported' | 'unavailable' | 'failed' };

/**
 * Downloads the model by creating a session and releasing it, reporting progress as a fraction.
 *
 * Only for a click on the welcome page. Chrome downloads on `create()` and only with user activation,
 * and a download nobody asked for is exactly what the adapter's `isAvailable()` refuses to start from
 * Gmail.
 *
 * Re-checks availability immediately before `create()`. When On-device AI is off, Chrome's create path
 * logs "The feature flag gating model execution was disabled." on the extension Errors page (even if
 * the promise is caught), so that call must not be made.
 */
export async function downloadOnDeviceModel(
  onProgress: (fraction: number) => void,
): Promise<ModelDownloadOutcome> {
  const factory = findFactory();
  const create = factory === null ? null : fn(factory.host, 'create');
  if (factory === null || create === null) return { ok: false, reason: 'unsupported' };
  try {
    // `probeAvailability` never returns `unsupported`; that is only from a missing factory above.
    const state = await probeAvailability(factory.host);
    if (state === 'unavailable') return { ok: false, reason: 'unavailable' };

    const monitor = (target: unknown): void => {
      fn(target, 'addEventListener')?.call(target, 'downloadprogress', (event: unknown) => {
        const loaded = isRecord(event) ? event['loaded'] : undefined;
        if (typeof loaded === 'number') onProgress(loaded);
      });
    };
    const session: unknown = await create.call(factory.host, { ...OUTPUT_LANGUAGE, monitor });
    if (!isRecord(session)) return { ok: false, reason: 'failed' };
    try {
      fn(session, 'destroy')?.call(session);
    } catch {
      // The model is on disk either way; a session that will not close is not worth reporting.
    }
    return { ok: true };
  } catch (error) {
    if (isOnDeviceSettingDisabledError(error)) return { ok: false, reason: 'unavailable' };
    return { ok: false, reason: 'failed' };
  }
}
