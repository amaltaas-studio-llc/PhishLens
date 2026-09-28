import type { AiMode, Settings } from './types.js';

/**
 * Defaults favour local processing: AI analysis, if it runs at all, runs on-device. Cloud is opt-in
 * and additionally requires a backend URL, so there is no configuration in which the MVP sends
 * message content off the machine.
 */
export const DEFAULT_SETTINGS: Readonly<Settings> = Object.freeze({
  aiMode: 'local',
  aiOnlyWhenFlagged: true,
  highlightEnabled: true,
  showBadgeWhenLow: true,
  listMarksEnabled: false,
  backendBaseUrl: '',
  modelBaseUrl: '',
  modelName: '',
  trustedSenders: Object.freeze([]),
});

export const STORAGE_KEY = 'phishlens.settings.v1';

const AI_MODES: readonly AiMode[] = ['off', 'local', 'cloud', 'server'];

function isAiMode(value: unknown): value is AiMode {
  return typeof value === 'string' && (AI_MODES as readonly string[]).includes(value);
}

/**
 * Coerces whatever is in storage into a valid `Settings`.
 *
 * Storage is not attacker-controlled in the usual sense, but it *is* persisted state from a possibly
 * older version of the extension, so it is validated rather than trusted.
 */
export function normalizeSettings(raw: unknown): Settings {
  if (raw === null || typeof raw !== 'object') return { ...DEFAULT_SETTINGS };
  const source = raw as Record<string, unknown>;

  return {
    aiMode: isAiMode(source['aiMode']) ? source['aiMode'] : DEFAULT_SETTINGS.aiMode,
    aiOnlyWhenFlagged:
      typeof source['aiOnlyWhenFlagged'] === 'boolean'
        ? source['aiOnlyWhenFlagged']
        : DEFAULT_SETTINGS.aiOnlyWhenFlagged,
    highlightEnabled:
      typeof source['highlightEnabled'] === 'boolean'
        ? source['highlightEnabled']
        : DEFAULT_SETTINGS.highlightEnabled,
    showBadgeWhenLow:
      typeof source['showBadgeWhenLow'] === 'boolean'
        ? source['showBadgeWhenLow']
        : DEFAULT_SETTINGS.showBadgeWhenLow,
    listMarksEnabled:
      typeof source['listMarksEnabled'] === 'boolean'
        ? source['listMarksEnabled']
        : DEFAULT_SETTINGS.listMarksEnabled,
    backendBaseUrl: normalizeBackendUrl(source['backendBaseUrl']),
    modelBaseUrl: normalizeModelBaseUrl(source['modelBaseUrl']),
    modelName: normalizeModelName(source['modelName']),
    trustedSenders: normalizeTrustList(source['trustedSenders']),
  };
}

/**
 * Only `https://` origins are accepted, and only as an origin + optional path prefix. Rejecting
 * anything else here means the cloud adapter cannot be pointed at `http://`, at a `javascript:` URL,
 * or at a vendor endpoint by editing storage.
 */
export function normalizeBackendUrl(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') return '';
  try {
    const url = new URL(value.trim());
    if (url.protocol !== 'https:') return '';
    const path = url.pathname.replace(/\/+$/u, '');
    return `${url.origin}${path}`;
  } catch {
    return '';
  }
}

/** True when the user has both chosen cloud mode and supplied our backend's URL. */
export function isCloudConfigured(settings: Settings): boolean {
  return settings.aiMode === 'cloud' && settings.backendBaseUrl !== '';
}

/**
 * Hosts for which plaintext HTTP is acceptable, because the request never reaches a network.
 *
 * `localhost` is included despite resolving through the OS, so a hosts file or a DNS answer could in
 * principle send it elsewhere. Excluding it would be the stricter choice and the wrong one: every model
 * runner's documentation gives `http://localhost:…`, so a rejection here reads as the feature being
 * broken, and a user who can edit their own hosts file can also simply type the address they were
 * redirected to. The protection that matters is that anything *not* on this list must use TLS.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

/**
 * Normalises the base URL of a user-run model server to an origin plus optional path prefix.
 *
 * Unlike `normalizeBackendUrl` this accepts `http:` — but only for loopback, where there is no wire to
 * intercept. Off the machine, TLS is required: the request carries the subject and body of the message
 * being read, and sending that in plaintext across a LAN would be a worse leak than any this extension
 * is meant to warn about. Everything else is rejected exactly as it is for the backend URL, so
 * `javascript:`, `file:`, `data:` and a bare hostname cannot become an endpoint by editing storage.
 *
 * The path prefix is kept because runners differ: Ollama serves `/v1`, Docker Model Runner
 * `/engines/v1`. Users paste what their own documentation told them.
 */
export function normalizeModelBaseUrl(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') return '';
  try {
    const url = new URL(value.trim());
    const loopback = isLoopbackHost(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return '';
    // Credentials in the URL would be sent to the server and shown in the options field; a model
    // server needing them is not a case worth supporting silently.
    if (url.username !== '' || url.password !== '') return '';
    const path = url.pathname.replace(/\/+$/u, '');
    return `${url.origin}${path}`;
  } catch {
    return '';
  }
}

/**
 * Bounded because the trust list lives in `chrome.storage.sync`, which caps a single item at 8 KB shared
 * with every other setting. Fifty is far more than the handful of senders this is for.
 */
export const MAX_TRUSTED_SENDERS = 50;

/** RFC 5321's maximum path length. Anything longer is not an address. */
export const MAX_ENTRY_CHARS = 254;

/**
 * And bounded again in total, because the two limits above do not compose: fifty entries at the maximum
 * address length is about 13 KB, which the 8 KB cap they were chosen to respect would reject — a write
 * that fails, taking every other setting in the same item with it.
 *
 * Reaching this needs deliberately absurd addresses; the realistic fifty-entry list is well under 2 KB.
 * It is here because a quota error is the worst way to discover an arithmetic slip, and because the
 * comment above claimed a guarantee the numbers did not provide.
 */
const MAX_TRUST_LIST_CHARS = 6000;

/**
 * Coerces a stored trust list into one that cannot surprise the matcher: lowercased, deduplicated,
 * bounded in both length and count, and containing nothing that is neither an address nor a domain.
 *
 * Validated rather than trusted even though the user wrote it, because it is persisted state that syncs
 * between installs and may have been written by an older version.
 *
 * Here rather than in `trust.ts` with the rest of the trust logic for the same reason as every other
 * `normalize*` in this file: it is what makes a stored value safe to use, and this is the file the storage
 * layer already depends on. It also keeps `trust.ts` — and the public suffix table it reaches — out of the
 * popup bundle, which needs settings and nothing else.
 */
export function normalizeTrustList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];

  const seen = new Set<string>();
  let chars = 0;
  for (const value of raw) {
    if (typeof value !== 'string') continue;
    const entry = value.trim().toLowerCase();
    if (entry === '' || entry.length > MAX_ENTRY_CHARS) continue;
    if (!isPlausibleEntry(entry)) continue;
    if (seen.has(entry)) continue;
    if (chars + entry.length > MAX_TRUST_LIST_CHARS) break;
    seen.add(entry);
    chars += entry.length;
    if (seen.size >= MAX_TRUSTED_SENDERS) break;
  }
  return [...seen];
}

/**
 * An address with one `@`, or a domain — in both cases spelled the way a hostname is spelled.
 *
 * Structural, rather than checked against the public suffix list: validation does not need to know which
 * suffixes exist, because an entry naming a suffix nobody registered matches nothing, which is the same
 * outcome as rejecting it. `matchingTrustEntry` does the real comparison.
 */
function isPlausibleEntry(entry: string): boolean {
  const at = entry.indexOf('@');
  if (at === 0 || at !== entry.lastIndexOf('@')) return false;
  return HOSTNAME.test(at < 0 ? entry : entry.slice(at + 1));
}

/**
 * At least two labels, each alphanumeric with interior hyphens, and a final label that starts with two
 * letters — which rules out the bare IP addresses a trust entry could never usefully name. Anchored and
 * bounded per label, so no input can make it expensive.
 */
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2}[a-z0-9-]{0,61}$/u;

/**
 * A model name is interpolated into a JSON request body, so it is bounded and stripped of control
 * characters. It is not otherwise constrained: runners name models as they please
 * (`qwen2.5:7b`, `ai/smollm2`, `hf.co/user/repo:Q4_K_M`).
 */
export function normalizeModelName(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, '')
    .trim()
    .slice(0, 200);
}

/**
 * True when the user has chosen their own model server and given both the pieces needed to call it.
 *
 * The model name counts: these servers reject or silently substitute an unknown model, and a mode that
 * looks enabled while every request fails is worse than one that is plainly not configured yet.
 */
export function isModelServerConfigured(settings: Settings): boolean {
  return settings.aiMode === 'server' && settings.modelBaseUrl !== '' && settings.modelName !== '';
}

/**
 * What a settings change asks of the message already on screen.
 *
 * Here rather than inside the content script so it can be asserted without a DOM, and in one place so the
 * question "does this setting change a verdict, or only the picture of one" has to be answered when a
 * setting is added. Getting it wrong is invisible in both directions: a verdict that silently keeps the
 * old model's contribution, or a badge that ignores the switch the reader just moved.
 */
export interface SettingsImpact {
  /** Cached results are no longer what an analysis would produce, so they have to be discarded. */
  rescore: boolean;
  /** Which model is asked, so a session built for the previous one is no longer the right one. */
  remodel: boolean;
  /** Only what is drawn has changed; the existing result stands and is simply applied again. */
  repaint: boolean;
  listMarks: boolean;
  highlights: boolean;
}

export function settingsImpact(previous: Settings, next: Settings): SettingsImpact {
  /*
   * The endpoint and model name count as much as the mode does. A different server is a different judge:
   * its reasons and its risk number differ, and it may be a large model where the last was a small one.
   * Leaving them out meant switching model and seeing the previous one's verdicts replayed from cache for
   * the life of the tab, which reads as the new setting having been ignored.
   */
  const remodel =
    previous.aiMode !== next.aiMode ||
    previous.modelBaseUrl !== next.modelBaseUrl ||
    previous.modelName !== next.modelName ||
    previous.backendBaseUrl !== next.backendBaseUrl;

  return {
    remodel,
    // The gate counts because a skipped reading is cached as settled: without it, switching the model
    // on for all mail would leave every message already opened saying it was skipped.
    rescore:
      remodel ||
      previous.aiOnlyWhenFlagged !== next.aiOnlyWhenFlagged ||
      !sameEntries(previous.trustedSenders, next.trustedSenders),
    repaint: previous.showBadgeWhenLow !== next.showBadgeWhenLow,
    listMarks: previous.listMarksEnabled !== next.listMarksEnabled,
    highlights: previous.highlightEnabled !== next.highlightEnabled,
  };
}

/** Order-insensitive, since the trust list is a set stored as an array. */
function sameEntries(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((entry) => b.includes(entry));
}

/** True when a configured model server is off this machine, and message content crosses a network. */
export function isModelServerRemote(settings: Settings): boolean {
  if (settings.modelBaseUrl === '') return false;
  try {
    return !isLoopbackHost(new URL(settings.modelBaseUrl).hostname);
  } catch {
    return false;
  }
}
