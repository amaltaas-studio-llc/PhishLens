/**
 * The content-script ↔ service-worker protocol.
 *
 * Kept deliberately tiny. The worker is stateless (docs/adr/0002-mv3-state-in-content-script.md), so every message is a
 * complete, self-contained request; nothing here depends on a previous message having been handled
 * by the same worker instance.
 */
import { DEFAULT_SETTINGS } from './settings.js';
import type { ToolbarBadgeAppearance } from './toolbar-badge.js';
import type {
  Classification,
  MessagePart,
  SemanticAnalysis,
  SemanticStatus,
  Settings,
} from './types.js';

export interface GetSettingsRequest {
  type: 'GET_SETTINGS';
}

export interface SetSettingsRequest {
  type: 'SET_SETTINGS';
  patch: Partial<Settings>;
}

/**
 * Payload for the (unbuilt) cloud path. Note what is *absent*: no raw body, no recipient address, no
 * attachment bytes, no message id. Built by `src/analysis/llm/redact.ts`.
 */
export interface CloudAnalyzeRequest {
  type: 'CLOUD_ANALYZE';
  payload: {
    subject: string;
    /** Truncated body with email addresses reduced to their domains. */
    bodyExcerpt: string;
    senderDomain: string;
    senderNameShape: string;
    replyToDomain?: string;
    linkDomains: string[];
    attachmentExtensions: string[];
    /** Ids of deterministic signals already found, so the backend need not re-derive them. */
    deterministicSignalIds: string[];
  };
}

/**
 * The message half of a prompt for a model server the user runs: exactly what the on-device model is
 * given, because that is the mode this one substitutes for.
 *
 * Note what is *not* here: no URL, no model name, and no system prompt. The worker reads the first two
 * from settings, so the only address it can ever be made to call is one that survived
 * `normalizeModelBaseUrl` and that the user granted access to. It supplies the system prompt itself, so
 * whatever sends this message cannot rewrite the model's instructions. Accepting an endpoint over this
 * channel would make the worker a general-purpose fetcher for whatever could send it a message.
 */
export interface ModelServerAnalyzeRequest {
  type: 'MODEL_SERVER_ANALYZE';
  payload: {
    user: string;
  };
}

/** Lists what the configured server has loaded, so the options page can offer real model names. */
export interface ListModelsRequest {
  type: 'LIST_MODELS';
}

/**
 * Paints the toolbar icon for the sending tab. Only the content script sends this; the worker applies
 * it with `sender.tab.id` so a tab never sets another tab's badge.
 */
export interface SetToolbarBadgeRequest extends ToolbarBadgeAppearance {
  type: 'SET_TOOLBAR_BADGE';
}

export type ExtensionRequest =
  | GetSettingsRequest
  | SetSettingsRequest
  | CloudAnalyzeRequest
  | ModelServerAnalyzeRequest
  | ListModelsRequest
  | SetToolbarBadgeRequest;

export type ExtensionResponse =
  | { ok: true; type: 'SETTINGS'; settings: Settings }
  | { ok: true; type: 'SEMANTIC'; analysis: SemanticAnalysis | null }
  | { ok: true; type: 'MODELS'; models: string[] }
  | { ok: true; type: 'ACKNOWLEDGED' }
  | { ok: false; error: string };

const REQUEST_TYPES: ReadonlySet<string> = new Set([
  'GET_SETTINGS',
  'SET_SETTINGS',
  'CLOUD_ANALYZE',
  'MODEL_SERVER_ANALYZE',
  'LIST_MODELS',
  'SET_TOOLBAR_BADGE',
]);

export function isExtensionRequest(value: unknown): value is ExtensionRequest {
  return hasType(value, REQUEST_TYPES);
}

function hasType(value: unknown, types: ReadonlySet<string>): boolean {
  if (value === null || typeof value !== 'object') return false;
  const type = (value as Record<string, unknown>)['type'];
  return typeof type === 'string' && types.has(type);
}

/** Both channels answer `{ ok: boolean, ... }`; anything else is treated as no answer. */
function isResponse(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  return typeof (value as Record<string, unknown>)['ok'] === 'boolean';
}

// ---------------------------------------------------------------------------
// The popup ↔ content-script channel
// ---------------------------------------------------------------------------

/**
 * What the toolbar popup can ask the tab about the message on screen.
 *
 * A separate union from `ExtensionRequest` because it travels a different route (`chrome.tabs.
 * sendMessage`, which reaches only content scripts) and is answered by different code. Merging them
 * would put requests the worker cannot handle into the worker's exhaustive switch, and requests the
 * content script cannot handle into its own.
 *
 * Deliberately read-only apart from `OPEN_PANEL`, which asks the tab to show the card it would have
 * shown had the badge been clicked. Nothing here can start an analysis or change a score: a popup that
 * could would be a second, differently-behaved entry point into the same state.
 */
export interface GetTabStatusRequest {
  type: 'GET_TAB_STATUS';
}

export interface OpenPanelRequest {
  type: 'OPEN_PANEL';
}

/**
 * The pasteable session report. Asked for separately from the status because building it walks every
 * selector candidate against the page, and nothing needs it until a user presses the button.
 */
export interface GetHealthReportRequest {
  type: 'GET_HEALTH_REPORT';
}

export type TabRequest = GetTabStatusRequest | OpenPanelRequest | GetHealthReportRequest;

/**
 * The state of the tab, as much of it as the popup needs.
 *
 * `headlines` carries finding *titles* (the extension's own wording, not message content), so the
 * popup can say what was found without re-deriving anything. The sender and subject are deliberately
 * absent: the popup is about whether ShoutPhish is working, and copying mail into a second surface buys
 * nothing when the card beside the message already names it.
 */
export type TabStatus =
  | { kind: 'no-message' }
  /** Extraction succeeded and the deterministic pass has not been applied yet. Momentary. */
  | { kind: 'pending' }
  | { kind: 'unreadable'; missing: MessagePart[] }
  | {
      kind: 'scored';
      score: number;
      classification: Classification;
      findings: number;
      headlines: string[];
      semantic: SemanticStatus;
    };

/**
 * How well the adapter has been reading this tab, accumulated since it loaded. See `content/health.ts`.
 *
 * Travels with the status because it is the other half of the same question. A verdict says what was
 * found in one message; this says whether the thing producing verdicts is still reading Gmail properly,
 * which is the failure a user has no other way to notice.
 */
export interface TabHealth {
  seen: number;
  unscorable: number;
  misses: readonly { part: MessagePart; count: number }[];
  /** Selector groups not matching their preferred candidate. Group names only, never message content. */
  drifted: readonly string[];
}

export type TabResponse =
  | { ok: true; type: 'TAB_STATUS'; status: TabStatus; health: TabHealth }
  | { ok: true; type: 'HEALTH_REPORT'; report: string }
  | { ok: true; type: 'ACKNOWLEDGED' }
  | { ok: false; error: string };

const TAB_REQUEST_TYPES: ReadonlySet<string> = new Set([
  'GET_TAB_STATUS',
  'OPEN_PANEL',
  'GET_HEALTH_REPORT',
]);

export function isTabRequest(value: unknown): value is TabRequest {
  return hasType(value, TAB_REQUEST_TYPES);
}

/**
 * Asks one tab. Resolves to `null` for every reason a tab may not answer (no content script on the
 * page, a tab that has navigated away, a page still loading), because to the popup these are one case:
 * there is nothing to report about this tab.
 */
export async function sendTabMessage(
  tabId: number,
  request: TabRequest,
): Promise<TabResponse | null> {
  try {
    const response: unknown = await chrome.tabs.sendMessage(tabId, request);
    return isResponse(response) ? (response as TabResponse) : null;
  } catch {
    return null;
  }
}

/**
 * `chrome.runtime.sendMessage` rejects when no receiver is alive (a worker mid-restart, or the
 * extension being reloaded). Callers get `null` rather than an unhandled rejection.
 */
export async function sendMessage(request: ExtensionRequest): Promise<ExtensionResponse | null> {
  try {
    const response: unknown = await chrome.runtime.sendMessage(request);
    return isResponse(response) ? (response as ExtensionResponse) : null;
  } catch {
    return null;
  }
}

/** Reads settings via the worker, falling back to defaults if it is mid-restart. */
export async function requestSettings(): Promise<Settings> {
  const response = await sendMessage({ type: 'GET_SETTINGS' });
  if (response !== null && response.ok && response.type === 'SETTINGS') return response.settings;
  return { ...DEFAULT_SETTINGS };
}
