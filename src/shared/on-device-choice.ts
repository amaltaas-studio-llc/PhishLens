/**
 * Whether the on-device model can be offered as a choice, for the welcome and options pages.
 *
 * Decided from what the browser reports, not from which browser it is: `unsupported` means no Prompt API
 * at all, which is Firefox, Safari, and Chromium browsers that do not ship one (Edge today). The other
 * states are all fixable from inside the browser, by a setting or a download, so the choice stays open
 * for them and the welcome page explains the fix.
 *
 * Disabled rather than hidden, and never without a reason beside it: a missing option reads as a broken
 * page, and a greyed-out one with no explanation invites the question of why it cannot be chosen. A mode
 * already set to `local` is not changed behind the reader's back; it is told that the choice does nothing
 * here and what to pick instead.
 */
import type { OnDeviceModelState } from '../analysis/llm/on-device.js';
import type { AiMode } from './types.js';

export interface OnDeviceChoice {
  selectable: boolean;
  /** Shown under the option when it is not selectable. */
  note: string | null;
}

export function onDeviceChoice(state: OnDeviceModelState, mode: AiMode): OnDeviceChoice {
  if (state !== 'unsupported') return { selectable: true, note: null };
  return {
    selectable: false,
    note:
      mode === 'local'
        ? 'Selected, but this browser offers no on-device model to extensions, so no model runs and the technical checks work alone. Choose Off, or your own model server.'
        : 'Not available in this browser: it offers no on-device model to extensions. Google Chrome does, on devices that qualify.',
  };
}
