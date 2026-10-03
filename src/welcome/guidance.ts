/**
 * What the welcome page says about the browser's on-device model, for each state the browser can report.
 *
 * Pure, so the wording is tested in Node like the popup's. The page cannot tell "On-device AI is
 * switched off" from "this device does not qualify" (Chrome reports both as `unavailable`), so that
 * state gives the steps for the first and says plainly what the second would look like.
 *
 * The steps are Chrome's own settings pages. Other Chromium browsers load the same build, and in them
 * those steps are not merely unhelpful but false: "update Chrome" can never add the API to a browser
 * that does not ship it. So outside Google Chrome the page names no browser page and offers no button
 * it cannot stand behind.
 */
import type { OnDeviceModelState } from '../analysis/llm/on-device.js';

/** On-device AI lives under Settings → System; `settings/ai` is a different page (AI Innovations). */
export const AI_SETTINGS_URL = 'chrome://settings/system';
export const UPDATE_CHROME_URL = 'chrome://settings/help';
export const HELP_URL = 'https://support.google.com/chrome/answer/16961953';

/** `other` is every browser whose settings pages this file does not know, not only other Chromiums. */
export type BrowserFamily = 'chrome' | 'other';

/**
 * From `navigator.userAgentData.brands`. The user-agent string cannot be used: Brave's is identical to
 * Chrome's, and Edge's and Opera's contain the `Chrome/` token too. A browser without client hints
 * (Firefox, Safari) passes `undefined` and is correctly `other`.
 */
export function browserFamily(brands: readonly { brand: string }[] | undefined): BrowserFamily {
  return brands?.some((entry) => entry.brand === 'Google Chrome') === true ? 'chrome' : 'other';
}

export type GuidanceAction = 'download' | 'track-download' | 'open-ai-settings' | 'update-chrome';

export interface Guidance {
  tone: 'ready' | 'waiting' | 'needs-action';
  headline: string;
  steps: readonly string[];
  note?: string;
  action?: GuidanceAction;
}

const WITHOUT_IT =
  'ShoutPhish works fully without it: every technical check still runs, and the card says the AI was not used.';

const INTERNALS = 'Chrome’s own status page, chrome://on-device-internals, shows the model’s state in detail.';

const SERVER_INSTEAD = 'Settings can connect ShoutPhish to a model server you run yourself instead.';

export function onDeviceGuidance(state: OnDeviceModelState, browser: BrowserFamily): Guidance {
  const chrome = browser === 'chrome';
  switch (state) {
    case 'available':
      return {
        tone: 'ready',
        headline: `${chrome ? 'Chrome’s' : 'This browser’s'} on-device model is ready. ShoutPhish will use it, and nothing leaves this device.`,
        steps: [],
      };
    /*
     * Chrome can report this for a long time without progressing: a background download waits for an
     * unmetered connection and an idle device, and `availability()` alone never moves it along. Calling
     * `create()` with a monitor is what shows the progress, and joins or restarts the download.
     */
    case 'downloading':
      return {
        tone: 'waiting',
        headline: `${chrome ? 'Chrome' : 'This browser'} is downloading its on-device model.`,
        steps: [
          'A download of several gigabytes can take a while. This page checks again every few seconds.',
          'To see its progress here, or to resume a download that seems stuck, use the button below.',
        ],
        note: chrome ? `${INTERNALS} ${WITHOUT_IT}` : WITHOUT_IT,
        action: 'track-download',
      };
    case 'downloadable':
      return {
        tone: 'needs-action',
        headline: `This device can run ${chrome ? 'Chrome’s' : 'this browser’s'} on-device model, but it has not been downloaded yet.`,
        steps: [
          'The download is several gigabytes and needs an unmetered connection.',
          'ShoutPhish never starts it from Gmail, only from this button.',
        ],
        note: WITHOUT_IT,
        action: 'download',
      };
    case 'unavailable':
      return chrome
        ? {
            tone: 'needs-action',
            headline: 'Chrome’s on-device model is not available yet. To turn it on:',
            steps: [
              `Open Chrome’s system settings at ${AI_SETTINGS_URL}.`,
              'Switch On-device AI on.',
              'Chrome then downloads the model in the background. It needs about 20 GB of free disk space, an unmetered connection, and hardware able to run it.',
              'Come back to this page. It checks again when you return.',
            ],
            note: `If the setting is already on, this device may not qualify. ${WITHOUT_IT}`,
            action: 'open-ai-settings',
          }
        : {
            tone: 'needs-action',
            headline: 'This browser offers on-device AI to extensions, but says its model cannot run here.',
            steps: [
              'It may be switched off in the browser’s settings, blocked by policy, or this device may not qualify.',
              SERVER_INSTEAD,
            ],
            note: WITHOUT_IT,
          };
    case 'unsupported':
      return chrome
        ? {
            tone: 'needs-action',
            headline: 'This version of Chrome does not offer its on-device model to extensions.',
            steps: [
              `Update Chrome at ${UPDATE_CHROME_URL} and restart it.`,
              `Then check that On-device AI is switched on at ${AI_SETTINGS_URL}.`,
              'Come back to this page. It checks again when you return.',
            ],
            note: WITHOUT_IT,
            action: 'update-chrome',
          }
        : {
            tone: 'needs-action',
            headline: 'This browser does not offer an on-device model to extensions.',
            steps: ['Google Chrome does, on devices that qualify.', SERVER_INSTEAD],
            note: WITHOUT_IT,
          };
  }
}

export const ACTION_LABELS: Readonly<Record<GuidanceAction, string>> = {
  download: 'Download the model',
  'track-download': 'Show download progress',
  'open-ai-settings': 'Open Chrome AI settings',
  'update-chrome': 'Check for Chrome updates',
};
