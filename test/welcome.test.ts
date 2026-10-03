import { describe, expect, it } from 'vitest';
import type { OnDeviceModelState } from '../src/analysis/llm/on-device.js';
import { AI_SETTINGS_URL, browserFamily, onDeviceGuidance } from '../src/welcome/guidance.js';

const STATES: readonly OnDeviceModelState[] = [
  'available',
  'downloadable',
  'downloading',
  'unavailable',
  'unsupported',
];

describe('welcome page guidance for the on-device model', () => {
  it('asks nothing of a reader whose model is ready', () => {
    const guidance = onDeviceGuidance('available', 'chrome');
    expect(guidance.tone).toBe('ready');
    expect(guidance.action).toBeUndefined();
    expect(guidance.steps).toEqual([]);
  });

  it('walks a reader with the setting off through chrome://settings/system', () => {
    const guidance = onDeviceGuidance('unavailable', 'chrome');
    expect(guidance.action).toBe('open-ai-settings');
    expect(AI_SETTINGS_URL).toBe('chrome://settings/system');
    expect(guidance.steps.join(' ')).toContain(AI_SETTINGS_URL);
    expect(guidance.steps.join(' ')).toMatch(/On-device AI/u);
    expect(guidance.steps.join(' ')).toMatch(/20 GB/u);
  });

  /** Chrome reports "switched off" and "this device cannot" identically, so the page must not guess. */
  it('says an ineligible device is possible rather than promising the steps will work', () => {
    expect(onDeviceGuidance('unavailable', 'chrome').note).toMatch(/may not qualify/u);
  });

  it('sends an old Chrome to be updated, since no setting can add the API', () => {
    expect(onDeviceGuidance('unsupported', 'chrome').action).toBe('update-chrome');
  });

  it('offers the download only as a button, never as something that happens by itself', () => {
    expect(onDeviceGuidance('downloadable', 'chrome').action).toBe('download');
    expect(onDeviceGuidance('downloadable', 'other').action).toBe('download');
  });

  /**
   * Chrome can report "downloading" indefinitely, and asking again never moves it along. A page that only
   * waited for it would read as stuck; creating a session with a monitor is what shows progress or resumes it.
   */
  it('gives a download in progress a way forward, not only a wait', () => {
    const guidance = onDeviceGuidance('downloading', 'chrome');
    expect(guidance.action).toBe('track-download');
    expect(guidance.note).toContain('chrome://on-device-internals');
  });

  it.each(STATES.filter((state) => state !== 'available'))(
    'tells a reader in state "%s" that the checks work without the model',
    (state) => {
      expect(onDeviceGuidance(state, 'chrome').note).toMatch(/works fully without it/u);
      expect(onDeviceGuidance(state, 'other').note).toMatch(/works fully without it/u);
    },
  );
});

/**
 * The same build loads in Edge, Brave, Opera and Vivaldi. Chrome's settings pages either do not exist
 * there or cannot add the API, so sending a reader to them is advice that cannot work.
 */
describe('welcome page guidance outside Google Chrome', () => {
  it.each(STATES)('names no Chrome page and offers no Chrome button in state "%s"', (state) => {
    const guidance = onDeviceGuidance(state, 'other');
    const text = [guidance.headline, ...guidance.steps, guidance.note ?? ''].join(' ');
    expect(text).not.toMatch(/chrome:\/\//u);
    expect(text).not.toMatch(/\bChrome’s\b|\bupdate Chrome\b/iu);
    expect(guidance.action).not.toBe('open-ai-settings');
    expect(guidance.action).not.toBe('update-chrome');
  });

  it('points a browser with no model at the alternatives instead of an update', () => {
    const steps = onDeviceGuidance('unsupported', 'other').steps.join(' ');
    expect(steps).toMatch(/Google Chrome does/u);
    expect(steps).toMatch(/model server you run yourself/u);
  });
});

describe('browserFamily', () => {
  it('recognises Google Chrome by its client-hint brand', () => {
    expect(
      browserFamily([{ brand: 'Not)A;Brand' }, { brand: 'Chromium' }, { brand: 'Google Chrome' }]),
    ).toBe('chrome');
  });

  it.each([
    ['Microsoft Edge', [{ brand: 'Chromium' }, { brand: 'Microsoft Edge' }]],
    ['Brave', [{ brand: 'Chromium' }, { brand: 'Brave' }]],
    ['Opera', [{ brand: 'Chromium' }, { brand: 'Opera' }]],
    ['a browser that reports only Chromium', [{ brand: 'Chromium' }]],
  ])('treats %s as another browser', (_name, brands) => {
    expect(browserFamily(brands)).toBe('other');
  });

  it('treats a browser without client hints as another browser', () => {
    expect(browserFamily(undefined)).toBe('other');
  });
});
