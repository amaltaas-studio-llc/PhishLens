import { describe, expect, it } from 'vitest';
import type { OnDeviceModelState } from '../src/analysis/llm/on-device.js';
import { AI_SETTINGS_URL, onDeviceGuidance } from '../src/welcome/guidance.js';

const STATES: readonly OnDeviceModelState[] = [
  'available',
  'downloadable',
  'downloading',
  'unavailable',
  'unsupported',
];

describe('welcome page guidance for the on-device model', () => {
  it('asks nothing of a reader whose model is ready', () => {
    const guidance = onDeviceGuidance('available');
    expect(guidance.tone).toBe('ready');
    expect(guidance.action).toBeUndefined();
    expect(guidance.steps).toEqual([]);
  });

  it('walks a reader with the setting off through chrome://settings/ai', () => {
    const guidance = onDeviceGuidance('unavailable');
    expect(guidance.action).toBe('open-ai-settings');
    expect(guidance.steps.join(' ')).toContain(AI_SETTINGS_URL);
    expect(guidance.steps.join(' ')).toMatch(/On-device AI/u);
    expect(guidance.steps.join(' ')).toMatch(/20 GB/u);
  });

  /** Chrome reports "switched off" and "this device cannot" identically, so the page must not guess. */
  it('says an ineligible device is possible rather than promising the steps will work', () => {
    expect(onDeviceGuidance('unavailable').note).toMatch(/may not qualify/u);
  });

  it('sends an old Chrome to be updated, since no setting can add the API', () => {
    expect(onDeviceGuidance('unsupported').action).toBe('update-chrome');
  });

  it('offers the download only as a button, never as something that happens by itself', () => {
    expect(onDeviceGuidance('downloadable').action).toBe('download');
  });

  /**
   * Chrome can report "downloading" indefinitely, and asking again never moves it along. A page that only
   * waited for it read as stuck; creating a session with a monitor is what shows progress or resumes it.
   */
  it('gives a download in progress a way forward, not only a wait', () => {
    const guidance = onDeviceGuidance('downloading');
    expect(guidance.action).toBe('track-download');
    expect(guidance.note).toContain('chrome://on-device-internals');
  });

  it.each(STATES.filter((state) => state !== 'available'))(
    'tells a reader in state "%s" that the checks work without the model',
    (state) => {
      expect(onDeviceGuidance(state).note).toMatch(/works fully without it/u);
    },
  );
});
