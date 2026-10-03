import { describe, expect, it } from 'vitest';

import type { OnDeviceModelState } from '../src/analysis/llm/on-device.js';
import { onDeviceChoice } from '../src/shared/on-device-choice.js';
import type { AiMode } from '../src/shared/types.js';

const FIXABLE: readonly OnDeviceModelState[] = [
  'available',
  'downloadable',
  'downloading',
  'unavailable',
];
const MODES: readonly AiMode[] = ['off', 'local', 'server', 'cloud'];

describe('onDeviceChoice', () => {
  it('keeps the choice open wherever the browser has a Prompt API, even one not ready yet', () => {
    for (const state of FIXABLE) {
      for (const mode of MODES) {
        expect(onDeviceChoice(state, mode)).toEqual({ selectable: true, note: null });
      }
    }
  });

  it('disables the choice, with a reason, where the browser has no on-device model at all', () => {
    for (const mode of MODES) {
      const choice = onDeviceChoice('unsupported', mode);
      expect(choice.selectable).toBe(false);
      expect(choice.note).toMatch(/no on-device model/);
    }
  });

  it('tells a reader who already chose it that nothing runs, and what to pick instead', () => {
    const note = onDeviceChoice('unsupported', 'local').note;
    expect(note).toMatch(/^Selected/);
    expect(note).toMatch(/no model runs/);
    expect(note).toMatch(/Choose Off, or your own model server/);
    expect(onDeviceChoice('unsupported', 'off').note).toMatch(/^Not available in this browser/);
  });
});
