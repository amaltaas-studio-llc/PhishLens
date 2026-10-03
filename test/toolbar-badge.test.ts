import { describe, expect, it } from 'vitest';

import type { TabStatus } from '../src/shared/messaging.js';
import { toolbarBadgeAppearance } from '../src/shared/toolbar-badge.js';

const showLow = { showBadgeWhenLow: true };
const hideLow = { showBadgeWhenLow: false };

function scored(
  score: number,
  classification: 'low' | 'caution' | 'suspicious' | 'high-risk',
): TabStatus {
  return {
    kind: 'scored',
    score,
    classification,
    findings: 1,
    headlines: ['example'],
    semantic: 'off',
  };
}

describe('toolbarBadgeAppearance', () => {
  it('clears when there is nothing to score yet', () => {
    expect(toolbarBadgeAppearance({ kind: 'no-message' }, showLow).text).toBe('');
    expect(toolbarBadgeAppearance({ kind: 'pending' }, showLow).text).toBe('');
  });

  it('marks an unreadable message without using a risk colour', () => {
    const badge = toolbarBadgeAppearance({ kind: 'unreadable', missing: ['sender'] }, showLow);
    expect(badge.text).toBe('?');
    expect(badge.background).toBe('#5f6368');
    expect(badge.title).toMatch(/Not checked/u);
  });

  it('shows the score and a band colour for each classification', () => {
    const low = toolbarBadgeAppearance(scored(12, 'low'), showLow);
    expect(low.text).toBe('12');
    expect(low.background).toBe('#137333');
    expect(low.title).toBe('ShoutPhish: Low Risk 12/100');

    const caution = toolbarBadgeAppearance(scored(30, 'caution'), showLow);
    expect(caution.background).toBe('#e37400');

    const suspicious = toolbarBadgeAppearance(scored(55, 'suspicious'), showLow);
    expect(suspicious.background).toBe('#d93025');

    const high = toolbarBadgeAppearance(scored(80, 'high-risk'), showLow);
    expect(high.text).toBe('80');
    expect(high.background).toBe('#b3261e');
    expect(high.title).toBe('ShoutPhish: High Risk 80/100');
  });

  /** Same rule as the in-mail badge: hiding low risk must not leave a green "12" on the toolbar. */
  it('honours showBadgeWhenLow for low scores only', () => {
    expect(toolbarBadgeAppearance(scored(12, 'low'), hideLow).text).toBe('');
    expect(toolbarBadgeAppearance(scored(55, 'suspicious'), hideLow).text).toBe('55');
  });

  it('keeps badge text short enough for the toolbar', () => {
    expect(toolbarBadgeAppearance(scored(100, 'high-risk'), showLow).text.length).toBeLessThanOrEqual(
      4,
    );
  });
});
