import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MODEL_DATA_COLLECTION, egressPermissions } from '../src/shared/egress-permissions.js';

const firefoxManifest = JSON.parse(
  readFileSync(new URL('../src/manifest.firefox.json', import.meta.url), 'utf8'),
) as { browser_specific_settings: { gecko: { data_collection_permissions: Record<string, string[]> } } };
const declared = firefoxManifest.browser_specific_settings.gecko.data_collection_permissions;

describe('egressPermissions', () => {
  /** Chrome rejects an unknown key in a permissions request outright, so it must never see this one. */
  it('asks Chromium browsers for the origin alone', () => {
    expect(egressPermissions('http://127.0.0.1/*', 'chromium')).toEqual({ origins: ['http://127.0.0.1/*'] });
  });

  it('asks Firefox for the origin and consent to send message text, together', () => {
    expect(egressPermissions('https://models.example/*', 'firefox')).toEqual({
      origins: ['https://models.example/*'],
      data_collection: ['personalCommunications'],
    });
  });
});

/**
 * Firefox only lets an extension request data consent it declared as optional, and shows required data
 * at install. A default install sends nothing, so nothing may be required, and what is requested on
 * Connect must be exactly what the manifest declares.
 */
describe('the Firefox data-collection declaration', () => {
  it('requires nothing, so a default install truthfully collects no data', () => {
    expect(declared['required']).toEqual(['none']);
  });

  it('declares as optional exactly what Connect asks for', () => {
    expect(declared['optional']).toEqual([...MODEL_DATA_COLLECTION]);
  });
});
