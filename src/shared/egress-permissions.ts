/**
 * The permissions that must all be held before anything is sent to an address.
 *
 * Everywhere, that is the host permission for the address's origin. On Firefox it is also consent to
 * transmit personal communications: Mozilla counts anything handled outside the browser as
 * transmission, and a model server is outside the browser even on loopback, since it is another
 * process. The manifest declares `none` as required data and this type as optional
 * (`src/manifest.firefox.json`), so a default install truthfully collects nothing, and the consent is
 * asked for on the same click as the host permission, for the same reason.
 *
 * Requested, checked and revoked as one set, so the worker can never hold one half and act as if it
 * held both. Chrome has no such permission and rejects the unknown key, hence the target switch.
 */
import type { BuildTarget } from './target.js';

export const MODEL_DATA_COLLECTION = ['personalCommunications'] as const;

/** `chrome.permissions.Permissions` plus Firefox's key, which `@types/chrome` does not describe. */
export interface EgressPermissions {
  origins: string[];
  data_collection?: string[];
}

export function egressPermissions(pattern: string, target: BuildTarget): EgressPermissions {
  return target === 'firefox'
    ? { origins: [pattern], data_collection: [...MODEL_DATA_COLLECTION] }
    : { origins: [pattern] };
}
