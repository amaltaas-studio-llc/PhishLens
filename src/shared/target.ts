/**
 * Which browser family this bundle was built for, fixed at build time by `scripts/build.mjs`.
 *
 * A build-time constant rather than feature detection, because the one difference it gates (Firefox's
 * data-collection consent) is a key Chrome rejects outright rather than ignores, so probing for it
 * would mean calling the API wrongly in one browser to learn which one this is. Tests and the harness
 * define no target and get `chromium`, the build the repository has always produced.
 */
declare const __SHOUTPHISH_TARGET__: BuildTarget;

export type BuildTarget = 'chromium' | 'firefox';

export const BUILD_TARGET: BuildTarget =
  typeof __SHOUTPHISH_TARGET__ === 'undefined' ? 'chromium' : __SHOUTPHISH_TARGET__;
