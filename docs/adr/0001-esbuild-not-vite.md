# 0001. esbuild, not Vite; zero runtime dependencies

**Status:** Accepted

## Context

The extension has three entry points with different output shapes: the content script must be an
IIFE (MV3 classic scripts), while the service worker and options page are ESM. Output is a flat,
unhashed `dist/`. The primary UI is injected into Gmail inside a shadow root, so a localhost HMR
server cannot preview it. As a security product, transitive dependency surface and auditability matter.

## Decision

- Bundle with esbuild driven by `scripts/build.mjs`.
- TypeScript targeting ES2022 with `strict` and `noUncheckedIndexedAccess`.
- Vitest in Node; ESLint 9 with typed rules.
- No UI framework and no runtime `dependencies` — only `devDependencies`.
- `analysis/` and `shared/` must not import `chrome.*` or touch `document`, so the engine runs under Vitest.

## Consequences

- Rebuilds are tens of milliseconds; watch plus extension reload covers options work.
- The detection engine is fast enough to be useful in CI because it is plain Node.
- Reviewers can read the dependency tree in one glance.

## Rejected alternatives

- **Vite / Rollup HTML pipeline.** Fighting mixed IIFE/ESM and flat emit; HMR does not apply to
  shadow-injected Gmail UI; more transitive deps for little gain.
