# 0001. esbuild, not Vite; zero runtime dependencies

**Status:** Accepted

## Context

The extension has five entry points with different output shapes: the content script must be an
IIFE (MV3 classic scripts), while the service worker and the options, popup and welcome pages are ESM.
Output is a flat,
unhashed `dist/`. The primary UI is injected into Gmail inside a shadow root, so a localhost HMR
server cannot preview it. As a security product, transitive dependency surface and auditability matter.

## Decision

- Bundle with esbuild driven by `scripts/build.mjs`.
- TypeScript targeting ES2022 with `strict` and `noUncheckedIndexedAccess`.
- Vitest in Node; ESLint (flat config, `typescript-eslint` typed rules).
- No UI framework and no runtime `dependencies` — only `devDependencies`.
- `analysis/` must not reference `chrome.*`, `document`, `window` or `fetch`, so the engine runs under
  Vitest; ESLint enforces this for direct references. `shared/` is mostly pure helpers, but also holds the
  thin `chrome.*` wrappers (`messaging.ts` sends runtime and tab messages). Those touch `chrome` only
  inside the functions that send, never at import time, so the model adapters in `analysis/llm/` can
  import them and still load in Node, where a test that sends stubs `chrome` itself.

## Consequences

- Rebuilds are tens of milliseconds; watch plus extension reload covers options work.
- The detection engine is fast enough to be useful in CI because it is plain Node.
- Reviewers can read the dependency tree in one glance.

## Rejected alternatives

- **Vite / Rollup HTML pipeline.** Fighting mixed IIFE/ESM and flat emit; HMR does not apply to
  shadow-injected Gmail UI; more transitive deps for little gain.
