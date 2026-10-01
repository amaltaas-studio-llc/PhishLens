#!/usr/bin/env node
/**
 * Runs the corpus evaluation in scripts/eval/ (see main.ts there for options).
 *
 *   npm run eval -- ~/corpora/phishing ~/Takeout/mail.mbox --since 2025-10-01
 *
 * Bundled with esbuild rather than run by a TypeScript loader, which would be a dependency for one
 * script, and Node's own type stripping cannot follow the `.js` specifiers the sources import `.ts`
 * files by. The bundle goes under node_modules/ so that jsdom, left external, resolves from it.
 */
import * as esbuild from 'esbuild';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outfile = path.join(root, 'node_modules', '.cache', 'phishlens-eval', 'main.mjs');

await esbuild.build({
  entryPoints: [path.join(root, 'scripts', 'eval', 'main.ts')],
  outfile,
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  packages: 'external',
  logLevel: 'warning',
  define: {
    __PHISHLENS_DEV__: 'false',
    __PHISHLENS_VERSION__: JSON.stringify('eval'),
  },
});

process.env.PHISHLENS_REPO_ROOT = root;
await import(pathToFileURL(outfile).href);
