#!/usr/bin/env node
/**
 * Exports synthetic evaluation requests only. No model is contacted and no mailbox is read.
 *
 *   npm run eval:prompts -- [outputDir] [baselineRef]   # defaults: harness/.build/semantic-eval, HEAD
 *
 * The baseline is only `prompt.ts` as it was at `baselineRef`. Its imports (`shared/text.ts`,
 * `shared/types.ts`, …) resolve from the working tree, because esbuild is handed that one file's text and
 * a resolve directory on disk. So a change to a helper the prompt imports — the truncation limit, the
 * category list — appears in *both* files, and the pair measures only edits made inside `prompt.ts`.
 * Compare against a full checkout of the old ref when a prompt change spans files.
 */
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.resolve(root, process.argv[2] ?? 'harness/.build/semantic-eval');
const baselineRef = process.argv[3] ?? 'HEAD';
const promptPath = 'src/analysis/llm/prompt.ts';
const cases = JSON.parse(readFileSync(path.join(root, 'test/fixtures/semantic/cases.json'), 'utf8'));

async function compilePrompt(contents) {
  const result = await build({
    stdin: { contents, loader: 'ts', resolveDir: path.join(root, 'src/analysis/llm') },
    bundle: true,
    platform: 'node',
    format: 'esm',
    write: false,
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`);
}

const baseline = await compilePrompt(execFileSync('git', ['show', `${baselineRef}:${promptPath}`], { cwd: root, encoding: 'utf8' }));
const candidate = await compilePrompt(readFileSync(path.join(root, promptPath), 'utf8'));
mkdirSync(output, { recursive: true });
for (const [name, prompt] of [['baseline', baseline], ['candidate', candidate]]) {
  const requests = cases.map(({ id, subject, bodyText }) => ({
    id,
    messages: [
      { role: 'system', content: prompt.SYSTEM_PROMPT },
      { role: 'user', content: prompt.buildUserPrompt({ senderName: 'Northwind', subject, bodyText, links: [], attachments: [] }) },
    ],
  }));
  writeFileSync(path.join(output, `${name}.jsonl`), requests.map(row => JSON.stringify(row)).join('\n') + '\n');
}
// Expectations never enter model requests: evaluating against labels supplied to the model is circular.
writeFileSync(path.join(output, 'review.json'), JSON.stringify(cases.map(({ id, expectation, review }) => ({ id, expectation, review })), null, 2) + '\n');
writeFileSync(path.join(output, 'metadata.json'), JSON.stringify({ baselineRef, cases: cases.length, note: 'Synthetic smoke evaluation; no measured accuracy claim. Record model version and runtime settings with responses.' }, null, 2) + '\n');
console.log(`Exported ${cases.length} paired requests and a separate review rubric to ${output}. No model was contacted.`);
