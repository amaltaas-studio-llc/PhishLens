import { expect, it, vi } from 'vitest';
import { Readings } from '../src/content/readings.js';
import { analyze } from '../src/analysis/engine.js';
import type { EmailMessage, SemanticAnalysis } from '../src/shared/types.js';
const email: EmailMessage = { senderEmail: 'person@northwind-tools.com', subject: 'Hello', bodyText: 'Hello', links: [], attachments: [] };
const answer: SemanticAnalysis = { risk: 90, confidence: 1, categories: ['payment_fraud'], reasons: ['A payment request.'], source: 'local' };
it.each(['clear', 'navigate'])('invalidates availability waits on %s', async (action) => {
  const readings = new Readings();
  let available!: (value: boolean) => void;
  const infer = vi.fn(() => Promise.resolve(answer));
  const lookup = readings.lookup('prompt', () => ({ id: 'old', isAvailable: () => new Promise<boolean>(r => { available = r; }), analyze: infer }));
  const pending = analyze(email, lookup?.analyzer ?? null);
  if (action === 'clear') readings.clear();
  else readings.cancelUnless('other');
  available(true);
  await pending;
  expect(infer).not.toHaveBeenCalled();
  expect(readings.has('prompt')).toBe(false);
});
it('does not cache an answer that ignores cancellation', async () => {
  const readings = new Readings();
  let finish!: (value: SemanticAnalysis) => void;
  const lookup = readings.lookup('prompt', () => ({ id: 'old', isAvailable: () => Promise.resolve(true), analyze: () => new Promise<SemanticAnalysis>(r => { finish = r; }) }));
  const pending = lookup!.analyzer.analyze(email);
  readings.clear();
  finish(answer);
  await pending;
  expect(readings.has('prompt')).toBe(false);
});
