/**
 * Scores a corpus of stored mail with the deterministic engine and reports how it classified it.
 *
 *   npm run eval -- [options] <path>...
 *
 * A path is a directory of single-message files, one message file, an mbox (Google Takeout's included),
 * or a CSV with `sender`, `sender_domain`, `receiver_domain`, `subject`, `body`, `urls`, `source` and
 * `label` columns. Mbox mail carrying `X-Gmail-Labels` is split into `mail` and `spam`, and what was only
 * sent, or is chat, is skipped: neither is mail anyone received.
 *
 *   --since <date>   skip messages dated before it
 *   --limit <n>      stop each group after n scored messages
 *   --group <name>   report every path as one group, rather than one group per path
 *   --rows <dir>     also write every flagged message's sender, subject, link hosts and findings
 *
 * The report on stdout holds rule ids, severities and counts — nothing from any message — so it can be
 * pasted into an issue. `--rows` is the opposite, which is why it refuses a directory inside this
 * repository: corpora used here include people's own mailboxes, and one `git add .` would publish them.
 */
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { analyzeDeterministic } from '../../src/analysis/engine.js';
import { scoreFloor } from '../../src/analysis/scoring/aggregate.js';
import { MAX_BODY_CHARS, truncate } from '../../src/shared/text.js';
import type { EmailMessage } from '../../src/shared/types.js';
import { normalizeDomain, parseUrl } from '../../src/shared/url.js';
import { toEmailMessage } from './message.js';

const MAX_MESSAGE_BYTES = 3_000_000;

interface Options {
  since: number;
  limit: number;
  rows: string | undefined;
  group: string | undefined;
  inputs: string[];
}

interface Group {
  scored: number;
  byClass: Record<string, number>;
  floors: Record<string, number>;
  rules: Record<string, Record<string, number>>;
  rows: unknown[];
}

const groups = new Map<string, Group>();
const skipped: Record<string, number> = {};

function parseArgs(argv: string[]): Options {
  const options: Options = { since: -Infinity, limit: Infinity, rows: undefined, group: undefined, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    const value = (): string => {
      const next = argv[++i];
      if (next === undefined) fail(`${arg} needs a value`);
      return next;
    };
    if (arg === '--since') options.since = Date.parse(value());
    else if (arg === '--limit') options.limit = Number(value());
    else if (arg === '--rows') options.rows = path.resolve(value());
    else if (arg === '--group') options.group = value();
    else if (arg.startsWith('--')) fail(`unknown option ${arg}`);
    else options.inputs.push(arg);
  }
  if (options.inputs.length === 0) fail('usage: npm run eval -- [--since date] [--limit n] [--group name] [--rows dir] <path>...');
  if (Number.isNaN(options.since) || !(options.limit > 0)) fail('--since needs a date and --limit a positive number');
  if (options.rows !== undefined) {
    const repo = process.env['PHISHLENS_REPO_ROOT'];
    if (repo === undefined) fail('run through `npm run eval`, which locates the repository');
    const relative = path.relative(repo, options.rows);
    if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
      fail('--rows must be outside the repository: rows hold message content');
    }
  }
  return options;
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function skip(reason: string): void {
  skipped[reason] = (skipped[reason] ?? 0) + 1;
}

function group(name: string): Group {
  let g = groups.get(name);
  if (g === undefined) {
    g = { scored: 0, byClass: {}, floors: {}, rules: {}, rows: [] };
    groups.set(name, g);
  }
  return g;
}

function score(email: EmailMessage, groupName: string, options: Options, id: string): void {
  const g = group(groupName);
  if (g.scored >= options.limit) { skip('over limit'); return; }
  // The adapter refuses to score a message with no sender (`isScorable`), so this does too.
  if (email.senderEmail === undefined) { skip('no sender'); return; }
  const result = analyzeDeterministic(email);
  g.scored++;
  g.byClass[result.classification] = (g.byClass[result.classification] ?? 0) + 1;
  const floor = scoreFloor(result.signals);
  if (floor.basis !== null) g.floors[floor.basis] = (g.floors[floor.basis] ?? 0) + 1;

  const seen = new Set<string>();
  for (const signal of result.signals) {
    if (signal.score <= 0) continue;
    const rule = signal.id.replace(/\.\d+$/u, '');
    const key = `${rule}|${signal.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const bySeverity = (g.rules[rule] ??= {});
    bySeverity[signal.severity] = (bySeverity[signal.severity] ?? 0) + 1;
  }

  if (options.rows !== undefined && result.classification !== 'low') {
    g.rows.push({
      id,
      score: result.score,
      classification: result.classification,
      name: email.senderName,
      sender: email.senderEmail,
      replyTo: email.replyTo,
      subject: email.subject?.slice(0, 160),
      auth: email.auth,
      linkHosts: [...new Set(email.links.map((link) => link.normalizedDomain))].slice(0, 8),
      attachments: email.attachments.map((a) => a.filename).slice(0, 4),
      signals: result.signals
        .filter((s) => s.score > 0)
        .map((s) => ({ id: s.id, severity: s.severity, score: s.score, evidence: s.evidence })),
    });
  }
}

/** Gmail's labels decide the group, and whether the message was received at all. */
function scoreRaw(buf: Buffer, options: Options, id: string, fallbackGroup: string): void {
  const head = buf.subarray(0, 64_000).toString('latin1');
  const end = head.search(/\r?\n\r?\n/u);
  const headers = (end < 0 ? head : head.slice(0, end)).replace(/\r?\n[ \t]+/gu, ' ');
  const labels = /^X-Gmail-Labels: ?(.*)$/imu.exec(headers)?.[1];
  let groupName = fallbackGroup;
  if (labels !== undefined) {
    const has = (label: string) => new RegExp(`(?:^|,)${label}(?:,|$)`, 'u').test(labels);
    if (has('Chat')) { skip('chat'); return; }
    if (has('Sent') && !has('Inbox')) { skip('sent'); return; }
    groupName = has('Spam') ? 'spam' : 'mail';
  }
  if (options.since > -Infinity) {
    const date = Date.parse((/^Date: ?(.*)$/imu.exec(headers)?.[1] ?? '').replace(/\s*\(.*\)\s*$/u, ''));
    if (!Number.isFinite(date) || date < options.since) { skip('before --since'); return; }
  }
  let email: EmailMessage;
  try {
    email = toEmailMessage(buf);
  } catch {
    skip('unparseable'); return;
  }
  score(email, groupName, options, id);
}

async function readMbox(file: string, options: Options, groupName: string): Promise<void> {
  const name = path.basename(file);
  let lines: string[] = [];
  let bytes = 0;
  let index = 0;
  let previousBlank = true;
  const flush = () => {
    if (lines.length > 0) scoreRaw(Buffer.from(lines.join('\n'), 'latin1'), options, `${name}#${String(index++)}`, groupName);
    lines = [];
    bytes = 0;
  };
  const input = createReadStream(file, { encoding: 'latin1', highWaterMark: 1 << 20 });
  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    if (previousBlank && /^From \S+ /u.test(line)) flush();
    else if (bytes < MAX_MESSAGE_BYTES) {
      lines.push(line);
      bytes += line.length + 1;
    }
    previousBlank = line === '';
  }
  flush();
}

function* csvRows(text: string): Generator<string[]> {
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (quoted) {
      if (c !== '"') field += c;
      else if (text[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field.replace(/\r$/u, ''));
      yield row;
      row = [];
      field = '';
    } else field += c;
  }
  if (field !== '' || row.length > 0) yield [...row, field];
}

const NOT_A_LINK = /\.(?:gif|jpe?g|png|bmp|css|js|dtd|xsd)(?:\?|$)|w3\.org\/|schemas\.microsoft\.com|purl\.org/iu;

/**
 * A row of a pre-extracted dataset. These carry the sender's *domain* only, so the address is
 * reconstructed with a neutral local part, and the URL column has no anchor text: link checks comparing
 * text with destination have nothing to compare, and results on such a set understate them.
 */
function readCsv(file: string, options: Options): void {
  const rows = csvRows(readFileSync(file, 'utf8'));
  const head = rows.next();
  if (head.done === true) return;
  const column = (name: string) => head.value.indexOf(name);
  const at = { sender: column('sender'), senderDomain: column('sender_domain'), recipientDomain: column('receiver_domain'), subject: column('subject'), body: column('body'), urls: column('urls'), source: column('source'), label: column('label') };
  if (Object.values(at).some((i) => i < 0)) fail(`${file}: missing one of the columns ${Object.keys(at).join(', ')}`);
  const strip = (s: string) => s.replace(/<\|[A-Z_]+\|>/gu, ' ');
  let index = 0;
  for (const row of rows) {
    index++;
    if (row.length !== head.value.length) {
      skip('malformed row');
      continue;
    }
    const cell = (i: number) => row[i] ?? '';
    const senderDomain = cell(at.senderDomain).trim().toLowerCase();
    const recipientDomain = (cell(at.recipientDomain).split(/[\s,;]+/u)[0] ?? '').trim().toLowerCase();
    const name = /^(.*?)</u.exec(cell(at.sender))?.[1]?.replace(/"/gu, '').trim() ?? '';
    const email: EmailMessage = {
      ...(name !== '' ? { senderName: name } : {}),
      ...(senderDomain !== '' ? { senderEmail: `sender@${senderDomain}` } : {}),
      ...(recipientDomain !== '' ? { recipientEmail: `reader@${recipientDomain}` } : {}),
      subject: strip(cell(at.subject)),
      bodyText: truncate(strip(cell(at.body)), MAX_BODY_CHARS),
      links: cell(at.urls)
        .split(/[\s,]+/u)
        .map((u) => u.trim().replace(/["'>)\].,;]+$/u, ''))
        .filter((u) => /^(?:https?|ftp|file|javascript|data):/iu.test(u) && !NOT_A_LINK.test(u))
        .slice(0, 300)
        .map((href) => {
          const parsed = parseUrl(href);
          return { text: '', href, normalizedDomain: parsed === null ? '' : normalizeDomain(parsed.hostname) };
        }),
      attachments: [],
    };
    const kind = cell(at.label).startsWith('0') ? 'legitimate' : 'malicious';
    score(email, `${cell(at.source) || path.basename(file)}:${kind}`, options, `${path.basename(file)}#${String(index)}`);
  }
}

/** Every message under a path lands in one group, named for the path unless `--group` names it. */
async function read(input: string, options: Options, groupName: string): Promise<void> {
  if (statSync(input).isDirectory()) {
    for (const file of readdirSync(input).sort()) {
      const full = path.join(input, file);
      if (statSync(full).isFile()) await read(full, options, groupName);
    }
    return;
  }
  if (/\.csv$/iu.test(input)) {
    readCsv(input, options);
    return;
  }
  const start = Buffer.alloc(5);
  const fd = openSync(input, 'r');
  readSync(fd, start, 0, start.length, 0);
  closeSync(fd);
  if (start.toString('latin1') === 'From ') {
    await readMbox(input, options, groupName);
    return;
  }
  if (statSync(input).size > MAX_MESSAGE_BYTES) {
    skip('too large');
    return;
  }
  scoreRaw(readFileSync(input), options, path.basename(input), groupName);
}

function report(options: Options): void {
  const out: string[] = [];
  for (const [name, g] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    const flagged = (g.byClass['suspicious'] ?? 0) + (g.byClass['high-risk'] ?? 0);
    const share = ((100 * flagged) / Math.max(g.scored, 1)).toFixed(2);
    out.push(`\n== ${name}: ${String(g.scored)} scored, ${String(flagged)} suspicious or worse (${share}%)`);
    out.push(`   classes ${JSON.stringify(g.byClass)}`);
    out.push(`   floors  ${JSON.stringify(g.floors)}`);
    const total = (counts: Record<string, number>) => Object.values(counts).reduce((x, y) => x + y, 0);
    const ranked = Object.entries(g.rules).sort(([, a], [, b]) => total(b) - total(a));
    for (const [rule, counts] of ranked.slice(0, 30)) out.push(`   ${rule.padEnd(52)} ${JSON.stringify(counts)}`);
    if (options.rows !== undefined) {
      mkdirSync(options.rows, { recursive: true });
      writeFileSync(path.join(options.rows, `${name.replace(/[^\w.-]+/gu, '_')}-rows.json`), JSON.stringify(g.rows, null, 1));
    }
  }
  out.push(`\nskipped ${JSON.stringify(skipped)}\n`);
  process.stdout.write(out.join('\n'));
}

const options = parseArgs(process.argv.slice(2));
for (const input of options.inputs) await read(input, options, options.group ?? path.basename(input));
report(options);
