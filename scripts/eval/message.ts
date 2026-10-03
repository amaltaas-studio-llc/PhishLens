/**
 * A stored message → the `EmailMessage` the Gmail adapter would have produced from it on screen.
 *
 * The point of an evaluation is to measure the extension, so the conversion follows what Gmail renders
 * rather than what is convenient to parse, and borrows the adapter's own pieces wherever they are pure:
 * the selector lists, the hidden-subtree scan, the whitespace and URL helpers. Each place it cannot
 * follow Gmail exactly is a place a corpus result can differ from a user's, and is named below.
 *
 * - **The HTML part wins.** Gmail renders `text/html` from a `multipart/alternative` whenever one exists.
 *   Preferring `text/plain` would measure something no user sees: plenty of senders put markup, hidden
 *   preheaders included, in the plain part, so the "body" would be tag soup with a handful of links and
 *   bulk mail would stop looking like bulk mail.
 * - **Authentication comes from headers.** The adapter reads Gmail's details table; the first
 *   `Authentication-Results` header is what that table is drawn from, but Gmail's banner, `via`
 *   annotation and unauthenticated avatar have no header and are never set.
 * - **Stylesheets are not applied**, exactly as in the adapter, whose hidden-text scan reads inline
 *   styles only. jsdom gives the same answer for the same reason.
 */
import { JSDOM, VirtualConsole } from 'jsdom';
import { separateBlocks } from '../../src/gmail/block-text.js';
import { countContentChars, findHiddenSubtrees } from '../../src/gmail/hidden-text.js';
import { SELECTORS, outermost, queryAll, queryAllUnion } from '../../src/gmail/selectors.js';
import { MAX_BODY_CHARS, collapseWhitespace, fileExtension, truncate } from '../../src/shared/text.js';
import type { AuthVerdict, EmailAuthInfo, EmailLink, EmailMessage } from '../../src/shared/types.js';
import { normalizeDomain, parseUrl } from '../../src/shared/url.js';
import { decodeWords, header, parseMessage } from './mime.js';

const MAX_LINKS = 300;
const MAX_HTML_CHARS = 2_000_000;

export function toEmailMessage(buf: Buffer): EmailMessage {
  const parsed = parseMessage(buf);
  const from = address(header(parsed.headers, 'from'));
  const replyTo = address(header(parsed.headers, 'reply-to')).email;
  const to = address(header(parsed.headers, 'to')).email;
  const subject = decodeWords(header(parsed.headers, 'subject'));
  const html = parsed.html.join('\n');
  const body = html !== '' ? fromHtml(html) : fromText(parsed.text.join('\n'));
  const auth = authentication(parsed.headers.get('authentication-results')?.[0]);
  const senderEmail = from.email.toLowerCase();

  return {
    ...(from.name !== '' ? { senderName: from.name } : {}),
    ...(senderEmail !== '' ? { senderEmail } : {}),
    ...(replyTo !== '' ? { replyTo: replyTo.toLowerCase() } : {}),
    subject: collapseWhitespace(subject),
    bodyText: body.text,
    ...(body.hidden !== undefined ? { hiddenText: body.hidden } : {}),
    links: body.links,
    attachments: parsed.attachments.map((filename) => ({ filename, extension: fileExtension(filename) })),
    ...(auth !== undefined ? { auth } : {}),
    ...(to !== '' ? { recipientEmail: to.toLowerCase() } : {}),
    raw: { ...(from.email !== senderEmail ? { senderEmail: from.email } : {}), subject: truncate(subject, 998) },
  };
}

interface Body {
  text: string;
  links: EmailLink[];
  hidden?: { chars: number; techniques: string[] };
}

/** A console attached to nothing, so a sender's malformed CSS is not reported on stdout as ours. */
const SILENT = new VirtualConsole();

/**
 * jsdom with its defaults, which matter here: scripts are not run and no subresource is loaded, so
 * parsing a message dereferences nothing in it, the same guarantee the extension makes.
 */
function fromHtml(html: string): Body {
  const { document } = new JSDOM(truncate(html, MAX_HTML_CHARS), { virtualConsole: SILENT }).window;
  const root = document.body;
  const links = linksIn(root);

  for (const nonContent of queryAll(root, ['style', 'script', 'head', 'title'])) nonContent.remove();
  const quoted = outermost(queryAllUnion(root, SELECTORS.quotedContent));
  for (const block of quoted) block.remove();
  const own = pruneHidden(root);
  separateBlocks(root);
  let text = truncate(normalizeBodyWhitespace(root.textContent), MAX_BODY_CHARS);
  let chars = own.chars;
  const techniques = new Set(own.techniques);

  // As in the adapter: a message that is nothing but quoted history is read rather than scored empty.
  if (countContentChars(text) === 0 && quoted.length > 0) {
    const history = document.createElement('div');
    history.append(...quoted);
    const pruned = pruneHidden(history);
    separateBlocks(history);
    text = truncate(normalizeBodyWhitespace(history.textContent), MAX_BODY_CHARS);
    chars += pruned.chars;
    for (const technique of pruned.techniques) techniques.add(technique);
  }
  return { text, links, ...(chars > 0 ? { hidden: { chars, techniques: [...techniques] } } : {}) };
}

/** A plain-text body, linkified the way Gmail renders bare URLs. Markup in it is shown, so it is text. */
function fromText(text: string): Body {
  const body = truncate(normalizeBodyWhitespace(text), MAX_BODY_CHARS);
  const links = [...body.matchAll(/https?:\/\/[^\s<>"')\]]+/giu)]
    .slice(0, MAX_LINKS)
    .map(([href]) => toLink(href, href));
  return { text: body, links };
}

function pruneHidden(container: Element): { chars: number; techniques: string[] } {
  const scan = findHiddenSubtrees(container);
  let chars = 0;
  for (const hidden of scan.roots) {
    chars += hidden.chars;
    hidden.element.before(...hidden.visible);
    hidden.element.remove();
  }
  return { chars, techniques: scan.techniques };
}

/** Every anchor, quoted or not, for the reason `extractLinks` in the adapter gives. */
function linksIn(root: Element): EmailLink[] {
  const links: EmailLink[] = [];
  const seen = new Set<string>();
  for (const anchor of queryAll(root, SELECTORS.bodyLink)) {
    if (links.length >= MAX_LINKS) break;
    const href = anchor.getAttribute('href')?.trim() ?? '';
    if (href === '' || href.startsWith('#')) continue;
    const text = collapseWhitespace(anchor.textContent);
    const key = `${text}\u0000${href}`;
    if (seen.has(key)) continue;
    seen.add(key);
    links.push(toLink(text, href));
  }
  return links;
}

function toLink(text: string, href: string): EmailLink {
  const parsed = parseUrl(href);
  return {
    text: truncate(text, 512),
    href: truncate(href, 4096),
    normalizedDomain: parsed === null ? '' : normalizeDomain(parsed.hostname),
  };
}

function normalizeBodyWhitespace(text: string): string {
  return text
    .replace(/\r\n?/gu, '\n')
    .replace(/[ \t\u00a0]+/gu, ' ')
    .replace(/ ?\n ?/gu, '\n')
    .replace(/\n{3,}/gu, '\n\n')
    .trim();
}

function address(value: string): { name: string; email: string } {
  const decoded = decodeWords(value);
  const angle = /^(.*?)<([^>]*)>/u.exec(decoded);
  if (angle !== null) {
    return {
      name: (angle[1] ?? '').trim().replace(/^"|"$/gu, '').trim(),
      email: (angle[2] ?? '').trim(),
    };
  }
  return { name: '', email: /[^\s<>"]+@[^\s<>"]+/u.exec(decoded)?.[0] ?? '' };
}

const VERDICTS = new Set<string>(['pass', 'fail', 'softfail', 'neutral', 'none']);

function verdict(results: string, method: string): AuthVerdict | undefined {
  const m = new RegExp(`\\b${method}=([a-z]+)`, 'iu').exec(results);
  if (m?.[1] === undefined) return undefined;
  const value = m[1].toLowerCase();
  if (VERDICTS.has(value)) return value as AuthVerdict;
  return value === 'bestguesspass' ? 'neutral' : 'unknown';
}

function authentication(results: string | undefined): EmailAuthInfo | undefined {
  if (results === undefined) return undefined;
  const info: EmailAuthInfo = {};
  const spf = verdict(results, 'spf');
  const dkim = verdict(results, 'dkim');
  const dmarc = verdict(results, 'dmarc');
  if (spf !== undefined) info.spf = spf;
  if (dkim !== undefined) info.dkim = dkim;
  if (dmarc !== undefined) info.dmarc = dmarc;
  const signedBy = /header\.d=([a-z0-9.-]+)/iu.exec(results)?.[1] ?? /header\.i=@?([a-z0-9.-]+)/iu.exec(results)?.[1];
  if (signedBy !== undefined && dkim === 'pass') info.signedBy = signedBy.toLowerCase();
  const mailedBy = /smtp\.mailfrom=(?:[^@\s;]*@)?([a-z0-9.-]+)/iu.exec(results)?.[1];
  if (mailedBy !== undefined && spf === 'pass') info.mailedBy = mailedBy.toLowerCase();
  return info;
}
