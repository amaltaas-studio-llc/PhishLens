/**
 * Just enough RFC 5322 and MIME to turn a stored message into the parts Gmail would render.
 *
 * Not a general parser, and deliberately so: it exists to feed the engine what the content script would
 * read, so anything Gmail does not show — every header but a handful, alternative parts it does not
 * pick, attachment bytes — is dropped as early as possible. Every loop is bounded, because a corpus of
 * phishing mail is exactly where a message with ten thousand nested parts turns up.
 */

const MAX_DEPTH = 8;
const MAX_PARTS = 50;
const MAX_ATTACHMENTS = 60;

type Headers = Map<string, string[]>;

interface Part {
  headers: Headers;
  body: Buffer;
}

export interface ParsedMessage {
  /** Top-level headers, lowercased names, values unfolded and undecoded. */
  headers: Headers;
  /** Decoded `text/plain` parts, in order. */
  text: string[];
  /** Decoded `text/html` parts, in order. */
  html: string[];
  /** Filenames of every part Gmail would show as an attachment chip. */
  attachments: string[];
}

export function header(headers: Headers, name: string): string {
  return headers.get(name)?.[0] ?? '';
}

export function parseMessage(buf: Buffer): ParsedMessage {
  const top = splitPart(buf);
  const acc: ParsedMessage = { headers: top.headers, text: [], html: [], attachments: [] };
  walk(top, acc, 0);
  return acc;
}

/** RFC 2047 encoded words, which is how nearly every non-ASCII display name and subject arrives. */
export function decodeWords(value: string): string {
  return value.replace(
    /=\?([^?]{1,40})\?([bq])\?([^?]*)\?=(\s+(?==\?))?/giu,
    (_m, charset: string, encoding: string, text: string) => {
      const bytes =
        encoding.toLowerCase() === 'b'
          ? Buffer.from(text, 'base64')
          : Buffer.from(
              text.replace(/_/gu, ' ').replace(/=([0-9a-f]{2})/giu, (_x, hex: string) =>
                String.fromCharCode(parseInt(hex, 16)),
              ),
              'latin1',
            );
      return decodeCharset(bytes, charset.split('*')[0] ?? '');
    },
  );
}

function splitPart(buf: Buffer): Part {
  const s = buf.toString('latin1');
  let end = s.search(/\r?\n\r?\n/u);
  if (end < 0) end = s.length;
  const separator = /^\r?\n\r?\n/u.exec(s.slice(end))?.[0].length ?? 0;
  const headers: Headers = new Map();
  for (const line of s.slice(0, end).replace(/\r?\n[ \t]+/gu, ' ').split(/\r?\n/u)) {
    const m = /^([!-9;-~]+):\s*(.*)$/u.exec(line);
    if (m?.[1] === undefined) continue;
    const name = m[1].toLowerCase();
    headers.set(name, [...(headers.get(name) ?? []), m[2] ?? '']);
  }
  return { headers, body: buf.subarray(end + separator) };
}

function decodeCharset(bytes: Buffer, charset: string): string {
  try {
    return new TextDecoder(charset === '' ? 'utf-8' : charset).decode(bytes);
  } catch {
    return bytes.toString('utf8');
  }
}

function param(value: string, name: string): string {
  const m = new RegExp(`(?:^|;)\\s*${name}\\*?=\\s*(?:"([^"]*)"|([^;\\s]+))`, 'iu').exec(value);
  return m === null ? '' : decodeWords(m[1] ?? m[2] ?? '');
}

function transferDecode(part: Part): Buffer {
  const encoding = header(part.headers, 'content-transfer-encoding').trim().toLowerCase();
  if (encoding === 'base64') {
    return Buffer.from(part.body.toString('latin1').replace(/[^A-Za-z0-9+/=]/gu, ''), 'base64');
  }
  if (encoding === 'quoted-printable') {
    const s = part.body
      .toString('latin1')
      .replace(/=\r?\n/gu, '')
      .replace(/=([0-9A-Fa-f]{2})/gu, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    return Buffer.from(s, 'latin1');
  }
  return part.body;
}

function walk(part: Part, acc: ParsedMessage, depth: number): void {
  if (depth > MAX_DEPTH) return;
  const contentType = header(part.headers, 'content-type') || 'text/plain';
  const type = (contentType.split(';')[0] ?? '').trim().toLowerCase();
  const disposition = header(part.headers, 'content-disposition');
  const filename = param(disposition, 'filename') || param(contentType, 'name');

  if (type.startsWith('multipart/')) {
    const boundary = param(contentType, 'boundary');
    if (boundary === '') return;
    const pieces = part.body.toString('latin1').split(`--${boundary}`).slice(1, MAX_PARTS + 1);
    for (const piece of pieces) {
      if (piece.startsWith('--')) break;
      walk(splitPart(Buffer.from(piece.replace(/^\r?\n/u, ''), 'latin1')), acc, depth + 1);
    }
    return;
  }
  if (type === 'message/rfc822') {
    walk(splitPart(transferDecode(part)), acc, depth + 1);
    return;
  }
  if (filename !== '' || /^attachment/iu.test(disposition)) {
    if (acc.attachments.length < MAX_ATTACHMENTS) acc.attachments.push(filename || 'unnamed');
    return;
  }
  const charset = param(contentType, 'charset');
  if (type === 'text/html') acc.html.push(decodeCharset(transferDecode(part), charset));
  else if (type === 'text/plain') acc.text.push(decodeCharset(transferDecode(part), charset));
}
