/**
 * URL and domain primitives.
 *
 * Rule for this file: parsing is done by the platform `URL` parser, never by hand-rolled regexes.
 * `new URL()` applies WHATWG normalisation, IDNA/punycode encoding, and percent-decoding rules that
 * an ad-hoc regex will get wrong in exactly the ways an attacker is counting on.
 */
import {
  KNOWN_CLICK_TRACKERS,
  KNOWN_SENDING_PLATFORMS,
  MULTI_LABEL_SUFFIXES,
  OPEN_HOSTING_SUFFIXES,
  URL_SHORTENERS,
} from './public-suffix.js';
import { emailDomain } from './text.js';
import { IANA_TLDS } from './tlds.js';

/** Schemes we consider "web navigation". */
const WEB_SCHEMES = new Set(['http:', 'https:']);

/**
 * Schemes that are actively dangerous or strongly indicate something other than a normal link.
 *
 * `no-script-url` is disabled for this list only. The rule exists to stop `javascript:` being *used*
 * as a URL; here the string is data in a denylist that exists to detect it. Nothing in this module
 * navigates to, assigns, or evaluates any of these.
 */
const DANGEROUS_SCHEMES = new Set([
  // eslint-disable-next-line no-script-url
  'javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'ftp:', 'smb:', 'ms-msdt:', 'search-ms:',
  'ms-appinstaller:', 'ms-officecmd:', 'chrome:', 'chrome-extension:', 'about:',
]);

/** Schemes that are benign but not navigations. */
const NON_NAVIGATION_SCHEMES = new Set(['mailto:', 'tel:', 'sms:', 'callto:', 'skype:', 'webcal:']);

/**
 * Parses a URL without ever throwing.
 *
 * Deliberately does **not** supply a base: a relative href in an email body is itself a signal
 * (malformed / template leakage), and silently resolving it against `mail.google.com` would invent
 * a Google destination that does not exist.
 */
export function parseUrl(href: string): URL | null {
  const raw = href.trim();
  if (raw === '') return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/**
 * Lowercases a hostname and strips the trailing root dot and a leading `www.`.
 * `URL` has already applied IDNA, so this receives punycode (`xn--…`) form for non-ASCII names.
 */
export function normalizeDomain(hostname: string): string {
  let host = hostname.trim().toLowerCase();
  // A bracketed IPv6 literal is returned by URL as `[::1]`; keep it intact.
  if (host.startsWith('[')) return host;
  while (host.endsWith('.')) host = host.slice(0, -1);
  if (host.startsWith('www.')) host = host.slice(4);
  return host;
}

/** The normalised domain of an email address, or `''` when there is not one. */
export function addressDomain(address: string | undefined): string {
  return normalizeDomain(emailDomain(address));
}

export function domainLabels(hostname: string): string[] {
  const host = normalizeDomain(hostname);
  if (host === '' || isIpHost(host)) return [];
  return host.split('.').filter((l) => l !== '');
}

/**
 * eTLD+1 using the curated suffix table. Returns the host unchanged for IP literals and
 * single-label hosts.
 */
export function registrableDomain(hostname: string): string {
  const host = normalizeDomain(hostname);
  if (host === '' || isIpHost(host)) return host;

  const labels = host.split('.').filter((l) => l !== '');
  if (labels.length <= 2) return labels.join('.');

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

/** Everything to the left of the registrable domain. */
export function subdomainOf(hostname: string): string {
  const host = normalizeDomain(hostname);
  const reg = registrableDomain(host);
  if (host === reg || !host.endsWith(`.${reg}`)) return '';
  return host.slice(0, host.length - reg.length - 1);
}

export function tldOf(hostname: string): string {
  const labels = domainLabels(hostname);
  return labels.length > 0 ? (labels[labels.length - 1] ?? '') : '';
}

/**
 * True when the hostname's TLD is not one IANA has delegated — i.e. the name cannot exist.
 *
 * Distinct from `isMalformedHost`, which asks whether a TLD is *shaped* like one. `.ldk` passes that
 * test and is still not a place mail can come from.
 *
 * Returns `false` for anything where the question does not apply — an empty host, an IP literal, a
 * single-label name, a name that cannot be reduced to the ASCII form the list is written in — so a caller
 * gets "this TLD does not exist" and not "there was no TLD to check". Both are absences; only one is
 * evidence.
 */
export function hasUnknownTld(hostname: string): boolean {
  const ascii = asciiHost(hostname);
  if (ascii === null) return false;

  const labels = domainLabels(ascii);
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1] ?? '';
  return tld !== '' && !IANA_TLDS.has(tld);
}

/**
 * A host in the ASCII form IANA publishes its list in, or `null` if it has none.
 *
 * `.рф` is delegated; `xn--p1ai` is how it is written down. Comparing the Unicode spelling against the
 * list would report every internationalised domain in the world as nonexistent, so the conversion is
 * mandatory rather than defensive — and a host that will not convert must be nobody's finding, since the
 * alternative is a fabricated-sender verdict drawn from our own inability to parse a name.
 *
 * Deliberately not folded into `normalizeDomain`: that value is compared against brands and shown as
 * evidence, and rewriting a legitimate `президент.рф` to punycode there would both mangle the display and
 * trip `hasPunycode`, whose entire premise is that the *sender* chose that encoding.
 */
function asciiHost(hostname: string): string | null {
  if (!/[^\u0000-\u007f]/u.test(hostname)) return hostname;
  try {
    const converted = new URL(`http://${hostname}`).hostname;
    return /[^\u0000-\u007f]/u.test(converted) ? null : converted;
  } catch {
    return null;
  }
}

/**
 * The name part of a domain, with its suffix removed: `northwind-supply.co.uk` → `northwind-supply`.
 *
 * What lookalike comparison has to run on. Comparing whole domains would rate `example.com` and
 * `example.de` as one edit apart when they are usually the same organisation, while missing that
 * `example.com` and `examp1e.com` differ in the only part a reader reads.
 */
export function domainCore(hostname: string): string {
  const registrable = registrableDomain(hostname);
  const dot = registrable.indexOf('.');
  return dot <= 0 ? registrable : registrable.slice(0, dot);
}

/**
 * True for any host that is an IP literal rather than a name — including the obfuscated forms
 * (`http://3232235777/`, `http://0xc0a80001/`, `http://0300.0250.0.1/`) that the WHATWG parser
 * accepts and silently canonicalises. We check the *parsed* result where possible, and fall back to
 * pattern checks for the raw string.
 */
export function isIpHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (host === '') return false;
  if (host.startsWith('[') && host.endsWith(']')) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;

  // The WHATWG parser canonicalises decimal/hex/octal IPv4 forms, so by the time a hostname reaches
  // us from `new URL()` it is dotted-quad. These extra checks catch strings not run through URL.
  if (/^\d+$/.test(host)) return true;
  if (/^0x[0-9a-f]+$/.test(host)) return true;
  if (/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))+$/.test(host) && !/[a-z]/.test(host.replace(/0x/g, ''))) {
    return true;
  }
  return false;
}

/**
 * True for an IP literal no one outside the reader's own network can reach: RFC 1918 private ranges,
 * loopback, link-local, carrier-grade NAT, and their IPv6 counterparts.
 *
 * Expects the hostname `URL` produced, which has already canonicalised the obfuscated decimal, hex and
 * octal forms to a dotted quad; anything else is answered `false`, so an unparsed trick still reads as a
 * public address rather than escaping as a private one.
 */
export function isPrivateIpHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/u.exec(host);
  if (v4 !== null) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    const v6 = host.slice(1, -1);
    return v6 === '::1' || /^f[cd][0-9a-f]{0,2}:/u.test(v6) || /^fe[89ab][0-9a-f]?:/u.test(v6);
  }
  return false;
}

/** True when any label is punycode-encoded, i.e. the display form contains non-ASCII characters. */
export function hasPunycode(hostname: string): boolean {
  return domainLabels(hostname).some((label) => label.startsWith('xn--'));
}

export function isWebUrl(url: URL): boolean {
  return WEB_SCHEMES.has(url.protocol);
}

export function isDangerousScheme(url: URL): boolean {
  return DANGEROUS_SCHEMES.has(url.protocol);
}

export function isNonNavigationScheme(url: URL): boolean {
  return NON_NAVIGATION_SCHEMES.has(url.protocol);
}

export function isShortener(hostname: string): boolean {
  const host = normalizeDomain(hostname);
  return URL_SHORTENERS.has(host) || URL_SHORTENERS.has(registrableDomain(host));
}

/** A third party that sends or relays mail for its customers. Envelope hosts only; see the list. */
export function isKnownSendingPlatform(hostname: string): boolean {
  const host = normalizeDomain(hostname);
  return KNOWN_SENDING_PLATFORMS.has(host) || KNOWN_SENDING_PLATFORMS.has(registrableDomain(host));
}

/** The URL is a recognised click-tracking or link-protection endpoint. See `KNOWN_CLICK_TRACKERS`. */
export function isKnownClickTracker(url: URL): boolean {
  if (!WEB_SCHEMES.has(url.protocol)) return false;
  const host = normalizeDomain(url.hostname);
  return KNOWN_CLICK_TRACKERS.some(
    (tracker) =>
      (host === tracker.host || (tracker.subdomains === true && host.endsWith(`.${tracker.host}`))) &&
      (tracker.path === undefined || tracker.path.test(url.pathname)),
  );
}

export function openHostingSuffix(hostname: string): string | null {
  const host = normalizeDomain(hostname);
  for (const suffix of OPEN_HOSTING_SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return suffix;
  }
  return null;
}

/**
 * A hostname that is syntactically legal for `URL` but cannot be a real public host.
 * `URL` is permissive; it will happily accept `http://foo` or `http://a..b`.
 */
export function isMalformedHost(hostname: string): boolean {
  const host = normalizeDomain(hostname);
  if (host === '') return true;
  if (host.startsWith('[')) return false; // IPv6 literal, handled elsewhere
  if (isIpHost(host)) return false;
  if (host.includes('..')) return true;
  if (host.startsWith('.') || host.startsWith('-') || host.endsWith('-')) return true;
  if (!host.includes('.')) return true; // single-label, not resolvable publicly
  const labels = host.split('.');
  if (labels.some((l) => l.length > 63 || l === '' || l.startsWith('-') || l.endsWith('-'))) return true;
  if (host.length > 253) return true;
  const tld = labels[labels.length - 1] ?? '';
  // A public TLD is alphabetic and at least two characters (or punycode).
  if (!/^(?:[a-z]{2,}|xn--[a-z0-9-]{2,})$/.test(tld)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Redirect unwrapping
// ---------------------------------------------------------------------------

const REDIRECT_PARAM_NAMES = [
  'q', 'url', 'u', 'target', 'dest', 'destination', 'redirect', 'redirect_uri', 'redirect_url',
  'redirecturl', 'return', 'returnurl', 'return_url', 'next', 'continue', 'goto', 'go', 'to',
  'link', 'out', 'r', 'ref_url', 'forward', 'checkout_url',
];

export interface UnwrapResult {
  /** The deepest URL we could resolve. Equals the input when nothing was unwrapped. */
  url: URL;
  /** How many redirect layers were peeled. */
  hops: number;
  /** The hostnames we passed through, outermost first. */
  chain: string[];
  /** The URLs behind `chain`, outermost first: the input, then each target peeled from it. */
  urls: URL[];
  /**
   * True when a redirect parameter was present but its value was not a parseable absolute URL —
   * i.e. the link looks like an open redirector but we cannot see the destination.
   */
  opaqueRedirect: boolean;
}

/**
 * Peels redirect wrappers so comparisons are made against real destinations.
 *
 * Gmail rewrites body links to `https://www.google.com/url?q=<real>`, and attackers chain open
 * redirectors. Bounded to 3 hops — an attacker controls the input and we will not loop on it.
 */
export function unwrapRedirects(input: URL, maxHops = 3): UnwrapResult {
  let current = input;
  const chain: string[] = [normalizeDomain(input.hostname)];
  const urls: URL[] = [input];
  let hops = 0;
  let opaqueRedirect = false;

  while (hops < maxHops) {
    const candidate = extractRedirectTarget(current);
    if (candidate === null) break;
    if (candidate.parsed === null) {
      opaqueRedirect = true;
      break;
    }
    current = candidate.parsed;
    chain.push(normalizeDomain(current.hostname));
    urls.push(current);
    hops += 1;
  }

  return { url: current, hops, chain, urls, opaqueRedirect };
}

function extractRedirectTarget(url: URL): { parsed: URL | null } | null {
  if (!WEB_SCHEMES.has(url.protocol)) return null;

  let opaque = false;
  for (const name of REDIRECT_PARAM_NAMES) {
    const value = url.searchParams.get(name);
    if (value === null || value.trim() === '') continue;
    // Only treat it as a redirect if the value actually looks like a URL; `?q=invoice` on a search
    // page is not a redirect.
    if (!/^(?:https?:)?\/\//i.test(value) && !/^https?%3a/i.test(value)) continue;
    const normalized = value.startsWith('//') ? `https:${value}` : value;
    const parsed = parseUrl(normalized) ?? parseUrl(safeDecode(normalized));
    if (parsed !== null && WEB_SCHEMES.has(parsed.protocol)) return { parsed };
    // URL-shaped but unresolvable: the link conceals its destination, which is itself worth reporting.
    // Recorded and set aside rather than returned, so a decoy `?q=//` cannot stop us finding the real
    // target in a later parameter.
    opaque = true;
  }

  // Path-embedded redirects, e.g. `/redirect/https://evil.example/login`.
  //
  // The separators are matched percent-encoded as well, because that is the form the click trackers of
  // the large sending platforms use: `…/L0/https:%2F%2Fexample.com%2Fpath`. `URL` does not decode `%2F`
  // in a pathname — correctly, since a decoded slash would change the path's structure — so a pattern
  // written only for the literal form reads the tracker's own host as the destination. Every rule that
  // asks where a link goes then answers with the tracker, which is how a brand's genuine mail came to
  // be reported as sending its readers to a domain the brand does not own.
  const embedded = /https?:(?:\/\/|%2f%2f)[^\s"'<>]+/i.exec(url.pathname.slice(1));
  if (embedded !== null) {
    const parsed = parseUrl(safeDecode(embedded[0]));
    if (parsed !== null && WEB_SCHEMES.has(parsed.protocol)) return { parsed };
  }
  const encoded = base64Target(`${url.pathname}${url.search}`);
  if (encoded !== null) return { parsed: encoded };
  return opaque ? { parsed: null } : null;
}

/**
 * A destination carried base64-encoded, as link-protection gateways rewrite every link in a message.
 *
 * Matched by its content rather than by any vendor's URL layout: base64 of `http` always begins `aHR0c`,
 * so the token is found wherever a gateway puts it, in a path segment or a parameter, and a decode that
 * is not a web URL is discarded. URL-safe and standard alphabets both occur; a `/` ends the token, since
 * in a path it is a separator. Bounded, because the input is the attacker's.
 */
function base64Target(text: string): URL | null {
  const token = /(?<![A-Za-z0-9+_-])aHR0c[A-Za-z0-9+_-]{8,2048}(?:={0,2}|(?:%3[dD]){0,2})/u.exec(text);
  if (token === null) return null;
  const body = token[0].replace(/(?:=|%3[dD])+$/u, '').replaceAll('-', '+').replaceAll('_', '/');
  let decoded: string;
  try {
    decoded = atob(body + '='.repeat((4 - (body.length % 4)) % 4));
  } catch {
    return null;
  }
  const target = /^https?:\/\/[\x21-\x7e]+/u.exec(decoded);
  if (target === null) return null;
  const parsed = parseUrl(target[0]);
  return parsed !== null && WEB_SCHEMES.has(parsed.protocol) ? parsed : null;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** True when the URL carries a redirect-style parameter at all, regardless of resolvability. */
export function hasRedirectParam(url: URL): boolean {
  if (!WEB_SCHEMES.has(url.protocol)) return false;
  for (const name of REDIRECT_PARAM_NAMES) {
    const value = url.searchParams.get(name);
    if (value !== null && /^(?:https?:)?(?:\/\/|%2f%2f)/i.test(value)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Anchor text interpretation
// ---------------------------------------------------------------------------

/**
 * Interprets anchor text as a URL *if a reader would read it as one*.
 *
 * This is the core of the "displayed URL differs from actual URL" check, so it must be strict: we
 * only claim the text is a URL when it really looks like one, otherwise ordinary link text like
 * "Click here to sign in" would generate mismatch findings on every legitimate email.
 */
export function parseDisplayedUrl(text: string): URL | null {
  const trimmed = text.trim().replace(/[.,;:!?)\]]+$/, '');
  if (trimmed === '' || trimmed.length > 2048) return null;
  if (/\s/.test(trimmed)) return null;

  if (/^https?:\/\//i.test(trimmed)) return parseUrl(trimmed);

  // Bare host or host/path, e.g. `login.microsoftonline.com/verify`.
  if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/?#].*)?$/i.test(trimmed)) {
    const parsed = parseUrl(`https://${trimmed}`);
    if (parsed === null) return null;
    // Reject things like `file.tar.gz` or `v1.2.3` being read as hostnames.
    if (isMalformedHost(parsed.hostname)) return null;
    // An attachment link labelled `image0.jpeg` or `statement.pdf` is a filename, not an address a
    // reader was shown. Only a delegated TLD makes bare text an address, which deliberately keeps the
    // extensions that are also TLDs (`.zip`, `.mov`): a filename that resolves is the trick itself.
    if (hasUnknownTld(parsed.hostname)) return null;
    return parsed;
  }
  return null;
}

/** Whether two hosts belong to the same organisation, as far as we can tell from names alone. */
export function sameRegistrableDomain(a: string, b: string): boolean {
  const ra = registrableDomain(a);
  const rb = registrableDomain(b);
  return ra !== '' && ra === rb;
}

export function countSubdomainLabels(hostname: string): number {
  const sub = subdomainOf(hostname);
  return sub === '' ? 0 : sub.split('.').length;
}

/** Renders a URL for display: host + truncated path, never the raw attacker string. */
export function describeUrl(url: URL): string {
  const host = normalizeDomain(url.hostname);
  const path = url.pathname === '/' ? '' : url.pathname;
  const suffix = `${path}${url.search}`;
  const shown = suffix.length > 48 ? `${suffix.slice(0, 45)}…` : suffix;
  return `${host}${shown}`;
}
