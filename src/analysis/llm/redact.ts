/**
 * Builds the minimised payload for the (unbuilt) cloud path.
 *
 * This module exists so that "what would leave the browser" is a single, readable, reviewable
 * function rather than an implicit consequence of whatever the cloud adapter happens to serialise.
 * If cloud analysis is ever enabled, this file is the thing to audit.
 *
 * What is deliberately dropped:
 *  - the recipient's address (the backend does not need to know who received the mail)
 *  - the sender's local part (`accounts-noreply@` → just the domain)
 *  - message and thread ids (no cross-request correlation of a user's mailbox)
 *  - attachment filenames (extensions only — filenames contain client names, case numbers, staff names)
 *  - full link URLs (registrable domains only — paths and query strings carry tracking identifiers
 *    that tie the message to a specific recipient)
 */
import { collapseWhitespace, truncate } from '../../shared/text.js';
import type { EmailMessage } from '../../shared/types.js';
import { addressDomain, normalizeDomain, registrableDomain } from '../../shared/url.js';
import type { CloudAnalyzeRequest } from '../../shared/messaging.js';
import { MAX_PROMPT_BODY_CHARS } from './prompt.js';

export type CloudPayload = CloudAnalyzeRequest['payload'];

/** The bounds of the contract, named because two functions have to agree on them. */
const MAX_SUBJECT_CHARS = 300;
const MAX_LINK_DOMAINS = 25;
const MAX_ATTACHMENT_EXTENSIONS = 15;
const MAX_SIGNAL_IDS = 40;

export function buildCloudPayload(
  email: EmailMessage,
  deterministicSignalIds: readonly string[],
): CloudPayload {
  const senderDomain = addressDomain(email.senderEmail);
  const replyToDomain = addressDomain(email.replyTo);

  return {
    subject: redactedExcerpt(collapseWhitespace(email.subject ?? ''), MAX_SUBJECT_CHARS),
    bodyExcerpt: redactedExcerpt(email.bodyText, MAX_PROMPT_BODY_CHARS),
    senderDomain,
    // The display name's *shape* is what matters for impersonation, not the name itself.
    senderNameShape: describeNameShape(email.senderName ?? ''),
    ...(replyToDomain !== '' && replyToDomain !== senderDomain ? { replyToDomain } : {}),
    linkDomains: [
      ...new Set(
        email.links
          .map((l) => registrableDomain(l.normalizedDomain))
          .filter((d) => d !== ''),
      ),
    ].slice(0, MAX_LINK_DOMAINS),
    attachmentExtensions: [
      ...new Set(email.attachments.map((a) => a.extension.toLowerCase()).filter((e) => e !== '')),
    ].slice(0, MAX_ATTACHMENT_EXTENSIONS),
    deterministicSignalIds: [...deterministicSignalIds].slice(0, MAX_SIGNAL_IDS),
  };
}

/**
 * Re-imposes the contract above on a payload that arrived over a runtime message.
 *
 * `buildCloudPayload` runs in the content script, but the service worker is the only part of the
 * extension that can reach the network, and it is handed the built payload rather than the message.
 * Trusting that hand-off means the redaction this file exists to guarantee is enforced nowhere the
 * network can see it: any surface able to call `sendMessage` — including a content script running on a
 * page that has found a way to talk to it — could post a full mailbox to a configured backend, and the
 * tests pinning this contract would still pass, because they test the builder.
 *
 * So the fields, lengths and shapes are checked again here, at the egress point. A field that cannot be
 * made to fit is dropped rather than corrected, since a value we cannot recognise is one we cannot
 * describe, and something that is not an object at all is refused outright.
 */
export function sanitizeCloudPayload(raw: unknown): CloudPayload | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const source = raw as Record<string, unknown>;

  const senderDomain = domainOnly(source['senderDomain']);
  const replyToDomain = domainOnly(source['replyToDomain']);
  const shape = typeof source['senderNameShape'] === 'string' ? source['senderNameShape'] : '';

  return {
    subject: redactedExcerpt(collapseWhitespace(asString(source['subject'])), MAX_SUBJECT_CHARS),
    bodyExcerpt: redactedExcerpt(asString(source['bodyExcerpt']), MAX_PROMPT_BODY_CHARS),
    senderDomain,
    // A shape is a hyphenated vocabulary this file controls. Anything else is reported as `unknown`
    // rather than passed through, because a display name is exactly what this field exists not to carry,
    // and `unknown` is not a value `describeNameShape` can produce — so it also says where it came from.
    senderNameShape: /^[a-z-]{1,64}$/u.test(shape) ? shape : 'unknown',
    ...(replyToDomain !== '' && replyToDomain !== senderDomain ? { replyToDomain } : {}),
    linkDomains: registrableList(source['linkDomains'], MAX_LINK_DOMAINS),
    attachmentExtensions: patternList(
      source['attachmentExtensions'],
      MAX_ATTACHMENT_EXTENSIONS,
      /^[a-z0-9]{1,16}$/u,
    ),
    deterministicSignalIds: patternList(
      source['deterministicSignalIds'],
      MAX_SIGNAL_IDS,
      /^[a-z0-9_.]{1,64}$/u,
    ),
  };
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** A bare hostname, or nothing. A local part reaching here would be the leak the payload is shaped to avoid. */
function domainOnly(value: unknown): string {
  if (typeof value !== 'string') return '';
  const domain = normalizeDomain(value);
  if (domain === '' || domain.length > 253 || /[@/\s]/u.test(domain)) return '';
  return domain;
}

/** Registrable domains only: a subdomain can name the recipient, which is why the contract drops them. */
function registrableList(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  const out = new Set<string>();
  for (const entry of value) {
    const registrable = registrableDomain(domainOnly(entry));
    if (registrable !== '') out.add(registrable);
    if (out.size >= max) break;
  }
  return [...out];
}

function patternList(value: unknown, max: number, pattern: RegExp): string[] {
  if (!Array.isArray(value)) return [];
  const out = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const normalized = entry.trim().toLowerCase();
    if (!pattern.test(normalized)) continue;
    out.add(normalized);
    if (out.size >= max) break;
  }
  return [...out];
}

/**
 * Replaces email addresses in body text with `<address@domain>`.
 *
 * The domain is retained because it is load-bearing for the analysis (a body that quotes a
 * mismatched address is a real signal); the local part is not.
 */
export function redactAddresses(text: string): string {
  return text.replace(
    /[\p{L}\p{N}._%+-]+@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)/gu,
    (_match, domain: string) => `<address@${normalizeDomain(domain)}>`,
  );
}

/**
 * Redacted, then cut. The other order lets the cut land inside an address, and `jane.doe@example` with
 * no dot after the `@` no longer looks like one, so its local part would leave unredacted. Redacting
 * first is bounded by a generous pre-cut, since nothing past twice the limit can survive the real one.
 */
function redactedExcerpt(text: string, max: number): string {
  return truncate(redactAddresses(text.slice(0, max * 2)), max);
}

/**
 * Describes a display name without revealing it: `"Jane Okonkwo"` → `"two-words"`,
 * `"Microsoft Account Team"` → `"three-words-brandlike"`.
 *
 * Enough for the backend to reason about impersonation shape, not enough to identify a person.
 */
export function describeNameShape(name: string): string {
  const trimmed = collapseWhitespace(name);
  if (trimmed === '') return 'empty';

  const words = trimmed.split(' ').filter((w) => w !== '');
  const parts: string[] = [`${countWord(words.length)}-word${words.length === 1 ? '' : 's'}`];

  if (/[<>@]/u.test(trimmed)) parts.push('contains-address');
  if (/^[A-Z\s]+$/u.test(trimmed) && trimmed.length > 3) parts.push('all-caps');
  if (/[^\p{ASCII}]/u.test(trimmed)) parts.push('non-ascii');
  if (/\b(team|support|service|security|admin|notification|alert|help ?desk|no-?reply)\b/iu.test(trimmed)) {
    parts.push('role-account');
  }
  return parts.join('-');
}

function countWord(n: number): string {
  const names = ['zero', 'one', 'two', 'three', 'four', 'five'];
  return names[n] ?? 'many';
}
