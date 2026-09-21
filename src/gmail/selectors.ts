/**
 * **The only file in the project permitted to know a Gmail CSS class.**
 *
 * Gmail's markup is minified, obfuscated, and changes without notice. Two rules keep that from
 * becoming an outage:
 *
 *  1. Every selector is a **prioritised list of candidates**, tried in order. Attribute-based
 *     selectors come first (`[email]`, `data-legacy-message-id`, `data-tooltip`) because data
 *     attributes are part of Gmail's own internal contract and churn far more slowly than class
 *     names like `.a3s` or `.gD`.
 *  2. Nothing here throws or asserts. A selector that matches nothing means one field is missing,
 *     which the analysis handles, rather than an exception that kills the extension.
 *
 * If Gmail changes, this file and `dom-adapter.ts` are the only things that need to change.
 */

export const SELECTORS = {
  /** The conversation view root. Used as the MutationObserver target. */
  conversationRoot: [
    'div[role="main"]',
    '.nH.if',
    '.aeF',
    '#\\:2',
  ],

  /** An individual expanded message within a thread. */
  messageContainer: [
    'div[data-message-id]',
    'div[data-legacy-message-id]',
    '.gs',
    '.adn.ads',
  ],

  /**
   * The collapsed/expanded state marker. Gmail collapses all but the last message in a thread; we
   * analyse the one the user is actually reading, i.e. the last expanded one.
   */
  collapsedMessage: ['.kv', '.kQ', '.gt.adO'],

  /** Sender element. The `email` attribute is the reliable part. */
  senderSpan: [
    'span[email]',
    'span.gD',
    '.go span[email]',
    'h3.iw span[email]',
  ],

  /** Fallback: the raw `name <addr>` text Gmail puts in the header. */
  senderTextual: ['.gD', '.go', '.qu .gD'],

  /**
   * The header block holding the sender line — display name, address, and the annotations Gmail adds
   * beside them, of which `via <host>` is the one detection reads.
   *
   * Needed as its own selector because those annotations are *siblings* of the sender element, not
   * inside it: reading the sender element's text gets the display name and nothing else. Widest-first
   * here, unlike everywhere else in this file, because the point is to capture the whole line rather
   * than to locate one node.
   */
  senderHeaderBlock: ['.gE.iv.gt', 'table.cf.gJ', '.gE', '.iw', '.hb'],

  /**
   * Anything in a message header that names a party by address — sender and recipient chips alike.
   *
   * Attribute-based on purpose. Which classes Gmail uses for the recipient row has changed repeatedly,
   * but both attributes below are part of how Gmail itself finds a person (they drive the hover card),
   * so scanning for them is more durable than naming the row. Used to tell a message the user *sent*
   * from one that merely claims to be from them; see `readAudience` in `dom-adapter.ts`, which is
   * careful to scan only the header, never the body.
   */
  addressCarrier: ['[email]', '[data-hovercard-id*="@"]'],

  /** Subject line. */
  subject: [
    'h2[data-thread-perm-id]',
    'h2.hP',
    '.hP',
    '.ha h2',
  ],

  /**
   * Rendered message body. `.a3s` is the message HTML container; `.ii` wraps it. Both are
   * long-standing but obfuscated, hence the list.
   */
  body: ['div.a3s.aiL', 'div.a3s', '.ii.gt div[dir]', '.ii.gt'],

  /** Quoted / trimmed content, excluded from analysis so replies are not re-analysed. */
  quotedContent: ['.gmail_quote', '.im', 'blockquote.gmail_quote', '.ajR', 'div[class*="quote"]'],

  /** The "show details" table Gmail renders with mailed-by / signed-by / to. */
  detailsTable: ['table.cf.gJ', '.hb table', '.ajA table', 'table.gJ'],

  /** The expandable details trigger, whose tooltip often carries the full header summary. */
  detailsToggle: ['.ajz', 'img.ajT', '[aria-label*="details" i]'],

  /** Attachment chips in the message footer. */
  attachmentChip: [
    '.aQH span.aV3',
    'span.aV3',
    '.aZo .aQA .aV3',
    '[download_url]',
    '.aSG .aV3',
  ],

  /**
   * Gmail's own red warning banner.
   *
   * The last candidate is far broader than anything else in this file, and safe only because of where
   * it is read: `readGmailWarning` accepts the text only when it reads as a verdict about the message,
   * so matching one of Gmail's other live regions yields nothing rather than a phantom finding. Do not
   * copy the pattern to a group whose match is used directly.
   */
  warningBanner: [
    '.gJ .aiG',
    'div[jsname="ohI2vc"]',
    '.PhishingBanner',
    '.ni .n4',
    '.aiG',
    'div[role="alert"]',
  ],

  /** The unauthenticated-sender indicator (the `?` avatar). */
  unauthenticatedIndicator: [
    'img[src*="unknown_avatar"]',
    '.h7 img[alt="?"]',
    'span[aria-label*="not verified" i]',
    'span[data-tooltip*="not verify" i]',
  ],

  /**
   * The right-hand cluster of the message header — the cell holding the timestamp, star and reply
   * controls — which is where the badge is attached.
   *
   * Chosen over the header container itself because appending to the container makes the badge the
   * last block in it, which renders on a line of its own *below* the recipient row. Inside this cell
   * it sits on the sender's line, right-aligned, in the empty space Gmail leaves beside the date.
   *
   * Ordered narrowest-first: the timestamp wrapper is the tightest fit, the enclosing cell is the
   * safe fallback, and if neither exists `dom-adapter.ts` falls back to the header container so the
   * badge is misplaced rather than missing.
   */
  headerRightCluster: ['td.gH div.gK', 'td.gH.bAk', 'td.gH', '.gH .gK'],

  /**
   * Where the badge goes when none of the above is there.
   *
   * A group of its own despite overlapping `senderHeaderBlock`, because the two lists are consumed
   * differently: that one is read as text and may legitimately name a `<table>`, and appending an element
   * inside a table is a layout accident rather than a worse position. Kept here rather than inline in
   * `dom-adapter.ts` for the reason the whole file exists — when Gmail moves its markup, one file should
   * need editing, and a list that lives beside the code that uses it is the one nobody remembers to change.
   *
   * Every candidate is a placement, not a requirement. A badge on the wrong line is an acceptable
   * outcome; no badge is not.
   */
  headerFallbackBlock: ['.gE.iv.gt', '.gE', '.iw', '.gK', '.go', '.hb'],

  /**
   * A row in a message list — inbox, search results, a label.
   *
   * `tr.zA` is the long-standing one and `[role="row"]` is the semantic fallback, which also matches
   * rows in Gmail's newer list layouts. Both are scoped to the list container, never the whole page:
   * the conversation view has rows of its own (the details table) that must not be mistaken for these.
   */
  listRow: ['tr.zA', 'tr[role="row"][id]', 'div[role="row"]'],

  /**
   * The sender cell of a list row.
   *
   * The `email` attribute is what makes this worth doing at all: Gmail puts the real address there even
   * though the row displays only a name, so a row can be triaged without parsing anything. Where it is
   * absent there is no address, and triage correctly says nothing.
   */
  listSender: ['span[email]', '.yW span[name]', '.bA4 span[name]', '.yW span', '.bA4 span'],

  /**
   * Where the marker is inserted, before the subject.
   *
   * Ordered innermost first, and that order is the whole point: `.y6` and the subject's link wrapper hold
   * inline spans, so a glyph prepended there sits on the subject's own line. The `td` is a last resort
   * because its children are blocks — a mark there lands on a line of its own and makes marked rows
   * taller than their neighbours, which is worse than no mark.
   */
  listSubjectCell: ['.y6', 'td.xY div[role="link"]', 'td.xY.a4W'],

  /** Anchors within the message body. */
  bodyLink: ['a[href]'],

  /** Gmail's account chrome, whose `aria-label` contains the signed-in address. */
  accountLink: ['a[aria-label*="@"]'],
} as const satisfies Record<string, readonly string[]>;

/**
 * The groups read from the page rather than from inside one message.
 *
 * Only the drift probe needs this, and only to keep one distinction straight: a group that misses inside
 * the message and then matches somewhere on the page has not fallen through to a worse selector, it has
 * been found somewhere the adapter would never look. Without the distinction every message with no
 * warning banner reported `warningBanner` as drifting, because the page always holds something carrying
 * `role="alert"` for the last candidate to find.
 *
 * The list groups belong here even though the code reads them from a row, not the page: a probe holding
 * one open message cannot reach a row, so the page is the closest scope it can honestly report.
 */
export const PAGE_SCOPED: ReadonlySet<string> = new Set([
  'conversationRoot',
  'subject',
  'accountLink',
  'listRow',
  'listSender',
  'listSubjectCell',
]);

/** Returns the first element matching any candidate selector, or `null`. */
export function queryFirst(root: ParentNode, candidates: readonly string[]): Element | null {
  for (const selector of candidates) {
    try {
      const found = root.querySelector(selector);
      if (found !== null) return found;
    } catch {
      // An invalid selector in the candidate list must not break the chain.
    }
  }
  return null;
}

/** Returns matches for the first candidate selector that matches anything. */
export function queryAll(root: ParentNode, candidates: readonly string[]): Element[] {
  for (const selector of candidates) {
    try {
      const found = root.querySelectorAll(selector);
      if (found.length > 0) return [...found];
    } catch {
      // Skip invalid selectors.
    }
  }
  return [];
}

/** Union of matches across every candidate selector, de-duplicated. */
export function queryAllUnion(root: ParentNode, candidates: readonly string[]): Element[] {
  const seen = new Set<Element>();
  for (const selector of candidates) {
    try {
      for (const element of root.querySelectorAll(selector)) seen.add(element);
    } catch {
      // Skip invalid selectors.
    }
  }
  return [...seen];
}
