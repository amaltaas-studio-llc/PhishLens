/**
 * Static stylesheets for the injected UI.
 *
 * Authored here, never derived from message content. The visual language is deliberately restrained:
 * a security tool that shouts is one users learn to dismiss, and the difference between "caution" and
 * "high risk" has to survive being seen a hundred times a day. Colour is a secondary cue behind the
 * text label, so the states remain distinguishable to colour-blind users and in high-contrast modes.
 */

export const BADGE_CSS = `
/*
 * The host sits in the header's right-hand cluster, beside the timestamp. It is inline-block with a
 * left margin rather than floated or absolutely positioned, so it occupies space Gmail has already
 * laid out instead of overlapping something.
 */
:host { all: initial; display: inline-block; vertical-align: middle; margin-left: 8px; }
* { box-sizing: border-box; }

.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-family: 'Google Sans', Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif;
  /* A shade smaller than the body badge would be: it shares a line with Gmail's own header controls. */
  font-size: 11px;
  font-weight: 500;
  line-height: 1;
  padding: 4px 8px;
  border-radius: 999px;
  border: 1px solid transparent;
  cursor: pointer;
  white-space: nowrap;
  transition: box-shadow 120ms ease, background-color 120ms ease;
  -webkit-font-smoothing: antialiased;
}
.badge:hover { box-shadow: 0 1px 4px rgb(0 0 0 / 18%); }
.badge:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }

.glyph { font-size: 11px; line-height: 1; }
.score { opacity: 0.75; font-variant-numeric: tabular-nums; }
.sep { opacity: 0.4; }

.badge[data-state="low"]        { background: #e6f4ea; color: #137333; border-color: #ceead6; }
.badge[data-state="caution"]    { background: #fef7e0; color: #8a5300; border-color: #fde293; }
.badge[data-state="suspicious"] { background: #fce8e6; color: #b3261e; border-color: #f9d2cf; }
.badge[data-state="high-risk"]  { background: #b3261e; color: #ffffff; border-color: #8c1d18; }
.badge[data-state="pending"]    { background: #f1f3f4; color: #5f6368; border-color: #e0e3e5; cursor: default; }
/*
 * Deliberately not on the green-to-red scale. "Not checked" is not a low reading, and any colour from
 * the risk palette would be read as one; a dashed neutral border says "this is not a verdict" without
 * competing with Gmail's own header controls for attention.
 */
.badge[data-state="unreadable"] { background: #ffffff; color: #5f6368; border-color: #9aa0a6; border-style: dashed; }

@media (prefers-color-scheme: dark) {
  .badge[data-state="low"]        { background: #1e3a28; color: #81c995; border-color: #2d5a3d; }
  .badge[data-state="caution"]    { background: #3d3122; color: #fdd663; border-color: #5c4a2e; }
  .badge[data-state="suspicious"] { background: #452420; color: #f28b82; border-color: #6b322c; }
  .badge[data-state="high-risk"]  { background: #b3261e; color: #ffffff; border-color: #d93025; }
  .badge[data-state="pending"]    { background: #2d2e30; color: #9aa0a6; border-color: #3c4043; }
  .badge[data-state="unreadable"] { background: #202124; color: #9aa0a6; border-color: #5f6368; }
}

@media (prefers-reduced-motion: reduce) {
  .badge { transition: none; }
}
`;

/**
 * The advisory card.
 *
 * Pinned to the bottom-right of the viewport rather than anchored to the badge. Anchoring meant the
 * card was positioned from the badge's viewport rect, so scrolling the message carried it off screen
 * — the explanation disappeared exactly when the user scrolled down to check the thing it described.
 * A fixed corner has no such coupling: it needs no scroll listener, no reflow on resize, and it does
 * not fight Gmail's own scroll containers for space.
 *
 * It is deliberately *not* modal. There is no backdrop, so Gmail stays fully interactive while the
 * card is open — a security advisory the user must dismiss before they can look at the message is an
 * advisory that gets dismissed unread.
 */
export const PANEL_CSS = `
:host { all: initial; }
* { box-sizing: border-box; }

/*
 * One colour per category, set as a custom property wherever a \`data-category\` appears, so the ring
 * slice, the group's dot, the breakdown bar and a quotation's rule all name the same category by the
 * same colour without four copies of the palette. Chosen to stay apart from the risk palette's
 * green-amber-red: a category is not a severity, and a red slice would read as one.
 */
[data-category="identity"] { --cat: #8e24aa; }
[data-category="link"] { --cat: #1a73e8; }
[data-category="authentication"] { --cat: #00897b; }
[data-category="content"] { --cat: #e37400; }
[data-category="attachment"] { --cat: #d81b60; }
[data-category="llm"] { --cat: #5c6bc0; }

.panel {
  --state: #9aa0a6;
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 2147483001;
  display: flex;
  flex-direction: column;
  width: 392px;
  max-width: calc(100vw - 32px);
  max-height: min(76vh, 660px);
  /* The state colour lives in this 4px strip, so the card itself stays neutral and legible. */
  padding-left: 4px;
  overflow: hidden;
  background: #ffffff;
  color: #202124;
  border: 1px solid #dadce0;
  border-radius: 14px;
  box-shadow: 0 10px 32px rgb(0 0 0 / 16%), 0 2px 6px rgb(0 0 0 / 8%);
  font-family: 'Google Sans', Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif;
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.panel[data-state="low"] { --state: #34a853; }
.panel[data-state="caution"] { --state: #f9ab00; }
.panel[data-state="suspicious"] { --state: #ea4335; }
.panel[data-state="high-risk"] { --state: #b3261e; }

.panel::before {
  content: '';
  position: absolute;
  inset: 0 auto 0 0;
  width: 4px;
  /* Neutral for "not checked", for the same reason as the badge: there is no reading to colour. */
  background: var(--state);
}

/* Head is fixed; only the findings scroll. */
.head { flex: none; padding: 12px 16px 12px; border-bottom: 1px solid #f1f3f4; }
.scroll { flex: 1 1 auto; overflow-y: auto; overscroll-behavior: contain; }

/*
 * Scrollbar, restyled to belong to the card. Chromium's default is a 15px grey channel with a hard
 * inner edge and arrow buttons, which inside a rounded card reads as a seam pinned to the right side —
 * and it runs straight through the rounded bottom corner, because the footer scrolls with the findings.
 *
 * Drawn instead as an overlay over the card's own surface: transparent track, and a thin thumb inset
 * from the edge so it floats clear of both the border and the corner radius. The inset comes from a
 * transparent border with \`background-clip: padding-box\` — scrollbar parts do not honour margin or
 * padding, so the border is the only way to get breathing room around the thumb. For the same reason
 * the hover rule sets \`background-color\`, not the \`background\` shorthand, which would reset the clip
 * back to \`border-box\` and refill the inset.
 *
 * Uses the \`-webkit-\` pseudo-elements rather than the standard \`scrollbar-width\`/\`scrollbar-color\`
 * pair. The two are mutually exclusive in Chromium — declaring either standard property makes it
 * ignore the pseudo-elements — and only the pseudo-elements can inset the thumb. Chrome-only support is
 * not a constraint for a Chrome extension.
 *
 * The thumb is quiet but always visible while the content overflows. It is the only cue that findings
 * continue below the fold, and on a security advisory a hidden cue is a finding the user never reads;
 * hover-to-reveal was rejected for that reason.
 */
.scroll::-webkit-scrollbar { width: 10px; }
.scroll::-webkit-scrollbar-track { background: transparent; }
.scroll::-webkit-scrollbar-thumb {
  background-color: #dadce0;
  background-clip: padding-box;
  border: 3px solid transparent;
  border-radius: 8px;
}
.scroll::-webkit-scrollbar-thumb:hover { background-color: #bdc1c6; }
.scroll::-webkit-scrollbar-button, .scroll::-webkit-scrollbar-corner { display: none; }

.head-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.brand { font-size: 10px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: #80868b; }

/*
 * The score as a ring with the number inside, beside the verdict. The ring replaces a flat meter: a
 * bar can say how much, but not what it is made of, and "made of links" is the first thing a reader
 * wants to know after "how bad".
 */
.hero { display: grid; grid-template-columns: 72px 1fr; align-items: center; gap: 14px; margin-top: 4px; }
.ring { position: relative; width: 72px; height: 72px; color: var(--state); }
.ring svg { display: block; width: 100%; height: 100%; }
.ring .track { stroke: #eef0f2; }
.ring .seg { stroke: var(--cat); }
.ring-label {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  line-height: 1;
}
.score-value { font-size: 22px; font-weight: 600; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.score-max { margin-top: 3px; font-size: 9px; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase; color: #80868b; }

.hero-text { min-width: 0; }
.verdict {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  line-height: 1.4;
  background: #f1f3f4;
  color: #3c4043;
}
.verdict[data-state="low"] { background: #e6f4ea; color: #137333; }
.verdict[data-state="caution"] { background: #fef7e0; color: #8a5300; }
.verdict[data-state="suspicious"] { background: #fce8e6; color: #b3261e; }
.verdict[data-state="high-risk"] { background: #b3261e; color: #ffffff; }
.summary { margin: 6px 0 0; font-size: 12px; color: #3c4043; }

/*
 * The "not checked" head. Alone in the row, the verdict *is* the headline — there is no score for it to
 * sit beside — so it is set as a heading rather than as a pill that would read like a risk level.
 */
.score-row { display: flex; align-items: baseline; gap: 6px; margin-top: 6px; }
.score-row .verdict:only-child { padding: 0; background: none; font-size: 18px; font-weight: 500; color: inherit; }

/*
 * Which message this is about. The card does not sit beside the header it describes, so it has to
 * say — otherwise a stale card in the corner is indistinguishable from a current one.
 */
.ref { margin-top: 12px; display: grid; gap: 1px; }
.ref-line { font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ref-subject { color: #3c4043; font-weight: 500; }
.ref-sender { color: #80868b; }

.close {
  flex: none;
  border: none;
  background: transparent;
  color: #5f6368;
  font-size: 18px;
  line-height: 1;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  cursor: pointer;
}
.close:hover { background: #f1f3f4; }
.close:focus-visible { outline: 2px solid #1a73e8; outline-offset: 1px; }

section { padding: 14px 16px; border-bottom: 1px solid #f1f3f4; }

.section-title {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #5f6368;
  margin: 0 0 2px;
}
.section-note { font-size: 11px; color: #80868b; margin: 0; }
.empty { color: #5f6368; margin: 8px 0 0; }

.dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--cat, #9aa0a6); }
/* The floor's marker, matching the hatched part of the ring. Square, because a hatched circle at this size
   reads as a "prohibited" sign. */
.dot.hatch {
  border-radius: 2px;
  background: repeating-linear-gradient(45deg, var(--state) 0 1.5px, transparent 1.5px 3px);
  box-shadow: inset 0 0 0 1px var(--state);
}

/* Findings, grouped by category. */
.group { margin-top: 12px; }
.group-head { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; color: #3c4043; }
.group-points { margin-left: auto; font-weight: 500; color: #80868b; font-variant-numeric: tabular-nums; }

ul { list-style: none; margin: 0; padding: 0; }
ul.findings { display: grid; gap: 2px; margin-top: 4px; }

li.finding { padding: 8px 10px; margin: 0 -10px; border-radius: 10px; }
li.finding[data-locatable="true"] { cursor: pointer; }
li.finding[data-locatable="true"]:hover { background: #f8f9fa; }
li.finding:focus-visible { outline: 2px solid #1a73e8; outline-offset: -2px; }

.finding-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.finding-title { margin: 0; font-weight: 600; line-height: 1.4; }
.finding-desc { margin: 4px 0 0; font-size: 12.5px; line-height: 1.55; color: #5f6368; }

.sev {
  flex: none;
  margin-top: 1px;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.05em;
}
.sev[data-severity="critical"] { background: #b3261e; color: #fff; }
.sev[data-severity="high"] { background: #fce8e6; color: #b3261e; }
.sev[data-severity="medium"] { background: #fef7e0; color: #8a5300; }
.sev[data-severity="low"] { background: #e8f0fe; color: #1967d2; }
.sev[data-severity="info"] { background: #f1f3f4; color: #5f6368; }

/*
 * Evidence, in two shapes. A measured value — a domain, where a link goes, a filename — is code: exact,
 * monospaced, breakable anywhere, and never mistaken for a sentence. Words from the email are a
 * quotation, ruled in the category's colour, so the sender's voice is never mistaken for PhishLens's.
 */
.evidence { margin: 8px 0 0; display: grid; gap: 3px; }
.evidence-label { font-size: 10px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: #80868b; }
.code {
  display: block;
  padding: 5px 8px;
  background: #f1f3f4;
  border-radius: 6px;
  font-family: 'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.45;
  color: #202124;
  word-break: break-all;
  white-space: pre-wrap;
}
.quote-block { padding: 2px 0 2px 10px; border-left: 3px solid var(--cat, #dadce0); }
.quote-block blockquote {
  margin: 0;
  font-size: 12.5px;
  font-style: italic;
  line-height: 1.5;
  color: #3c4043;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.quote-block blockquote::before { content: '\\201C'; }
.quote-block blockquote::after { content: '\\201D'; }

.locate { margin: 6px 0 0; font-size: 11.5px; font-weight: 500; color: #1a73e8; }
.locate::after { content: ' \\2192'; }

/* The AI section. */
.ai-note {
  margin: 8px 0 0;
  padding: 8px 10px;
  background: #f8f9fa;
  border-radius: 8px;
  font-size: 11.5px;
  color: #5f6368;
}

/*
 * Waiting on the model. Deliberately understated — the deterministic verdict is already on screen and
 * complete, so this is a footnote about a refinement, not a "loading" screen for the card. The counter
 * is what turns "is it stuck?" into "it is working, and this is how long it takes on this machine".
 */
.pending { display: flex; align-items: center; gap: 8px; margin: 8px 0 0; color: #3c4043; }
.elapsed { margin-left: auto; font-size: 11.5px; color: #80868b; font-variant-numeric: tabular-nums; }
.spinner {
  flex: none;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid #dadce0;
  border-top-color: #1a73e8;
}
/*
 * The ring is static without the animation, which still reads as an indicator next to the label; the
 * label is what actually carries the meaning, so nothing is lost when motion is not wanted.
 */
@media (prefers-reduced-motion: no-preference) {
  .spinner { animation: phishlens-spin 800ms linear infinite; }
  @keyframes phishlens-spin { to { transform: rotate(360deg); } }
}

.action {
  margin-top: 10px;
  padding: 7px 14px;
  font-family: inherit;
  font-size: 12.5px;
  font-weight: 500;
  color: #ffffff;
  background: #1a73e8;
  border: none;
  border-radius: 999px;
  cursor: pointer;
}
.action:hover { background: #1765cc; }
.action:disabled { opacity: 0.6; cursor: default; }
.action:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }

.reading { margin-top: 12px; }
.reading-title { margin: 0; font-weight: 600; line-height: 1.4; }
.chips { display: flex; flex-wrap: wrap; gap: 4px; margin: 8px 0 2px; }
.chip {
  padding: 2px 7px;
  border-radius: 999px;
  background: #f1f3f4;
  color: #3c4043;
  font-size: 11px;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.chip[data-scored="true"] { background: #e8eaf6; color: #3949ab; }
.reasons-label { margin: 12px 0 4px; font-size: 10px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: #80868b; }
ul.reasons { list-style: disc; padding-left: 18px; display: grid; gap: 4px; }
ul.reasons li { font-size: 12.5px; line-height: 1.5; color: #3c4043; }
ul.reasons li::marker { color: var(--cat, #9aa0a6); }
.reasons { --cat: #5c6bc0; }
.quote { font-style: italic; color: #202124; background: #f1f3f4; padding: 0 3px; border-radius: 3px; }
.quote::before { content: '\\201C'; }
.quote::after { content: '\\201D'; }

/* How the score adds up. */
ul.rows { display: grid; gap: 8px; margin-top: 10px; }
li.row { display: grid; grid-template-columns: 8px 92px 1fr auto; align-items: center; gap: 8px; font-size: 12px; }
li.row.floor { grid-template-columns: 8px 1fr auto; }
.row-name { color: #3c4043; }
.bar { height: 6px; border-radius: 3px; background: #eef0f2; overflow: hidden; }
.bar-fill { display: block; height: 100%; border-radius: 3px; background: var(--cat); }
.row-value { min-width: 44px; text-align: right; font-size: 11.5px; color: #5f6368; font-variant-numeric: tabular-nums; }
.total {
  display: flex;
  justify-content: space-between;
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px dashed #e0e3e5;
  font-size: 12px;
  font-weight: 600;
}
.total-value { font-variant-numeric: tabular-nums; }
.silent { margin-top: 8px; }

/*
 * The "not checked" card. No score, no ring, no findings — so the explanation is the content, at body
 * size rather than the 11px used for notes, because it is the only thing there is to read.
 */
.notes { margin: 8px 0 0; padding: 0; }
.notes p { margin: 0 0 8px; }
.notes p:last-child { margin-bottom: 0; }
/* The sentence that says an absent warning is not an all-clear. Weighted so it is not skimmed past. */
.notes p.emphatic { font-weight: 500; color: #202124; }

.diagnostic { margin-top: 12px; }
.diagnostic summary { cursor: pointer; color: #1a73e8; font-size: 11px; }
.diagnostic summary:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }
.diagnostic pre {
  margin: 8px 0 0;
  padding: 8px;
  max-height: 180px;
  overflow: auto;
  background: #f8f9fa;
  border: 1px solid #f1f3f4;
  border-radius: 6px;
  font-family: 'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10px;
  line-height: 1.45;
  color: #3c4043;
  /* Selectable and pre-formatted: the copy button is a convenience, not the only way out. */
  white-space: pre;
  user-select: text;
}

.trust .section-note { margin-top: 4px; }
.copy {
  margin-top: 10px;
  padding: 6px 12px;
  font-family: inherit;
  font-size: 12px;
  color: #1a73e8;
  background: transparent;
  border: 1px solid #dadce0;
  border-radius: 999px;
  cursor: pointer;
}
.copy:hover { background: #f8f9fa; }
.copy:focus-visible { outline: 2px solid #1a73e8; outline-offset: 1px; }

.foot {
  padding: 10px 16px 14px;
  font-size: 11px;
  color: #80868b;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.timing { color: #5f6368; font-variant-numeric: tabular-nums; }

/*
 * Entrance. Notification-like rather than decorative: it rises 8px and fades in once, which is what
 * makes the corner card read as "this just appeared" instead of "this has always been here".
 * Re-renders (the deterministic result being refined by the model) reuse the existing element, so the
 * animation does not replay and the scroll position is kept.
 */
@media (prefers-reduced-motion: no-preference) {
  .panel { animation: phishlens-rise 140ms cubic-bezier(0.2, 0, 0, 1); }
  @keyframes phishlens-rise {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: none; }
  }
}

/* Narrow windows: span the width rather than crowding one corner. */
@media (max-width: 480px) {
  .panel {
    left: 12px;
    right: 12px;
    bottom: 12px;
    width: auto;
    max-width: none;
    max-height: 80vh;
  }
}

@media (prefers-color-scheme: dark) {
  [data-category="identity"] { --cat: #ce93d8; }
  [data-category="link"] { --cat: #8ab4f8; }
  [data-category="authentication"] { --cat: #4db6ac; }
  [data-category="content"] { --cat: #fcad70; }
  [data-category="attachment"] { --cat: #f48fb1; }
  [data-category="llm"] { --cat: #9fa8da; }
  .reasons { --cat: #9fa8da; }

  .panel { background: #292a2d; color: #e8eaed; border-color: #3c4043; --state: #5f6368; }
  .panel[data-state="low"] { --state: #81c995; }
  .panel[data-state="caution"] { --state: #fdd663; }
  .panel[data-state="suspicious"] { --state: #f28b82; }
  .panel[data-state="high-risk"] { --state: #ee675c; }
  .head { border-bottom-color: #3c4043; }
  section { border-bottom-color: #3c4043; }
  .score-max, .section-title, .section-note, .foot, .empty, .brand, .ref-sender, .group-points,
  .evidence-label, .reasons-label, .elapsed { color: #9aa0a6; }
  .ref-subject, .summary, .group-head, .row-name, .quote { color: #e8eaed; }
  .finding-desc, .ai-note, .row-value, .timing, ul.reasons li, .quote-block blockquote { color: #bdc1c6; }
  .ring .track, .bar { stroke: #3c4043; background: #3c4043; }
  .verdict { background: #3c4043; color: #e8eaed; }
  .verdict[data-state="low"] { background: #1e3a28; color: #81c995; }
  .verdict[data-state="caution"] { background: #3d3122; color: #fdd663; }
  .verdict[data-state="suspicious"] { background: #452420; color: #f28b82; }
  .verdict[data-state="high-risk"] { background: #b3261e; color: #ffffff; }
  .score-row .verdict:only-child { background: none; color: inherit; }
  .close { color: #9aa0a6; }
  .close:hover { background: #3c4043; }
  .scroll::-webkit-scrollbar-thumb { background-color: #5f6368; }
  .scroll::-webkit-scrollbar-thumb:hover { background-color: #80868b; }
  li.finding[data-locatable="true"]:hover { background: #35363a; }
  .code, .chip, .quote { background: #202124; color: #e8eaed; }
  .chip[data-scored="true"] { background: #283046; color: #aecbfa; }
  .ai-note { background: #202124; }
  .total { border-top-color: #5f6368; }
  .locate, .diagnostic summary { color: #8ab4f8; }
  .notes p.emphatic { color: #e8eaed; }
  .diagnostic pre { background: #202124; border-color: #3c4043; color: #bdc1c6; }
  .copy { color: #8ab4f8; border-color: #5f6368; }
  .copy:hover { background: #35363a; }
  .action { background: #8ab4f8; color: #202124; }
  .action:hover { background: #aecbfa; }
  .pending { color: #e8eaed; }
  .spinner { border-color: #3c4043; border-top-color: #8ab4f8; }
  .sev[data-severity="high"] { background: #452420; color: #f28b82; }
  .sev[data-severity="medium"] { background: #3d3122; color: #fdd663; }
  .sev[data-severity="low"] { background: #1f3047; color: #8ab4f8; }
  .sev[data-severity="info"] { background: #3c4043; color: #9aa0a6; }
}
`;

/**
 * Highlight styles, injected into the *main* document rather than a shadow root, because the elements
 * being highlighted are Gmail's own.
 *
 * The highlight is applied by adding a single class token to an existing element and removing it
 * afterwards. Nothing is wrapped, re-parented, or replaced, so Gmail's event handlers on those
 * elements are untouched — which is the constraint the brief sets. `!important` is used because Gmail's
 * own link styles are specific, and losing the highlight would make the feature silently useless.
 */
export const HIGHLIGHT_CSS = `
.phishlens-highlight {
  outline: 2px solid #ea4335 !important;
  outline-offset: 2px !important;
  background-color: rgb(234 67 53 / 12%) !important;
  border-radius: 2px !important;
  scroll-margin: 120px;
}
.phishlens-highlight-subtle {
  outline: 2px dashed #f9ab00 !important;
  outline-offset: 2px !important;
  scroll-margin: 120px;
}
@media (prefers-reduced-motion: no-preference) {
  .phishlens-highlight, .phishlens-highlight-subtle {
    transition: outline-color 120ms ease, background-color 120ms ease;
  }
}
`;
