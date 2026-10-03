/**
 * Where rendered text breaks that `textContent` does not.
 *
 * `textContent` concatenates text nodes exactly, so two table cells or two `<div>`s a reader sees on
 * separate lines come back as one word: a footer of "Privacy policy" beside "Unsubscribe" reads
 * `policyunsubscribe`. Every rule anchored on a word boundary then misses the word, and a newsletter's
 * unsubscribe line becomes invisible to the bulk-mail test whose job is to stop marketing wording being
 * read as a scam.
 *
 * The list is HTML's block-level and line-breaking elements, not Gmail markup, which is why it is here
 * rather than in `selectors.ts`. `display` set by CSS is not consulted, for the reason the hidden-text scan
 * gives: computing style for every node of a large message is a layout read the content script cannot
 * afford. A block styled inline still gets a break, which costs at most a sentence split in two.
 */
export const BLOCK_BOUNDARY =
  'address, article, aside, blockquote, br, center, dd, details, div, dl, dt, fieldset, figcaption, ' +
  'figure, footer, form, h1, h2, h3, h4, h5, h6, header, hr, li, main, nav, ol, p, pre, section, ' +
  'summary, table, tbody, td, tfoot, th, thead, tr, ul';

/**
 * Past this many elements the remaining ones are left fused. The cost is words a rule may miss, which is
 * no worse than reading `textContent` with no breaks inserted at all.
 */
const MAX_BOUNDARIES = 20_000;

/**
 * Puts a line break either side of every block in `root`, so its `textContent` reads as it renders.
 *
 * Mutates, so it is only ever called on a copy. Breaks go on both sides because a block separates its text
 * from what precedes it as well as from what follows: `Total<div>0.5 BTC</div>` is two lines.
 */
export function separateBlocks(root: Element): void {
  const blocks = root.querySelectorAll(BLOCK_BOUNDARY);
  const count = Math.min(blocks.length, MAX_BOUNDARIES);
  for (let i = 0; i < count; i++) {
    const block = blocks[i];
    if (block === undefined) continue;
    block.before('\n');
    block.after('\n');
  }
}
