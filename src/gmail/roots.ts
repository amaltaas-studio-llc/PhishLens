/**
 * Watching a Gmail region that Gmail may replace rather than change.
 *
 * A `MutationObserver` holds the node it was given. Gmail swaps out whole regions — the conversation
 * container on some in-place actions, the main region on a view change — and an observer then sits on an
 * element outside the document, reporting nothing again for the lifetime of the tab. Nothing notices,
 * because in both consumers every trigger is downstream of a mutation, so the extension goes quiet on a
 * page that still looks like it is working, with whatever it last drew still on screen.
 *
 * Watching the ancestors' child lists is what makes the swap observable: replacing any node on the path
 * out of the root is a child-list change on its parent, and that is the one form of Gmail churn that
 * happens outside the observed subtree. Watching `document.body` with `subtree` would catch it too, and
 * would also wake on every advert and chat-roster change, which for the message observer means
 * re-extracting a message.
 *
 * Shared by `observer.ts` and `content/list-marks.ts` because both learned this the same way. The rule is
 * one rule — watch the region, and watch for the region being replaced — and a second copy of it is the
 * copy that is missing the day Gmail changes shape.
 */

/** Ancestors watched for the observed root being replaced. Enough to reach `<body>` from a Gmail pane. */
const MAX_WATCHED_ANCESTORS = 24;

/**
 * The ancestors of an element, outward to the document.
 *
 * Bounded because it is walked on every reattachment and the shape of the page is Gmail's to change; the
 * limit is generous enough to reach `<body>` from the conversation container several times over.
 */
export function pathToDocument(element: Element): Element[] {
  const path: Element[] = [];
  let current: Element | null = element.parentElement ?? null;
  while (current !== null && path.length < MAX_WATCHED_ANCESTORS) {
    path.push(current);
    current = current.parentElement ?? null;
  }
  return path;
}

/**
 * Observes `root` as the caller asked, and every ancestor for `root` itself being replaced.
 *
 * The ancestor watches are `childList` without `subtree` deliberately: a replacement is a child-list
 * change on the parent, and anything wider would deliver the whole page's churn twice over.
 */
export function observeWithPath(
  observer: MutationObserver,
  root: Element,
  options: MutationObserverInit,
): void {
  observer.observe(root, options);
  for (const ancestor of pathToDocument(root)) {
    observer.observe(ancestor, { childList: true });
  }
}
