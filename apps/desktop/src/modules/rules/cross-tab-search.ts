// Cross-tab search bridge: lets another module send the Rules tab a DSL query.
//
// The Rules tab is only mounted while it is active, so a plain
// `window.dispatchEvent` fires before its listener exists. This holds one
// pending query across mount/unmount instead: producers call
// `requestRulesSearch`, and RuleModule calls `consumePendingRulesSearch` once
// on mount and `subscribeRulesSearch` while it is mounted.

let pendingQuery: string | null = null;
const listeners = new Set<(q: string) => void>();

/** Producer side. If the Rules tab is mounted right now, deliver the
 *  query immediately to every live subscriber. Otherwise queue it for
 *  the next mount. */
export function requestRulesSearch(query: string): void {
  if (listeners.size > 0) {
    for (const l of listeners) l(query);
    return;
  }
  pendingQuery = query;
}

/** Consumer side, called once on RuleModule mount. Returns the queued
 *  query (or `null` if none) and clears the slot. */
export function consumePendingRulesSearch(): string | null {
  const v = pendingQuery;
  pendingQuery = null;
  return v;
}

/** Consumer side, called for the lifetime of the Rules tab so that
 *  subsequent in-tab pivots also apply (e.g. user is on Rules, opens the
 *  command palette, picks a "search by port" action). Returns the
 *  unsubscribe handle. */
export function subscribeRulesSearch(listener: (q: string) => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
