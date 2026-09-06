// Virtualized row heights that follow the user's interface size.
//
// The three big tables (log events, alerts, rules) are virtualized, so their
// row height is a number handed to the virtualizer rather than something CSS
// works out. Those numbers were pixel constants, which was fine while the
// base size was also a constant — once it became a setting, raising it made
// text overflow rows that had not grown with it.
//
// Expressing them as multiples of the root font size keeps the proportion the
// layout was designed at: 28px at the original 16px base is 1.75rem.

import { useEffect, useState } from "react";

/** Fired by `applyPrefs` so anything measuring rem can re-measure. */
export const PREFS_EVENT = "ppxray:prefs-changed";

function rootFontPx(): number {
  const raw = getComputedStyle(document.documentElement).fontSize;
  const px = Number.parseFloat(raw);
  // A non-finite value here would make the virtualizer render zero-height
  // rows, i.e. an empty table with a working scrollbar.
  return Number.isFinite(px) && px > 0 ? px : 16;
}

/**
 * `rem` expressed in pixels, recomputed whenever the interface size changes.
 */
export function useRem(rem: number): number {
  const [px, setPx] = useState(() => Math.round(rem * rootFontPx()));

  useEffect(() => {
    const update = () => setPx(Math.round(rem * rootFontPx()));
    update();
    window.addEventListener(PREFS_EVENT, update);
    return () => window.removeEventListener(PREFS_EVENT, update);
  }, [rem]);

  return px;
}
