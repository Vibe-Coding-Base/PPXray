// Typography preferences: interface base size and both font stacks.
//
// Stored in `localStorage` rather than `settings.json` because they must be
// applied before the first paint; a Tauri IPC round trip happens after React
// mounts, which would flash the default size first.

import { PREFS_EVENT } from "@/hooks/use-row-height";

const KEY = "ppxray.ui-prefs";

export interface UiPrefs {
  /** Root font size in px. Mantine sizes everything in rem against this, so
   *  it moves control heights and padding too, not just text. */
  baseSizePx: number;
  /** CSS font-family stack for the interface. */
  fontFamily: string;
  /** CSS font-family stack for hostnames, IPs, process names and SQL. */
  monoFamily: string;
}

/** Font stacks offered in Settings. The value is the CSS stack itself, so a
 *  user editing localStorage by hand can put anything here. */
export const UI_FONTS: { label: string; value: string }[] = [
  {
    label: "System",
    value:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  },
  { label: "Segoe UI", value: '"Segoe UI", system-ui, sans-serif' },
  { label: "Inter", value: 'Inter, "Segoe UI", system-ui, sans-serif' },
  { label: "Roboto", value: 'Roboto, "Segoe UI", system-ui, sans-serif' },
  { label: "Verdana", value: "Verdana, Tahoma, sans-serif" },
];

/**
 * Fonts that were offered here and should not have been.
 *
 * Georgia was on the list as a serif option. It has incomplete Vietnamese
 * coverage, so a word like "được" fell back per character to whatever else
 * had the glyph - which reads as broken text, not as a different typeface.
 * Anyone who picked it is moved back to the default rather than left with a
 * setting that quietly damages their own language.
 */
const WITHDRAWN_FONTS = ["Georgia"];

export const MONO_FONTS: { label: string; value: string }[] = [
  {
    label: "System monospace",
    value:
      '"JetBrains Mono", "Cascadia Code", "Fira Code", Consolas, "Liberation Mono", monospace',
  },
  { label: "Consolas", value: 'Consolas, "Courier New", monospace' },
  { label: "Cascadia Code", value: '"Cascadia Code", Consolas, monospace' },
  { label: "JetBrains Mono", value: '"JetBrains Mono", Consolas, monospace' },
  { label: "Courier New", value: '"Courier New", monospace' },
];

export const MIN_SIZE = 13;
export const MAX_SIZE = 24;

export const DEFAULT_PREFS: UiPrefs = {
  // 16 is the browser default and left this dense layout at 11-12px text.
  // 18 is a deliberate step up for a tool people read for hours; anyone who
  // wants the denser original can drag it back down.
  baseSizePx: 18,
  fontFamily: UI_FONTS[0].value,
  monoFamily: MONO_FONTS[0].value,
};

export function loadPrefs(): UiPrefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<UiPrefs>;
    return {
      baseSizePx: clampSize(parsed.baseSizePx ?? DEFAULT_PREFS.baseSizePx),
      fontFamily: usableFont(parsed.fontFamily),
      monoFamily: parsed.monoFamily || DEFAULT_PREFS.monoFamily,
    };
  } catch {
    // A corrupt or unavailable store must not stop the app from rendering.
    return DEFAULT_PREFS;
  }
}

function usableFont(stored: string | undefined): string {
  if (!stored) return DEFAULT_PREFS.fontFamily;
  return WITHDRAWN_FONTS.some((f) => stored.includes(f))
    ? DEFAULT_PREFS.fontFamily
    : stored;
}

export function savePrefs(prefs: UiPrefs): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    // Preferences are a convenience; failing to persist them is not worth
    // interrupting the session over.
  }
}

export function clampSize(px: number): number {
  if (!Number.isFinite(px)) return DEFAULT_PREFS.baseSizePx;
  return Math.min(MAX_SIZE, Math.max(MIN_SIZE, Math.round(px)));
}

/**
 * Push preferences into the document.
 *
 * Writes inline styles on `<html>` rather than swapping a stylesheet, so the
 * values win over `global.css` without an `!important` arms race, and so the
 * change is visible the moment the slider moves.
 */
export function applyPrefs(prefs: UiPrefs): void {
  const root = document.documentElement;
  root.style.fontSize = `${clampSize(prefs.baseSizePx)}px`;
  root.style.setProperty("--ppxray-font", prefs.fontFamily);
  root.style.setProperty("--mono", prefs.monoFamily);
  // The virtualized tables size their rows in JS, not CSS, so they have to be
  // told. Dispatched on `window` rather than threaded through React state
  // because the listeners are leaf components in three separate modules.
  window.dispatchEvent(new Event(PREFS_EVENT));
}
