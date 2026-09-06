import { useEffect, useRef } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { confirm as tauriConfirm } from "@tauri-apps/plugin-dialog";

/**
 * Intercept the window close request and ask the user to confirm when there
 * are unsaved profile edits.
 *
 * Four things this has to get right:
 * 1. Register the listener once, reading `dirty` from a ref — re-running the
 *    effect leaks handlers, especially under StrictMode.
 * 2. Call `preventDefault()` synchronously before the first `await`, or Tauri
 *    proceeds with the close while the dialog is open.
 * 3. If registration is still pending at unmount, unlisten as soon as it
 *    lands, so no zombie listener survives.
 * 4. "Close anyway" must call `window.destroy()`; the native close was
 *    already cancelled.
 */
export function useDirtyGuard(dirty: boolean) {
  // The close handler is registered once and must see the *current* dirty
  // flag, so it reads through a ref. Updating that ref in an effect rather
  // than during render keeps render side-effect free.
  const dirtyRef = useRef(dirty);
  useEffect(() => {
    dirtyRef.current = dirty;
  }, [dirty]);

  useEffect(() => {
    const window = getCurrentWindow();
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    let confirmInFlight = false;

    window
      .onCloseRequested(async (event) => {
        // Clean path: no dirty state → don't block the close.
        if (!dirtyRef.current) return;

        // Guard against a second X-click while the previous confirm is still
        // open: swallow the event but don't spawn another dialog.
        if (confirmInFlight) {
          event.preventDefault();
          return;
        }

        event.preventDefault();
        confirmInFlight = true;
        try {
          const ok = await tauriConfirm(
            "You have unsaved changes in this profile. Close anyway?",
            { title: "Unsaved changes", kind: "warning" },
          );
          if (ok) {
            await window.destroy();
          }
        } finally {
          confirmInFlight = false;
        }
      })
      .then((fn) => {
        if (cancelled) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch(() => {
        // Running outside Tauri (vite preview / tests) — no window API.
      });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);
}
