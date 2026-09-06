// Checking for a new release.
//
// With the assistant disabled — which is how ppxray ships — this is the only
// network request it makes, and it only happens when the user asks for it:
// there is no background poll and no telemetry
// riding along. The request goes out from the Rust side (the updater plugin
// uses its own HTTP client), so it is not subject to the webview CSP.
//
// The downloaded bundle is verified against the ed25519 public key compiled
// into the binary (`tauri.conf.json → plugins.updater.pubkey`) before
// anything is installed. Installers are not code-signed, but updates are:
// only the first install needs manual SHA-256 verification.

import { notifications } from "@mantine/notifications";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";

export interface UpdateCheckResult {
  available: boolean;
  version?: string;
}

/**
 * Check for a newer release and, if the user confirms, install and relaunch.
 *
 * `silent` suppresses only the "you're up to date" notification; failures and
 * available updates always surface.
 */
export async function checkForUpdates(silent = false): Promise<UpdateCheckResult> {
  let update;
  try {
    update = await check();
  } catch (e) {
    notifications.show({
      title: "Update check failed",
      message: String(e),
      color: "red",
    });
    return { available: false };
  }

  if (!update) {
    if (!silent) {
      notifications.show({
        title: "No updates available",
        message: "You're running the latest release.",
        color: "teal",
      });
    }
    return { available: false };
  }

  const { version } = update;
  notifications.show({
    id: "update-download",
    title: `Version ${version} available`,
    message: "Downloading and verifying…",
    color: "blue",
    loading: true,
    autoClose: false,
  });

  try {
    // Resolves once the bundle is downloaded, signature-checked, and staged.
    await update.downloadAndInstall();
  } catch (e) {
    notifications.update({
      id: "update-download",
      title: "Update failed",
      message: String(e),
      color: "red",
      loading: false,
      autoClose: 8000,
    });
    return { available: true, version };
  }

  notifications.update({
    id: "update-download",
    title: `Version ${version} installed`,
    message: "Relaunching…",
    color: "teal",
    loading: false,
    autoClose: 3000,
  });

  // The new binary is staged; only a relaunch swaps it in.
  await relaunch();
  return { available: true, version };
}
