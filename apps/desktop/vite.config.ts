import { readFileSync } from "node:fs";
import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Injected rather than read at runtime through Tauri's app API, which would
// need a capability and a round trip. The release workflow refuses to build
// unless package.json, Cargo.toml and tauri.conf.json all agree with the tag,
// so this string cannot drift from what actually shipped.
// The *workspace root* package.json, which is the file release.yml's verify
// job checks against the tag. Reading the app's own copy let the two drift:
// the root said 0.2.0 while About kept reporting 0.1.0, so the dialog was
// naming a version the build was not.
const { version } = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../package.json"), "utf8"),
) as { version: string };

// Tauri dev defaults. We listen on a fixed port so the Rust side's
// `devUrl` in tauri.conf.json matches, and disable HMR overlay on
// Windows where WebView2 occasionally swallows the overlay socket.
export default defineConfig(async () => ({
  plugins: [react()],
  clearScreen: false,
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // Bind IPv4 explicitly. Vite 6's default ("localhost") binds IPv6-only
    // on Windows (`[::1]:5173`), which WebView2's IPv4 lookup for `localhost`
    // can't reach → "refused to connect". We pair this with an IPv4 devUrl
    // in `src-tauri/tauri.conf.json`.
    host: "127.0.0.1",
    watch: {
      // Avoid restarting on Rust/Cargo changes; Tauri handles that side.
      ignored: ["**/src-tauri/**", "**/target/**", "**/crates/**"],
    },
  },
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  envPrefix: ["VITE_", "TAURI_"],
}));
