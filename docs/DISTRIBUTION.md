# Installing a release

ppxray release artifacts are **not code-signed**. Commercial Authenticode and
Apple Developer ID certificates are not worth the cost for a free tool, so
your OS will warn you on first run. The trade is that you verify the download
yourself, once.

Every release publishes a SHA-256 for each artifact in its release notes.
Check it before running anything.

## Windows

SmartScreen will say *"Windows protected your PC — Microsoft Defender
SmartScreen prevented an unrecognized app from starting."* That is what
Windows says about any unsigned binary.

```powershell
certutil -hashfile ppxray_0.2.0_x64_en-US.msi SHA256
```

If it matches the release notes: right-click the installer → **Properties** →
tick **Unblock** → **OK**, then run it. If SmartScreen still appears, choose
**More info** → **Run anyway**.

## macOS

Gatekeeper will say *"ppxray can't be opened because Apple cannot check it for
malicious software."*

```sh
shasum -a 256 ~/Downloads/ppxray_0.2.0_aarch64.dmg
```

If it matches: open the `.dmg`, drag ppxray to `/Applications`, then
**right-click the app → Open** and confirm. If macOS instead claims the app is
*"damaged"* — common on Apple Silicon — clear the quarantine flag:

```sh
xattr -dr com.apple.quarantine /Applications/ppxray.app
```

## Linux

```sh
# AppImage — portable, no install
sha256sum ppxray_0.2.0_amd64.AppImage
chmod +x ppxray_0.2.0_amd64.AppImage
./ppxray_0.2.0_amd64.AppImage

# Debian / Ubuntu
sha256sum ppxray_0.2.0_amd64.deb
sudo dpkg -i ppxray_0.2.0_amd64.deb
sudo apt-get install -f   # pull in any missing dependencies
```

## Why the Linux downloads differ so much

The AppImage is 92 MB and the `.deb` is 20 MB, for the same application.
That is the format, not the app.

An AppImage runs on any distribution without installing anything, which it
achieves by carrying its dependencies. Measured on a release build,
compressed:

| Inside the AppImage | |
| --- | --- |
| `libwebkit2gtk-4.1.so.0` | 30.9 MB |
| `libjavascriptcoregtk-4.1.so.0` | 10.5 MB |
| `libicudata.so.70` | 10.3 MB |
| **the browser engine** | **51.7 MB — 56% of the download** |
| `ppxray` itself, DuckDB included | 17.5 MB |
| everything else | ~22 MB |

The `.deb` declares WebKitGTK as a dependency instead, so apt installs a copy
shared with everything else on the system. Take the `.deb` on Debian or
Ubuntu; take the AppImage when you want no installation, no root, or a
distribution the `.deb` does not cover.

Two notes for anyone tempted to shrink it:

* Excluding WebKitGTK would cut roughly 52 MB and break the one promise the
  format makes. The failure would land at runtime, on someone else's machine,
  as a missing symbol.
* `bundle.linux.appimage.bundleMediaFramework` adds another 15–35 MB of
  GStreamer. It is off, and nothing here plays audio or video.

`librsvg` is currently written into the image three times — `librsvg-2.so`,
`.so.2` and `.so.2.48.0` are identical files rather than symlinks, costing
about 6 MB. That comes from Tauri's own AppImage script and there is no
configuration knob for it. Repacking the image afterwards would mean
re-signing it, and a mistake there breaks updates silently, so it is left
alone.

## Updates

**Settings → Check for updates** asks the GitHub release channel whether a
newer version exists. Nothing happens in the background, and the app makes no
other network request.

Update bundles are signed with a project-controlled ed25519 key; the public
half is compiled into every binary, and a bundle that fails verification is
refused before installation. That is why only the first install needs the
SHA-256 check above.

To cross-check the key yourself, compare
`src-tauri/tauri.conf.json → plugins.updater.pubkey` against the
`ppxray.key.pub` published with the first release. If they differ, do not
trust the update — open an issue.

## Signing it yourself

If your organisation requires signed installers, re-sign the released bundles
with your own certificate.

```powershell
# Windows — signtool.exe from the Windows SDK
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com `
  /f your-cert.pfx /p "$env:CERT_PASSWORD" ppxray_0.2.0_x64_en-US.msi
```

```sh
# macOS — Developer ID certificate in your keychain
codesign --deep --force --verify --verbose --timestamp --options runtime \
  --sign "Developer ID Application: YOUR_NAME (TEAM_ID)" /Applications/ppxray.app
xcrun notarytool submit ppxray.app.zip --keychain-profile "notary" --wait
xcrun stapler staple /Applications/ppxray.app
```

AppImages are usually left unsigned; `.deb` packages can be signed with
`dpkg-sig` against your GPG key.

## Reporting a crash

A rolling log of the last few days lives under your app-data directory:

| OS | Path |
| --- | --- |
| Windows | `%AppData%\com.tonynguyen.ppxray\logs\` |
| macOS | `~/Library/Application Support/com.tonynguyen.ppxray/logs/` |
| Linux | `~/.local/share/com.tonynguyen.ppxray/logs/` |

Attach the relevant `ppxray.log.YYYY-MM-DD` — or just its tail — to the issue.
It contains file paths and process names from your own machine, so read it
before posting.
