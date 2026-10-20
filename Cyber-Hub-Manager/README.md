# DB Manager — 0.2.2 development build

Android file manager and APK/DEX editor using a local WebView interface and native Java tools. Core tools work offline. Android 8.0 / API 26 or newer is required.

**Package name is now `david.manager`** (was `com.cyberhub.manager`). Android treats this as a different app, so 0.1.7 installs **next to** the old one and does not update it. The old app's private Workspace stays in the old app; copy anything you need out first. versionCode is 8.

## New in 0.1.7 (APK tools)

Open an APK → **Function**, or select files/folders:

- **Edit manifest / version**: change package name, app name, version name/code. Writes a new `-edited.apk`, signed and verified.
- **Clone APK (new package)**: same, but also pins relative class names (`.MainActivity`) to the original package, moves provider authorities and custom permissions to the new package, and drops `sharedUserId`, so the clone installs beside the original.
- **Remove permissions**: tick individual `uses-permission` entries (Advertising-ID ones are pre-ticked) or remove all.
- **Add / replace file in APK**, and inside an APK **Replace with file…** and **Remove from archive**. PNG/JPEG/WebP replacements are type-checked.
- **Hex view / patch** for any file or archive entry: go to offset, find (hex or "text"), overwrite bytes. Files get a one-time `.bak`; archive entries produce a new signed copy. Same-length patches only.
- **String resources (arsc)**: list and edit strings in `resources.arsc` (`res/...` paths are hidden). An edit applies to every place that uses exactly that text.
- **Decode to project folder / Build APK project**: apktool-style at XML level. Every file is extracted and binary XML (manifest, layouts, drawables, menus) becomes editable text; Build re-encodes changed XML, adds new files, drops deleted ones, signs and verifies. `resources.arsc` and DEX are not decompiled to `values/` XML or Smali folders; use String resources and the DEX editor for those.
- **Protect APK**: adds one small Application-subclass guard to an APK (Function menu, or long-press an APK). It only works on an APK that does not already set its own `android:name` on `<application>` (tells you so if it does); no existing class is modified, only a new class and the manifest. Tick any combination:
  - Stop if re-signed with another key (signing-certificate pin)
  - Stop on rooted devices
  - Stop if a debugger is attached
  - Stop on emulators (BlueStacks, LDPlayer, Genymotion, generic AVDs)
  - Stop if Frida or Xposed is detected
  - Stop if DEX, resources.arsc or assets were edited after protecting (SHA-256 content hash of each, not just size — stored in AndroidManifest.xml meta-data rather than inside the DEX itself, since a file cannot contain its own exact hash; overlaps with the signing-certificate pin above, which already covers every byte of the APK cryptographically — this adds a second, independent check); multidex-safe — every classes*.dex is hashed, not just the one carrying the guard
  - Block screenshots / screen recording (silent, doesn't stop the app)
  - Stop unless installed from one of the installer packages you list
  - Stop the app after a date you choose
  - Disable backup / data extraction (`android:allowBackup="false"`, blocks `adb backup`)
  - Force non-debuggable (`android:debuggable="false"`)
  - Block tapjacking (ignores touches while another app's window is drawn on top, the standard Android defence)
  - Stop if a user-added CA certificate is installed (a common sign of a MITM proxy such as Charles/Fiddler/Burp inspecting the app's traffic)
  The original APK is never changed; the result is a new `-protected.apk`, signed and verified.

Not included: SFTP (needs an SSH library; only FTP/FTPS exist), merging several DEX files into one, one-tap ad removal (needs code edits, not just permissions), decoding `resources.arsc` to `values/*.xml` or DEX to Smali folders on disk, and brand-new symbolic resources. Cloned apps that check their own signature, package name or licence server may not run.

## APKS → APK conversion

Tap a `.apks` file → **Convert to APK**, or long press it and choose **Convert to APK**. Select a variant if the archive contains multiple alternatives, choose the destination/name, then tap **Convert**. The result dialog offers **Open folder** and **Install**. The source APKS is never changed and existing output files are never overwritten.

- SAI-style bundles: validate and merge base, configuration resources, feature manifests, assets, native libraries and DEX files. Base identification uses the manifest, not filenames or a launcher-activity heuristic.
- Bundletool: read `toc.pb` and keep variants separate. Split and standalone outputs are separate choices. A verified standalone APK is copied byte-for-byte with its original signature; unsigned standalone and merged outputs are signed with the bundled development key.
- ARSCLib 1.4.0 merges binary resource tables; split-only manifest flags and delivery metadata are removed after checking required split dependencies/types. APK contents are aligned, signed and verified before publication.
- Native-worker progress shows the actual stage. Duplicate conversion and accidental Back dismissal are blocked while work runs. Keep the app open until it finishes.
- Mixed packages/versions (including versionCodeMajor), missing bases/features, duplicate split IDs/classes, conflicting file paths, unsafe paths and damaged entries fail without publishing an APK. Failed signing leaves the original unchanged.

Limits: 256 MB per embedded APK, 1 GB selected/expanded content, 1,024 APKs, 64 MB resource tables and 128 MB individual DEX files. Complex Play Asset Delivery, OBB, instant/system/APEX/archived apps, SDK-runtime and conditional/device-targeted delivery not safely handled by this converter are rejected. One variant is not necessarily universal across all devices. Apps depending on Play delivery services, original signatures, licensing or server checks may not work after merging/re-signing. Successful structural/signature verification does not prove every third-party app will install or run on every phone. Large bundles still require device memory/disk testing.

Merged APKs cannot update an installed app signed with a different developer key. Conversion does not automatically uninstall or replace an installed app.

## Retained editing and performance improvements

- Pinch previews use a compositor transform. The editor lays out the final font once on release, with the code position as its scroll anchor. Java, Smali, XML and text retain separate 4–32 px sizes.
- Typing uses CodeMirror history generations for dirty tracking. It no longer reads/scans the whole buffer on each keystroke. Method highlighting uses the visible-line tokenizer; highlighting gets a smaller work budget.
- Closing menus/dialogs reuses isolated animation surfaces and moves existing nodes instead of cloning whole subtrees and reparsing styles each time. Offscreen file rows can skip rendering on supporting WebViews.
- APK thumbnails have a separate native executor and shared request cache. They do not hold up foreground operations or flash the progress indicator. Disk capacity is read once per folder listing.
- **Java is editable.** Save compiles valid Java with ECJ, converts emitted bytecode to DEX, validates it, and merges only the edited class family into the selected DEX files. Android API and project signature stubs are compile-only; stub implementations never enter the edited APK.
- Java toolbar has undo, redo, save and line tools. **Find and replace** edits the live buffer and is undoable. Smali register tools are hidden in Java; comments use the correct language syntax.
- Failed Java compilation keeps the buffer open and shows diagnostics with a jump-to-line action. Concurrent saves compile once. Buffer changes during an asynchronous save are not falsely marked clean.
- **Save and sign APK** rewrites, signs and verifies V1/V2/V3 before committing to the source with an exact backup. Failed signing leaves the source unchanged. Exporting a copy no longer clears the unsaved-project flag. Opening another DEX asks how to handle unsaved work.

## Edit → save → sign

1. Grant file access, tap an APK, choose **View**, then open `classes.dex` and select the DEX files needed by the project.
2. Open a class. Edit Smali directly or use **Editor menu → View Java**. Java opens the enclosing class when you select a nested class.
3. Edit the source and tap Save. Returning from a dirty DEX editor also attempts to compile; an error keeps you in the editor. Save changes the temporary project, not the original APK yet.
4. Use **Editor/DEX menu → Save and sign APK**. This writes the verified signed result to the source path and keeps its previous contents as a backup. The result dialog offers Install.
5. Alternatively, **Save project / Save and exit** writes unsigned changes with a backup; **Export DEX / APK** creates a separate copy. Use APK **Function → Sign a copy** when signing an exported APK. Repeat sign-copy uses a unique output name.
6. A `.bak` file can be restored from its Rename dialog. Existing backups are retained with unique suffixes.

Java compilation requires valid, compilable source. Decompiled Java is not guaranteed to reconstruct the original source or behavior. Obfuscated names, unresolved dependencies, incomplete JADX output or unsupported language constructs can require manual correction or Smali editing. Incomplete-method placeholders are rejected. Package/class renaming is rejected. The compiler targets Java 8 syntax and Android API 34 signatures; lambdas/method references needing desugaring are rejected rather than emitting unsafe bytecode. New APIs still need the appropriate runtime Android version. These limits do not make the Java editor read-only.

## Available tools

| Area | Working implementation |
| --- | --- |
| Files | Two panes, folder/history navigation, selection, copy/move, batch rename, bookmarks, recycle/restore, backup restore, create, filter, properties/SHA-256, share. |
| Archives | ZIP, 7z, TAR, TAR.GZ/XZ/ZST/BZ2/LZ4, GZIP; format-appropriate compression, ZIP/7z AES passwords, split archives, extraction. |
| APK | Metadata/icon, signature verification, browse/extract, edited archive output, signing, Android install intent. Protection is not assessed. |
| APKS | Convert base/config/feature split sets; select bundletool variants; preserve signed standalone APKs; sign and verify merged APKs; install output. |
| APK tools | Manifest/version edit, clone, permission removal, add/replace/remove entries, hex view/patch, arsc string editing, XML project decode/build, own signing key. |
| Binary XML | Decode/edit/encode; preserve existing typed values and resource IDs. New symbolic resources need a separate resource compiler. |
| DEX | MultiDex tree/history/search, string occurrences, member navigation, usages/subclasses/overrides, Smali/Java editing, compile/save/export/sign. |
| Editors | Syntax colors, line tools, search/replace, go to line, wrap, undo/redo, export, text zoom. Smali register analysis/increase. |
| Resources | ARSC/AXML string-pool viewing, filtering, copy and export. Full resource-table editing is not included. |
| Installed apps | List/filter and inspect/extract base APKs. Installed-app export reads the base APK; use an APKS bundle for split conversion. |
| Tools | Local profile/preferences, activity record, file comparisons, shell terminal, own-format `.sh` plugins. |
| Network | FTP/explicit FTPS client; token-protected read-only local HTTP sharing; local MCP `list_files`/`read_text`. |

Remote/network tools run only while the app process lives and respect Android permissions. Terminal commands have a 20-second timeout. DEX searches are capped; usage search covers selected DEX instructions/type declarations, not reflection. Register analysis is a usage/count view, not liveness analysis. General resource-table editing, root escalation, cloud subscriptions, remote desktop control and proprietary plugins are not provided.

## Validation and limits

See `VALIDATION.txt`, `tests/results/` and `tests/performance-profile.cjs` for the actual checks. Native code runs in JVM tests with real ZIP/DEX/AXML/signatures; UI tests use a mocked bridge and Happy DOM. The profile counts expensive operations on a 15,003-line buffer. It is **not a device FPS measurement**.

No physical Android device/emulator was available. Installation, actual WebView frame pacing, pinch/keyboard rendering, device memory pressure, FTP endpoints and Android JNI execution still require device testing. The local browser runtime was unavailable and cloud local-preview access was denied; that restriction was respected. This is a development build, not a promise of pixel-perfect or universally lag-free behavior.

The signing certificate is a **public development key** bundled to make local signing work. It cannot update an app signed by a different developer; use your own key for a production identity. APK size includes the offline Java compiler, compile-only Android API library and resource-aware APKS merge engine. The API library is copied to cache only on the first Java compilation.

## Build

JDK 17, Android SDK 34 and build-tools 35.0.0:

```sh
bash gradlew assembleDebug
```

All runtime JARs, four Zstandard Android ABIs and local UI assets are included. Gradle needs network access for its build plugin on first run. The delivered APK uses the fallback builder:

```sh
python tools/build.py --sdk /absolute/path/to/android-sdk
```

Its default build-tools selection is 34.0.0; pass `--tools` for another installed build-tools directory. Output: `dist/Cyber-Hub-Manager-0.1.7.apk`. It compiles with desktop ECJ, converts with D8, aligns, signs, verifies signatures and checks packaged assets before publishing.

`python tools/dependencies.py` recreates pinned runtime JARs. `python tools/compiler-api.py /path/to/platforms/android-34/android.jar` recreates the compile-only classpath asset. Dependency/source/license information is in `THIRD-PARTY-NOTICES.txt`, `DEPENDENCIES.json` and `licenses/`.

## Source and tests

- `app/src/main/assets/`: HTML/CSS/JS interface, CodeMirror and compile-only API asset.
- `MainActivity.java` / `DataEngine.java`: WebView bridge, OS actions, native dispatch and documents.
- `DexEngine.java` / `JavaEditCompiler.java`: decompile, compile, transactional DEX merge, commit/export.
- `ApkSigning.java`: temporary signing, mandatory verification, atomic publication.
- `FileOps.java`, `Axml.java`, `ArchiveTools.java`, `BatchFiles.java`, `CompareTools.java`: file/format engines.
- `LocalService.java`, `FtpTools.java`: explicitly started network tools.

```sh
python tests/run-core.py
# Install Happy DOM 15.11.7 separately and set HAPPY_DOM_PATH to its lib/index.js.
node tests/startup-smoke.cjs
node tests/dom-smoke.cjs
node tests/layout-smoke.cjs
node tests/video-ui-smoke.cjs
node tests/motion-zoom-smoke.cjs
node tests/java-edit-ui-smoke.cjs
node tests/performance-profile.cjs
```

`tests/ui-smoke.cjs` is an optional Playwright visual harness and has not run successfully in this environment. Reference screenshots/videos are not redistributed in this package.
