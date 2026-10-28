BUILD AND TEST

Build with tools/build.py first. Run python tests/run-core.py for 121 native JVM
checks (Core, APK, tree, video features, Java editing/signing, 34 APKS merge/rejection checks). Optionally pass a
resource ZIP as the first argument; a generated fixture is included.

Use Node.js + Happy DOM 15.11.7. Set HAPPY_DOM_PATH to its lib/index.js if it is
not at ../../toolchain/test-node/node_modules/happy-dom/lib/index.js.
Run startup-smoke.cjs, dom-smoke.cjs, layout-smoke.cjs, video-ui-smoke.cjs,
motion-zoom-smoke.cjs, java-edit-ui-smoke.cjs and apks-ui-smoke.cjs for 95 checks.

performance-profile.cjs counts full-buffer reads, line-mark visits and editor
refreshes on a 15,003-line file. UI_SCRIPT can point to an older app.js for
comparison. It does not measure paint, GPU, Android frame pacing or device FPS.

ui-smoke.cjs is an optional Playwright rendering harness. It was not run
successfully here. No physical Android test result is claimed.

make-apks-fixtures.py creates base/French splits with aapt2. ApksSmokeTest
adds generated Smali classes and feature manifests, verifies resource and DEX
retention, TOC variant isolation, signatures, original preservation and rollback.
No proprietary or user-supplied APK is bundled in these fixtures.
