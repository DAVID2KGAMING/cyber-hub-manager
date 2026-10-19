# Protection layers added

## 1. R8 / ProGuard (`app/build.gradle`, `app/proguard-rules.pro`)
Release builds now minify, shrink, and rename classes. Rules keep the
reflection-heavy third-party libs (jadx, smali/dexlib2, apksig, ARSCLib,
asm, gson, protobuf) from breaking.
**Status: logic reviewed, not build-tested (no Android SDK in this environment).**

## 2. Signature verification (`IntegrityCheck.java`)
Compares the running app's signing cert SHA-256 against a hardcoded value.
**You must set `EXPECTED_SHA256`** after your first real release build, or
this check silently no-ops.

## 3. Anti-debug (`AntiDebug.java`)
Exits the app if a debugger is attached, in release builds only. Includes
an optional background watcher for mid-session attach.

## 4. Root detection (`RootDetector.java`) & Emulator detection (`EmulatorDetector.java`)
Heuristic checks (su binaries, root-manager packages, build tags, known
emulator fingerprints). Wired into `MainActivity.onCreate()` as **warnings
only (logged, not blocking)** — root/emulator detection has false positives
(e.g. legitimate power users, QA on emulators), so exiting the app outright
is a product decision, not something I set by default. To enforce, change
the `Log.w(...)` calls to `System.exit(0)`.

## 5. Dex encryption + runtime loading (`DexProtector.java`, `tools/encrypt_dex.py`)
AES-256-GCM encrypted secondary dex, decrypted and loaded at runtime via
`InMemoryDexClassLoader`, so a decompiler only sees the loader stub, not the
protected logic.

**The crypto round-trip is verified** — I encrypted a test payload with
`encrypt_dex.py` and decrypted it using the exact byte layout `DexProtector
.decrypt()` implements (12-byte nonce + ciphertext+tag); it matched the
original byte-for-byte.

**What is NOT done for you:** actually splitting your classes into a
protected dex. This requires restructuring part of the app into a separate
Gradle module (e.g. `:core`) that compiles independently, so its dex never
gets merged into the main `classes.dex`. That's a real architectural change
to an already-working app, and I don't have an Android SDK/emulator in this
environment to build and test it end-to-end — so rather than guess and risk
breaking your project, I'm giving you the working loader + encryption tool
and the steps, for you to wire up and build on your own machine. Happy to
help debug specific errors you hit.

Steps:
1. Create a `:core` library module, move the classes you want hidden into it
   (keep `MainActivity` and anything referenced directly in the manifest in `:app`).
2. Build `:core`, locate its compiled `classes.dex`.
3. `pip install cryptography`, then:
   `python tools/encrypt_dex.py path/to/core/classes.dex app/src/main/assets/core.enc <your-hex-key>`
4. Put the same hex key in `DexProtector.AES_KEY_HEX`.
5. Call `DexProtector.loadProtectedClass(this, "core.enc", "your.full.ClassName")`
   wherever you currently reference a class that now lives in `:core`.

## General honesty note
None of this (including commercial packers) makes an app un-reverse-engineerable
— it raises the cost/time needed. Treat it as "slows a casual attacker down,"
not "unbreakable."
