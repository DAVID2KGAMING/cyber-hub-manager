package david.manager;

import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.dexbacked.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.writer.pool.DexPool;

final class ApkProtect {
    private ApkProtect() {}
    static final String GUARD_SIMPLE = "ChGuard";
    static final int SX = 0x5A;   // XOR seed for string obfuscation
    static final Pattern DATE = Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}");
    static final String DEX_KEY = "CyberHubSecretKey2024"; // Key para sa DEX Encryption

    /** XOR+Base64 encode a string for the generated guard (no plaintext paths in the DEX). */
    static String enc(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < b.length; i++) b[i] ^= (SX ^ ((i * 7) & 0xFF));
        return java.util.Base64.getEncoder().encodeToString(b);
    }

    /** XOR encrypt/decrypt bytes for DEX shelling. */
    static byte[] xorCrypt(byte[] data, String key) {
        byte[] k = key.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ k[i % k.length]);
        return out;
    }

    static JSONObject info(File apk) throws Exception {
        String xml = new Axml().decode(ApkTools.manifestBytes(apk));
        Matcher am = Pattern.compile("<application\\b[^>]*>").matcher(xml);
        String atag = am.find() ? am.group() : "";
        String existing = ApkTools.attr(atag, "android:name");
        return new JSONObject().put("package", ApkTools.attr(find(xml), "package"))
                .put("hasCustomApplication", !existing.isEmpty())
                .put("existingApplication", existing);
    }
    static String find(String xml) {
        Matcher m = Pattern.compile("<manifest\\b[^>]*>").matcher(xml);
        return m.find() ? m.group() : "";
    }

    static JSONObject run(ApkTools.Host e, JSONObject a) throws Exception {
        File src = new File(a.getString("path"));
        if (!src.getName().toLowerCase(Locale.ROOT).endsWith(".apk")) throw new IOException("Choose an APK file");

        boolean sig = a.optBoolean("signatureCheck", true);
        boolean root = a.optBoolean("rootCheck", true);
        boolean dbg = a.optBoolean("debuggerCheck", true);
        boolean emulator = a.optBoolean("emulatorCheck", false);
        boolean frida = a.optBoolean("fridaCheck", false);
        boolean screenshot = a.optBoolean("screenshotBlock", false);
        boolean installSrc = a.optBoolean("installSourceCheck", false);
        boolean expiry = a.optBoolean("expiryCheck", false);
        boolean integrity = a.optBoolean("integrityCheck", false);
        boolean disableBackup = a.optBoolean("disableBackup", false);
        boolean forceNonDebuggable = a.optBoolean("forceNonDebuggable", false);
        boolean tapjacking = a.optBoolean("tapjackingCheck", false);
        boolean mitm = a.optBoolean("mitmCheck", false);
        boolean accessibility = a.optBoolean("accessibilityCheck", false);
        boolean overlay = a.optBoolean("overlayCheck", false);
        boolean usbDebug = a.optBoolean("usbDebugCheck", false);
        boolean cloning = a.optBoolean("cloningCheck", false);
        boolean timeTamper = a.optBoolean("timeTamperCheck", false);
        boolean deviceBinding = a.optBoolean("deviceBindingCheck", false);
        boolean suspiciousApps = a.optBoolean("suspiciousAppsCheck", false);
        boolean guardSelf = a.optBoolean("guardSelfCheck", false);
        boolean dexEncrypt = a.optBoolean("dexEncryption", false); // NEW

        String installPkgsRaw = a.optString("installSourcePackages", "").trim();
        List<String> installPkgs = new ArrayList<>();
        if (installSrc) {
            if (installPkgsRaw.isEmpty()) throw new IOException("Enter at least one allowed installer package");
            for (String p : installPkgsRaw.split(",")) {
                String t = p.trim();
                if (!t.isEmpty()) {
                    if (!t.matches("[A-Za-z][A-Za-z0-9_.]*")) throw new IOException("Not a valid package name: " + t);
                    installPkgs.add(t);
                }
            }
        }
        long expiryMillis = 0;
        if (expiry) {
            String d = a.optString("expiryDate", "").trim();
            if (!DATE.matcher(d).matches()) throw new IOException("Enter the expiry date (YYYY-MM-DD)");
            java.text.SimpleDateFormat f = new java.text.SimpleDateFormat("yyyy-MM-dd");
            f.setTimeZone(TimeZone.getTimeZone("UTC"));
            f.setLenient(false);
            try { expiryMillis = f.parse(d).getTime(); }
            catch (Exception ex) { throw new IOException("Not a valid date: " + d); }
        }
        if (!sig && !root && !dbg && !emulator && !frida && !screenshot && !installSrc
                && !expiry && !integrity && !disableBackup && !forceNonDebuggable && !tapjacking
                && !mitm && !accessibility && !overlay && !usbDebug && !cloning
                && !timeTamper && !deviceBinding && !suspiciousApps && !guardSelf && !dexEncrypt)
            throw new IOException("Choose at least one protection");

        Axml ax = new Axml();
        String xml = ax.decode(ApkTools.manifestBytes(src));
        Matcher rm = Pattern.compile("<manifest\\b[^>]*>").matcher(xml);
        if (!rm.find()) throw new IOException("AndroidManifest.xml has no <manifest> element");
        String pkg = ApkTools.attr(rm.group(), "package");
        if (pkg.isEmpty()) throw new IOException("Cannot read the package name");
        Matcher am = Pattern.compile("<application\\b[^>]*>").matcher(xml);
        if (!am.find()) throw new IOException("AndroidManifest.xml has no <application> element");
        String appTag = am.group();
        String existingName = ApkTools.attr(appTag, "android:name");
        if (!existingName.isEmpty()) throw new IOException("This APK already has a custom Application class (" + existingName + "). Chaining is not supported yet.");

        byte[] certSha256 = sig ? e.devSigningCert() : null;
        String guardBin = pkg.replace('.', '/') + "/" + GUARD_SIMPLE;
        String guardType = "L" + guardBin + ";";
        File apiJar = e.androidApiJar();

        String dexEntry = firstDexEntry(src);
        byte[] dexBytes = FileOps.zipEntry(src, dexEntry, 256L * 1024 * 1024);
        String arscHash = null;
        try { arscHash = sha256Hex(FileOps.zipEntry(src, "resources.arsc", 256L * 1024 * 1024)); } catch (Exception ignored) {}
        String assetsHash = hashAssets(src);

        List<String> allDex = integrity ? allDexEntries(src) : Collections.singletonList(dexEntry);
        LinkedHashMap<String, String> dexHashes = new LinkedHashMap<>();
        if (integrity && !dexEncrypt) for (String d : allDex) if (!d.equals(dexEntry)) dexHashes.put(d, sha256Hex(FileOps.zipEntry(src, d, 256L * 1024 * 1024)));

        LinkedHashMap<String, String> libHashes = new LinkedHashMap<>();
        if (integrity) for (Map.Entry<String, byte[]> en : allLibEntries(src).entrySet())
            libHashes.put(en.getKey(), sha256Hex(en.getValue()));

        Map<String, byte[]> repl = new HashMap<>();
        Set<String> removals = new HashSet<>();

        // --- DEX ENCRYPTION LOGIC ---
        if (dexEncrypt) {
            List<String> allDexNames = allDexEntries(src);
            int idx = 0;
            for (String dexName : allDexNames) {
                byte[] origDex = FileOps.zipEntry(src, dexName, 256L * 1024 * 1024);
                byte[] encDex = xorCrypt(origDex, DEX_KEY);
                repl.put("assets/ch_d_" + idx + ".bin", encDex);
                if (!dexName.equals(dexEntry)) removals.add(dexName);
                idx++;
            }
        }

        byte[] mergedDex = buildMergedDex(src, dexEntry, dexBytes, guardType, guardBin, pkg, certSha256,
                sig, root, dbg, emulator, frida, screenshot, installSrc, installPkgs, expiry, expiryMillis,
                integrity, tapjacking, mitm, accessibility, overlay, usbDebug, cloning, timeTamper,
                deviceBinding, suspiciousApps, guardSelf, dexEncrypt, apiJar, e.workspace());
        
        if (integrity && !dexEncrypt) dexHashes.put(dexEntry, sha256Hex(mergedDex));

        String newAppTag = appTag.substring(0, appTag.length() - 1) + " android:name=\"" + ApkTools.escape("." + GUARD_SIMPLE) + "\">";
        if (disableBackup) newAppTag = ApkTools.setOrAddAttr(newAppTag, "android:allowBackup", "false");
        if (forceNonDebuggable) newAppTag = ApkTools.setOrAddAttr(newAppTag, "android:debuggable", "false");
        StringBuilder meta = new StringBuilder();
        if (integrity) {
            StringBuilder entries = new StringBuilder(), hashes = new StringBuilder(), le = new StringBuilder(), lh = new StringBuilder();
            for (String d : allDex) { if (entries.length() > 0) { entries.append(','); hashes.append(','); } entries.append(d); hashes.append(dexHashes.get(d)); }
            for (String d : libHashes.keySet()) { if (le.length() > 0) { le.append(','); lh.append(','); } le.append(d); lh.append(libHashes.get(d)); }
            meta.append("<meta-data android:name=\"chGuardDexEntries\" android:value=\"").append(ApkTools.escape(entries.toString())).append("\"/>");
            meta.append("<meta-data android:name=\"chGuardDexHashes\" android:value=\"").append(hashes).append("\"/>");
            if (arscHash != null) meta.append("<meta-data android:name=\"chGuardArsc\" android:value=\"").append(arscHash).append("\"/>");
            meta.append("<meta-data android:name=\"chGuardAssets\" android:value=\"").append(assetsHash).append("\"/>");
            if (le.length() > 0) {
                meta.append("<meta-data android:name=\"chGuardLibEntries\" android:value=\"").append(ApkTools.escape(le.toString())).append("\"/>");
                meta.append("<meta-data android:name=\"chGuardLibHashes\" android:value=\"").append(lh).append("\"/>");
            }
        }
        String editedXml = xml.substring(0, am.start()) + newAppTag + meta + xml.substring(am.end());

        repl.put("AndroidManifest.xml", ax.encode(editedXml));
        repl.put(dexEntry, mergedDex);
        
        JSONObject r = ApkTools.publish(e, src, repl, removals, "-protected", true);

        JSONObject ck = new JSONObject()
                .put("signature", sig).put("root", root).put("debugger", dbg).put("emulator", emulator)
                .put("frida", frida).put("screenshotBlock", screenshot).put("installSource", installSrc)
                .put("expiry", expiry).put("integrity", integrity).put("dexCount", allDex.size())
                .put("disableBackup", disableBackup).put("forceNonDebuggable", forceNonDebuggable)
                .put("tapjacking", tapjacking).put("mitm", mitm).put("accessibility", accessibility)
                .put("overlay", overlay).put("usbDebug", usbDebug).put("cloning", cloning)
                .put("timeTamper", timeTamper).put("deviceBinding", deviceBinding)
                .put("suspiciousApps", suspiciousApps).put("guardSelf", guardSelf)
                .put("dexEncryption", dexEncrypt)
                .put("libCount", libHashes.size());
        return r.put("checks", ck).put("class", pkg + "." + GUARD_SIMPLE);
    }

    static String sha256Hex(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    static String hashAssets(File apk) throws Exception {
        TreeMap<String, byte[]> sorted = new TreeMap<>();
        try (ZipFile z = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                if (ze.isDirectory() || !ze.getName().startsWith("assets/")) continue;
                try (InputStream in = z.getInputStream(ze)) { sorted.put(ze.getName(), ApkTools.readLimited(in, 64L * 1024 * 1024)); }
            }
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (Map.Entry<String, byte[]> en : sorted.entrySet()) {
            md.update(en.getKey().getBytes(StandardCharsets.UTF_8)); md.update((byte) 0); md.update(en.getValue());
        }
        return hex(md.digest());
    }

    static TreeMap<String, byte[]> allLibEntries(File apk) throws Exception {
        TreeMap<String, byte[]> out = new TreeMap<>();
        try (ZipFile z = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                String n = ze.getName();
                if (ze.isDirectory() || !n.startsWith("lib/") || !n.endsWith(".so")) continue;
                try (InputStream in = z.getInputStream(ze)) { out.put(n, ApkTools.readLimited(in, 256L * 1024 * 1024)); }
            }
        }
        return out;
    }

    static byte[] buildMergedDex(File src, String dexEntry, byte[] dexBytes, String guardType, String guardBin, String javaPkg,
                                 byte[] certSha256, boolean sig, boolean root, boolean dbg, boolean emulator, boolean frida,
                                 boolean screenshot, boolean installSrc, List<String> installPkgs, boolean expiry, long expiryMillis,
                                 boolean integrity, boolean tapjacking, boolean mitm, boolean accessibility, boolean overlay,
                                 boolean usbDebug, boolean cloning, boolean timeTamper, boolean deviceBinding,
                                 boolean suspiciousApps, boolean guardSelf, boolean dexEncrypt, File apiJar, File workspace) throws Exception {
        String source = guardSource(javaPkg, certSha256, sig, root, dbg, emulator, frida, screenshot,
                installSrc, installPkgs, expiry, expiryMillis, integrity, tapjacking, mitm, accessibility,
                overlay, usbDebug, cloning, timeTamper, deviceBinding, suspiciousApps, guardSelf, dexEncrypt);
        List<ClassDef> guardClasses = compileStandalone(guardType, source, apiJar, workspace);

        if (dexEncrypt) {
            File out = File.createTempFile(".guard-out-", ".dex", workspace);
            try {
                DexPool.writeTo(out.getPath(), new ImmutableDexFile(Opcodes.getDefault(), guardClasses));
                return java.nio.file.Files.readAllBytes(out.toPath());
            } finally { out.delete(); }
        }

        File tmpDex = File.createTempFile(".guard-src-", ".dex", workspace);
        try {
            java.nio.file.Files.write(tmpDex.toPath(), dexBytes);
            DexBackedDexFile original = DexFileFactory.loadDexFile(tmpDex, Opcodes.getDefault());
            if (original.getClasses().stream().anyMatch(c -> c.getType().equals(guardType)))
                throw new IOException("A class named " + GUARD_SIMPLE + " already exists in this package.");
            List<ClassDef> all = new ArrayList<>();
            for (ClassDef c : original.getClasses()) all.add(c);
            all.addAll(guardClasses);
            File out = File.createTempFile(".guard-out-", ".dex", workspace);
            try {
                DexPool.writeTo(out.getPath(), new ImmutableDexFile(original.getOpcodes(), all));
                return java.nio.file.Files.readAllBytes(out.toPath());
            } finally { out.delete(); }
        } finally { tmpDex.delete(); }
    }

    static String firstDexEntry(File apk) throws Exception {
        try (ZipFile z = new ZipFile(apk)) {
            if (z.getEntry("classes.dex") != null) return "classes.dex";
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) { String n = en.nextElement().getName(); if (n.matches("classes\\d*\\.dex")) return n; }
        }
        throw new IOException("No DEX found in this APK");
    }
    static List<String> allDexEntries(File apk) throws Exception {
        TreeSet<String> names = new TreeSet<>((a, b) -> a.length() != b.length() ? a.length() - b.length() : a.compareTo(b));
        try (ZipFile z = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) { String n = en.nextElement().getName(); if (n.matches("classes\\d*\\.dex")) names.add(n); }
        }
        if (names.isEmpty()) throw new IOException("No DEX found in this APK");
        return new ArrayList<>(names);
    }

    static List<ClassDef> compileStandalone(String type, String text, File platform, File workspace) throws Exception {
        if (!platform.isFile()) throw new IOException("Compiler API library is missing");
        File work = new File(workspace, "guard-" + UUID.randomUUID());
        if (!work.mkdirs()) throw new IOException("Cannot create compiler workspace");
        try {
            String binary = type.substring(1, type.length() - 1), simple = binary.substring(binary.lastIndexOf('/') + 1);
            File source = new File(work, simple + ".java"), output = new File(work, "classes");
            output.mkdirs();
            FileOps.writeAtomic(source, text.getBytes(StandardCharsets.UTF_8), false);
            StringWriter log = new StringWriter();
            PrintWriter messages = new PrintWriter(log);
            boolean ok = org.eclipse.jdt.core.compiler.batch.BatchCompiler.compile(new String[]{
                    "-1.8", "-proc:none", "-g", "-nowarn", "-encoding", "UTF-8", "-maxProblems", "30",
                    "-bootclasspath", platform.getPath(), "-d", output.getPath(), source.getPath()
            }, messages, messages, null);
            messages.flush();
            if (!ok) throw new IOException("Guard class failed to compile:\n" + log);
            File classJar = new File(work, "compiled.jar");
            List<File> compiled = new ArrayList<>();
            collectClasses(output, compiled);
            if (compiled.isEmpty()) throw new IOException("The compiler did not emit any classes");
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(classJar))) {
                for (File f : compiled) {
                    String name = output.toPath().relativize(f.toPath()).toString().replace(File.separatorChar, '/');
                    zip.putNextEntry(new ZipEntry(name));
                    zip.write(FileOps.read(f, 8L * 1024 * 1024));
                    zip.closeEntry();
                }
            }
            File dex = new File(work, "compiled.dex");
            ByteArrayOutputStream dxLog = new ByteArrayOutputStream();
            PrintStream dxOut = new PrintStream(dxLog, true, "UTF-8");
            com.android.dx.command.dexer.DxContext context = new com.android.dx.command.dexer.DxContext(dxOut, dxOut);
            int result = com.android.dx.command.dexer.CyberCompiler.compile(context, classJar.getPath(), dex.getPath());
            if (result != 0 || !dex.isFile()) throw new IOException("Guard class failed to convert to DEX:\n" + dxLog.toString("UTF-8"));
            DexBackedDexFile parsed = DexFileFactory.loadDexFile(dex, Opcodes.getDefault());
            String family = type.substring(0, type.length() - 1) + "$";
            List<ClassDef> family_ = new ArrayList<>();
            boolean found = false;
            for (ClassDef c : parsed.getClasses()) {
                if (c.getType().equals(type)) { found = true; family_.add(ImmutableClassDef.of(c)); }
                else if (c.getType().startsWith(family)) family_.add(ImmutableClassDef.of(c));
            }
            if (!found) throw new IOException("Compiled class not found: " + type);
            return family_;
        } finally { FileOps.deleteTree(work); }
    }
    static void collectClasses(File dir, List<File> out) {
        File[] fs = dir.listFiles();
        if (fs == null) return;
        for (File f : fs) if (f.isDirectory()) collectClasses(f, out); else if (f.getName().endsWith(".class")) out.add(f);
    }
    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte v : b) s.append(String.format("%02x", v & 255));
        return s.toString();
    }

    static void encArr(StringBuilder b, String varName, String[] values) {
        b.append("String[] ").append(varName).append("={");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) b.append(',');
            b.append("d(\"").append(enc(values[i])).append("\")");
        }
        b.append("};");
    }
    static String encStr(String s) { return "d(\"" + enc(s) + "\")"; }

    static final String[] ROOT_PATHS = {
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
        "/system/bin/magisk", "/sbin/magisk", "/system/xbin/magisk",
        "/system/bin/.ext", "/system/xbin/daemonsu", "/system/app/SuperSU",
        "/data/adb", "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu",
        "/data/adb/ap", "/dev/.magisk.unblock", "/.magisk"
    };
    static final String[] ROOT_PACKAGES = {
        "com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
        "com.keramidas.TitaniumBackup", "eu.chainfire.supersu",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.formyhm.hideroot", "com.amphoras.hidemyroot", "com.byapps.hidemyroot"
    };
    static final String[] HOOK_PACKAGES = {
        "org.lsposed.manager", "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.frida.android", "re.frida.server", "com.mwr.dz"
    };
    static final String[] CLONE_PACKAGES = {
        "com.lbe.parallel", "com.excelliance.dualaid", "com.parallel.space.lite",
        "com.virtualapp", "com.applisto.appcloner", "com.cloneapp.parallel"
    };
    static final String[] SUSPICIOUS_PACKAGES = {
        "com.topjohnwu.magisk", "me.weishu.kernelsu", "org.lsposed.manager",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.mwr.dz",
        "com.frida.android", "re.frida.server", "com.keramidas.TitaniumBackup",
        "eu.chainfire.supersu", "com.devadvance.rootcloak", "com.formyhm.hideroot",
        "com.lbe.parallel", "com.excelliance.dualaid", "com.virtualapp",
        "com.applisto.appcloner", "com.mspy", "com.flexispy"
    };

    static String guardSource(String pkg, byte[] certSha256, boolean sig, boolean root, boolean dbg,
                              boolean emulator, boolean frida, boolean screenshot, boolean installSrc,
                              List<String> installPkgs, boolean expiry, long expiryMillis, boolean integrity,
                              boolean tapjacking, boolean mitm, boolean accessibility, boolean overlay,
                              boolean usbDebug, boolean cloning, boolean timeTamper, boolean deviceBinding,
                              boolean suspiciousApps, boolean guardSelf, boolean dexEncrypt) {
        StringBuilder b = new StringBuilder();
        b.append("package ").append(pkg).append(";\n");
        b.append("import android.app.Application;import android.app.Activity;import android.app.ActivityManager;");
        b.append("import android.content.Context;import android.content.pm.*;import android.os.Build;import android.os.Bundle;");
        b.append("import android.os.Debug;import android.os.Process;import android.os.SystemClock;import android.provider.Settings;");
        b.append("import android.view.WindowManager;import android.hardware.Sensor;import android.hardware.SensorManager;");
        b.append("import android.telephony.TelephonyManager;import android.net.ConnectivityManager;import android.net.Network;");
        b.append("import android.net.NetworkCapabilities;import java.security.MessageDigest;import java.security.KeyStore;");
        b.append("import java.io.*;import java.util.*;import java.util.zip.ZipFile;import java.util.zip.ZipEntry;");
        b.append("import java.net.Socket;import java.net.InetSocketAddress;\n");
        b.append("public final class ").append(GUARD_SIMPLE).append(" extends Application {\n");

        // --- DEX DECRYPTION STUB ---
        if (dexEncrypt) {
            b.append(" @Override protected void attachBaseContext(Context base) {\n");
            b.append("  super.attachBaseContext(base);\n");
            b.append("  try {\n");
            b.append("   if (Build.VERSION.SDK_INT >= 26) {\n");
            b.append("    java.util.List<java.nio.ByteBuffer> buffers = new java.util.ArrayList<>();\n");
            b.append("    int i = 0;\n");
            b.append("    while (true) {\n");
            b.append("     String name = \"ch_d_\" + i + \".bin\";\n");
            b.append("     try {\n");
            b.append("      java.io.InputStream is = getAssets().open(name);\n");
            b.append("      java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();\n");
            b.append("      byte[] buf = new byte[8192]; int n;\n");
            b.append("      while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);\n");
            b.append("      is.close();\n");
            b.append("      byte[] data = bos.toByteArray();\n");
            b.append("      byte[] key = \"").append(ApkProtect.DEX_KEY).append("\".getBytes(\"UTF-8\");\n");
            b.append("      for (int j = 0; j < data.length; j++) data[j] ^= key[j % key.length];\n");
            b.append("      buffers.add(java.nio.ByteBuffer.wrap(data));\n");
            b.append("      i++;\n");
            b.append("     } catch (java.io.IOException e) { break; }\n");
            b.append("    }\n");
            b.append("    if (!buffers.isEmpty()) {\n");
            b.append("     ClassLoader cl = new dalvik.system.InMemoryDexClassLoader(buffers.toArray(new java.nio.ByteBuffer[0]), getClassLoader());\n");
            b.append("     java.lang.reflect.Field pathListField = Class.forName(\"dalvik.system.BaseDexClassLoader\").getDeclaredField(\"pathList\");\n");
            b.append("     pathListField.setAccessible(true);\n");
            b.append("     Object oldPathList = pathListField.get(getClassLoader());\n");
            b.append("     Object newPathList = pathListField.get(cl);\n");
            b.append("     java.lang.reflect.Field dexElementsField = Class.forName(\"dalvik.system.DexPathList\").getDeclaredField(\"dexElements\");\n");
            b.append("     dexElementsField.setAccessible(true);\n");
            b.append("     Object[] oldElements = (Object[]) dexElementsField.get(oldPathList);\n");
            b.append("     Object[] newElements = (Object[]) dexElementsField.get(newPathList);\n");
            b.append("     Object[] combined = (Object[]) java.lang.reflect.Array.newInstance(oldElements.getClass().getComponentType(), oldElements.length + newElements.length);\n");
            b.append("     System.arraycopy(newElements, 0, combined, 0, newElements.length);\n");
            b.append("     System.arraycopy(oldElements, 0, combined, newElements.length, oldElements.length);\n");
            b.append("     dexElementsField.set(oldPathList, combined);\n");
            b.append("    }\n");
            b.append("   }\n");
            b.append("  } catch (Throwable t) {}\n");
            b.append(" }\n");
        }

        // onCreate
        b.append(" @Override public void onCreate(){super.onCreate();try{check(this);}catch(Throwable t){fail();}\n");
        if (screenshot || tapjacking) {
            b.append("  registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks(){\n");
            b.append("   public void onActivityCreated(Activity a,Bundle s){try{\n");
            if (screenshot) b.append("    a.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,WindowManager.LayoutParams.FLAG_SECURE);\n");
            if (tapjacking) b.append("    a.getWindow().getDecorView().setFilterTouchesWhenObscured(true);\n");
            b.append("   }catch(Throwable t){}}\n");
            b.append("   public void onActivityStarted(Activity a){}\n   public void onActivityResumed(Activity a){}\n");
            b.append("   public void onActivityPaused(Activity a){}\n   public void onActivityStopped(Activity a){}\n");
            b.append("   public void onActivitySaveInstanceState(Activity a,Bundle s){}\n   public void onActivityDestroyed(Activity a){}\n");
            b.append("  });\n");
        }
        b.append(" }\n");

        // check()
        b.append(" static void check(Context c)throws Exception{\n");

        // ---- Guard self-check
        if (guardSelf) {
            b.append("  if(!ChGuard.class.getName().equals(getClass().getName()))fail();\n");
            b.append("  try{ChGuard.class.getDeclaredMethod(\"onCreate\");}catch(NoSuchMethodException e){fail();}\n");
        }

        // ---- Signature
        if (sig && certSha256 != null) {
            b.append("  String expected=").append(encStr(hex(certSha256))).append(";\n");
            b.append("  PackageInfo pi=c.getPackageManager().getPackageInfo(c.getPackageName(),")
             .append("Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES);\n");
            b.append("  Signature[] sigs=null;\n");
            b.append("  if(Build.VERSION.SDK_INT>=28){SigningInfo si=pi.signingInfo;if(si==null)fail();")
             .append("if(si.hasMultipleSigners())fail();sigs=si.getApkContentsSigners();}\n");
            b.append("  else sigs=pi.signatures;\n");
            b.append("  if(sigs==null||sigs.length!=1)fail();\n");
            b.append("  MessageDigest md=MessageDigest.getInstance(\"SHA-256\");byte[] dh=md.digest(sigs[0].toByteArray());\n");
            b.append("  StringBuilder hb=new StringBuilder();for(byte x:dh)hb.append(String.format(\"%02x\",x&255));\n");
            b.append("  if(!hb.toString().equals(expected))fail();\n");
        }

        // ---- Root
        if (root) {
            encArr(b, "rootPaths", ROOT_PATHS);
            b.append("\n  for(String p:rootPaths)if(new File(p).exists())fail();\n");
            encArr(b, "rootPkgs", ROOT_PACKAGES);
            b.append("\n  PackageManager pm=c.getPackageManager();\n");
            b.append("  for(String p:rootPkgs){try{pm.getPackageInfo(p,0);fail();}catch(PackageManager.NameNotFoundException ignored){}}\n");
            b.append("  String tags=Build.TAGS;if(tags!=null&&tags.contains(\"test-keys\"))fail();\n");
            b.append("  String dr=System.getProperty(\"ro.debuggable\"),sc=System.getProperty(\"ro.secure\"),");
            b.append("sl=System.getProperty(\"ro.build.selinux\"),adr=System.getProperty(\"service.adb.root\");\n");
            b.append("  if(\"1\".equals(dr)||\"0\".equals(sc)||\"0\".equals(sl)||\"1\".equals(adr))fail();\n");
            b.append("  try(BufferedReader r=new BufferedReader(new FileReader(\"/proc/mounts\"))){String l;");
            b.append("while((l=r.readLine())!=null){String lo=l.toLowerCase();")
             .append("if(lo.contains(\"magisk\")||lo.contains(\"worker\")||(lo.contains(\"overlay\")&&lo.contains(\"/system\")))fail();}}\n");
            b.append("  catch(Exception ignored){}\n");
        }

        // ---- Debugger
        if (dbg) {
            b.append("  if(Debug.isDebuggerConnected()||Debug.waitingForDebugger())fail();\n");
            b.append("  try(BufferedReader r=new BufferedReader(new FileReader(\"/proc/self/status\"))){String l;");
            b.append("while((l=r.readLine())!=null){if(l.startsWith(\"TracerPid:\")&&!l.trim().endsWith(\"0\"))fail();")
             .append("if(l.startsWith(\"Seccomp:\")&&!l.trim().endsWith(\"0\"))fail();}}\n");
            b.append("  catch(Exception ignored){}\n");
        }

        // ---- Emulator
        if (emulator) {
            b.append("  String fp=Build.FINGERPRINT,model=Build.MODEL,manu=Build.MANUFACTURER,hardware=Build.HARDWARE,")
             .append("prod=Build.PRODUCT,brand=Build.BRAND,dev=Build.DEVICE,serial=Build.SERIAL;\n");
            b.append("  boolean emu=(fp!=null&&(fp.startsWith(\"generic\")||fp.startsWith(\"unknown\")||fp.contains(\"vbox\")||fp.contains(\"test-keys\")))\n");
            b.append("   ||(model!=null&&(model.contains(\"google_sdk\")||model.contains(\"Emulator\")||model.contains(\"Android SDK built for\")))\n");
            b.append("   ||(manu!=null&&manu.toLowerCase().contains(\"genymotion\"))\n");
            b.append("   ||(brand!=null&&brand.startsWith(\"generic\")&&dev!=null&&dev.startsWith(\"generic\"))\n");
            b.append("   ||(hardware!=null&&(hardware.contains(\"goldfish\")||hardware.contains(\"ranchu\")))\n");
            b.append("   ||(prod!=null&&prod.contains(\"sdk\"))||\"unknown\".equals(serial)||\"00000000000000\".equals(serial)\n");
            b.append("   ||new File(\"/dev/socket/qemud\").exists()||new File(\"/dev/qemu_pipe\").exists()||new File(\"/dev/socket/genyd\").exists();\n");
            b.append("  try{TelephonyManager tm=(TelephonyManager)c.getSystemService(Context.TELEPHONY_SERVICE);")
             .append("if(tm!=null){String id=tm.getDeviceId();if(id!=null&&id.matches(\"0{14,}\"))emu=true;}}catch(Throwable ignored){}\n");
            b.append("  try{SensorManager sm=(SensorManager)c.getSystemService(Context.SENSOR_SERVICE);")
             .append("if(sm!=null&&sm.getSensorList(Sensor.TYPE_ALL).size()<5)emu=true;}catch(Throwable ignored){}\n");
            b.append("  if(emu)fail();\n");
        }

        // ---- Frida / Xposed / hook frameworks
        if (frida) {
            encArr(b, "hookFiles", new String[]{
                "/system/framework/XposedBridge.jar", "/system/lib/libxposed_art.so",
                "/system/lib64/libxposed_art.so", "/data/local/tmp/frida-server",
                "/data/local/tmp/re.frida.server"
            });
            b.append("\n  for(String p:hookFiles)if(new File(p).exists())fail();\n");
            b.append("  try(BufferedReader r=new BufferedReader(new FileReader(\"/proc/self/maps\"))){String l;");
            b.append("while((l=r.readLine())!=null){String lo=l.toLowerCase();")
             .append("if(lo.contains(\"frida\")||lo.contains(\"xposed\")||lo.contains(\"substrate\")||lo.contains(\"lsposed\"))fail();}}\n");
            b.append("  catch(Exception ignored){}\n");
            b.append("  try{Class.forName(\"de.robv.android.xposed.XposedBridge\");fail();}catch(Throwable ignored){}\n");
            b.append("  try{Class.forName(\"de.robv.android.xposed.XC_MethodHook\");fail();}catch(Throwable ignored){}\n");
            b.append("  for(Map.Entry<Thread,StackTraceElement[]> en:Thread.getAllStackTraces().entrySet())");
            b.append("for(StackTraceElement ste:en.getValue()){String cn=ste.getClassName();")
             .append("if(cn!=null&&(cn.contains(\"XposedBridge\")||cn.contains(\"de.robv\")||cn.contains(\"Frida\")))fail();}\n");
            encArr(b, "hookPkgs", HOOK_PACKAGES);
            b.append("\n  PackageManager pm2=c.getPackageManager();");
            b.append("for(String p:hookPkgs){try{pm2.getPackageInfo(p,0);fail();}catch(PackageManager.NameNotFoundException ignored){}}\n");
            b.append("  int[] fridaPorts={27042,27043};for(int port:fridaPorts){try(Socket s=new Socket()){")
             .append("s.connect(new InetSocketAddress(\"127.0.0.1\",port),100);fail();}catch(Exception ignored){}}\n");
        }

        // ---- Install source
        if (installSrc) {
            b.append("  String installer;\n");
            b.append("  if(Build.VERSION.SDK_INT>=30){InstallSourceInfo isi=c.getPackageManager().getInstallSourceInfo(c.getPackageName());installer=isi.getInstallingPackageName();}\n");
            b.append("  else installer=c.getPackageManager().getInstallerPackageName(c.getPackageName());\n");
            String[] allowed = installPkgs.toArray(new String[0]);
            encArr(b, "allowed", allowed);
            b.append("\n  boolean ok=false;if(installer!=null)for(String a:allowed)if(installer.equals(a))ok=true;if(!ok)fail();\n");
        }

        // ---- Expiry
        if (expiry) b.append("  if(System.currentTimeMillis()>").append(expiryMillis).append("L)fail();\n");

        // ---- Integrity (DEX + arsc + assets + libs)
        if (integrity && !dexEncrypt) {
            b.append("  ApplicationInfo ai=c.getPackageManager().getApplicationInfo(c.getPackageName(),PackageManager.GET_META_DATA);\n");
            b.append("  android.os.Bundle gm=ai.metaData;if(gm==null)fail();\n");
            b.append("  String de=gm.getString(\"chGuardDexEntries\"),dh=gm.getString(\"chGuardDexHashes\"),")
             .append("ea=gm.getString(\"chGuardArsc\"),eas=gm.getString(\"chGuardAssets\"),")
             .append("le=gm.getString(\"chGuardLibEntries\"),lh=gm.getString(\"chGuardLibHashes\");\n");
            b.append("  ZipFile zf=new ZipFile(ai.sourceDir);\n");
            b.append("  try{\n");
            b.append("   if(de!=null&&dh!=null){String[] n=de.split(\",\"),h=dh.split(\",\");")
             .append("if(n.length!=h.length)fail();for(int i=0;i<n.length;i++)if(!sha256(readEntry(zf,n[i])).equals(h[i]))fail();}\n");
            b.append("   if(ea!=null){if(!sha256(readEntry(zf,\"resources.arsc\")).equals(ea))fail();}\n");
            b.append("   if(eas!=null){TreeMap<String,byte[]> s=new TreeMap<>();Enumeration<? extends ZipEntry> en=zf.entries();")
             .append("while(en.hasMoreElements()){ZipEntry e2=en.nextElement();if(!e2.isDirectory()&&e2.getName().startsWith(\"assets/\"))s.put(e2.getName(),readEntry(zf,e2.getName()));}")
             .append("MessageDigest md=MessageDigest.getInstance(\"SHA-256\");for(Map.Entry<String,byte[]> e2:s.entrySet()){")
             .append("md.update(e2.getKey().getBytes(\"UTF-8\"));md.update((byte)0);md.update(e2.getValue());}")
             .append("if(!hex(md.digest()).equals(eas))fail();}\n");
            b.append("   if(le!=null&&lh!=null){String[] n=le.split(\",\"),h=lh.split(\",\");")
             .append("if(n.length!=h.length)fail();for(int i=0;i<n.length;i++)if(!sha256(readEntry(zf,n[i])).equals(h[i]))fail();}\n");
            b.append("  }finally{zf.close();}\n");
            b.append("  static byte[] readEntry(ZipFile z,String n)throws IOException{ZipEntry e=z.getEntry(n);if(e==null)return new byte[0];")
             .append("ByteArrayOutputStream o=new ByteArrayOutputStream();InputStream in=z.getInputStream(e);byte[] buf=new byte[65536];")
             .append("int k;while((k=in.read(buf))>0)o.write(buf,0,k);in.close();return o.toByteArray();}\n");
            b.append("  static String sha256(byte[] d)throws Exception{return hex(MessageDigest.getInstance(\"SHA-256\").digest(d));}\n");
            b.append("  static String hex(byte[] d){StringBuilder h=new StringBuilder();for(byte x:d)h.append(String.format(\"%02x\",x&255));return h.toString();}\n");
        }

        // ---- MITM (user CA + proxy + VPN)
        if (mitm) {
            b.append("  try{KeyStore ks=KeyStore.getInstance(\"AndroidCAStore\");ks.load(null,null);")
             .append("Enumeration<String> al=ks.aliases();while(al.hasMoreElements())if(al.nextElement().startsWith(\"user:\"))fail();}")
             .append("catch(Throwable ignored){}\n");
            b.append("  String ph=System.getProperty(\"http.proxyHost\"),pp=System.getProperty(\"https.proxyHost\");")
             .append("if((ph!=null&&ph.length()>0)||(pp!=null&&pp.length()>0))fail();\n");
            b.append("  try{ConnectivityManager cm=(ConnectivityManager)c.getSystemService(Context.CONNECTIVITY_SERVICE);")
             .append("Network n=cm.getActiveNetwork();if(n!=null){NetworkCapabilities nc=cm.getNetworkCapabilities(n);")
             .append("if(nc!=null&&nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN))fail();}}catch(Throwable ignored){}\n");
            b.append("  int[] proxyPorts={8080,8888,3128,1080,8118};for(int p:proxyPorts){try(Socket s=new Socket()){")
             .append("s.connect(new InetSocketAddress(\"127.0.0.1\",p),100);fail();}catch(Exception ignored){}}\n");
        }

        // ---- Accessibility services (block non-system)
        if (accessibility) {
            b.append("  try{String acc=Settings.Secure.getString(c.getContentResolver(),Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);")
             .append("if(acc!=null&&acc.length()>0){String my=c.getPackageName();for(String p:acc.split(\":\")){")
             .append("if(p==null||p.length()==0)continue;String pk=p.split(\"/\")[0];")
             .append("if(pk.startsWith(\"com.android.\")||pk.startsWith(\"android.\")||pk.equals(my))continue;fail();}}}")
             .append("catch(Throwable ignored){}\n");
        }

        // ---- Overlay
        if (overlay) {
            b.append("  try{if(Settings.canDrawOverlays(c))fail();}catch(Throwable ignored){}\n");
        }

        // ---- USB debugging / developer options
        if (usbDebug) {
            b.append("  try{if(Settings.Global.getInt(c.getContentResolver(),Settings.Global.ADB_ENABLED,0)==1)fail();")
             .append("if(Settings.Global.getInt(c.getContentResolver(),Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,0)==1)fail();}")
             .append("catch(Throwable ignored){}\n");
        }

        // ---- Cloning / parallel space
        if (cloning) {
            b.append("  try{String dd=c.getApplicationInfo().dataDir;if(dd!=null){")
             .append("if(dd.contains(\"/virtual/\")||dd.contains(\"/clone/\")||dd.contains(\"/parallel/\")||dd.contains(\"/999/\"))fail();}}")
             .append("catch(Throwable ignored){}\n");
            encArr(b, "clonePkgs", CLONE_PACKAGES);
            b.append("\n  PackageManager pm3=c.getPackageManager();for(String p:clonePkgs){")
             .append("try{pm3.getPackageInfo(p,0);fail();}catch(PackageManager.NameNotFoundException ignored){}}\n");
        }

        // ---- Time tamper (wall vs elapsedRealtime divergence)
        if (timeTamper) {
            b.append("  try{android.content.SharedPreferences sp=c.getSharedPreferences(\"__cg_t\",Context.MODE_PRIVATE);")
             .append("long sw=sp.getLong(\"w\",0),se=sp.getLong(\"e\",0);long nw=System.currentTimeMillis(),ne=SystemClock.elapsedRealtime();")
             .append("if(sw==0)sp.edit().putLong(\"w\",nw).putLong(\"e\",ne).commit();")
             .append("else{long dw=nw-sw,de2=ne-se;if(Math.abs(dw-de2)>3600000L)fail();}}catch(Throwable ignored){}\n");
        }

        // ---- Device binding (first-run fingerprint)
        if (deviceBinding) {
            b.append("  try{String aid=Settings.Secure.getString(c.getContentResolver(),Settings.Secure.ANDROID_ID);")
             .append("String raw=aid+\"|\"+Build.FINGERPRINT+\"|\"+Build.MANUFACTURER+\"|\"+Build.MODEL;")
             .append("MessageDigest dm=MessageDigest.getInstance(\"SHA-256\");byte[] db=dm.digest(raw.getBytes(\"UTF-8\"));")
             .append("String dev=hex(db);android.content.SharedPreferences sp=c.getSharedPreferences(\"__cg_d\",Context.MODE_PRIVATE);")
             .append("String saved=sp.getString(\"id\",null);")
             .append("if(saved==null)sp.edit().putString(\"id\",dev).commit();else if(!saved.equals(dev))fail();}catch(Throwable ignored){}\n");
        }

        // ---- Suspicious installed apps (analysis/root/hook tools)
        if (suspiciousApps) {
            encArr(b, "susPkgs", SUSPICIOUS_PACKAGES);
            b.append("\n  PackageManager pm4=c.getPackageManager();for(String p:susPkgs){")
             .append("try{pm4.getPackageInfo(p,0);fail();}catch(PackageManager.NameNotFoundException ignored){}}\n");
        }

        b.append(" }\n");  // end check()

        // ---- String decoder
        b.append(" static String d(String s){try{byte[] b=android.util.Base64.decode(s,android.util.Base64.NO_WRAP);")
         .append("for(int i=0;i<b.length;i++)b[i]^=(0x5A^((i*7)&0xFF));return new String(b,\"UTF-8\");}catch(Exception e){return \"\";}}\n");

        // ---- Multi-kill fail (all kill paths; block as last resort)
        b.append(" static void fail(){")
         .append("try{Process.sendSignal(Process.myPid(),9);}catch(Throwable t){}")
         .append("try{Process.killProcess(Process.myPid());}catch(Throwable t){}")
         .append("try{System.exit(1);}catch(Throwable t){}")
         .append("try{Runtime.getRuntime().halt(1);}catch(Throwable t){}")
         .append("try{Thread.sleep(999999999L);}catch(Throwable t){}}\n");
        b.append("}\n");
        return b.toString();
    }
}