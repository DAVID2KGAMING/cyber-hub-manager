# ---- General hardening ----
-optimizationpasses 5
-overloadaggressively
-repackageclasses ''
-allowaccessmodification
-dontpreverify

# Strip logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# Keep your own entry points (Activities/Services/Providers referenced from the manifest)
-keep class david.manager.MainActivity { *; }
-keep class david.manager.LocalService { *; }
-keep class david.manager.ShareProvider { *; }

# ---- Third-party libs that rely on reflection / are easy to break if renamed ----
# jadx (decompiler core) + plugins
-keep class jadx.** { *; }
-dontwarn jadx.**

# smali / baksmali / dexlib2 (bytecode assembler/disassembler)
-keep class org.jf.** { *; }
-dontwarn org.jf.**

# dalvik dx (dexer) + your CyberCompiler wrapper
-keep class com.android.dx.** { *; }
-keep class com.android.dx.command.dexer.CyberCompiler { *; }
-dontwarn com.android.dx.**

# apksig (APK signing library)
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# ARSCLib (resource table parsing)
-keep class com.reandroid.** { *; }
-dontwarn com.reandroid.**

# ASM (bytecode manipulation)
-keep class org.objectweb.asm.** { *; }
-dontwarn org.objectweb.asm.**

# Gson (uses reflection for (de)serialization)
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Protobuf
-keep class com.google.protobuf.** { *; }
-dontwarn com.google.protobuf.**

# ANTLR / ECJ (used by jadx internally)
-dontwarn org.antlr.**
-dontwarn org.eclipse.jdt.**

# Guava / Apache Commons (reflective edge cases in some codepaths)
-dontwarn com.google.common.**
-dontwarn org.apache.commons.**

# Zstd/XZ/zip4j native bindings
-keep class com.github.luben.zstd.** { *; }
-keep class org.tukaani.xz.** { *; }
-keep class net.lingala.zip4j.** { *; }
-dontwarn com.github.luben.zstd.**

# slf4j
-dontwarn org.slf4j.**
