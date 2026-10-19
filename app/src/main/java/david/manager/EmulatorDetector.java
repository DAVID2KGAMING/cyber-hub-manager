package david.manager;

import android.os.Build;

/**
 * Heuristic emulator detection, based on common fingerprint/hardware
 * signatures of AVD, Genymotion, and generic x86 emulator images.
 */
public final class EmulatorDetector {

    private EmulatorDetector() {}

    public static boolean isLikelyEmulator() {
        return (Build.FINGERPRINT != null && (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.FINGERPRINT.contains("vbox")
                || Build.FINGERPRINT.contains("test-keys")))
                || (Build.MODEL != null && (Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MODEL.toLowerCase().contains("sdk_gphone")))
                || (Build.MANUFACTURER != null && Build.MANUFACTURER.contains("Genymotion"))
                || (Build.BRAND != null && Build.BRAND.startsWith("generic") && Build.DEVICE != null && Build.DEVICE.startsWith("generic"))
                || "goldfish".equals(Build.HARDWARE)
                || "ranchu".equals(Build.HARDWARE)
                || "vbox86".equals(Build.HARDWARE)
                || (Build.PRODUCT != null && (Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("vbox86p")))
                || (Build.BOARD != null && Build.BOARD.equalsIgnoreCase("QC_Reference_Phone"))
                || android.os.Build.HOST != null && android.os.Build.HOST.startsWith("Build");
    }
}
