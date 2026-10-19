package david.manager;

import android.content.Context;
import android.content.pm.PackageManager;
import java.io.File;

/**
 * Heuristic root detection. Not foolproof (nothing is), but raises the bar
 * against casual tampering/instrumentation on rooted devices.
 */
public final class RootDetector {

    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/su/bin/su", "/system/app/Superuser.apk", "/cache/su"
    };

    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
            "com.koushikdutta.superuser", "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine", "com.devadvance.rootcloak", "com.saurik.substrate"
    };

    private RootDetector() {}

    public static boolean isLikelyRooted(Context ctx) {
        return hasSuBinary() || hasRootPackages(ctx) || hasTestKeysBuild() || canExecuteSu();
    }

    private static boolean hasSuBinary() {
        for (String path : SU_PATHS) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private static boolean hasRootPackages(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return false;
    }

    private static boolean hasTestKeysBuild() {
        String tags = android.os.Build.TAGS;
        return tags != null && tags.contains("test-keys");
    }

    private static boolean canExecuteSu() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            return process.getInputStream().read() != -1;
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }
}
