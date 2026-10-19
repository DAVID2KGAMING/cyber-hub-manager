package david.manager;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import java.security.MessageDigest;

/**
 * Verifies the app was signed with your release key and hasn't been
 * repackaged/re-signed by someone else.
 *
 * Usage:
 *   1. Build a release APK once, note the SHA-256 it prints (see getSigningCertSha256),
 *      and hardcode that value into EXPECTED_SHA256 below.
 *   2. Call IntegrityCheck.verifyOrExit(this) early in MainActivity.onCreate().
 */
public final class IntegrityCheck {

    // TODO: replace with your real release-key SHA-256 (uppercase hex, no colons)
    private static final String EXPECTED_SHA256 = "PUT_YOUR_RELEASE_CERT_SHA256_HERE";

    private IntegrityCheck() {}

    public static boolean isSignatureValid(Context ctx) {
        String actual = getSigningCertSha256(ctx);
        return actual != null && actual.equalsIgnoreCase(EXPECTED_SHA256);
    }

    /** Call this near the top of onCreate(); exits the app if the signature doesn't match. */
    public static void verifyOrExit(Context ctx) {
        if (EXPECTED_SHA256.startsWith("PUT_YOUR")) {
            // Not configured yet — skip enforcement so debug builds keep working.
            return;
        }
        if (!isSignatureValid(ctx)) {
            android.util.Log.e("IntegrityCheck", "Signature mismatch — refusing to run.");
            System.exit(0);
        }
    }

    @SuppressWarnings("deprecation")
    public static String getSigningCertSha256(Context ctx) {
        try {
            PackageInfo info;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info = ctx.getPackageManager().getPackageInfo(
                        ctx.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] sigs = info.signingInfo.hasMultipleSigners()
                        ? info.signingInfo.getApkContentsSigners()
                        : info.signingInfo.getSigningCertificateHistory();
                return sha256Hex(sigs[0].toByteArray());
            } else {
                info = ctx.getPackageManager().getPackageInfo(
                        ctx.getPackageName(), PackageManager.GET_SIGNATURES);
                return sha256Hex(info.signatures[0].toByteArray());
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
