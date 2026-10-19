package david.manager;

import android.content.Context;
import dalvik.system.InMemoryDexClassLoader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Loads an AES-encrypted secondary dex at runtime instead of shipping it as
 * a plain classes*.dex — so a decompiler only ever sees this loader, not the
 * logic inside the encrypted dex, unless it also captures the key and
 * memory-dumps the process.
 *
 * ---- Required project changes (you need to set this up, not just drop this file in) ----
 * 1. Move the classes you want protected into a separate Gradle module,
 *    e.g. ":core" (com.android.library), that does NOT get merged into the
 *    app's primary dex. Keep MainActivity (and anything the manifest
 *    references directly) in :app, since the OS needs those classes
 *    available at normal class-load time.
 * 2. After building :core, locate its compiled classes.dex
 *    (build/intermediates/dex/release/.../classes.dex) and encrypt it with
 *    tools/encrypt_dex.py (included) to produce app/src/main/assets/core.enc.
 * 3. At runtime (e.g. in MainActivity.onCreate, after IntegrityCheck/AntiDebug),
 *    call DexProtector.loadProtectedClass(this, "core.enc", "david.manager.DataEngine")
 *    to get a Class<?> you can instantiate via reflection.
 *
 * This IS wired up: MainActivity loads DataEngine exactly this way (see
 * MainActivity.loadEngine()). app/src/core/java holds the protected classes;
 * tools/build.py compiles and dexes them separately, encrypts that dex to
 * app/src/main/assets/core.enc, and dexes app/src/main/java (the entry
 * points only) into the normal, unencrypted classes.dex.
 */
public final class DexProtector {

    // Must match the key used by tools/encrypt_dex.py. Replace both before real use,
    // and consider deriving this from something device/signature-specific instead
    // of a hardcoded constant for stronger protection.
    private static final String AES_KEY_HEX = "6b45548bbe17bc3460b9dc9b0d0939dbd3fcc8a65990bf7332c98b6cbf95ab7d";
    private static final int GCM_TAG_BITS = 128;

    private DexProtector() {}

    /**
     * Decrypts the named asset (AES-256-GCM: 12-byte nonce + ciphertext+tag)
     * and loads it with InMemoryDexClassLoader, then returns the requested class.
     */
    public static Class<?> loadProtectedClass(Context ctx, String assetName, String className) throws Exception {
        byte[] encrypted = readAsset(ctx, assetName);
        byte[] dexBytes = decrypt(encrypted);
        ClassLoader parent = ctx.getClassLoader();
        InMemoryDexClassLoader loader = new InMemoryDexClassLoader(ByteBuffer.wrap(dexBytes), parent);
        return loader.loadClass(className);
    }

    private static byte[] readAsset(Context ctx, String name) throws IOException {
        try (InputStream in = ctx.getAssets().open(name);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static byte[] decrypt(byte[] blob) throws Exception {
        if (blob.length < 13) throw new IllegalArgumentException("Encrypted dex blob too short");
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 0, nonce, 0, 12);
        byte[] ciphertext = new byte[blob.length - 12];
        System.arraycopy(blob, 12, ciphertext, 0, ciphertext.length);

        SecretKeySpec key = new SecretKeySpec(hexToBytes(AES_KEY_HEX), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(ciphertext);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
