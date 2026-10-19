package david.manager;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Keeps sensitive string constants (API keys, internal URLs, tokens) out of
 * the plain strings table, so they don't show up in a quick `strings`/jadx
 * scan of the APK. This is obfuscation, not real encryption — it raises the
 * bar against casual inspection, not a determined attacker with a debugger.
 *
 * ---- How to obfuscate a new secret ----
 * 1. Run SecretObfuscator.encode("your-secret-value") once (e.g. from a throwaway
 *    main() or unit test) to get the obfuscated Base64 string.
 * 2. Paste that Base64 string into your code instead of the plaintext secret.
 * 3. At runtime, call SecretObfuscator.decode("...") to get the real value back.
 *
 * Example:
 *   private static final String API_KEY = SecretObfuscator.decode("EgEIBQcLBw==");
 */
public final class SecretObfuscator {

    // Change this to your own value before using in a real project.
    private static final byte[] KEY = "CyberHub-Manager-2026!".getBytes(StandardCharsets.UTF_8);

    private SecretObfuscator() {}

    /** Obfuscate a plaintext secret into a Base64 string to embed in source. */
    public static String encode(String plaintext) {
        byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] out = xor(input);
        return Base64.getEncoder().encodeToString(out);
    }

    /** Recover the original secret from an obfuscated Base64 string. */
    public static String decode(String obfuscatedBase64) {
        byte[] input = Base64.getDecoder().decode(obfuscatedBase64);
        byte[] out = xor(input);
        return new String(out, StandardCharsets.UTF_8);
    }

    private static byte[] xor(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ KEY[i % KEY.length]);
        }
        return out;
    }
}
