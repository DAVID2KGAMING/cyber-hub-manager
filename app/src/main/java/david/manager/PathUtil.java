package david.manager;

import java.io.File;
import java.io.IOException;

/**
 * Entry-point-safe duplicate of FileOps.child(). FileOps itself lives in the
 * dex-encrypted :core module now, so the couple of call sites in :app that
 * still need a safe single-segment child path keep this tiny copy instead of
 * reaching across the reflection boundary for one two-line check.
 */
final class PathUtil {
    private PathUtil() {}

    static File child(File parent, String name) throws IOException {
        if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0)
            throw new IOException("Enter a single file or folder name");
        File f = new File(parent, name);
        if (!f.getCanonicalFile().getParentFile().equals(parent.getCanonicalFile())) throw new IOException("Invalid path");
        return f;
    }
}
