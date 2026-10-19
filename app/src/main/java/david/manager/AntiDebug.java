package david.manager;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

/**
 * Lightweight anti-tampering checks: detects whether a debugger is attached
 * or the app was built/installed as debuggable. Use alongside IntegrityCheck
 * (signature verification) for layered protection.
 *
 * Usage, near the top of MainActivity.onCreate(), AFTER IntegrityCheck:
 *   AntiDebug.protect(this);
 */
public final class AntiDebug {

    private AntiDebug() {}

    /** True if a debugger is currently attached to this process. */
    public static boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    /** True if this build has android:debuggable="true" (should be false for release). */
    public static boolean isDebuggableBuild(Context ctx) {
        ApplicationInfo info = ctx.getApplicationInfo();
        return (info.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    /**
     * Call once at startup. In a release build, exits the app if a debugger
     * is attached. Does nothing on debuggable (development) builds, so your
     * normal dev workflow in Android Studio still works.
     */
    public static void protect(Context ctx) {
        if (isDebuggableBuild(ctx)) {
            // Development build — don't enforce, so you can still debug normally.
            return;
        }
        if (isDebuggerAttached()) {
            android.util.Log.e("AntiDebug", "Debugger detected on release build — exiting.");
            System.exit(0);
        }
    }

    /**
     * Optional: call periodically (e.g. from a background thread/handler) to catch
     * a debugger attached *after* startup, not just at launch.
     */
    public static void startWatcher(Context ctx, long intervalMs) {
        if (isDebuggableBuild(ctx)) return;
        new Thread(() -> {
            while (true) {
                if (isDebuggerAttached()) {
                    android.util.Log.e("AntiDebug", "Debugger attached mid-session — exiting.");
                    System.exit(0);
                }
                try { Thread.sleep(intervalMs); } catch (InterruptedException e) { return; }
            }
        }, "anti-debug-watcher").start();
    }
}
