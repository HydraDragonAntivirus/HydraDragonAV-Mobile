package com.hydradragon.antivirus.security;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.WindowManager;

/**
 * Applies the Guardsquare-recommended defenses for a sensitive screen (the
 * App Lock PIN entry, in this app):
 *
 * <ul>
 *   <li>{@link WindowManager.LayoutParams#FLAG_SECURE} — blocks screenshots,
 *       screen recording, and non-secure display mirroring/casting of this
 *       window.</li>
 *   <li>"Show taps" (developer option) detection — even WITH FLAG_SECURE, the
 *       system draws the show-taps touch indicator dot as a SEPARATE overlay
 *       that FLAG_SECURE does NOT hide, so a screen recording can still
 *       reveal approximate tap positions. There's no API to disable this
 *       setting from an app, so the caller is told to refuse/warn instead.</li>
 *   <li>Periodic FLAG_SECURE self-check — FLAG_SECURE can be stripped by
 *       runtime instrumentation (e.g. a Frida hook on
 *       {@code Window.setFlags}/{@code addFlags} that silently no-ops the
 *       call) without modifying the APK at all, so static tamper checks
 *       (signature/IntegrityCheck) wouldn't catch it. Re-reading the ACTUAL
 *       live window attributes periodically and comparing against what we
 *       expect catches that: if a hook suppressed our addFlags() call, the
 *       flag bit genuinely won't be set when we read it back here — this is
 *       reading real OS state, not a value the same hook already spoofed.
 *       Not foolproof (a sufficiently deep hook could also fake the readback
 *       API), but raises the bar past a simple flag-strip.</li>
 * </ul>
 */
public final class SecureWindowGuard {

    /** Callback invoked from the self-check loop if FLAG_SECURE is found to
     *  be missing when it should be set — treat this as a tamper signal. */
    public interface OnSecureFlagLost {
        void onSecureFlagLost();
    }

    private final Activity activity;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable selfCheck = this::checkSecureFlagStillSet;
    private OnSecureFlagLost callback;
    private boolean watching;
    private long intervalMs = 2000;

    public SecureWindowGuard(Activity activity) {
        this.activity = activity;
    }

    /** Apply FLAG_SECURE now. Call from onCreate, before setContentView. */
    public void applyFlagSecure() {
        activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }

    public void removeFlagSecure() {
        activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }

    /** True if "Show taps" (Settings > Developer options > Show taps) is on.
     *  FLAG_SECURE does not hide this system-drawn overlay, so the caller
     *  should refuse to display secret input (PIN pad) while it's enabled. */
    public static boolean isShowTapsEnabled(android.content.Context context) {
        try {
            return Settings.System.getInt(context.getContentResolver(), "show_touches") == 1;
        } catch (Settings.SettingNotFoundException e) {
            return false;
        }
    }

    /** Start polling every {@code intervalMs} to make sure FLAG_SECURE is
     *  still actually set on this window — see class javadoc for why this
     *  can catch a runtime-hook removal that static checks can't. */
    public void startWatching(OnSecureFlagLost cb, long intervalMs) {
        this.callback = cb;
        this.watching = true;
        handler.postDelayed(selfCheck, intervalMs);
    }

    public void stopWatching() {
        watching = false;
        handler.removeCallbacks(selfCheck);
    }

    private void checkSecureFlagStillSet() {
        if (!watching) return;
        int flags = activity.getWindow().getAttributes().flags;
        if ((flags & WindowManager.LayoutParams.FLAG_SECURE) == 0) {
            if (callback != null) callback.onSecureFlagLost();
            return; // don't reschedule past a detected tamper — caller decides what happens next
        }
        handler.postDelayed(selfCheck, 2000);
    }
}
