package com.hydradragon.antivirus.engine;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;

/**
 * Immediate-action response shared by EVERY behaviour-based detector in this
 * app (UI/notification spam, root exploit, dynamic risk score, ransomware
 * rename burst, file-trap hit) — waiting for the user to open HydraDragon and
 * find the threat on the next scan is too slow once a package has already
 * been flagged with real confidence; something may still be actively
 * happening right now.
 *
 * <p>Honest about what a regular (non-system, non-Device-Owner) app can
 * actually do here — there is NO API for a third-party app to force-stop or
 * silently uninstall another app:
 * <ul>
 *   <li>{@link ActivityManager#killBackgroundProcesses} DOES work immediately
 *       whenever the flagged app isn't the current foreground app (e.g. an
 *       encryption loop or spam service running in the background) — this is
 *       the common case and genuinely halts it right away.</li>
 *   <li>The system uninstall confirmation dialog ({@code Intent.ACTION_DELETE})
 *       is triggered immediately rather than waiting for a notification tap —
 *       the user still has to confirm it themselves (Android never allows a
 *       silent uninstall for a regular app), but they're prompted the instant
 *       this fires, not whenever they next happen to open the antivirus app.</li>
 * </ul>
 * If the flagged app IS currently in the foreground, neither of those stops
 * it mid-action — there's no way around that without root/Device Owner, which
 * this app deliberately doesn't require/use.
 */
public final class BehaviorResponse {

    private static final String TAG = "HydraDragon-BehaviorResp";

    private BehaviorResponse() {}

    public static void killAndPromptUninstall(Context context, String pkg) {
        if (pkg == null || pkg.isEmpty()) return;
        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) am.killBackgroundProcesses(pkg);
        } catch (Throwable t) {
            Log.w(TAG, "killBackgroundProcesses failed for " + pkg, t);
        }
        try {
            Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + pkg));
            del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(del);
        } catch (Throwable t) {
            Log.w(TAG, "uninstall prompt failed for " + pkg, t);
        }
    }
}
