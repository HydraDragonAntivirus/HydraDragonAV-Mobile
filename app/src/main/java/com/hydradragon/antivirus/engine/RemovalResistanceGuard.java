package com.hydradragon.antivirus.engine;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.util.HashMap;
import java.util.Map;

/**
 * Detects malware defending itself from removal: the device-admin
 * deactivation screen ("Deactivate this device admin app?") or the app-info
 * / uninstall confirmation screen for a package opens and then closes again
 * abnormally fast — faster than a human could read and decide — landing the
 * user right back on that same app. A real removal flow stays on screen for
 * seconds while the user reads it; a malicious app racing its own
 * AccessibilityService to slam GLOBAL_ACTION_BACK the instant that screen
 * appears is what produces a sub-1.5s open-close-return cycle instead.
 *
 * Reference: https://www.guardsquare.com/mobile-app-security-research-center/malware/behaviors/device-admin
 *
 * One occurrence could be a fumbled tap; repeated occurrences for the same
 * package within a few minutes is the "many times" pattern that means malware.
 */
public final class RemovalResistanceGuard {

    private static final String TAG = "HydraDragon-RemovalRes";

    /** Screen open -> gone-again faster than this is too fast for a human read+tap. */
    private static final long KICK_MAX_MS = 1_500;
    private static final long KICK_WINDOW_MS = 5L * 60L * 1000L; // 5 min
    private static final int KICK_THRESHOLD = 3;

    private static String pendingTarget = null;
    private static long pendingOpenedAt = 0;
    private static boolean pendingConfirmed = false;
    private static String pendingKind = "";

    /** package -> [windowStartMs, kickCount]. */
    private static final Map<String, long[]> kickBurst = new HashMap<>();

    private RemovalResistanceGuard() {}

    /** Called on every window switch. {@code prevPkg} is whoever was in the
     *  foreground just before this switch — the candidate "target" if the new
     *  window turns out to be a device-admin/uninstall screen. */
    public static synchronized void onWindowSwitch(Context c, String newPkg, String prevPkg,
                                                     boolean newIsSensitiveScreen) {
        if (!BehaviorDetectionSettings.isEnabled(c, BehaviorDetectionSettings.REMOVAL_RESISTANCE)) return;
        long now = System.currentTimeMillis();

        if (newIsSensitiveScreen) {
            if (prevPkg != null && !prevPkg.isEmpty() && !TrustedPackages.isTrusted(c, prevPkg)) {
                pendingTarget = prevPkg;
                pendingOpenedAt = now;
                pendingConfirmed = false;
                pendingKind = "";
            } else {
                pendingTarget = null;
            }
            return;
        }

        if (pendingTarget == null) return;
        long elapsed = now - pendingOpenedAt;
        if (pendingConfirmed && elapsed <= KICK_MAX_MS && pendingTarget.equals(newPkg)) {
            recordKick(c, pendingTarget, pendingKind);
        }
        pendingTarget = null;
        pendingConfirmed = false;
    }

    /** Called from the settings/installer node walk when on-screen text
     *  matches an uninstall or device-admin-deactivation prompt — confirms
     *  the currently pending screen (if any) is actually one of those,
     *  rather than just any fast Settings navigation. */
    public static synchronized void confirmSensitiveScreenText(String kind) {
        if (pendingTarget != null) {
            pendingConfirmed = true;
            pendingKind = kind;
        }
    }

    private static void recordKick(Context c, String pkg, String kind) {
        if (UserDecisions.isThreatAllowed(c, pkg)) return;
        long now = System.currentTimeMillis();
        long[] burst = kickBurst.get(pkg);
        if (burst == null || now - burst[0] > KICK_WINDOW_MS) {
            burst = new long[]{now, 1};
            kickBurst.put(pkg, burst);
        } else {
            burst[1]++;
        }
        HipsMonitor.reportRemovalResistance(pkg, (int) burst[1], kind, KICK_WINDOW_MS,
            burst[1] >= KICK_THRESHOLD);
        if (burst[1] < KICK_THRESHOLD) return;

        String reason = "Removal resistance: kicked the user off the " + kind
            + " screen " + burst[1] + "x within " + (KICK_WINDOW_MS / 60_000) + " min";
        Log.e(TAG, "REMOVAL RESISTANCE (" + pkg + "): " + reason);
        BehaviorFlags.flag(c, pkg, reason);
        com.hydradragon.antivirus.service.ThreatLogger.logThreat(c, pkg, pkg, reason);
        alert(c, pkg, reason);
        BehaviorResponse.killAndPromptUninstall(c, pkg);
        kickBurst.remove(pkg); // reset window after responding
    }

    private static void alert(Context context, String pkg, String reason) {
        if (!ProtectionState.isEnabled(context)) return;
        NotificationManager nm = context.getSystemService(NotificationManager.class);
        if (nm == null) return;
        String appName = pkg;
        try {
            appName = context.getPackageManager()
                .getApplicationLabel(context.getPackageManager().getApplicationInfo(pkg, 0)).toString();
        } catch (Throwable ignore) { }

        int id = 0x8A17_100 + (pkg.hashCode() & 0xFF);
        android.content.Intent ignoreIntent = new android.content.Intent(
                context, com.hydradragon.antivirus.service.UserActionReceiver.class)
            .setAction(com.hydradragon.antivirus.service.UserActionReceiver.ACTION_IGNORE)
            .putExtra(com.hydradragon.antivirus.service.UserActionReceiver.EXTRA_ID, pkg)
            .putExtra(com.hydradragon.antivirus.service.UserActionReceiver.EXTRA_NOTIF, id);
        android.app.PendingIntent ignorePi = android.app.PendingIntent.getBroadcast(
            context, pkg.hashCode(), ignoreIntent,
            android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT);

        Notification n = new NotificationCompat.Builder(context, "hydradragon_guard")
            .setSmallIcon(com.hydradragon.antivirus.R.drawable.ic_threat)
            .setContentTitle(context.getString(com.hydradragon.antivirus.R.string.removal_resistance_title))
            .setContentText(context.getString(com.hydradragon.antivirus.R.string.removal_resistance_msg, appName))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setColor(0xFF0000)
            .addAction(0, context.getString(com.hydradragon.antivirus.R.string.btn_ignore), ignorePi)
            .build();
        nm.notify(id, n);
    }
}
