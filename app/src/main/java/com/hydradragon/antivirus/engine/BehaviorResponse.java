package com.hydradragon.antivirus.engine;

import android.app.ActivityManager;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.service.UserActionReceiver;
import com.hydradragon.antivirus.ui.MalwareFoundActivity;

/**
 * Immediate-action response shared by EVERY behaviour-based detector in this
 * app (UI/notification spam, root exploit, dynamic risk score, ransomware
 * rename burst, file-trap hit) AND, via {@link #killAndPromptUninstall(Context,
 * ThreatResult)}, by every regular scan (background or manual) the instant it
 * finds something above {@link ThreatResult#isThreat()} — waiting for the user
 * to open HydraDragon and tap the threat is too slow once something has
 * already been flagged with real confidence; something may still be actively
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
 *
 * <p>A detection isn't always an installed app, though — a standalone file
 * (a bare .apk sitting on storage, or any other malicious file) has no
 * process to kill and no package to uninstall. {@link
 * #killAndPromptUninstall(Context, ThreatResult)} tells the two apart and
 * routes the file case to {@link #promptDeleteFile} instead.
 */
public final class BehaviorResponse {

    private static final String TAG = "HydraDragon-BehaviorResp";
    private static final String CHANNEL_ID = "hydradragon_guard";

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

    /** Entry point for a regular scan result (quick/full/custom, background or
     *  manual — anything past {@link ThreatResult#isThreat()}): kill + prompt
     *  uninstall for an installed app, or ask to delete for a standalone file
     *  that was never installed. Also throws up the full-screen "MALWARE
     *  FOUND" page (same local-WebView pattern BlockActivity uses for a
     *  malicious URL) on top of whatever the user is doing right now — the
     *  notification alone is easy to miss/swipe away without reading, and per
     *  the user this should be unmissable. Safe to call from a Service with
     *  no UI: SYSTEM_ALERT_WINDOW is already declared as the documented
     *  background-activity-start exemption (see AndroidManifest.xml). */
    public static void killAndPromptUninstall(Context context, ThreatResult threat) {
        killAndPromptUninstall(context, threat, false);
    }

    public static void killAndPromptUninstall(Context context, ThreatResult threat, boolean isFromScan) {
        if (threat == null) return;
        String pkg = threat.getPackageName();
        boolean installed = pkg != null && !pkg.isEmpty() && isPackageInstalled(context, pkg);
        if (installed) {
            killAndPromptUninstall(context, pkg);
        } else {
            promptDeleteFile(context, threat);
        }
        showMalwareFoundScreen(context, threat, !installed, isFromScan);
    }

    /** Full-screen "MALWARE FOUND" warning, launched over whatever app the
     *  user currently has in the foreground — the kill+uninstall (or
     *  delete-file prompt) has ALREADY fired by the time this shows; it's the
     *  unmissable backdrop, not a confirmation gate of its own. */
    private static void showMalwareFoundScreen(Context context, ThreatResult threat, boolean isFile, boolean isFromScan) {
        if (!hasOverlayOrNotifPermission(context)) {
            if (isFromScan) {
                return;
            }
            Log.i(TAG, "Overlay or Notification permission missing -> redirecting directly to HydraDragon Scan Screen with threat alert");
            redirectToScanScreen(context, threat);
            return;
        }
        try {
            Intent i = new Intent(context, MalwareFoundActivity.class);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP
                    | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            i.putExtra(MalwareFoundActivity.EXTRA_APP_NAME, threat.getAppName());
            i.putExtra(MalwareFoundActivity.EXTRA_RISK_SCORE, threat.getRiskScore());
            i.putExtra(MalwareFoundActivity.EXTRA_REASON,
                    threat.getReasons().isEmpty() ? "-" : threat.getReasons().get(0));
            i.putExtra(MalwareFoundActivity.EXTRA_IS_FILE, isFile);
            i.putExtra(MalwareFoundActivity.EXTRA_PACKAGE_NAME, threat.getPackageName());
            i.putExtra(MalwareFoundActivity.EXTRA_APK_PATH, threat.getApkPath());
            context.startActivity(i);
        } catch (Throwable t) {
            Log.w(TAG, "showMalwareFoundScreen failed -> redirecting to Scan Screen", t);
            redirectToScanScreen(context, threat);
        }
    }

    public static boolean hasOverlayOrNotifPermission(Context context) {
        boolean hasOverlay = true;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            hasOverlay = android.provider.Settings.canDrawOverlays(context);
        }
        boolean hasNotif = androidx.core.app.NotificationManagerCompat.from(context).areNotificationsEnabled();
        return hasOverlay && hasNotif;
    }

    private static void redirectToScanScreen(Context context, ThreatResult threat) {
        try {
            Intent open = new Intent(context, com.hydradragon.antivirus.MainActivity.class);
            open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            open.putExtra("open_scan_tab", true);
            if (threat != null) {
                open.putExtra("alert_threat_name", threat.getAppName());
                open.putExtra("alert_threat_pkg", threat.getPackageName());
                open.putExtra("alert_threat_reason", threat.getReasons().isEmpty() ? "-" : threat.getReasons().get(0));
                open.putExtra("alert_threat_risk", threat.getRiskScore());
                open.putExtra("alert_threat_is_file", threat.isStandaloneFile());
                open.putExtra("alert_threat_path", threat.getApkPath());
            }
            context.startActivity(open);
        } catch (Throwable t) {
            Log.w(TAG, "redirectToScanScreen failed", t);
        }
    }

    /** Entry point used when {@link AutoDeleteMalware} is on: removes the
     *  threat right away with no ask/notification step. An installed app
     *  still has to go through the system uninstall confirmation (auto-fired
     *  immediately, same as the ask path) since Android gives no third-party
     *  app a truly silent uninstall; a standalone file needs no such
     *  confirmation so it's deleted outright. No {@link #showMalwareFoundScreen}
     *  here — that screen exists to ask, and there's nothing left to ask once
     *  the removal has already happened. */
    public static void autoDeleteThreat(Context context, ThreatResult threat) {
        if (threat == null) return;
        String pkg = threat.getPackageName();
        boolean installed = pkg != null && !pkg.isEmpty() && isPackageInstalled(context, pkg);
        if (installed) {
            killAndPromptUninstall(context, pkg);
            com.hydradragon.antivirus.service.ThreatLogger.logThreat(context, threat,
                    "auto-delete: uninstall requested");
        } else {
            String path = threat.getApkPath();
            if (path != null && !path.isEmpty()) {
                try {
                    java.io.File f = new java.io.File(path);
                    boolean deleted = f.exists() && f.delete();
                    Log.i(TAG, "autoDeleteThreat: " + (deleted ? "deleted " : "failed to delete ") + path);
                } catch (Throwable t) {
                    Log.w(TAG, "autoDeleteThreat: delete failed for " + path, t);
                }
            }
            com.hydradragon.antivirus.service.ThreatLogger.logThreat(context, threat,
                    "auto-delete: file removed");
        }
    }

    private static boolean isPackageInstalled(Context context, String pkg) {
        try {
            context.getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Not an installed app — nothing to kill or uninstall, just a file on
     *  disk. Android has no "delete another app's file" API either, so this
     *  can only ASK: a high-priority notification with a Destroy action,
     *  wired through {@link UserActionReceiver} the same way a real-time
     *  malicious-download hit already asks (see GuardService#scanDownloadedFile). */
    private static void promptDeleteFile(Context context, ThreatResult threat) {
        String path = threat.getApkPath() != null ? threat.getApkPath() : threat.getPackageName();
        if (path == null || path.isEmpty()) return;
        try {
            NotificationManager nm = context.getSystemService(NotificationManager.class);
            if (nm == null) return;
            int notifId = (int) System.currentTimeMillis();

            Intent removeIntent = new Intent(context, UserActionReceiver.class)
                    .setAction(UserActionReceiver.ACTION_REMOVE_FILE)
                    .putExtra(UserActionReceiver.EXTRA_ID, path)
                    .putExtra(UserActionReceiver.EXTRA_NOTIF, notifId);
            PendingIntent removePI = PendingIntent.getBroadcast(context, notifId, removeIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            Intent ignoreIntent = new Intent(context, UserActionReceiver.class)
                    .setAction(UserActionReceiver.ACTION_IGNORE)
                    .putExtra(UserActionReceiver.EXTRA_ID, path)
                    .putExtra(UserActionReceiver.EXTRA_NOTIF, notifId);
            PendingIntent ignorePI = PendingIntent.getBroadcast(context, notifId + 1, ignoreIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            android.app.Notification notification = new NotificationCompat.Builder(context, CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_threat)
                    .setContentTitle(context.getString(R.string.malware_found_title))
                    .setContentText(threat.getAppName() + " — " + context.getString(R.string.btn_destroy_hint))
                    .setPriority(NotificationCompat.PRIORITY_MAX)
                    .setCategory(NotificationCompat.CATEGORY_ALARM)
                    .setAutoCancel(true)
                    .setColor(0xFF0040)
                    .addAction(0, context.getString(R.string.btn_destroy), removePI)
                    .addAction(0, context.getString(R.string.btn_ignore), ignorePI)
                    .build();
            nm.notify(notifId, notification);
        } catch (Throwable t) {
            Log.w(TAG, "promptDeleteFile failed for " + path, t);
        }
    }
}
