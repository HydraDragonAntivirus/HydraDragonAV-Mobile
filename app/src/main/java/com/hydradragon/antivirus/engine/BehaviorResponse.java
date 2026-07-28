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

    /** @return true if the app was in the foreground and force-stop via accessibility was initiated */
    public static boolean killAndPromptUninstall(Context context, String pkg) {
        return killAndPromptUninstall(context, pkg, null, null, false);
    }

    public static boolean killAndPromptUninstall(Context context, String pkg, String appName, String reason) {
        return killAndPromptUninstall(context, pkg, appName, reason, false);
    }

    private static boolean isSystemApp(Context context, String pkg) {
        try {
            android.content.pm.ApplicationInfo ai = context.getPackageManager()
                .getApplicationInfo(pkg, 0);
            return (ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                || (ai.flags & android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean killAndPromptUninstall(Context context, String pkg, String appName, String reason, boolean skipUninstall) {
        if (pkg == null || pkg.isEmpty()) return false;

        boolean usedAccessibility = false;

        // forceStopForegroundApp navigates Settings -> App Info -> "Force
        // Stop" -> "OK" via accessibility automation. Despite its name, it
        // does NOT require pkg to be the current foreground app -- opening
        // ACTION_APPLICATION_DETAILS_SETTINGS works for any installed app,
        // running or not, foreground or background. That's why it's tried
        // before killBackgroundProcesses: it's the more thorough method
        // (Android 12+ restricts what killBackgroundProcesses can actually
        // kill), not a foreground-only special case.
        //
        // Its return value only tells us the Settings screen navigation
        // itself started -- the later steps (finding/clicking "Force Stop"
        // then "OK") happen asynchronously and can fail silently (wrong
        // locale text, OEM-specific Settings layout, dialog never showing).
        // We can't detect that synchronously, but we CAN detect it a few
        // seconds later: if the automation is still "pending" for this exact
        // package, it stalled, and killBackgroundProcesses is run as a
        // backup instead of trusting a stuck automation.
        if (com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(
                context, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.AUTO_KILL)
                && com.hydradragon.antivirus.service.DynamicAnalysisService.getInstance() != null) {
            Log.i(TAG, "killAndPromptUninstall: accessibility force-stop for " + pkg);
            usedAccessibility = com.hydradragon.antivirus.service.DynamicAnalysisService
                    .forceStopForegroundApp(pkg, appName, reason);
            if (!usedAccessibility) {
                Log.w(TAG, "killAndPromptUninstall: accessibility force-stop failed to start for " + pkg);
            } else {
                final String finalPkgForStallCheck = pkg;
                final Context appCtxForStallCheck = context.getApplicationContext();
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                    if (finalPkgForStallCheck.equals(
                            com.hydradragon.antivirus.service.DynamicAnalysisService.getPendingForceStopTarget())) {
                        Log.w(TAG, "killAndPromptUninstall: force-stop automation stalled for "
                                + finalPkgForStallCheck + " -> killBackgroundProcesses as backup");
                        try {
                            ActivityManager am = (ActivityManager)
                                appCtxForStallCheck.getSystemService(Context.ACTIVITY_SERVICE);
                            if (am != null) am.killBackgroundProcesses(finalPkgForStallCheck);
                        } catch (Throwable t) {
                            Log.w(TAG, "stalled-automation killBackgroundProcesses failed for "
                                    + finalPkgForStallCheck, t);
                        }
                    }
                }, 4000L);
            }
        }

        if (!usedAccessibility) {
            // Fallback: killBackgroundProcesses (unreliable on Android 12+,
            // but still the only non-root option when accessibility isn't
            // available or its automation failed to even start).
            try {
                ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                if (am != null) am.killBackgroundProcesses(pkg);
            } catch (Throwable t) {
                Log.w(TAG, "killBackgroundProcesses failed for " + pkg, t);
            }
        }

        if (!skipUninstall) {
            // Delay uninstall prompt slightly so the force-stop animation can
            // complete and the app is no longer in the foreground when the
            // system uninstall dialog appears.
            final String finalPkg = pkg;
            final Context appCtx = context.getApplicationContext();
            long delayMs = usedAccessibility ? 1500L : 0L;
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                try {
                    Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + finalPkg));
                    del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    appCtx.startActivity(del);
                } catch (Throwable t) {
                    Log.w(TAG, "uninstall prompt failed for " + finalPkg, t);
                }
            }, delayMs);
        }
        return usedAccessibility;
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
        boolean activeRunning = installed && isProcessRunning(context, pkg);

        if (isFromScan) {
            // For scan results: only trigger process kill / popup if the threat is ACTIVELY RUNNING right now
            if (activeRunning) {
                killAndPromptUninstall(context, pkg,
                    threat.getAppName(),
                    threat.getReasons().isEmpty() ? null : threat.getReasons().get(0),
                    true);
                showMalwareFoundScreen(context, threat, false, true);
            }
            // If the threat is passive / not running, let ScanFragment present it in the scan report.
            return;
        }

        // Real-time behavioral triggers (inherently active threats):
        if (installed) {
            killAndPromptUninstall(context, pkg,
                threat.getAppName(),
                threat.getReasons().isEmpty() ? null : threat.getReasons().get(0),
                true);
        }

        showMalwareFoundScreen(context, threat, !installed, isFromScan);
    }

    /** Best-effort "is this app currently active" check for gating the
     *  scan-result kill/alert path.
     *
     *  <p>The previous implementation used {@code
     *  ActivityManager#getRunningAppProcesses()}, which on API 22+ only
     *  returns the CALLING app's own process for a regular (non-privileged,
     *  non-system) app — it can never see another package's process. That
     *  made this method return {@code false} for every real threat, which
     *  silently disabled the scan-result kill+uninstall+alert-screen path
     *  entirely (every scan hit looked "passive" and was left for
     *  ScanFragment to just list).
     *
     *  <p>This uses the two real signals this app actually has:
     *  <ol>
     *    <li>{@link com.hydradragon.antivirus.service.DynamicAnalysisService
     *        #getForegroundPackage()} — live, accessibility-service-driven
     *        foreground tracking (the same source GuardService itself
     *        trusts elsewhere), when the accessibility service is on.</li>
     *    <li>{@link android.app.usage.UsageStatsManager}, over a short
     *        recent window, when the user has granted Usage Access — used
     *        as a fallback when accessibility isn't enabled.</li>
     *  </ol>
     *  Neither signal can prove a purely-background service (no foreground
     *  contact) is running — no non-root API can, for a third-party app.
     *  If NEITHER signal is available at all, we deliberately return
     *  {@code true} rather than {@code false}: for a security app, silently
     *  dropping a real, active threat is worse than one extra kill/alert
     *  attempt on an app that turns out to be idle. */
    public static boolean isProcessRunning(Context context, String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;

        try {
            String fg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
            if (fg != null && !fg.isEmpty()) {
                return pkg.equals(fg);
            }
        } catch (Throwable ignored) {}

        try {
            if (android.os.Build.VERSION.SDK_INT >= 22) {
                android.app.AppOpsManager appOps = (android.app.AppOpsManager)
                    context.getSystemService(Context.APP_OPS_SERVICE);
                if (appOps != null) {
                    int mode = appOps.checkOpNoThrow(
                        android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
                        android.os.Process.myUid(), context.getPackageName());
                    if (mode == android.app.AppOpsManager.MODE_ALLOWED) {
                        android.app.usage.UsageStatsManager usm = (android.app.usage.UsageStatsManager)
                            context.getSystemService(Context.USAGE_STATS_SERVICE);
                        if (usm != null) {
                            long now = System.currentTimeMillis();
                            java.util.List<android.app.usage.UsageStats> stats =
                                usm.queryUsageStats(
                                    android.app.usage.UsageStatsManager.INTERVAL_BEST,
                                    now - 5000, now);
                            if (stats != null) {
                                for (android.app.usage.UsageStats s : stats) {
                                    if (pkg.equals(s.getPackageName())) return true;
                                }
                                // Usage Access is granted and gave us a real
                                // (if short-window) answer, and pkg wasn't in
                                // it -- trust that answer.
                                return false;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // Neither accessibility foreground-tracking nor Usage Access is
        // available -- we genuinely can't tell. Fail open.
        Log.w(TAG, "isProcessRunning: no signal available for " + pkg + " -> assuming active");
        return true;
    }

    private static boolean hasScreenLockerReason(ThreatResult threat) {
        if (threat == null || threat.getReasons() == null) return false;
        for (String r : threat.getReasons()) {
            if (r == null) continue;
            String lower = r.toLowerCase();
            if (lower.contains("screen_locker") || lower.contains("screen locker") || lower.contains("kilitleyici") || lower.contains("overlay")) {
                return true;
            }
        }
        return false;
    }

    /** Full-screen "MALWARE FOUND" warning, launched over whatever app the
     *  user currently has in the foreground — the process kill has already
     *  fired but the uninstall/delete prompt waits for the user to tap the
     *  action button on this screen. MalwareFoundActivity is a regular
     *  Activity (not a system overlay), so no SYSTEM_ALERT_WINDOW is needed
     *  to launch it FROM A FOREGROUND CONTEXT. But most callers here (behaviour
     *  detectors, background scans) fire from a Service with nothing in the
     *  foreground, and on Android 10+ a background-context startActivity()
     *  without an exemption (e.g. SYSTEM_ALERT_WINDOW actually granted, not
     *  just declared) is typically blocked SILENTLY by the system — no
     *  exception is thrown, so a bare try/catch cannot detect the failure.
     *  That's why we check the real runtime permission state up front and
     *  only attempt startActivity when it's safe to assume it'll work; the
     *  try/catch below is a secondary safety net for other launch failures
     *  (e.g. FLAG_ACTIVITY_NEW_TASK edge cases), not the primary guard. */
    private static void showMalwareFoundScreen(Context context, ThreatResult threat, boolean isFile, boolean isFromScan) {
        if (!hasOverlayOrNotifPermission(context)) {
            // Overlay/notification permission missing: always redirect to scan screen
            // so the user still sees the uninstall/delete alert dialog there.
            Log.i(TAG, "Overlay or Notification permission missing -> redirecting to HydraDragon Scan Screen with threat alert");
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
                    threat.getReasons().isEmpty() ? "-" : String.join("\n", threat.getReasons()));
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
                open.putExtra("alert_threat_reason", threat.getReasons().isEmpty() ? "-" : String.join("\n", threat.getReasons()));
                open.putExtra("alert_threat_risk", threat.getRiskScore());
                open.putExtra("alert_threat_is_file", threat.isStandaloneFile());
                open.putExtra("alert_threat_path", threat.getApkPath());
            }
            context.startActivity(open);
        } catch (Throwable t) {
            Log.w(TAG, "redirectToScanScreen failed", t);
        }
    }

    /** Same as the background portion of {@link #killAndPromptUninstall} but
     *  without the foreground-force-stop path — used by {@link #autoDeleteThreat}
     *  which must be silent and cannot involve the accessibility navigation. */
    private static void killBackgroundOnly(Context context, String pkg) {
        if (pkg == null || pkg.isEmpty()) return;
        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) am.killBackgroundProcesses(pkg);
        } catch (Throwable t) {
            Log.w(TAG, "killBackgroundOnly failed for " + pkg, t);
        }
        try {
            Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + pkg));
            del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(del);
        } catch (Throwable t) {
            Log.w(TAG, "uninstall prompt (auto-delete) failed for " + pkg, t);
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
            killBackgroundOnly(context, pkg);
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
