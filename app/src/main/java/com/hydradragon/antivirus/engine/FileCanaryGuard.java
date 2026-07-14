package com.hydradragon.antivirus.engine;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * File-trap (canary) ransomware detection. Complements
 * {@link RansomwareBehaviorGuard}'s statistical rename-burst heuristic with
 * something that needs no statistics at all: a decoy file NO legitimate app
 * has any reason to ever touch. If it gets renamed with an appended suffix
 * (the same in-place-encryption shape RansomwareBehaviorGuard already looks
 * for) or its content changes, that alone is proof — not a pattern that
 * merely looks suspicious.
 *
 * <h3>When traps are deployed</h3>
 * Only when ALL of the following line up (see
 * {@link #maybeDeployFor(Context, String)}, called from
 * {@link RansomwareBehaviorGuard#onForegroundPermissionCheck}):
 * <ul>
 *   <li>the app was JUST granted "All Files Access" on screen (not one it's
 *       had since some earlier session);</li>
 *   <li>it's genuinely unknown — not a trusted (Google/OEM/system) package,
 *       not already behaviour-flagged, not user-allowlisted;</li>
 *   <li>it was installed recently (within {@link #FRESH_INSTALL_WINDOW_MS}) —
 *       an app the user has had and used safely for a long time granting
 *       this permission is a far weaker signal than a just-downloaded,
 *       never-vetted APK doing it moments after install.</li>
 * </ul>
 * A long-installed, already-trusted app never gets a trap dropped into its
 * user's file browser — this is deliberately narrow to avoid the exact
 * "confusing clutter" problem the traps would otherwise cause.
 *
 * <h3>Why the filename matters</h3>
 * Ransomware typically encrypts a directory listing in the order the
 * filesystem/API returns it, which is usually alphabetical. A canary named
 * to sort first (see {@link #CANARY_NAME}) is therefore one of the FIRST
 * files touched — catching the attack after a single file, not after real
 * user photos/documents are already gone — while its content is ordinary
 * enough (plain prose, not obviously a trap) that opening it doesn't tip
 * off the malware author either.
 *
 * <h3>Temporary by design</h3>
 * Traps are deleted after {@link #TRAP_LIFETIME_MS} regardless of outcome —
 * see {@link #scheduleCleanup}. Leaving them indefinitely would eventually
 * confuse the user ("what's this weird file in my Downloads?"); the window
 * only needs to cover the period where a freshly-installed, freshly-granted
 * app would actually act, not the app's entire lifetime.
 */
public final class FileCanaryGuard {

    private static final String TAG = "HydraDragon-Canary";
    private static final String PREFS = "hydra_canary";

    /** Sorts before virtually every real user filename (digit, then
     *  uppercase) in a typical alphabetical directory listing, while still
     *  reading as an ordinary "please don't touch this" file rather than an
     *  obvious trap. */
    private static final String CANARY_NAME = "0000_Important_Do_Not_Delete.txt";

    private static final long FRESH_INSTALL_WINDOW_MS = 24L * 60L * 60L * 1000L; // 24h
    private static final long TRAP_LIFETIME_MS = 24L * 60L * 60L * 1000L; // 24h
    private static final AtomicInteger notifId = new AtomicInteger(0xCA1A_000);

    /** canary file path -> its original (fake) content, so tampering can be
     *  told apart from a clean, still-present file. */
    private static final Map<String, byte[]> deployed = new HashMap<>();
    private static final List<FileObserver> observers = new ArrayList<>();
    private static final Handler handler = new Handler(Looper.getMainLooper());
    private static volatile boolean cleanupScheduled = false;

    private FileCanaryGuard() {}

    private static File[] targetDirs() {
        return new File[]{
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
        };
    }

    /** Called by RansomwareBehaviorGuard right after it observes a fresh
     *  "All Files Access" grant. Cheap to call unconditionally — every gate
     *  below is a quick check, and deployment itself is a handful of small
     *  file writes done at most once per suspect package. */
    public static synchronized void maybeDeployFor(Context c, String pkg) {
        if (!BehaviorDetectionSettings.isEnabled(c, BehaviorDetectionSettings.FILE_CANARY)) return;
        if (pkg == null || pkg.isEmpty()) return;
        if (BehaviorFlags.isFlagged(c, pkg)) return;
        if (TrustedPackages.isTrusted(c, pkg)) return;
        if (UserDecisions.isThreatAllowed(c, pkg)) return;
        if (!deployed.isEmpty() && prefs(c).getString("deployed_for", "").equals(pkg)) {
            return; // already have live traps out for this exact package
        }
        if (!isFreshInstall(c, pkg)) return;

        deploy(c, pkg);
    }

    private static boolean isFreshInstall(Context c, String pkg) {
        try {
            PackageInfo info = c.getPackageManager().getPackageInfo(pkg, 0);
            long age = System.currentTimeMillis() - info.firstInstallTime;
            return age >= 0 && age < FRESH_INSTALL_WINDOW_MS;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void deploy(Context c, String pkg) {
        byte[] content = fakeContent();
        int count = 0;
        for (File dir : targetDirs()) {
            if (dir == null || (!dir.exists() && !dir.mkdirs())) continue;
            File trap = new File(dir, CANARY_NAME);
            try (FileOutputStream out = new FileOutputStream(trap)) {
                out.write(content);
                deployed.put(trap.getAbsolutePath(), content);
                watchDir(c, dir, pkg);
                count++;
            } catch (Throwable t) {
                Log.w(TAG, "canary write failed: " + trap, t);
            }
        }
        if (count == 0) return;
        prefs(c).edit()
            .putString("deployed_for", pkg)
            .putLong("deployed_at", System.currentTimeMillis())
            .apply();
        Log.i(TAG, "Deployed " + count + " file trap(s) for suspect " + pkg);
        scheduleCleanup(c);
    }

    private static void watchDir(Context context, File dir, String suspectPkg) {
        int mask = FileObserver.MOVED_TO | FileObserver.CLOSE_WRITE | FileObserver.DELETE;
        FileObserver obs;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            obs = new FileObserver(dir, mask) {
                @Override
                public void onEvent(int event, String path) {
                    if (path == null) return;
                    onCanaryDirEvent(context, dir, event, path, suspectPkg);
                }
            };
        } else {
            obs = new FileObserver(dir.getAbsolutePath(), mask) {
                @Override
                public void onEvent(int event, String path) {
                    if (path == null) return;
                    onCanaryDirEvent(context, dir, event, path, suspectPkg);
                }
            };
        }
        try {
            obs.startWatching();
            observers.add(obs);
        } catch (Throwable ignore) { }
    }

    private static synchronized void onCanaryDirEvent(Context c, File dir, int event, String path, String suspectPkg) {
        File trapFile = new File(dir, CANARY_NAME);
        String trapPath = trapFile.getAbsolutePath();
        byte[] original = deployed.get(trapPath);
        if (original == null) return; // not (or no longer) a live trap in this dir

        boolean tampered = false;
        String detail;
        if (path.equals(CANARY_NAME)) {
            // The canary's own name: DELETE (removed outright, e.g. wiped and
            // replaced) or CLOSE_WRITE with different bytes (encrypted in
            // place, name kept) both count.
            if ((event & FileObserver.DELETE) != 0 && !trapFile.exists()) {
                tampered = true;
                detail = "the file trap was deleted";
            } else if (trapFile.exists() && !contentMatches(trapFile, original)) {
                tampered = true;
                detail = "the file trap's content was modified";
            } else {
                return;
            }
        } else if (path.startsWith(CANARY_NAME + ".")) {
            // Renamed with an appended suffix — in-place encryption's exact
            // shape, same as RansomwareBehaviorGuard's general heuristic, but
            // here on a file that had NO legitimate reason to be touched at
            // all, so one hit alone is already conclusive.
            tampered = true;
            detail = "the file trap was renamed to \"" + path + "\"";
        } else {
            return;
        }

        // Attribute to whichever app is actually in the foreground right now
        // (the real-time signal), falling back to the package we deployed
        // this trap for if that's unavailable.
        String fg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
        String pkg = (fg != null && !fg.isEmpty()) ? fg : suspectPkg;
        if (pkg == null || pkg.isEmpty()) pkg = suspectPkg;
        if (TrustedPackages.isTrusted(c, pkg) || UserDecisions.isThreatAllowed(c, pkg)) return;

        String reason = "Ransomware behaviour (file trap): " + detail
            + " — no legitimate app has any reason to touch this file";
        Log.e(TAG, "FILE TRAP TRIGGERED (" + pkg + "): " + reason);
        BehaviorFlags.flag(c, pkg, reason);
        HipsMonitor.reportCanary(pkg, true);
        com.hydradragon.antivirus.service.ThreatLogger.logThreat(c, pkg, pkg, reason);
        alert(c, pkg);
        BehaviorResponse.killAndPromptUninstall(c, pkg);

        // The trap did its job — remove all of them now rather than waiting
        // out the full lifetime, and stop watching.
        cleanupNow(c);
    }

    private static boolean contentMatches(File file, byte[] expected) {
        try {
            byte[] actual = java.nio.file.Files.readAllBytes(file.toPath());
            return java.util.Arrays.equals(actual, expected);
        } catch (Throwable t) {
            return false; // unreadable is itself a change worth flagging as tampering
        }
    }

    private static void scheduleCleanup(Context context) {
        if (cleanupScheduled) return;
        cleanupScheduled = true;
        handler.postDelayed(() -> cleanupNow(context), TRAP_LIFETIME_MS);
    }

    /** Deletes every deployed trap, stops watching, and clears state — called
     *  either once the lifetime window elapses or immediately after a trap
     *  actually fires (no point leaving the rest out at that point). */
    private static synchronized void cleanupNow(Context context) {
        for (String path : deployed.keySet()) {
            try {
                new File(path).delete();
            } catch (Throwable ignore) { }
        }
        deployed.clear();
        for (FileObserver obs : observers) {
            try { obs.stopWatching(); } catch (Throwable ignore) { }
        }
        observers.clear();
        cleanupScheduled = false;
        prefs(context).edit().clear().apply();
        Log.i(TAG, "File traps cleaned up");
    }

    private static byte[] fakeContent() {
        String text = "Personal Notes\n\n"
            + "- Remember to renew the car insurance next month.\n"
            + "- Dentist appointment moved to Thursday afternoon.\n"
            + "- Ask about the wifi router warranty before it expires.\n"
            + "- Grocery list is on the fridge, don't forget the milk.\n"
            + "- Call back about the electricity bill discrepancy.\n";
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static android.content.SharedPreferences prefs(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static void alert(Context context, String pkg) {
        if (!ProtectionState.isEnabled(context)) return;
        NotificationManager nm = context.getSystemService(NotificationManager.class);
        if (nm == null) return;
        String appName = pkg;
        try {
            appName = context.getPackageManager()
                .getApplicationLabel(context.getPackageManager().getApplicationInfo(pkg, 0)).toString();
        } catch (Throwable ignore) { }

        int id = notifId.incrementAndGet();
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
            .setContentTitle(context.getString(com.hydradragon.antivirus.R.string.file_trap_title))
            .setContentText(context.getString(com.hydradragon.antivirus.R.string.file_trap_msg, appName))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setColor(0xFF0000)
            .addAction(0, context.getString(com.hydradragon.antivirus.R.string.btn_ignore), ignorePi)
            .build();
        nm.notify(id, n);
    }
}
