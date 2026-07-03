package com.hydradragon.antivirus.engine;

import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dynamic (behavioural) ransomware detection — deliberately NOT based on any
 * hardcoded output extension (real ransomware families each invent their own,
 * e.g. ".locked", ".crypt", ".enc", a random string...), so this looks at the
 * SHAPE of the behaviour instead of a specific string:
 *
 * <ol>
 *   <li>An app is observed (via the accessibility service, which already
 *       tracks the foreground app on every screen change) transitioning from
 *       NOT having storage/file access to HAVING it — i.e. the user just
 *       granted it, on screen, moments ago.</li>
 *   <li>Shortly after that grant, files this app can reach start disappearing
 *       and being replaced by a same-named file with an EXTRA suffix tacked
 *       onto the end of the original name (whatever it is — "doc.pdf" becoming
 *       "doc.pdf.anything" is exactly what mass in-place encryption looks
 *       like from the filesystem's point of view, regardless of what
 *       "anything" is).</li>
 *   <li>That pattern repeats across enough distinct files in a short window
 *       to rule out a coincidence (a single renamed file proves nothing; a
 *       burst of them right after a permission grant does).</li>
 * </ol>
 *
 * Both conditions have to line up — a permission grant alone, or occasional
 * unrelated renames alone, are each far too common in legitimate apps (a file
 * manager, a backup tool, a photo editor) to mean anything by themselves.
 */
public final class RansomwareBehaviorGuard {

    private static final String TAG = "HydraDragon-Ransom";

    /** How long after a fresh file-access grant a rename burst still counts as
     *  caused by that grant, rather than unrelated later activity. */
    private static final long GRANT_WINDOW_MS = 15L * 60L * 1000L; // 15 min
    private static final long RENAME_BURST_WINDOW_MS = 60L * 1000L; // 1 min
    private static final int RENAME_BURST_THRESHOLD = 5;
    private static final int MAX_NAMES_PER_DIR = 500;

    /** Bit flags for {@link #storageState(Context, String)} — kept distinct so
     *  a fresh grant of "All files access" (MANAGE_EXTERNAL_STORAGE, which
     *  bypasses scoped storage entirely and is what real Android ransomware
     *  actually needs) can be told apart from the much more common, weaker
     *  READ/WRITE_EXTERNAL_STORAGE. */
    private static final int FLAG_READ_WRITE = 1;
    private static final int FLAG_ALL_FILES = 2;

    /** package -> last-observed state bitmask. Absent = never observed yet. */
    private static final Map<String, Integer> lastStorageState = new HashMap<>();
    private static final Map<String, Long> grantedAt = new HashMap<>();
    private static final Map<String, Boolean> grantWasAllFiles = new HashMap<>();
    /** dir path -> (file name -> first-seen time), bounded, oldest evicted. */
    private static final Map<String, LinkedHashMap<String, Long>> knownNamesByDir = new HashMap<>();
    /** package -> [windowStartMs, renameCount]. */
    private static final Map<String, long[]> renameBurst = new HashMap<>();
    private static final Map<String, String> sampleExt = new HashMap<>();
    private static final AtomicInteger notifId = new AtomicInteger(0x8A17_000);

    private RansomwareBehaviorGuard() {}

    /** Called by DynamicAnalysisService on every foreground-window change —
     *  cheap (a couple of PackageManager/AppOpsManager checks) compared to the
     *  UI-tree walk that already happens on the same event. Only a state
     *  CHANGE after we've already seen a baseline for this package counts as
     *  a fresh grant — the very first observation just records whatever the
     *  app already had (which could be an install-time grant from long ago,
     *  not something the user just approved on screen), so it is deliberately
     *  NOT treated as "recent". */
    public static synchronized void onForegroundPermissionCheck(Context c, String pkg) {
        if (!BehaviorDetectionSettings.isEnabled(c, BehaviorDetectionSettings.RANSOMWARE)) return;
        if (pkg == null || pkg.isEmpty()) return;
        int state = storageState(c, pkg);
        Integer prev = lastStorageState.put(pkg, state);
        if (prev == null) return; // first-ever observation: baseline only, not a "grant"
        boolean newlyGranted = state != 0 && (prev & state) != state; // gained a bit it didn't have
        if (newlyGranted) {
            grantedAt.put(pkg, System.currentTimeMillis());
            boolean isAllFiles = (state & FLAG_ALL_FILES) != 0 && (prev & FLAG_ALL_FILES) == 0;
            grantWasAllFiles.put(pkg, isAllFiles);
            Log.d(TAG, (isAllFiles ? "All-files-access" : "File-access") + " grant observed for " + pkg);
            if (isAllFiles) {
                FileCanaryGuard.maybeDeployFor(c, pkg);
            }
        }
    }

    private static int storageState(Context c, String pkg) {
        int state = 0;
        try {
            PackageManager pm = c.getPackageManager();
            if (pm.checkPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE, pkg)
                    == PackageManager.PERMISSION_GRANTED
                || pm.checkPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE, pkg)
                    == PackageManager.PERMISSION_GRANTED) {
                state |= FLAG_READ_WRITE;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                AppOpsManager aom = c.getSystemService(AppOpsManager.class);
                if (aom != null) {
                    int uid = pm.getPackageUid(pkg, 0);
                    int mode = aom.unsafeCheckOpNoThrow(
                        "android:manage_external_storage", uid, pkg);
                    if (mode == AppOpsManager.MODE_ALLOWED) state |= FLAG_ALL_FILES;
                }
            }
        } catch (Throwable ignore) { }
        return state;
    }

    /** Called for every file created/finalized in a watched directory (see
     *  GuardService's Downloads/full-storage FileObservers). */
    public static synchronized void onFileEvent(Context c, String dirPath, String fileName) {
        if (!BehaviorDetectionSettings.isEnabled(c, BehaviorDetectionSettings.RANSOMWARE)) return;
        if (dirPath == null || fileName == null || fileName.isEmpty()) return;

        LinkedHashMap<String, Long> known = knownNamesByDir.get(dirPath);
        if (known == null) {
            known = new LinkedHashMap<>();
            knownNamesByDir.put(dirPath, known);
        }

        // Is this new name just an EARLIER known file with something appended
        // to the end of it? ("report.pdf" -> "report.pdf.xyz") — the shape of
        // mass in-place file encryption, whatever the appended text actually is.
        String matchedBase = null;
        for (String existing : known.keySet()) {
            if (!existing.equals(fileName) && fileName.startsWith(existing + ".")) {
                matchedBase = existing;
                break;
            }
        }

        if (!known.containsKey(fileName)) {
            if (known.size() >= MAX_NAMES_PER_DIR) {
                Iterator<String> it = known.keySet().iterator();
                if (it.hasNext()) { it.next(); it.remove(); }
            }
            known.put(fileName, System.currentTimeMillis());
        }
        if (matchedBase == null) return;

        String pkg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
        Long grantTime = (pkg == null || pkg.isEmpty()) ? null : grantedAt.get(pkg);
        if (grantTime == null || System.currentTimeMillis() - grantTime > GRANT_WINDOW_MS) {
            return; // no recent on-screen file-access grant to pin this on
        }
        if (BehaviorFlags.isFlagged(c, pkg)) return;
        if (TrustedPackages.isTrusted(c, pkg)) return; // never flag Google/OEM/system apps
        if (UserDecisions.isThreatAllowed(c, pkg)) return; // user already said "safe, ignore"

        String appendedSuffix = fileName.substring(matchedBase.length()); // e.g. ".locked"
        long now = System.currentTimeMillis();
        long[] burst = renameBurst.get(pkg);
        if (burst == null || now - burst[0] > RENAME_BURST_WINDOW_MS) {
            renameBurst.put(pkg, new long[]{now, 1});
            sampleExt.put(pkg, appendedSuffix);
            return;
        }
        burst[1]++;
        if (burst[1] < RENAME_BURST_THRESHOLD) return;

        boolean wasAllFiles = Boolean.TRUE.equals(grantWasAllFiles.get(pkg));
        String reason = "Ransomware behaviour: " + burst[1]
            + " files renamed with an appended suffix (\"" + sampleExt.get(pkg)
            + "\") within " + (RENAME_BURST_WINDOW_MS / 1000)
            + "s of this app being granted " + (wasAllFiles ? "All Files Access" : "file access");
        Log.e(TAG, "RANSOMWARE BEHAVIOUR (" + pkg + "): " + reason);
        BehaviorFlags.flag(c, pkg, reason);
        com.hydradragon.antivirus.service.ThreatLogger.logThreat(c, pkg, pkg, reason);
        alert(c, pkg);
        BehaviorResponse.killAndPromptUninstall(c, pkg);
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
            .setContentTitle(context.getString(com.hydradragon.antivirus.R.string.ransomware_behavior_title))
            .setContentText(context.getString(com.hydradragon.antivirus.R.string.ransomware_behavior_msg, appName))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setColor(0xFF0000)
            .addAction(0, context.getString(com.hydradragon.antivirus.R.string.btn_ignore), ignorePi)
            .build();
        nm.notify(id, n);
    }
}
