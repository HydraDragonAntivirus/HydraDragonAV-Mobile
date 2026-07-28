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
 * <h3>Multi-sensor fusion</h3>
 * Three independent sensors are combined, and the rename-burst threshold
 * drops as more of them agree:
 * <ul>
 *   <li><b>Memory pressure</b> — {@link MemoryMonitor} reads
 *       {@code /proc/meminfo}; low available RAM during file churn matches
 *       the profile of holding plaintext + ciphertext in memory during
 *       encryption (+2 to threshold drop).</li>
 *   <li><b>File entropy</b> — {@link FileEntropy} computes Shannon entropy
 *       of the new (presumably encrypted) file; values above 7.5 indicate
 *       encrypted or compressed content (+1 to threshold drop).</li>
 *   <li><b>Rename-suffix pattern</b> — always required as the base signal
 *       (no drop without it).</li>
 * </ul>
 */
public final class RansomwareBehaviorGuard {

    private static final String TAG = "HydraDragon-Ransom";

    /** How long after a fresh file-access grant a rename burst still counts as
     *  caused by that grant, rather than unrelated later activity. */
    private static final long GRANT_WINDOW_MS = 15L * 60L * 1000L; // 15 min
    private static final long RENAME_BURST_WINDOW_MS = 60L * 1000L; // 1 min
    /** Base rename burst threshold.  Lowered dynamically by {@link
     *  #effectiveThreshold(boolean)} when memory pressure and/or high file
     *  entropy are observed. */
    private static final int RENAME_BURST_THRESHOLD = 5;
    private static final int MAX_NAMES_PER_DIR = 500;

    /** Bit flags for {@link #storageState(Context, String)} — kept distinct so
     *  a fresh grant of "All files access" (MANAGE_EXTERNAL_STORAGE, which
     *  bypasses scoped storage entirely and is what real Android ransomware
     *  actually needs) can be told apart from the much more common, weaker
     *  READ/WRITE_EXTERNAL_STORAGE. */
    private static final int FLAG_READ_WRITE = 1;
    private static final int FLAG_ALL_FILES = 2;

    // ── File creation / copy detection ─────────────────────────────────────
    private static final long FILE_CREATE_WINDOW_MS = 60_000L;
    private static final int FILE_CREATE_BURST_THRESHOLD = 5;
    /** package -> [windowStartMs, createCount]. */
    private static final Map<String, long[]> fileCreateBurst = new HashMap<>();
    private static final double COPY_SIZE_TOLERANCE = 0.15; // 15% size tolerance for copy correlation

    /** package -> last-observed state bitmask. Absent = never observed yet. */
    private static final Map<String, Integer> lastStorageState = new HashMap<>();
    private static final Map<String, Long> grantedAt = new HashMap<>();
    private static final Map<String, Boolean> grantWasAllFiles = new HashMap<>();
    /** dir path -> (file name -> first-seen time), bounded, oldest evicted. */
    private static final Map<String, LinkedHashMap<String, Long>> knownNamesByDir = new HashMap<>();
    /** package -> [windowStartMs, renameCount]. */
    private static final Map<String, long[]> renameBurst = new HashMap<>();
    private static final Map<String, String> sampleExt = new HashMap<>();

    // ── Wiper detection ──────────────────────────────────────────────────
    private static final long DELETION_WINDOW_MS = 60_000L;
    private static final int DELETION_BURST_THRESHOLD = 10;
    /** dir path -> last snapshot of filenames (for deletion detection). */
    private static final Map<String, java.util.HashSet<String>> dirSnapshots = new HashMap<>();
    /** dir path -> [windowStartMs, deleteCount, lastFlaggedPkg]. */
    private static final Map<String, Object[]> deletionBurst = new HashMap<>();

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

    /** Returns the effective rename-burst threshold for the current memory
     *  pressure, file-entropy state, and per-process memory.
     *
     *  <ul>
     *    <li>System memory pressure alone → {@code RENAME_BURST_THRESHOLD - 2} (3).</li>
     *    <li>High file entropy alone → {@code RENAME_BURST_THRESHOLD - 1} (4).</li>
     *    <li>Both → {@code RENAME_BURST_THRESHOLD - 3} (2).</li>
     *    <li>Per-process high memory (&gt;64MB) + entropy → {@code RENAME_BURST_THRESHOLD - 2} (3).</li>
     *    <li>Per-process high memory + system pressure → {@code RENAME_BURST_THRESHOLD - 3} (2).</li>
     *    <li>All three → {@code RENAME_BURST_THRESHOLD - 4} (1).</li>
     *    <li>Neither → {@code RENAME_BURST_THRESHOLD} (5).</li>
     *  </ul> */
    private static int effectiveThreshold(boolean highEntropy, boolean highProcMemory) {
        int drop = 0;
        if (MemoryMonitor.isUnderHighPressure()) drop += 2;
        if (highEntropy) drop += 1;
        if (highProcMemory) drop += 1;
        return Math.max(RENAME_BURST_THRESHOLD - drop, 1);
    }

    /** Called for every file created/finalized in a watched directory (see
     *  GuardService's Downloads/full-storage FileObservers).
     *
     *  <p>Three sensors are fused here:
     *  <ol>
     *    <li><b>Rename-suffix pattern</b> — a file replaced by one with an
     *        extra appended extension ({@code .pdf} &rarr; {@code .pdf.xyz}),
     *        which is the hallmark of in-place encryption.</li>
     *    <li><b>Memory pressure</b> — low available RAM during file churn
     *        is consistent with holding plaintext + ciphertext in memory
     *        during encryption.</li>
     *    <li><b>File entropy</b> — encrypted content has near-maximum Shannon
     *        entropy ({@code > 7.5}); plaintext and structured binaries score
     *        much lower.</li>
     *  </ol>
     *  The rename-burst threshold required to trigger an alert drops as more
     *  sensors agree. */
    public static synchronized void onFileEvent(Context c, String dirPath, String fileName) {
        if (dirPath == null || fileName == null || fileName.isEmpty()) return;

        // ── FILE_CREATED / FILE_COPY tracking (always runs, no RANSOMWARE gate) ──
        String pkg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();

        // Check whether the observed dir is already known
        LinkedHashMap<String, Long> known = knownNamesByDir.get(dirPath);
        if (known == null) {
            known = new LinkedHashMap<>();
            knownNamesByDir.put(dirPath, known);
        }
        boolean isNew = !known.containsKey(fileName);
        if (isNew) {
            if (known.size() >= MAX_NAMES_PER_DIR) {
                Iterator<String> it = known.keySet().iterator();
                if (it.hasNext()) { it.next(); it.remove(); }
            }
            known.put(fileName, System.currentTimeMillis());

            if (pkg != null && !pkg.isEmpty()) {
                long now = System.currentTimeMillis();
                long[] burst = fileCreateBurst.get(pkg);
                int createCount;
                if (burst == null || now - burst[0] > FILE_CREATE_WINDOW_MS) {
                    fileCreateBurst.put(pkg, new long[]{now, 1});
                    createCount = 1;
                } else {
                    burst[1]++;
                    createCount = (int) burst[1];
                }
                if (createCount >= FILE_CREATE_BURST_THRESHOLD) {
                    HipsMonitor.addBehaviorFlag(pkg, "FILE_CREATED_BURST:" + createCount);
                }
                HipsMonitor.addBehaviorFlag(pkg,
                    String.format("FILE_CREATED:path=%s:size=%d",
                        fileName, new java.io.File(dirPath, fileName).length()));

                java.util.List<FileReadEstimator.RecentRead> reads =
                    FileReadEstimator.getRecentReadsByPackage(pkg);
                java.io.File newFile = new java.io.File(dirPath, fileName);
                long newSize = newFile.exists() ? newFile.length() : 0;
                for (FileReadEstimator.RecentRead rr : reads) {
                    if (newSize <= 0) continue;
                    long diff = Math.abs(rr.sizeBytes - newSize);
                    double ratio = (double) diff / (double) Math.max(rr.sizeBytes, newSize);
                    if (ratio <= COPY_SIZE_TOLERANCE) {
                        HipsMonitor.addBehaviorFlag(pkg,
                            String.format("FILE_COPY:size=%d:src_size=%d:src=%s:conf=%.0f",
                                newSize, rr.sizeBytes, rr.filePath, rr.confidence * 100));
                        break;
                    }
                }

                // FILE_EXTENSION_ADDED: known file with an appended suffix
                // (e.g. "report.pdf" → "report.pdf.xyz")
                for (String existing : known.keySet()) {
                    if (!existing.equals(fileName) && fileName.startsWith(existing + ".")) {
                        String suffix = fileName.substring(existing.length());
                        HipsMonitor.addBehaviorFlag(pkg, "FILE_EXTENSION_ADDED:" + suffix);
                        break;
                    }
                }

                // FILE_EXTENSION_CHANGE: same stem, different extension
                // (e.g. "report.pdf" → "report.jpg")
                int dotIdx = fileName.lastIndexOf('.');
                if (dotIdx > 0) {
                    String newStem = fileName.substring(0, dotIdx);
                    String newExt = fileName.substring(dotIdx);
                    for (String existing : known.keySet()) {
                        if (existing.equals(fileName)) continue;
                        int edot = existing.lastIndexOf('.');
                        if (edot > 0 && existing.substring(0, edot).equals(newStem)
                                && !existing.substring(edot).equals(newExt)) {
                            String oldExt = existing.substring(edot);
                            HipsMonitor.addBehaviorFlag(pkg, "FILE_EXTENSION_CHANGE:" + oldExt + "→" + newExt);
                            break;
                        }
                    }
                }
            }
        }
        // Update directory snapshot for deletion tracking
        java.util.HashSet<String> snapshot = dirSnapshots.get(dirPath);
        if (snapshot == null) {
            snapshot = new java.util.HashSet<>();
            dirSnapshots.put(dirPath, snapshot);
        }
        if (isNew) snapshot.add(fileName);
        if (pkg == null || pkg.isEmpty()) return;

        // ── Ransomware rename-burst detection (gated by RANSOMWARE setting) ──
        if (!BehaviorDetectionSettings.isEnabled(c, BehaviorDetectionSettings.RANSOMWARE)) return;

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
        if (matchedBase == null) return;

        Long grantTime = (pkg == null || pkg.isEmpty()) ? null : grantedAt.get(pkg);
        if (grantTime == null || System.currentTimeMillis() - grantTime > GRANT_WINDOW_MS) {
            return; // no recent on-screen file-access grant to pin this on
        }
        if (BehaviorFlags.isFlagged(c, pkg)) return;
        if (TrustedPackages.isTrusted(c, pkg)) return;
        if (UserDecisions.isThreatAllowed(c, pkg)) return;

        String appendedSuffix = fileName.substring(matchedBase.length());
        long now = System.currentTimeMillis();
        long[] burst = renameBurst.get(pkg);
        if (burst == null || now - burst[0] > RENAME_BURST_WINDOW_MS) {
            renameBurst.put(pkg, new long[]{now, 1});
            sampleExt.put(pkg, appendedSuffix);
            return;
        }
        burst[1]++;

        // ── Sensor: file entropy ───────────────────────────────────────
        java.io.File newFile = new java.io.File(dirPath, fileName);
        double entropy = FileEntropy.entropyOf(newFile);
        boolean highEntropy = entropy >= 7.5;
        String entropyLabel = FileEntropy.label(entropy);

        // ── Sensor: per-process memory (from MinerDetector data) ───────
        boolean highProcMemory = HipsMonitor.packageHasMinerMemory(pkg, 64);

        int effective = effectiveThreshold(highEntropy, highProcMemory);
        String memInfo = MemoryMonitor.summary();
        Log.d(TAG, "rename+" + burst[1] + "/" + effective + " for " + pkg
            + " suffix=\"" + appendedSuffix + "\" entropy=" + entropyLabel
            + (entropy >= 0 ? String.format(" %.2f", entropy) : "")
            + " procMem=" + highProcMemory
            + " " + memInfo);
        if (burst[1] < effective) return;

        boolean wasAllFiles = Boolean.TRUE.equals(grantWasAllFiles.get(pkg));
        String entropyInfo = entropy >= 0
            ? String.format("entropy=%.2f(%s)", entropy, entropyLabel)
            : "entropy=unavailable";
        String procMemInfo = highProcMemory ? " +process memory >64MB" : "";
        String reason = "Ransomware behaviour: " + burst[1]
            + " files renamed with an appended suffix (\"" + sampleExt.get(pkg)
            + "\") within " + (RENAME_BURST_WINDOW_MS / 1000)
            + "s of this app being granted " + (wasAllFiles ? "All Files Access" : "file access")
            + " — " + entropyInfo + " " + memInfo + procMemInfo;
        Log.e(TAG, "RANSOMWARE BEHAVIOUR (" + pkg + "): " + reason);
        BehaviorFlags.flag(c, pkg, reason);
        HipsMonitor.addBehaviorFlag(pkg, "RANSOMWARE");
        if (highProcMemory) HipsMonitor.addBehaviorFlag(pkg, "RANSOMWARE_HIGH_MEM");
        if (highEntropy) HipsMonitor.addBehaviorFlag(pkg, "RANSOMWARE_HIGH_ENTROPY");
        HipsMonitor.reportRansomware(pkg, (int)burst[1], sampleExt.get(pkg),
            true, wasAllFiles, RENAME_BURST_WINDOW_MS, true);
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

    // ── Public accessors for behavior graph ──────────────────────────────

    /** Total unique files observed across all directories. */
    public static synchronized int countTotalObservedFiles() {
        int total = 0;
        for (LinkedHashMap<String, Long> names : knownNamesByDir.values()) {
            total += names.size();
        }
        return total;
    }

    /** Count files that have disappeared since the last snapshot. */
    public static synchronized int countRecentDeletions() {
        int deletions = 0;
        long now = System.currentTimeMillis();
        for (Map.Entry<String, java.util.HashSet<String>> entry : dirSnapshots.entrySet()) {
            String dirPath = entry.getKey();
            java.util.HashSet<String> snapshot = entry.getValue();
            java.io.File dir = new java.io.File(dirPath);
            if (!dir.isDirectory()) {
                deletions += snapshot.size();
                snapshot.clear();
                continue;
            }
            java.util.Set<String> current = new java.util.HashSet<>();
            java.io.File[] files = dir.listFiles();
            if (files != null) {
                for (java.io.File f : files) {
                    if (f.isFile()) current.add(f.getName());
                }
            }
            for (String name : snapshot) {
                if (!current.contains(name)) {
                    deletions++;
                }
            }
            snapshot.retainAll(current);
        }
        return deletions;
    }

    // ── Wiper detection ─────────────────────────────────────────────────

    /** Called periodically (e.g. every 30s) from GuardService to detect rapid
     *  file deletion combined with high per-process memory (wiper pattern). */
    public static synchronized void checkDeletions(Context ctx) {
        if (ctx == null) return;
        if (!BehaviorDetectionSettings.isEnabled(ctx, BehaviorDetectionSettings.WIPER)) return;
        String pkg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
        if (pkg == null || pkg.isEmpty()) return;
        if (BehaviorFlags.isFlagged(ctx, pkg)) return;
        if (TrustedPackages.isTrusted(ctx, pkg)) return;
        if (UserDecisions.isThreatAllowed(ctx, pkg)) return;

        long now = System.currentTimeMillis();
        int recentDeletions = 0;

        // Count recent deletions across all watched dirs
        for (Map.Entry<String, LinkedHashMap<String, Long>> dirEntry : knownNamesByDir.entrySet()) {
            String dirPath = dirEntry.getKey();
            java.io.File dir = new java.io.File(dirPath);
            if (!dir.isDirectory()) continue;
            java.util.Set<String> currentNames = new java.util.HashSet<>();
            java.io.File[] files = dir.listFiles();
            if (files != null) {
                for (java.io.File f : files) {
                    if (f.isFile()) currentNames.add(f.getName());
                }
            }
            for (String knownName : dirEntry.getValue().keySet()) {
                if (!currentNames.contains(knownName)) {
                    recentDeletions++;
                }
            }
        }

        if (recentDeletions < DELETION_BURST_THRESHOLD) return;

        // Track deletion burst window
        Object[] burst = deletionBurst.get(pkg);
        if (burst == null || now - (Long) burst[0] > DELETION_WINDOW_MS) {
            deletionBurst.put(pkg, new Object[]{now, 1, pkg});
            return;
        }
        burst[1] = (Integer) burst[1] + 1;
        int burstCount = (Integer) burst[1];

        // Check per-process memory
        boolean highMem = HipsMonitor.packageHasMinerMemory(pkg, 64);

        Log.d(TAG, "deletion burst=" + burstCount + "/" + DELETION_BURST_THRESHOLD
            + " for " + pkg + " mem=" + highMem);

        if (burstCount < DELETION_BURST_THRESHOLD) return;

        String flag = "WIPER:DELETED=" + recentDeletions + ":BURST=" + burstCount + ":MEM=" + highMem;
        HipsMonitor.addBehaviorFlag(pkg, flag);

        if (highMem) {
            String reason = "Wiper behaviour: " + recentDeletions
                + " files deleted in " + (DELETION_WINDOW_MS / 1000)
                + "s with high process memory (>64MB)";
            Log.e(TAG, "WIPER BEHAVIOUR (" + pkg + "): " + reason);
            BehaviorFlags.flag(ctx, pkg, reason);
            com.hydradragon.antivirus.service.ThreatLogger.logThreat(ctx, pkg, pkg, reason);
            HipsMonitor.addBehaviorFlag(pkg, "WIPER_CONFIRMED");
            BehaviorResponse.killAndPromptUninstall(ctx, pkg);
        }
    }
}
