package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.model.ScanResult;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ScanEngine {
    private static final String TAG = "HydraDragon-ScanEngine";

    // Dangerous-permission detection moved to the native (Rust) engine — it counts
    // them from the manifest bytes (covers in-memory/inner APKs). Java only applies
    // the 5/6 decision on the count the native scan returns.

    private static final List<String> TRUSTED_COMPANIES = Arrays.asList(
        "google", "meta", "facebook", "instagram", "whatsapp", "microsoft",
        "amazon", "spotify", "netflix", "twitter", "x corp",
        "telegram", "roblox", "kaspersky", "xiaomi", "samsung",
        "oppo", "vivo", "motorola", "lenovo", "huawei", "oneplus",
        "realme", "asus", "sony", "nokia", "lg", "htc", "zte", "tcl"
    );

    private static final List<String> WHITELIST_PREFIXES = Arrays.asList(
        "com.google.", "com.android.", "android", "com.whatsapp",
        "com.facebook.", "com.instagram.", "com.twitter", "com.spotify",
        "com.microsoft.", "org.telegram.", "com.discord",
        "com.miui.", "com.samsung.", "com.sec.", "com.oppo.", "com.vivo.",
        "com.motorola.", "com.huawei.", "com.oneplus.", "com.realme.",
        "com.asus.", "com.sony.", "com.coloros.", "com.heytap.",
        "com.termux", "io.github.", "com.github.", "org.fdroid."
    );

    private final Context context;
    private final AIEngine aiEngine;
    private final CodeAnalyzer codeAnalyzer;
    private final ExecutorService scanExecutor;
    // Dedicated pool for wrapping blocking native (JNI/Rust) calls so cancelScan()
    // can take effect almost immediately instead of Stop waiting out however
    // long the CURRENT file's native scan takes (large files can take seconds;
    // the native side has no interruption point). See runNativeInterruptible.
    private final ExecutorService nativeCallExecutor = Executors.newCachedThreadPool();
    // Static so invalidation from receivers reaches the live GuardService cache.
    private static final java.util.concurrent.ConcurrentHashMap<String, ThreatResult> photonCache = new java.util.concurrent.ConcurrentHashMap<>();

    /** Drop a cached scan result so the package is re-scanned fresh (e.g. after
     *  uninstall/update — otherwise a removed virus keeps "coming back"). */
    public static void invalidateCache(String packageName) {
        if (packageName != null) photonCache.remove(packageName);
    }

    public static void clearCache() {
        photonCache.clear();
    }
    private ScanCallback callback;
    // Per-engine cumulative timing (ms) for the current/last scan — used to
    // find the slowest engine. Reset at the start of each scanAllApps() run.
    private final java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong> engineTimingMs = new java.util.concurrent.ConcurrentHashMap<>();

    // Running count of storage FILES (APK or generic) actually passed through
    // the engine during a full scan's storage-root pass — separate from the
    // installed-APPS total, so a full scan's progress/"scanned" count reflects
    // the file-level work too, not just the up-front installed-apps loop.
    private final java.util.concurrent.atomic.AtomicInteger filesScannedCount = new java.util.concurrent.atomic.AtomicInteger();
    // Installed-apps total from the CURRENT scanAllApps() run's up-front loop —
    // added on top of filesScannedCount so the UI's "scanned" counter keeps
    // climbing through the storage-file phase instead of resetting back down
    // to 1, 2, 3... once the app loop hands off to file scanning.
    private volatile int appsScannedBase;

    private void addTiming(String engine, long ms) {
        engineTimingMs.computeIfAbsent(engine, k -> new java.util.concurrent.atomic.AtomicLong()).addAndGet(ms);
    }

    private void logEngineTimings() {
        List<java.util.Map.Entry<String, java.util.concurrent.atomic.AtomicLong>> entries =
            new ArrayList<>(engineTimingMs.entrySet());
        entries.sort((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()));
        for (java.util.Map.Entry<String, java.util.concurrent.atomic.AtomicLong> e : entries) {
            Log.i(TAG, "ENGINE_TIMING " + e.getKey() + " = " + e.getValue().get() + "ms");
        }
        if (!entries.isEmpty()) {
            Log.i(TAG, "SLOWEST_ENGINE " + entries.get(0).getKey() + " (" + entries.get(0).getValue().get() + "ms)");
        }
    }
    // SHA-256 hash whitelist now lives in NATIVE memory (fastbloom) — see
    // NativeScanner.isHashWhitelisted — so the large NSRL set never sits in the
    // Java heap. isHashWhitelisted() below delegates to it.
    /** EXACT known-good package names (NSRL Android, extension=apk). NOT a
     *  standalone clear — a package name is spoofable, so it only clears an app
     *  when combined with a trusted-store install (see analyzeApp). */
    private final java.util.HashSet<String> whitelistPackages = new java.util.HashSet<>();
    /** Set by {@link #cancelScan()} to abort an in-flight scan at the next loop
     *  boundary. Volatile so the UI thread's request is seen by the scan thread. */
    private volatile boolean cancelRequested = false;

    /** Request the running scan to stop as soon as possible. Native calls
     *  in flight are ABANDONED (see runNativeInterruptible), not killed —
     *  they keep running to completion on their own thread, but the scan loop
     *  stops waiting for them almost immediately instead of blocking until
     *  they return. */
    public void cancelScan() { cancelRequested = true; }

    /** Whether a stop was requested for the current/last scan. */
    public boolean isCancelled() { return cancelRequested; }

    /** Runs a blocking native (JNI/Rust) call on a background thread and polls
     *  for {@link #cancelRequested} every 150ms instead of blocking until it
     *  returns. The native side (clamav/YARA/ML over a whole file) has no
     *  interruption point of its own, and killing a thread mid-JNI-call is
     *  unsafe (can corrupt native state / crash the process) — so a cancelled
     *  call is simply ABANDONED: this method returns {@code null} right away,
     *  the caller treats that exactly like "no verdict" (every call site
     *  already has that null-handling), and the abandoned call quietly
     *  finishes on its own thread in the background with its result discarded.
     *  This is what lets Stop take effect in ~150ms instead of however long
     *  the file being scanned right now takes. */
    private NativeScanner.Verdict runNativeInterruptible(java.util.concurrent.Callable<NativeScanner.Verdict> call) {
        java.util.concurrent.Future<NativeScanner.Verdict> future = nativeCallExecutor.submit(call);
        while (true) {
            if (cancelRequested) return null;
            try {
                return future.get(150, java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch (java.util.concurrent.TimeoutException te) {
                // keep polling
            } catch (Exception e) {
                // Distinct from a cancellation: the native call itself failed
                // (or this thread was interrupted). Both end up returning null
                // (same "no verdict" handling every call site already has),
                // but silently — logging it means a genuine native-side
                // failure is never mistaken for "nothing found" without a trace.
                Log.e(TAG, "runNativeInterruptible: native call failed", e);
                return null;
            }
        }
    }

    /** Manual, user-requested signature generation for a specific APK — used by
     *  the "ask to generate a signature before removing this Zero-Trust UNKNOWN
     *  app" flow (see AskSignatureOnRemove). Called while the APK is STILL on
     *  disk, right before the uninstall intent is fired. Forces the native
     *  side to build a rule ({@code zero_trust=true}) regardless of the
     *  malicious verdict — the user explicitly asked for it here, so this is
     *  NOT gated behind the AutoRuleGeneration setting (that gate is only for
     *  the automatic/background path). Best-effort: never throws.
     *  @return true if a rule was generated and saved. */
    public boolean generateRuleForApp(String apkPath, String packageName) {
        if (apkPath == null || !NativeScanner.isReady()) return false;
        try {
            String md5 = fileMd5(new java.io.File(apkPath));
            NativeScanner.Verdict v = NativeScanner.scan(apkPath, packageName, md5, true);
            if (v == null || v.generatedRule == null || v.generatedRule.isEmpty()) return false;
            saveGeneratedRule(v);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public interface ScanCallback {
        void onProgress(int current, int total, String packageName);
        void onThreatFound(ThreatResult threat);
        void onScanComplete(ScanResult result);
        void onError(String error);
    }

    public ScanEngine(Context context, AIEngine aiEngine) {
        this.context = context;
        this.aiEngine = aiEngine;
        this.codeAnalyzer = new CodeAnalyzer(context);
        this.scanExecutor = Executors.newFixedThreadPool(4);
        loadPackageWhitelist();
        // Load YARA-X rulesets + ML model into the native engine (non-fatal).
        try { NativeScanner.init(context); } catch (Throwable t) { /* degrade gracefully */ }
    }

    /**
     * Scan an APK file with the native YARA + ML engine.
     *
     * @return JSON verdict string, or {@code {"error":...}} if unavailable.
     */
    public String nativeScanApk(String apkPath) {
        return NativeScanner.scanApk(apkPath);
    }

    /** True for ClamAV/YARA names denoting a Potentially-Unwanted App (PUA.* / PUA_*). */
    private static boolean isPuaName(String name) {
        if (name == null) return false;
        String u = name.toUpperCase(java.util.Locale.US);
        return u.contains("PUA.") || u.contains("PUA_");
    }

    /** True for the EICAR standard AV test signature (e.g. "test.test.eicar",
     *  "test.test.eicar.1040") — a deliberate test string every real antivirus
     *  recognizes, not actual malware. Matched anywhere in the name is enough:
     *  no legitimate detection name ever contains "eicar". */
    /** True for a self-learned rule this device generated itself (see
     *  saveGeneratedRule) — named "YARA-X.auto_<hash>". Heuristic, not a vetted
     *  signature, so a hit is reported as SUSPICIOUS/low-confidence (30/100 —
     *  just above the isThreat() threshold, so it still surfaces in results)
     *  rather than a certain MALWARE verdict. */
    private static boolean isAutoGeneratedName(String name) {
        return name != null && (name.startsWith("YARA-X.auto_") || name.startsWith("YARA.auto_"));
    }

    private static boolean isEicarName(String name) {
        return name != null && name.toLowerCase(java.util.Locale.US).contains("eicar");
    }

    /** True for the native DEX static-analysis heuristic (Rust dex_scan module
     *  — obfuscation/dynamic-loading/dangerous-API smells), named
     *  "DEX/High: ..." or "DEX/Critical: ...". A raw code-pattern heuristic,
     *  not a vetted signature — legitimate apps (plugin loaders, obfuscated
     *  but benign SDKs) routinely trip it. Dropped entirely from every
     *  verdict — never counts toward a threat, at any confidence level. */
    private static boolean isDexHeuristicName(String name) {
        return name != null && name.startsWith("DEX/");
    }

    private void loadPackageWhitelist() {
        // Known-good NSRL package keys (whitelist_packages.db, table
        // whitelist_package, column "key" = package_id^^file_name) into an exact
        // HashSet. Only clears an app WITH a trusted-store install (spoofable
        // alone). The SHA-256 hash whitelist is separate and lives natively
        // (fastbloom) — see NativeScanner.isHashWhitelisted.
        // Lives under assets/scan/ (not the assets root) so NativeScanner.init()
        // also copies it into the "hydra-scan" dir the Rust engine reads at
        // nativeInit — the same DB file backs both the Java package check here
        // AND the Rust exact-file skip check in NativeScanner_nativeScanApk.
        java.io.File dbFile = new java.io.File(context.getNoBackupFilesDir(), "whitelist_packages.db");
        try {
            if (!dbFile.exists()) {
                try (InputStream in = context.getAssets().open("scan/whitelist_packages.db");
                     java.io.OutputStream out = new java.io.FileOutputStream(dbFile)) {
                    byte[] buf = new byte[64 * 1024];
                    int n;
                    while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                }
            }
            try (android.database.sqlite.SQLiteDatabase db = android.database.sqlite.SQLiteDatabase.openDatabase(
                    dbFile.getAbsolutePath(), null, android.database.sqlite.SQLiteDatabase.OPEN_READONLY);
                 android.database.Cursor c = db.rawQuery("SELECT key FROM whitelist_package", null)) {
                while (c.moveToNext()) whitelistPackages.add(c.getString(0));
            }
        } catch (Exception e) { /* missing — package whitelist disabled */ }
    }

    /** True if {@code hash} (a whole-APK/file SHA-256) is a known-good NSRL hash.
     *  Delegates to the native fastbloom whitelist (native memory). */
    private boolean isHashWhitelisted(String hash) {
        return hash != null && NativeScanner.isHashWhitelisted(hash.toLowerCase(java.util.Locale.US));
    }

    /** True if {@code pkg} is an exact known-good NSRL package name. Spoofable on
     *  its own, so callers must combine it with a trusted-store install. */
    private boolean isPackageWhitelisted(String pkg) {
        return pkg != null && whitelistPackages.contains(pkg);
    }

    /** Lowercase-hex MD5 of a file's bytes (streamed), or null on error. We
     *  compute it in Java — the native side never sends raw bytes back, only the
     *  hash — so a known-good whole file can be cleared BEFORE the expensive
     *  yara/clamav/ML scan even runs (the "hash first" fast path). Reused natively
     *  (passed to scan) so the file isn't hashed a second time. */
    static String fileMd5(java.io.File file) {
        try (java.io.InputStream in = new java.io.FileInputStream(file)) {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            StringBuilder sb = new StringBuilder(32);
            for (byte b : md.digest()) sb.append(Character.forDigit((b >> 4) & 0xF, 16))
                                         .append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    /** A native detection is a false positive iff one of the APKs in its
     *  extraction lineage is whitelisted (the hit lives inside a known-good APK),
     *  OR the user has explicitly told the engine to ignore this exact
     *  signature name (see IgnoredSignatures — Settings, or the "ignore this
     *  signature" action on a completed scan's threat dialog). The latter is
     *  engine-wide (every app/file), unlike UserDecisions.allowThreat which
     *  only clears one specific app/file. */
    private boolean isDetectionWhitelisted(NativeScanner.Verdict.Detection d) {
        if (IgnoredSignatures.isIgnored(context, d.name)) {
            Log.d(TAG, "DETECTION-SUPPRESSED[ignored signature] " + d.name);
            return true;
        }
        for (String h : d.hashes) {
            if (isHashWhitelisted(h)) {
                Log.d(TAG, "DETECTION-SUPPRESSED[lineage hash whitelisted] " + d.name + " hash=" + h);
                return true;
            }
        }
        return false;
    }

    /** Write a yarGen-style auto-generated rule (see NativeScanner.Verdict#generatedRule)
     *  into the SAME "hydra-scan" directory NativeScanner.init() points the native
     *  engine at — under generated_rules/, so the native side re-loads and compiles
     *  every rule this device has ever generated on the NEXT app start: self-learning,
     *  a family this device already caught once is detected immediately on future
     *  scans, even a recompiled/renamed variant matching the same strings/package.
     *  Also hot-loads the rule into the LIVE engine right away (NativeScanner.learnRule)
     *  so the SAME session benefits too, not just the next app launch. One file per
     *  sample hash — re-scanning the same malicious sample overwrites, not duplicates.
     *  No-op when the native side didn't produce one (clean scan). */
    private void saveGeneratedRule(NativeScanner.Verdict v) {
        if (v == null || v.generatedRule == null || v.generatedRule.isEmpty()) return;
        try {
            java.io.File dir = new java.io.File(
                new java.io.File(context.getFilesDir(), "hydra-scan"), "generated_rules");
            if (!dir.exists() && !dir.mkdirs()) return;
            String name = (v.md5 != null && !v.md5.isEmpty()) ? v.md5 : String.valueOf(System.nanoTime());
            java.io.File out = new java.io.File(dir, "auto_" + name + ".yar");
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                fos.write(v.generatedRule.getBytes(StandardCharsets.UTF_8));
            }
            NativeScanner.learnRule(out.getAbsolutePath());
        } catch (Exception e) { /* best effort — never block the scan on this */ }
    }

    /** Detections that survive per-lineage whitelist suppression. A sibling
     *  non-APK virus (empty/non-whitelisted lineage) survives even when a
     *  whitelisted APK sits alongside it in the same archive. */
    private List<NativeScanner.Verdict.Detection> survivingDetections(NativeScanner.Verdict v) {
        List<NativeScanner.Verdict.Detection> out = new ArrayList<>();
        for (NativeScanner.Verdict.Detection d : v.detections)
            if (!isDetectionWhitelisted(d)) out.add(d);
        return out;
    }

    public void setCallback(ScanCallback callback) { this.callback = callback; }

    // Guards against two scanAllApps() runs overlapping — e.g. GuardService's
    // periodic background scan firing while a user-initiated scan (from
    // ScanFragment) is still in progress. Both would otherwise share this
    // engine's single `callback` + progress counters (filesScannedCount,
    // appsScannedBase, engineTimingMs), so whichever run finished FIRST would
    // fire onScanComplete on the UI's callback and show "scan complete/system
    // clean" while the user's own scan was still actively running, and each
    // run's counter resets would corrupt the other's in-flight numbers.
    private final java.util.concurrent.atomic.AtomicBoolean scanRunning =
        new java.util.concurrent.atomic.AtomicBoolean(false);

    public boolean isScanRunning() { return scanRunning.get(); }

    /** @return true if this call actually started a scan, false if one was
     *  already running (see scanRunning) and this request was skipped. The
     *  caller (e.g. ScanFragment) MUST check this — an isScanRunning() check
     *  done beforehand is not enough, since a background scan can start in
     *  the gap between that check and this call. Checking THIS return value
     *  instead closes that race. */
    public boolean scanAllApps(boolean isFullScan) {
        if (!scanRunning.compareAndSet(false, true)) {
            Log.w(TAG, "scanAllApps: a scan is already running, skipping this request");
            return false;
        }
        cancelRequested = false;
        engineTimingMs.clear();
        filesScannedCount.set(0);
        scanExecutor.execute(() -> {
          try {
            PackageManager pm = context.getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<ThreatResult> threats = new ArrayList<>();
            int total = apps.size();
            appsScannedBase = total;

            for (int i = 0; i < total; i++) {
                if (cancelRequested) break;
                ApplicationInfo app = apps.get(i);
                try {
                    if (callback != null) callback.onProgress(i + 1, total, app.packageName);
                    ThreatResult result = analyzeApp(app, pm, false);
                    if (result != null && result.isThreat()) {
                        threats.add(result);
                        if (callback != null) callback.onThreatFound(result);
                    }
                } catch (Exception e) { }
            }

            try {
                if (isFullScan && !cancelRequested) {
                    // Full scan = quick scan PLUS four extra passes:
                    //  1) every file under ALL storage volumes (not just /sdcard)
                    //  2) deep native (clamav/YARA/ML) scan of every installed APK
                    //  3) running / recently-active processes
                    //  4) accessible app-data & system directories
                    java.util.Set<String> installedPackages = new java.util.HashSet<>();
                    for (ApplicationInfo a : apps) if (a.packageName != null) installedPackages.add(a.packageName);
                    long t0 = android.os.SystemClock.elapsedRealtime();
                    scanAllStorageRoots(pm, threats, installedPackages);
                    addTiming("scanAllStorageRoots", android.os.SystemClock.elapsedRealtime() - t0);

                    t0 = android.os.SystemClock.elapsedRealtime();
                    deepNativeScanInstalledApks(apps, pm, threats);
                    addTiming("deepNativeScanInstalledApks", android.os.SystemClock.elapsedRealtime() - t0);

                    t0 = android.os.SystemClock.elapsedRealtime();
                    scanRecentProcesses(pm, threats);
                    addTiming("scanRecentProcesses", android.os.SystemClock.elapsedRealtime() - t0);

                    t0 = android.os.SystemClock.elapsedRealtime();
                    scanAccessibleDataDirs(pm, threats);
                    addTiming("scanAccessibleDataDirs", android.os.SystemClock.elapsedRealtime() - t0);
                } else if (!cancelRequested) {
                    // Quick scan: only APKs in Downloads.
                    scanDirectoryForApks(
                        android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS),
                        pm, threats, false);
                }
            } catch (Exception e) { }

            logEngineTimings();
            int scannedTotal = total + filesScannedCount.get() + threats.size();
            if (callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats));
          } finally {
              scanRunning.set(false);
          }
        });
        return true;
    }

    /** User-picked custom folder scan (see ScanFragment's folder-picker option
     *  in the Custom Scan dialog). Walks every file under {@code dir} — APKs
     *  through the full analyzeApp pipeline, everything else through the
     *  native engine — and reports through the SAME ScanCallback contract as
     *  scanAllApps(), so the existing progress/threat-found/complete UI wiring
     *  just works. Subject to the same one-scan-at-a-time guard.
     *  @return true if this call actually started the scan (see scanAllApps's
     *  javadoc — same race-free contract). */
    public boolean scanCustomFolder(java.io.File dir) {
        if (!scanRunning.compareAndSet(false, true)) {
            Log.w(TAG, "scanCustomFolder: a scan is already running, skipping this request");
            return false;
        }
        cancelRequested = false;
        engineTimingMs.clear();
        filesScannedCount.set(0);
        appsScannedBase = 0;
        scanExecutor.execute(() -> {
          try {
            PackageManager pm = context.getPackageManager();
            List<ThreatResult> threats = new ArrayList<>();
            scanDirectoryForApks(dir, pm, threats, true);
            logEngineTimings();
            int scannedTotal = filesScannedCount.get() + threats.size();
            if (callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats));
          } finally {
              scanRunning.set(false);
          }
        });
        return true;
    }

    private void scanDirectoryForApks(java.io.File dir, PackageManager pm,
                                      List<ThreatResult> threats, boolean fullScan) {
        scanDirectoryForApks(dir, pm, threats, fullScan, null);
    }

    /** Bump the storage-file counter and push a live progress update so a full
     *  scan's UI reflects the (potentially huge) storage-root file walk, not
     *  just the up-front installed-apps loop. Adds appsScannedBase so the
     *  displayed count keeps climbing from where the installed-apps loop left
     *  off, instead of resetting back down to 1, 2, 3... current==total on
     *  purpose: the eventual file count isn't known ahead of time, so this
     *  reports "how many scanned so far" rather than a completion percentage. */
    private void reportFileScanned(java.io.File file) {
        int n = appsScannedBase + filesScannedCount.incrementAndGet();
        if (callback != null) callback.onProgress(n, n, file.getName());
    }

    /** @param skipPackages installed-package names already analyzed by the main
     *  full-scan pass (scanAllApps's installed-apps loop) — a standalone APK file
     *  found on disk (e.g. sitting in Downloads) whose package name is already in
     *  this set is the SAME app already reported once as an installed app, so it's
     *  skipped here instead of being reported a second time under its file path. */
    private void scanDirectoryForApks(java.io.File dir, PackageManager pm,
                                      List<ThreatResult> threats, boolean fullScan,
                                      java.util.Set<String> skipPackages) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        java.io.File[] files = dir.listFiles();
        if (files == null) return;
        for (java.io.File file : files) {
            if (cancelRequested) return;
            // Still mid-download (MediaStore's ".pending-<id>-realname" temp
            // file) — guaranteed incomplete, parsing it as a zip/APK fails
            // outright. It'll get scanned under its real name once the
            // download finishes and the system renames it away from this.
            if (file.getName().startsWith(".pending-")) continue;
            if (file.isDirectory()) {
                scanDirectoryForApks(file, pm, threats, fullScan, skipPackages);
            } else if (file.getName().toLowerCase().endsWith(".apk")) {
                try {
                    PackageInfo pkgInfo = pm.getPackageArchiveInfo(file.getAbsolutePath(),
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
                    if (pkgInfo != null) {
                        String pkgName = pkgInfo.applicationInfo.packageName;
                        if (skipPackages != null && pkgName != null && skipPackages.contains(pkgName)) {
                            continue;
                        }
                        pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                        pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                        ThreatResult result = analyzeApp(pkgInfo.applicationInfo, pm, true);
                        if (result != null && result.isThreat()) {
                            threats.add(result);
                            if (callback != null) callback.onThreatFound(result);
                        }
                    }
                } catch (Exception e) { }
                reportFileScanned(file);
            } else if (fullScan) {
                // Non-APK file in a full scan: route through the native engine
                // (hydradragonextractor unpacking + clamav/YARA + ML). Permission
                // analysis doesn't apply — it isn't an installable app.
                scanGenericFile(file, threats);
                reportFileScanned(file);
            }
        }
    }

    /**
     * Scan ONE file that just appeared on disk (e.g. GuardService's Downloads
     * folder FileObserver, fired on CLOSE_WRITE) — APK or any other type — and
     * return the real verdict (native YARA/ClamAV/ML for generic files, the full
     * analyzeApp pipeline for an APK), or {@code null} if clean/unreadable.
     * Synchronous — call it off the caller's main/observer thread.
     */
    public ThreatResult scanSingleFile(java.io.File file) {
        if (file == null || !file.exists()) return null;
        PackageManager pm = context.getPackageManager();
        if (file.getName().toLowerCase(java.util.Locale.US).endsWith(".apk")) {
            try {
                PackageInfo pkgInfo = pm.getPackageArchiveInfo(file.getAbsolutePath(),
                    PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
                if (pkgInfo != null) {
                    pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                    pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                    ThreatResult result = analyzeApp(pkgInfo.applicationInfo, pm, true);
                    if (result != null && result.isThreat()) return result;
                }
            } catch (Exception e) { /* unreadable/corrupt APK — treat as no verdict */ }
            return null;
        }
        List<ThreatResult> out = new ArrayList<>();
        scanGenericFile(file, out);
        return out.isEmpty() ? null : out.get(0);
    }

    /**
     * Scan an arbitrary (non-APK) file with the native engine during a full
     * scan. The native side unpacks archives (zip/gz/tar/xz/lzma/7z/rar — so a
     * nested APK is reached too) and runs clamav signatures, YARA and the ML
     * model on every extracted buffer.
     */
    private void scanGenericFile(java.io.File file, List<ThreatResult> threats) {
        try {
            if (!NativeScanner.isReady()) return;
            if (!MaxScanFileSize.isWithinLimit(context, file)) {
                Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + file.getAbsolutePath());
                return;
            }
            String path = file.getAbsolutePath();
            // Hash-first fast path: known-good whole file → skip the scan entirely.
            // MD5 computed once here and reused natively.
            String md5 = fileMd5(new java.io.File(path));
            if (isHashWhitelisted(md5)) return;
            long nativeT0 = android.os.SystemClock.elapsedRealtime();
            NativeScanner.Verdict v = runNativeInterruptible(() ->
                NativeScanner.scan(path, null, md5, ZeroTrustMode.isEnabled(context)));
            long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
            addTiming("NativeScanner", nativeMs);
            Log.i(TAG, "FILE_ENGINE_TIMING " + file.getName()
                + " NativeScanner=" + nativeMs + "ms slowest=NativeScanner");
            if (v == null) return;
            saveGeneratedRule(v);
            // Per-detection whitelist suppression: a hit INSIDE a known-good
            // (whitelisted) APK is a false positive, but a non-APK virus sitting
            // alongside that APK in the same archive is NOT suppressed by the APK's
            // hash. Keep only the detections that survive.
            List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
            boolean malicious = !live.isEmpty();

            // Static string-based URL scan: extract every http(s) URL straight
            // from the file's bytes and check it against the malware/phishing
            // blooms. A FULL URL (with path) is far more specific than a bare
            // domain — much less collision-prone, so a hit here is stronger
            // evidence with fewer false positives than domain-only matching,
            // and it catches malicious/phishing links dropped in plain text
            // files (not just APKs) that never go through analyzeApp at all.
            java.util.Map<String, String> urlHits = java.util.Collections.emptyMap();
            if (DetectionCategories.isEnabled(context, DetectionCategories.URL_STRINGS)) {
                urlHits = scanFileForMaliciousUrls(file);
            }

            // Act on a surviving native hit, a dangerous-permission count, or a
            // malicious/phishing URL string.
            if (!malicious && v.permissions < 6 && urlHits.isEmpty()) return;

            ThreatResult.Builder b = new ThreatResult.Builder(path);
            List<String> reasons = new java.util.ArrayList<>();
            int riskScore = 0;
            boolean mlMalicious = false;
            boolean hasRealThreat = false;
            boolean hasEicar = false;
            for (NativeScanner.Verdict.Detection d : live) {
                if ("ML".equals(d.name)) {
                    if (DetectionCategories.isEnabled(context, DetectionCategories.ML)) {
                        mlMalicious = true;
                        hasRealThreat = true;
                    }
                } else if (isEicarName(d.name)) {
                    if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                        hasEicar = true;
                        reasons.add("🧪 [TEST] " + d.name);
                    }
                } else if (!isDexHeuristicName(d.name)) {
                    boolean isPua = isPuaName(d.name);
                    String category = isPua ? DetectionCategories.PUA : DetectionCategories.SIGNATURES;
                    if (DetectionCategories.isEnabled(context, category)) {
                        if (!isPua) hasRealThreat = true;
                        reasons.add((isPua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + d.name);
                    }
                }
            }
            // Decide by what actually survived CATEGORY gating (reasons), not
            // the raw pre-gating `malicious` flag — otherwise a fully
            // category-disabled hit would still fall through to a PUA verdict
            // with no reasons to show for it.
            if (!reasons.isEmpty() || hasRealThreat) {
                if (hasRealThreat) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                } else if (hasEicar) {
                    riskScore = 50;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.TEST_MALWARE);
                } else {
                    riskScore = 50;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                }
            }
            // Two-tier dangerous permissions (same as installed-app analysis):
            // 10+ => certain malware, exactly 9 => suspicious. Calibrated against
            // Malwarebytes' own permission footprint (contacts, SMS/MMS read+receive,
            // storage, draw-over-other-apps = 8/36 on this list) — the threshold
            // sits one above that so a legitimate heavy-permission security app
            // isn't itself flagged as malware.
            if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                if (v.permissions >= 10) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                    reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/36)");
                } else if (v.permissions == 9) {
                    riskScore = Math.max(riskScore, 30);
                    if (!hasRealThreat) {
                        b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                    }
                    reasons.add("🔐 Suspicious permissions (9/36)");
                }
            }
            if (mlMalicious) {
                String near = v.nearest != null ? "  ~" + v.nearest : "";
                reasons.add(String.format(java.util.Locale.US,
                    "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
            }
            if (!urlHits.isEmpty()) {
                boolean anyMalware = false;
                for (java.util.Map.Entry<String, String> hit : urlHits.entrySet()) {
                    boolean isPhishing = hit.getValue().contains("PHISHING");
                    if (!isPhishing) anyMalware = true;
                    reasons.add((isPhishing ? "🎣 [PHISHING URL] " : "☠️ [MALWARE URL] ")
                        + hit.getValue() + ": " + hit.getKey());
                }
                // Malware URL takes priority over phishing if both kinds of hit
                // are present in the same file. A full-URL bloom hit is treated
                // as certain (100), same weight as a native signature match —
                // see DetectionCategories.URL_STRINGS' javadoc for why a full
                // URL (not just a domain) is specific enough to earn that.
                riskScore = 100;
                b.setThreatType(anyMalware
                    ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE
                    : com.hydradragon.antivirus.model.ThreatResult.ThreatType.PHISHING);
            }
            if (v.md5 != null && !v.md5.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.md5);
            }
            b.setRiskScore(riskScore);
            b.setReasons(reasons);
            b.setAppName(file.getName() + " (FILE)");
            b.setApkPath(path);
            ThreatResult r = b.build();
            if (r.isThreat()) {
                threats.add(r);
                if (callback != null) callback.onThreatFound(r);
            }
        } catch (Throwable t) { /* degrade gracefully */ }
    }

    /** Read a bounded prefix of {@code file} as text and check every embedded
     *  http(s) URL against the native malware/phishing URL blooms. Bounded
     *  read (not the whole file) keeps this cheap even for large files — a
     *  malicious/phishing link is a short ASCII string, so it's virtually
     *  always found well within the first few MB regardless of overall file
     *  size.
     *  @return map of malicious URL -> category (empty if none / unreadable). */
    private static final int URL_SCAN_MAX_BYTES = 4 * 1024 * 1024;

    private java.util.Map<String, String> scanFileForMaliciousUrls(java.io.File file) {
        java.util.Map<String, String> hits = new java.util.LinkedHashMap<>();
        try (java.io.InputStream in = new java.io.FileInputStream(file)) {
            byte[] buf = new byte[64 * 1024];
            StringBuilder sb = new StringBuilder();
            int n, total = 0;
            while ((n = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, n, java.nio.charset.StandardCharsets.ISO_8859_1));
                total += n;
                if (total >= URL_SCAN_MAX_BYTES) break;
            }
            UrlThreatScanner scanner = UrlThreatScanner.get(context);
            for (String url : UrlThreatScanner.extractUrls(sb.toString())) {
                if (hits.containsKey(url)) continue;
                String cat = scanner.scanUrl(url);
                if (cat != null) hits.put(url, cat);
            }
        } catch (Throwable ignore) { }
        return hits;
    }

    // ──────────────────────── FULL-SCAN EXTRA PASSES ────────────────────────

    /** 1) Every file under ALL mounted storage volumes, not just primary /sdcard.
     *  {@code installedPackages} lets a standalone APK file whose package is
     *  already installed (and already scanned/reported by the main installed-apps
     *  pass) be skipped here — otherwise the same app shows up twice in the threat
     *  list: once as the installed app, once as its leftover installer file. */
    private void scanAllStorageRoots(PackageManager pm, List<ThreatResult> threats,
                                      java.util.Set<String> installedPackages) {
        java.util.LinkedHashSet<String> roots = new java.util.LinkedHashSet<>();
        try {
            java.io.File primary = android.os.Environment.getExternalStorageDirectory();
            if (primary != null) roots.add(primary.getAbsolutePath());
        } catch (Throwable ignore) { }
        try {
            java.io.File[] vols = new java.io.File("/storage").listFiles();
            if (vols != null) for (java.io.File v : vols) {
                String n = v.getName();
                if (v.isDirectory() && v.canRead() && !n.equals("self") && !n.equals("emulated"))
                    roots.add(v.getAbsolutePath());
            }
        } catch (Throwable ignore) { }
        for (String r : roots) {
            if (cancelRequested) return;
            try { scanDirectoryForApks(new java.io.File(r), pm, threats, true, installedPackages); }
            catch (Throwable ignore) { }
        }
    }

    /** 2) Deep native (clamav/YARA/ML) scan of every installed app's APK — runs
     *  even on name-whitelisted apps, since a signature/hash match is stronger
     *  than a trusted package name. Hash/package whitelist still suppresses FPs. */
    private void deepNativeScanInstalledApks(List<ApplicationInfo> apps, PackageManager pm,
                                             List<ThreatResult> threats) {
        if (!NativeScanner.isReady()) return;
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        for (ThreatResult t : threats) if (t.getPackageName() != null) seen.add(t.getPackageName());
        for (ApplicationInfo app : apps) {
            if (cancelRequested) return;
            try {
                if (app.sourceDir == null) continue;
                // Never deep-flag system files.
                if ((app.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                        || (app.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        || app.sourceDir.startsWith("/system/") || app.sourceDir.startsWith("/vendor/")
                        || app.sourceDir.startsWith("/product/") || app.sourceDir.startsWith("/apex/")) continue;
                if (app.packageName != null && (app.packageName.equals(context.getPackageName())
                        || seen.contains(app.packageName))) continue;
                // Size check BEFORE hashing — an oversized file shouldn't pay
                // for a full-file MD5 read just to be skipped a moment later.
                if (!MaxScanFileSize.isWithinLimit(context, new java.io.File(app.sourceDir))) {
                    Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + app.packageName);
                    continue;
                }
                // Hash-first fast path: known-good APK (MD5 match) → skip.
                // (No package-name skip — a package name is spoofable.)
                // MD5 computed once here and reused natively.
                String appMd5 = fileMd5(new java.io.File(app.sourceDir));
                if (isHashWhitelisted(appMd5)) continue;
                long nativeT0 = android.os.SystemClock.elapsedRealtime();
                NativeScanner.Verdict v = runNativeInterruptible(() ->
                    NativeScanner.scan(app.sourceDir, app.packageName, appMd5, ZeroTrustMode.isEnabled(context)));
                long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
                addTiming("NativeScanner", nativeMs);
                Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                    + " NativeScanner=" + nativeMs + "ms slowest=NativeScanner");
                if (v == null) continue;
                // Per-detection suppression (a hit inside a whitelisted APK is an
                // FP; a non-APK virus alongside it is not). Nothing survives → skip.
                List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
                if (live.isEmpty()) { reportFileScanned(new java.io.File(app.sourceDir)); continue; }
                ThreatResult.Builder b = new ThreatResult.Builder(
                    app.packageName != null ? app.packageName : app.sourceDir);
                List<String> reasons = new java.util.ArrayList<>();
                boolean real = false;
                boolean eicar = false;
                boolean autoOnly = false;
                for (NativeScanner.Verdict.Detection d : live) {
                    if ("ML".equals(d.name)) {
                        if (DetectionCategories.isEnabled(context, DetectionCategories.ML)) real = true;
                        continue;
                    }
                    if (isEicarName(d.name)) {
                        if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                            eicar = true; reasons.add("🧪 [TEST] " + d.name);
                        }
                        continue;
                    }
                    if (isDexHeuristicName(d.name)) continue;
                    boolean pua = isPuaName(d.name);
                    boolean auto = isAutoGeneratedName(d.name);
                    String category = pua ? DetectionCategories.PUA
                        : auto ? DetectionCategories.AUTO_RULES
                        : DetectionCategories.SIGNATURES;
                    if (!DetectionCategories.isEnabled(context, category)) continue;
                    if (auto) autoOnly = true;
                    if (!pua && !auto) real = true;
                    reasons.add((pua ? "⚠️ [PUA] " : auto ? "❔ [AUTO] " : "🛡️ [SIG] ") + d.name);
                }
                if (real) {
                    // Auto-signature generation only on an actual confirmed virus,
                    // gated behind the (default-off) Settings toggle.
                    if (AutoRuleGeneration.isEnabled(context)) saveGeneratedRule(v);
                }
                boolean anyEvidence = real || eicar || autoOnly || !reasons.isEmpty();
                if (!anyEvidence) { reportFileScanned(new java.io.File(app.sourceDir)); continue; }
                b.setThreatType(real
                    ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE
                    : eicar
                        ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.TEST_MALWARE
                        : autoOnly
                            ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS
                            : com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                b.setRiskScore(real ? 100 : autoOnly ? 30 : 50);
                if (v.md5 != null && !v.md5.isEmpty())
                    reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.md5);
                b.setReasons(reasons);
                CharSequence label = pm.getApplicationLabel(app);
                b.setAppName((label != null ? label.toString() : app.packageName) + " (DEEP)");
                b.setApkPath(app.sourceDir);
                ThreatResult r = b.build();
                if (r.isThreat()) {
                    threats.add(r);
                    if (app.packageName != null) seen.add(app.packageName);
                    if (callback != null) callback.onThreatFound(r);
                }
                reportFileScanned(new java.io.File(app.sourceDir));
            } catch (Throwable ignore) { }
        }
    }

    /** 3) Recently-active processes. Android 8+ restricts getRunningAppProcesses
     *  to our own process, so we use UsageStats to find recently-run packages and
     *  make sure they were analyzed. */
    private void scanRecentProcesses(PackageManager pm, List<ThreatResult> threats) {
        try {
            android.app.usage.UsageStatsManager usm = (android.app.usage.UsageStatsManager)
                context.getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm == null) return;
            long now = System.currentTimeMillis();
            java.util.List<android.app.usage.UsageStats> stats = usm.queryUsageStats(
                android.app.usage.UsageStatsManager.INTERVAL_DAILY, now - 24L * 3600 * 1000, now);
            if (stats == null) return;
            java.util.HashSet<String> seen = new java.util.HashSet<>();
            for (ThreatResult t : threats) if (t.getPackageName() != null) seen.add(t.getPackageName());
            for (android.app.usage.UsageStats s : stats) {
                if (cancelRequested) return;
                String pkg = s.getPackageName();
                if (pkg == null || seen.contains(pkg) || pkg.equals(context.getPackageName())) continue;
                seen.add(pkg);
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                    ThreatResult r = analyzeApp(ai, pm, false);
                    if (r != null && r.isThreat()) {
                        threats.add(r);
                        if (callback != null) callback.onThreatFound(r);
                    }
                    int n = appsScannedBase + filesScannedCount.incrementAndGet();
                    if (callback != null) callback.onProgress(n, n, pkg);
                } catch (Throwable ignore) { }
            }
        } catch (Throwable ignore) { }
    }

    /** 4) Accessible app-data & system directories (best effort; most need root,
     *  unreadable ones are silently skipped). */
    private void scanAccessibleDataDirs(PackageManager pm, List<ThreatResult> threats) {
        // No system directories (/system, /vendor, /product) — never scan/flag
        // system files. Only user-accessible app data.
        String[] roots = {
            "/sdcard/Android/data", "/sdcard/Android/obb", "/data/local/tmp"
        };
        for (String r : roots) {
            if (cancelRequested) return;
            try {
                java.io.File f = new java.io.File(r);
                if (f.isDirectory() && f.canRead()) scanDirectoryForApks(f, pm, threats, true);
            } catch (Throwable ignore) { }
        }
    }

    public ThreatResult analyzeSingleApp(ApplicationInfo app, PackageManager pm, boolean isApkFile) {
        return analyzeApp(app, pm, isApkFile);
    }

    public ThreatResult analyzeApp(ApplicationInfo app, PackageManager pm, boolean isApkFile) {
        if (app.packageName != null && photonCache.containsKey(app.packageName)) {
            Log.i(TAG, "Photon Cache Hit: " + app.packageName);
            return photonCache.get(app.packageName);
        }

        ThreatResult.Builder builder = new ThreatResult.Builder(app.packageName);

        // Never flag ourselves — exact match against our release + debug package
        // (debug build's packageName has a ".debug" suffix; a scanned own-APK
        // file reports the release id). equals(), not startsWith(), so malware
        // can't self-whitelist with a "com.hydradragon.antivirus.evil" prefix.
        if (app.packageName != null
            && (app.packageName.equals(context.getPackageName())
                || app.packageName.equals("com.hydradragon.antivirus")
                || app.packageName.equals("com.hydradragon.antivirus.debug"))) {
            builder.setRiskScore(0); return builder.build();
        }

        boolean isSystem = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0
            || (app.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
        if (app.sourceDir != null && (app.sourceDir.startsWith("/system/")
            || app.sourceDir.startsWith("/vendor/") || app.sourceDir.startsWith("/product/")
            || app.sourceDir.startsWith("/oem/") || app.sourceDir.startsWith("/odm/")
            || app.sourceDir.startsWith("/apex/"))) isSystem = true;
        if (isSystem) {
            Log.d(TAG, "CLEAR-EXIT[isSystem] " + app.packageName + " sourceDir=" + app.sourceDir);
            builder.setRiskScore(0); return builder.build();
        }

        boolean isFromStore = false;
        if (!isApkFile) {
            try {
                String installer = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R
                    ? pm.getInstallSourceInfo(app.packageName).getInstallingPackageName()
                    : pm.getInstallerPackageName(app.packageName);
                if (installer != null && (installer.equals("com.android.vending")
                    || installer.equals("com.sec.android.app.samsungapps")
                    || installer.equals("com.xiaomi.mipicks")
                    || installer.equals("com.huawei.appmarket")
                    || installer.equals("com.heytap.market")
                    || installer.equals("com.oppo.market"))) isFromStore = true;
            } catch (Exception e) { }
        }

        // Auto-clear requires TWO things together (neither alone is enough):
        //   1. a trusted-store install (isFromStore) — OS-enforced, hard to spoof, AND
        //   2. a known-good NSRL package name (isPackageWhitelisted).
        // A trusted store alone isn't trusted blindly (store malware exists); a
        // package name alone is spoofable (sideloaded impersonation). Requiring
        // both — a known app installed through a real store — is safe. System
        // apps already returned clean above; the `com.google.*` prefix list is
        // removed entirely. (Exact SHA-256 hash match still clears in the native
        // deep scan, independently.)
        if (isFromStore && isPackageWhitelisted(app.packageName)) {
            Log.d(TAG, "CLEAR-EXIT[store+NSRL-whitelisted] " + app.packageName);
            builder.setRiskScore(0); return builder.build();
        }

        // User previously marked this app safe ("Safe (ignore)") -> never flag.
        if (app.packageName != null && UserDecisions.isThreatAllowed(context, app.packageName)) {
            Log.d(TAG, "CLEAR-EXIT[user-allowed] " + app.packageName);
            builder.setRiskScore(0); return builder.build();
        }

        int riskScore = 0;
        boolean isWhitelisted = false;
        List<String> reasons = new ArrayList<>();
        String fileMd5Vt = null;   // top-level file MD5 from the native scan (for the VirusTotal link)
        String companyName = "Unknown Developer";
        String signatureHash = "NONE";
        // Captured for the Zero Trust "full known details" dump below — only
        // used when NOTHING else flagged this app (riskScore stays 0).
        List<String> requestedPermissions = new ArrayList<>();
        List<String> nativePackages = new ArrayList<>();
        List<String> nativeHashes = new ArrayList<>();
        int dangerousPermCount = -1;
        String mlSummary = null;

        try {
            PackageInfo pkgInfo = isApkFile
                ? pm.getPackageArchiveInfo(app.sourceDir, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES)
                : pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);

            if (pkgInfo != null && pkgInfo.requestedPermissions != null) {
                requestedPermissions.addAll(Arrays.asList(pkgInfo.requestedPermissions));
            }
            if (pkgInfo != null && pkgInfo.signatures != null && pkgInfo.signatures.length > 0) {
                Signature sig = pkgInfo.signatures[0];
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(sig.toByteArray()));
                String subject = cert.getSubjectDN().getName();
                for (String part : subject.split(","))
                    if (part.trim().startsWith("O=")) { companyName = part.trim().substring(2); break; }

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(sig.toByteArray());
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) { String h = Integer.toHexString(0xff & b); if (h.length()==1) sb.append('0'); sb.append(h); }
                signatureHash = sb.toString().toUpperCase().substring(0, 16) + "...";

                for (String trusted : TRUSTED_COMPANIES)
                    if (companyName.toLowerCase().contains(trusted)) {
                        isWhitelisted = true;
                        Log.d(TAG, "TRUSTED_COMPANIES match: " + app.packageName
                            + " companyName=\"" + companyName + "\" matched=\"" + trusted + "\" — signature checks skipped");
                        break;
                    }

                if (!isWhitelisted && (subject.contains("Android Debug") || subject.contains("test-keys"))) {
                    riskScore += 60;
                    reasons.add("INSECURE CERTIFICATE (Test Key)");
                }
            } else {
                riskScore += 100;
                reasons.add("CRITICAL: Digital signature not found!");
            }

            // Dangerous-permission DETECTION lives in the native (Rust) engine —
            // it counts them from the manifest bytes (works for in-memory/inner
            // APKs too). The 5/6 DECISION is applied below in Java where `v` is in
            // scope, so Java still owns the verdict + whitelist.
        } catch (Exception e) { }

        if (!isWhitelisted) {
            try {
                String apkPath = (isApkFile && app.sourceDir != null) ? app.sourceDir
                    : pm.getPackageInfo(app.packageName, 0).applicationInfo.sourceDir;
                // CodeAnalyzer is a cheap Java-side heuristic (raw substring search
                // over DEX bytes — "DexClassLoader", "Runtime.exec", etc). Those
                // strings show up in plenty of LEGITIMATE apps (plugin loaders,
                // shell helpers, reflection-based libraries), so on their own they
                // are NOT proof of malware. Its verdict is applied further down,
                // ONLY if the real engine (native YARA/ClamAV signatures, the ML
                // model, or a high dangerous-permission count) corroborates it —
                // "code smells like malware" plus "the antivirus also found
                // something" is what actually earns a MALWARE verdict.
                long codeT0 = android.os.SystemClock.elapsedRealtime();
                CodeAnalyzer.AnalysisResult codeResult = codeAnalyzer.analyzeApk(apkPath);
                long codeMs = android.os.SystemClock.elapsedRealtime() - codeT0;
                addTiming("CodeAnalyzer", codeMs);

                // Native engine: clamav (type-gated YARA + signatures) + ML model.
                // Hash-first: a known-good (whitelisted) APK skips the whole native
                // block. The file MD5 is computed once here and reused natively.
                // Size is checked BEFORE hashing — an oversized file shouldn't pay
                // for a full-file MD5 read just to be skipped a moment later.
                boolean withinSizeLimit = apkPath != null
                    && MaxScanFileSize.isWithinLimit(context, new java.io.File(apkPath));
                String apkMd5 = withinSizeLimit ? fileMd5(new java.io.File(apkPath)) : null;
                boolean nativeCorroborated = false;
                if (apkPath == null) {
                    Log.d(TAG, "NATIVE-SKIP[apkPath null] " + app.packageName);
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " CodeAnalyzer=" + codeMs + "ms NativeScanner=skipped slowest=CodeAnalyzer");
                } else if (!withinSizeLimit) {
                    Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + app.packageName + " path=" + apkPath);
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " CodeAnalyzer=" + codeMs + "ms NativeScanner=skipped(over-size-limit) slowest=CodeAnalyzer");
                } else if (!NativeScanner.isReady()) {
                    Log.d(TAG, "NATIVE-SKIP[engine not ready] " + app.packageName);
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " CodeAnalyzer=" + codeMs + "ms NativeScanner=skipped slowest=CodeAnalyzer");
                } else if (isHashWhitelisted(apkMd5)) {
                    Log.d(TAG, "NATIVE-SKIP[hash-whitelisted] " + app.packageName + " md5=" + apkMd5);
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " CodeAnalyzer=" + codeMs + "ms NativeScanner=skipped(hash-whitelisted) slowest=CodeAnalyzer");
                }
                if (withinSizeLimit && NativeScanner.isReady() && !isHashWhitelisted(apkMd5)) {
                    long nativeT0 = android.os.SystemClock.elapsedRealtime();
                    NativeScanner.Verdict v = runNativeInterruptible(() ->
                        NativeScanner.scan(apkPath, app.packageName, apkMd5, ZeroTrustMode.isEnabled(context)));
                    long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
                    addTiming("NativeScanner", nativeMs);
                    // Per-FILE breakdown (not the cumulative session totals
                    // logEngineTimings() prints at the end of a whole scan) —
                    // which engine was slowest for THIS specific app/file.
                    String slowestHere = nativeMs >= codeMs ? "NativeScanner" : "CodeAnalyzer";
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " CodeAnalyzer=" + codeMs + "ms NativeScanner=" + nativeMs
                        + "ms slowest=" + slowestHere);
                    Log.d(TAG, "NATIVE-RESULT " + app.packageName + " verdict="
                        + (v == null ? "NULL(cancelled/error)" : ("detections=" + v.detections.size()
                            + " permissions=" + v.permissions + " jaccard=" + v.jaccard + " anomaly=" + v.anomaly
                            + " error=" + v.error)));
                    // null = the scan was cancelled mid-file (see
                    // runNativeInterruptible) — NativeScanner.scan() itself
                    // never returns null. Skip the native-verdict processing
                    // below entirely rather than NPE on it.
                    if (v != null) {
                    fileMd5Vt = v.md5;
                    nativePackages.addAll(v.packages);
                    nativeHashes.addAll(v.hashes);
                    dangerousPermCount = v.permissions;
                    mlSummary = String.format(java.util.Locale.US,
                        "jaccard=%.2f anomaly=%.4f nearest=%s", v.jaccard, v.anomaly,
                        v.nearest != null ? v.nearest : "none");
                    // Per-detection whitelist suppression (hit inside a whitelisted
                    // APK = FP; non-APK virus alongside it survives).
                    List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
                    boolean mlMalicious = false;
                    if (!live.isEmpty()) {
                        // Split PUA.* / PUA_* hits (potentially-unwanted) and the
                        // EICAR test signature from real malware. Only-PUA (and no
                        // ML flag) => PUA, lower risk; EICAR-only => TEST_MALWARE,
                        // clearly labelled as a deliberate test, not a real threat.
                        boolean hasRealThreat = false;
                        boolean hasEicar = false;
                        boolean hasAutoOnly = false;
                        for (NativeScanner.Verdict.Detection d : live) {
                            if ("ML".equals(d.name)) {
                                if (DetectionCategories.isEnabled(context, DetectionCategories.ML)) {
                                    mlMalicious = true; hasRealThreat = true;
                                }
                                continue;
                            }
                            if (isEicarName(d.name)) {
                                if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                                    hasEicar = true; reasons.add("🧪 [TEST] " + d.name);
                                }
                                continue;
                            }
                            // Native DEX static-analysis heuristic ("DEX/High: ...")
                            // is dropped entirely — a raw code-pattern smell test,
                            // too false-positive-prone to count toward a verdict at
                            // all (unlike YARA.auto_*, which at least matched a
                            // concrete signature this device confirmed once before).
                            if (isDexHeuristicName(d.name)) continue;
                            boolean isPua = isPuaName(d.name);
                            boolean isAuto = isAutoGeneratedName(d.name);
                            String category = isPua ? DetectionCategories.PUA
                                : isAuto ? DetectionCategories.AUTO_RULES
                                : DetectionCategories.SIGNATURES;
                            if (!DetectionCategories.isEnabled(context, category)) continue;
                            if (isAuto) hasAutoOnly = true;
                            if (!isPua && !isAuto) hasRealThreat = true;
                            reasons.add((isPua ? "⚠️ [PUA] " : isAuto ? "❔ [AUTO] " : "🛡️ [SIG] ") + d.name);
                        }
                        // Decide by what actually survived category gating
                        // (reasons/hasRealThreat), not just "live wasn't empty"
                        // — otherwise a fully category-disabled hit would
                        // still fall through to a PUA verdict with nothing to
                        // show for it.
                        if (hasRealThreat) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                            nativeCorroborated = true;
                            // Auto-signature generation only on an actual confirmed
                            // virus (not PUA-only, not EICAR test, not an auto-rule
                            // hit) — same rule in both normal and Zero Trust mode.
                            // Off by default (high FP risk) — user must opt in.
                            if (AutoRuleGeneration.isEnabled(context)) saveGeneratedRule(v);
                        } else if (hasEicar) {
                            riskScore = Math.max(riskScore, 50);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.TEST_MALWARE);
                        } else if (hasAutoOnly) {
                            // Only a self-learned "YARA.auto_*" rule matched — a
                            // heuristic, not a vetted signature, so treated as
                            // low-confidence/uncertain rather than a firm verdict.
                            // Still >= isThreat()'s 30 threshold so it's not
                            // silently invisible in results.
                            riskScore = Math.max(riskScore, 30);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                        } else if (!reasons.isEmpty()) {
                            // Only PUA signatures matched.
                            riskScore = Math.max(riskScore, 50);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                        }
                        if (mlMalicious) {
                            String near = v.nearest != null ? "  ~" + v.nearest : "";
                            reasons.add(String.format(java.util.Locale.US,
                                "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
                        }
                    } else if (v.isError()) {
                        Log.w(TAG, "native scan error: " + v.error);
                    }

                    // Two-tier dangerous-permission decision on the native count
                    // (the full 36-permission "dangerous" set — see lib.rs
                    // DANGEROUS_PERMS: SMS, call/phone, contacts, location, mic,
                    // camera, calendar, sensors, nearby devices, storage, overlay).
                    // 10+ = almost certainly malware; exactly 9 = suspicious —
                    // calibrated one above Malwarebytes' own footprint (8/36).
                    if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                        if (v.permissions >= 10) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                            reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/36)");
                            nativeCorroborated = true;
                        } else if (v.permissions == 9) {
                            riskScore = Math.max(riskScore, 30);
                            if (riskScore < 50) builder.setThreatType(
                                com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                            reasons.add("🔐 Suspicious permissions (9/36)");
                            nativeCorroborated = true;
                        }
                    }
                    } // end if (v != null)
                }

                // Apply CodeAnalyzer's heuristic verdict now that the real engine has
                // had a chance to weigh in. Corroborated (native signature/YARA hit,
                // ML flag, or 6+ dangerous permissions) => full weight, genuine
                // finding. NOT corroborated => discarded entirely — a raw DEX
                // substring hit ("DexClassLoader", "Runtime.exec", etc.) with no
                // real-engine backing is noise, not evidence, and was showing up as
                // a "[CODE, unverified by engine]" reason on completely clean apps.
                if (codeResult.isMalicious && nativeCorroborated) {
                    riskScore = Math.min(100, riskScore + codeResult.riskScore);
                    if (riskScore >= 60) builder.setThreatType(codeResult.threatType);
                    for (String finding : codeResult.findings) {
                        if (!finding.startsWith("✅")) reasons.add("💻 [CODE] " + finding);
                    }
                }

                // (URL-based APK scan removed — too slow and false-positive prone:
                //  it unzipped every APK and flagged legitimate embedded URLs.)
            } catch (Exception e) { }
        }

        // Runtime behaviour flag (set by the dynamic-analysis accessibility
        // service when this app spammed UI events). Behaviour overrides — a
        // benign-looking package that misbehaves at runtime is malware.
        if (!isWhitelisted && app.packageName != null) {
            String behaviour = BehaviorFlags.reasonFor(context, app.packageName);
            if (behaviour != null) {
                riskScore = 100;
                builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                reasons.add("🧠 [BEHAVIOUR] " + behaviour);
            }
        }

        if (riskScore > 0 && !isWhitelisted) {
            reasons.add("✍️ Signature: " + companyName);
            reasons.add("🔐 SHA-256: " + signatureHash);
            if (fileMd5Vt != null && !fileMd5Vt.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + fileMd5Vt);
            }
        }

        // Zero Trust Mode: NONE of clamav/YARA, the ML model, DEX static
        // analysis, permissions, code analysis or behaviour flagged anything
        // (riskScore still 0) — normally that means "clean". With Zero Trust
        // on, refuse to call it clean: report SUSPICIOUS instead and attach
        // every known detail so the user decides, not the (absent) verdict.
        if (riskScore == 0 && !isWhitelisted && ZeroTrustMode.isEnabled(context)) {
            riskScore = 30; // matches ThreatResult.isThreat()'s threshold — surfaces the app in the threat list
            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.UNKNOWN);
            reasons.add("⚠️ ZERO TRUST: no detector matched this app — verdict is UNKNOWN, "
                + "not confirmed clean (not recommended: expect false positives on ordinary apps)");
            reasons.add("✍️ Signature: " + companyName);
            reasons.add("🔐 SHA-256: " + signatureHash);
            reasons.add("🔐 Dangerous permissions matched: "
                + (dangerousPermCount >= 0 ? dangerousPermCount + "/36" : "not scanned"));
            if (!requestedPermissions.isEmpty()) {
                reasons.add("📋 All requested permissions (" + requestedPermissions.size() + "): "
                    + String.join(", ", requestedPermissions));
            }
            if (!nativePackages.isEmpty()) {
                reasons.add("📦 Package(s) reached in-memory: " + String.join(", ", nativePackages));
            }
            if (!nativeHashes.isEmpty()) {
                reasons.add("🔍 APK/zip buffer hash(es): " + String.join(", ", nativeHashes));
            }
            if (mlSummary != null) {
                reasons.add("🤖 [ML] " + mlSummary);
            }
            if (fileMd5Vt != null && !fileMd5Vt.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + fileMd5Vt);
            }
            String netJson = NetworkObservations.buildReportJson(app.packageName);
            if (!netJson.isEmpty()) {
                reasons.add("🌐 Observed network/screen activity: " + netJson);
            }
        }

        builder.setRiskScore(riskScore);
        builder.setReasons(reasons);
        if (riskScore >= 30 && builder.build().getThreatType() == com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN) {
            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
        }
        CharSequence appName = pm.getApplicationLabel(app);
        if (appName == null || appName.toString().contains("com."))
            appName = new java.io.File(app.sourceDir).getName();
        if (isApkFile) appName = appName + " (SD CARD)";
        builder.setAppName(appName.toString());
        builder.setApkPath(app.sourceDir);
        
        ThreatResult finalRes = builder.build();
        if (app.packageName != null) photonCache.put(app.packageName, finalRes);
        return finalRes;
    }
}
