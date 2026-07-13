package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
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

    // Permissions that, alone, are common in legitimate apps, but combined with
    // "this app has no launcher icon" are the classic stealth-rootkit pattern:
    // install silently, hide from the app drawer, then persist/escalate via one
    // of these. Device-admin/accessibility grant near-total device control;
    // SYSTEM_ALERT_WINDOW enables overlay attacks; boot-completed + one of the
    // others gives silent persistence across reboots with no visible icon ever
    // needed to relaunch it.
    private static final List<String> ROOTKIT_SUSPICIOUS_PERMS = Arrays.asList(
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.PACKAGE_USAGE_STATS"
    );

    /** True iff the package declares no currently-enabled launcher (home-screen
     *  icon) activity — i.e. it can't be opened from the app drawer at all. A
     *  freshly-installed app with zero launcher entry points is unusual: most
     *  legitimate "headless" apps (widgets, wear companions, some system
     *  services) are already filtered out upstream by the isSystem/whitelist
     *  checks in analyzeApp, so by the time this runs a hit here is meaningful. */
    private boolean hasNoLauncherIcon(PackageManager pm, String packageName) {
        try {
            Intent launchIntent = new Intent(Intent.ACTION_MAIN);
            launchIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            launchIntent.setPackage(packageName);
            List<ResolveInfo> launchables = pm.queryIntentActivities(launchIntent, 0);
            return launchables.isEmpty();
        } catch (Exception e) {
            return false; // can't determine — don't guess
        }
    }

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
    // Process-wide, bounded below the device's core count. GuardService and
    // InstallReceiver each hold their own ScanEngine instance (InstallReceiver
    // creates a brand new one per install broadcast), so a per-instance pool —
    // especially the old unbounded cachedThreadPool below — let concurrent
    // scan triggers pile up many more native (JNI/Rust) threads than the
    // useful CPU budget. Each native ClamAV/YARA call is CPU-bound and may spawn
    // its own helper thread, so running one or two scans at a time is usually
    // faster on phones than saturating every core and forcing heavy preemption.
    // Sharing one bounded pool across every ScanEngine instance caps how many
    // native calls run at once, regardless of how many scan triggers fired.
    private static final int NATIVE_PARALLELISM =
        Math.max(1, Math.min(2, Runtime.getRuntime().availableProcessors() / 2));
    // These pools run CPU-bound native (clamav/YARA/ML/TLSH) work at normal
    // thread priority by default, which competes evenly with the UI thread's
    // Choreographer/render thread for CPU time and causes dropped frames
    // ("Skipped N frames"/"Davey!") during a scan on lower-core devices.
    // THREAD_PRIORITY_BACKGROUND tells the OS scheduler to favor the
    // renderer, at the cost of the scan itself taking a bit longer.
    private static final java.util.concurrent.ThreadFactory backgroundPriorityFactory = r ->
        new Thread(() -> {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
            r.run();
        });
    private static final ExecutorService scanExecutor =
        Executors.newFixedThreadPool(NATIVE_PARALLELISM, backgroundPriorityFactory);
    // Dedicated pool for wrapping blocking native (JNI/Rust) calls so cancelScan()
    // can take effect almost immediately instead of Stop waiting out however
    // long the CURRENT file's native scan takes (large files can take seconds;
    // the native side has no interruption point). See runNativeInterruptible.
    private static final ExecutorService nativeCallExecutor =
        Executors.newFixedThreadPool(NATIVE_PARALLELISM, backgroundPriorityFactory);
    // Small bounded pool for the lightweight orchestration wrappers that used
    // to be raw `new Thread(...).start()` calls in GuardService (per-download
    // scan) and InstallReceiver (per-install scan) — those threads don't do
    // CPU-bound work themselves (they mostly poll/sleep waiting on the actual
    // native call, which already goes through nativeCallExecutor above), but
    // spawning a brand new unmanaged OS thread per download/install burst
    // still adds scheduling overhead with no cap. Deliberately separate from
    // scanExecutor/nativeCallExecutor so orchestration wrappers can never
    // starve out a slot that real native scan work needs.
    private static final ExecutorService orchestrationExecutor =
        Executors.newFixedThreadPool(4);

    /** Submit a lightweight orchestration task (e.g. the per-download or
     *  per-install scan wrapper) to a small shared bounded pool instead of
     *  spawning a raw unmanaged thread. */
    public static void runOrchestrated(Runnable task) {
        orchestrationExecutor.execute(task);
    }

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

    private boolean photonCacheEnabled() {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("scan_cache_enabled", true);
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
    // SHA-256 hash whitelist now lives in NATIVE memory (xor filter) — see
    // NativeScanner.isHashWhitelisted — so the large NSRL set never sits in the
    // Java heap. isHashWhitelisted() below delegates to it.
    /** EXACT known-good package names (NSRL Android, extension=apk). NOT a
     *  standalone clear — a package name is spoofable, so it only clears an app
     *  when combined with a trusted-store install (see analyzeApp). */
    private final java.util.HashSet<String> whitelistPackages = new java.util.HashSet<>();
    /** Set by {@link #cancelScan()} to abort an in-flight scan at the next loop
     *  boundary. Volatile so the UI thread's request is seen by the scan thread. */
    private volatile boolean cancelRequested = false;
    
    /** Request the running scan to pause. Unlike cancel, pause preserves progress
     *  and allows resuming from where it left off. */
    private volatile boolean pauseRequested = false;

    /** Request the running scan to stop as soon as possible. Native calls
     *  in flight are ABANDONED (see runNativeInterruptible), not killed —
     *  they keep running to completion on their own thread, but the scan loop
     *  stops waiting for them almost immediately instead of blocking until
     *  they return. analyzeApp will skip caching the current app's result
     *  when cancelRequested is true, so the next scan re-evaluates it fresh. */
    public void cancelScan() {
        cancelRequested = true;
        pauseRequested = false; // Cancel overrides pause
    }

    /** Pause the running scan. Can be resumed with {@link #resumeScan()}. */
    public void pauseScan() {
        pauseRequested = true;
    }

    /** Resume a paused scan. */
    public void resumeScan() {
        pauseRequested = false;
    }

    /** Whether a stop was requested for the current/last scan. */
    public boolean isCancelled() { return cancelRequested; }
    
    /** Whether the scan is currently paused. */
    public boolean isPaused() { return pauseRequested; }

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
    /** Run a PackageManager blocking call on a background thread with a 5-second
     *  timeout. Vivo ROMs hang forever in AconfigFlags static init under
     *  getPackageArchiveInfo/getPackageInfo — this detects the hang, marks the
     *  analyzer as permanently broken (apkPkgAnalyzerBroken), and returns null so
     *  the caller degrades gracefully instead of blocking the scan thread. Once
     *  the flag is set, subsequent calls return null immediately without
     *  submitting work. */
    private PackageInfo runPkgInfoInterruptible(java.util.concurrent.Callable<PackageInfo> call) {
        if (apkPkgAnalyzerBroken) return null;
        java.util.concurrent.Future<PackageInfo> future = orchestrationExecutor.submit(call);
        try {
            return future.get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException te) {
            apkPkgAnalyzerBroken = true;
            Log.w(TAG, "getPackageArchiveInfo/getPackageInfo timed out after 5s"
                + " (Vivo AconfigFlags deadlock) — permanently disabled");
            return null;
        } catch (Throwable e) {
            // Plain exception/error (Vivo throws ExceptionInInitializerError too).
            // Mark broken so we don't retry next call.
            apkPkgAnalyzerBroken = true;
            Log.w(TAG, "getPackageArchiveInfo/getPackageInfo failed", e);
            return null;
        }
    }

    private NativeScanner.Verdict runNativeInterruptible(java.util.concurrent.Callable<NativeScanner.Verdict> call) {
        // Don't submit at all if we're already cancelled: nativeCallExecutor only
        // has 1-2 threads (NATIVE_PARALLELISM), and an "abandoned" call keeps
        // running to completion occupying a slot for however long that file
        // takes (seconds on a big APK). Submitting one anyway after cancel just
        // queues real work behind a result nobody will use, delaying every file
        // after it — this is what made scans look stuck/slow to resume.
        if (cancelRequested) return null;
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
            // Routed through the same bounded nativeCallExecutor as every other
            // native call (rather than calling NativeScanner.scan directly on
            // the caller's thread) so this one-off, user-triggered scan still
            // counts against — and waits its turn behind — the shared native
            // call budget instead of running as an extra, uncapped thread.
            NativeScanner.Verdict v = nativeCallExecutor
                .submit(() -> NativeScanner.scan(apkPath, packageName, null, true))
                .get();
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
     *  "DEX/High: ..." or "DEX/Critical: ...". Only "DEX/Critical: ..." is
     *  trusted as a real finding — everything below that severity is a raw
     *  code-pattern smell (legitimate apps like plugin loaders or obfuscated
     *  but benign SDKs routinely trip it) and is still dropped entirely. */
    private static boolean isDexHeuristicName(String name) {
        return name != null && name.startsWith("DEX/") && !name.startsWith("DEX/Critical");
    }

    private void loadPackageWhitelist() {
        // Known-good NSRL package keys (whitelist_packages.db, table
        // whitelist_package, column "key" = package_id^^file_name) into an exact
        // HashSet. Only clears an app WITH a trusted-store install (spoofable
        // alone). The SHA-256 hash whitelist is separate and lives natively
        // (xor filter) — see NativeScanner.isHashWhitelisted.
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
     *  Delegates to the native xor filter whitelist (native memory). */
    private boolean isHashWhitelisted(String hash) {
        return hash != null && NativeScanner.isHashWhitelisted(hash.toLowerCase(java.util.Locale.US));
    }

    /** True if {@code pkg} is an exact known-good NSRL package name. Spoofable on
     *  its own, so callers must combine it with a trusted-store install. */
    private boolean isPackageWhitelisted(String pkg) {
        return pkg != null && whitelistPackages.contains(pkg);
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
        pauseRequested = false;
        apkPkgAnalyzerBroken = false;
        engineTimingMs.clear();
        filesScannedCount.set(0);
        scanExecutor.execute(() -> {
          try {
            long scanStartMs = android.os.SystemClock.elapsedRealtime();
            PackageManager pm = context.getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<ThreatResult> threats = new ArrayList<>();
            int total = apps.size();
            appsScannedBase = total;

            for (int i = 0; i < total; i++) {
                if (cancelRequested) break;
                
                // Pause handling: wait while paused, wake up every 100ms to check
                while (pauseRequested && !cancelRequested) {
                    try { Thread.sleep(100); } catch (InterruptedException e) { break; }
                }
                if (cancelRequested) break;
                
                ApplicationInfo app = apps.get(i);
                try {
                    if (callback != null) callback.onProgress(i + 1, total, app.packageName);
                    ThreatResult result = analyzeApp(app, pm, false);
                    if (result != null && result.isThreat() && !threats.contains(result)) {
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
            long elapsedMs = android.os.SystemClock.elapsedRealtime() - scanStartMs;
            int scannedTotal = total + filesScannedCount.get() + threats.size();
            if (callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats, elapsedMs));
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
        pauseRequested = false;
        apkPkgAnalyzerBroken = false;
        engineTimingMs.clear();
        filesScannedCount.set(0);
        appsScannedBase = 0;
        scanExecutor.execute(() -> {
          try {
            long scanStartMs = android.os.SystemClock.elapsedRealtime();
            PackageManager pm = context.getPackageManager();
            List<ThreatResult> threats = new ArrayList<>();
            scanDirectoryForApks(dir, pm, threats, true);
            logEngineTimings();
            long elapsedMs = android.os.SystemClock.elapsedRealtime() - scanStartMs;
            int scannedTotal = filesScannedCount.get() + threats.size();
            if (callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats, elapsedMs));
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
            
            // Pause handling
            while (pauseRequested && !cancelRequested) {
                try { Thread.sleep(100); } catch (InterruptedException e) { break; }
            }
            if (cancelRequested) return;
            
            // Still mid-download (MediaStore's ".pending-<id>-realname" temp
            // file) — guaranteed incomplete, parsing it as a zip/APK fails
            // outright. It'll get scanned under its real name once the
            // download finishes and the system renames it away from this.
            if (file.getName().startsWith(".pending-")) continue;
            if (cancelRequested) return;
            if (file.isDirectory()) {
                scanDirectoryForApks(file, pm, threats, fullScan, skipPackages);
            } else if (file.getName().toLowerCase().endsWith(".apk")) {
                // runPkgInfoInterruptible handles Vivo ROM hangs/timeouts internally
                // and sets apkPkgAnalyzerBroken.
                PackageInfo pkgInfo = runPkgInfoInterruptible(() ->
                    pm.getPackageArchiveInfo(file.getAbsolutePath(),
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES));
                if (pkgInfo != null) {
                    String pkgName = pkgInfo.applicationInfo.packageName;
                    if (skipPackages != null && pkgName != null && skipPackages.contains(pkgName)) {
                        continue;
                    }
                    pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                    pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                    ThreatResult result = analyzeApp(pkgInfo.applicationInfo, pm, true);
                    if (result != null && result.isThreat() && !threats.contains(result)) {
                        threats.add(result);
                        if (callback != null) callback.onThreatFound(result);
                    }
                }
                if (!cancelRequested) reportFileScanned(file);
            } else if (fullScan) {
                // Non-APK file in a full scan: route through the native engine
                // (hydradragonextractor unpacking + clamav/YARA + ML). Permission
                // analysis doesn't apply — it isn't an installable app.
                scanGenericFile(file, threats);
                if (!cancelRequested) reportFileScanned(file);
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
    /** Set once the system {@code AconfigFlags} / {@code PackageParser2} static
     *  init fails on this device (e.g. missing /vendor/etc/aconfig_flags.pb on
     *  Vivo ROMs). Once set, every future call to
     *  {@code PackageManager.getPackageArchiveInfo} would throw
     *  {@code NoClassDefFoundError} anyway, so skip the whole APK analysis path
     *  and fall through directly to the native engine. Reset at the start of
     *  each full/custom-folder scan (see scanAllApps/scanCustomFolder) — a
     *  single early Vivo crash used to permanently degrade PackageManager-
     *  based analysis (permissions/signature/whitelist checks) for every APK
     *  in every scan for the rest of the process, not just the run that hit
     *  it; re-probing each scan lets a later successful call recover. */
    private static volatile boolean apkPkgAnalyzerBroken;

    public ThreatResult scanSingleFile(java.io.File file) {
        // scanAllApps/scanCustomFolder reset this at their own start, but this
        // entry point (manual single-file scan) didn't — so a Stop pressed on
        // a PREVIOUS scan left cancelRequested permanently true on this shared
        // ScanEngine instance, and every manual scan after that silently
        // returned null at the first runNativeInterruptible check below,
        // looking exactly like "can't be scanned".
        cancelRequested = false;
        if (file == null || !file.exists()) return null;
        // If the file looks like an APK (named .apk AND starts with PK zip magic),
        // try the PackageManager analysis path. Otherwise skip straight to the
        // native engine to avoid noisy framework errors on non-APK content.
        String name = file.getName().toLowerCase(java.util.Locale.US);
        if (name.endsWith(".apk") && !apkPkgAnalyzerBroken) {
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(file, "r")) {
                byte[] magic = new byte[4];
                if (raf.read(magic) == 4 && magic[0] == 0x50 && magic[1] == 0x4b
                        && magic[2] == 0x03 && magic[3] == 0x04) {
                    PackageInfo pkgInfo = runPkgInfoInterruptible(() ->
                        context.getPackageManager().getPackageArchiveInfo(file.getAbsolutePath(),
                            PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES));
                    if (pkgInfo != null) {
                        pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                        pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                        ThreatResult result = analyzeApp(pkgInfo.applicationInfo, context.getPackageManager(), true);
                        if (result != null && result.isThreat()) return result;
                    }
                }
            } catch (Throwable e) {
                // Residual: RandomAccessFile I/O error (getPackageArchiveInfo is
                // on this Vivo build its internal PackageParser2 static init
                // (ParsingPackageUtils.<clinit> -> AconfigFlags.<init>) throws
                // ExceptionInInitializerError — an Error, not an Exception — when
                // it can't open its aconfig flags file (ENOENT). catch(Exception)
                // let that fall through uncaught, killing the whole scan thread
                // and restarting the app process. Catch Throwable here instead so
                // this ROM bug degrades to "fall through to native engine", not a
                // crash. Once it fails once, the class is permanently broken, so
                // set the flag to skip getPackageArchiveInfo entirely next time.
                apkPkgAnalyzerBroken = true;
                Log.w(TAG, "scanSingleFile: getPackageArchiveInfo failed for " + file.getAbsolutePath(), e);
            }
        }
        List<ThreatResult> out = new ArrayList<>();
        if (!scanGenericFile(file, out)) {
            // Genuinely crashed before reaching a verdict — NOT the same as
            // "scanned, found nothing". Throwing here (unchecked, no signature
            // change needed) lets both existing callers' Throwable/Exception
            // catches do the right thing: ScanFragment.scanCustomFile's second
            // try block shows error_scanning_file instead of falsely reporting
            // "System clean", and GuardService.scanDownloadedFile's
            // catch (Throwable t) logs it the same as any other scan failure.
            throw new RuntimeException("scanGenericFile failed for " + file.getAbsolutePath());
        }
        return out.isEmpty() ? null : out.get(0);
    }

    /** True if {@code file} IS our own running APK on disk (its installed
     *  sourceDir/publicSourceDir) — e.g. a full-scan directory walk reaching
     *  into /data/app, or a raw-file scan path that never went through
     *  analyzeApp()'s package-name exclusion. equals() against the real
     *  installed path, not a name/prefix guess. */
    private boolean isOwnAppFile(java.io.File file) {
        try {
            String path = file.getAbsolutePath();
            android.content.pm.ApplicationInfo self = context.getApplicationInfo();
            return path.equals(self.sourceDir) || path.equals(self.publicSourceDir);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Scan an arbitrary (non-APK) file with the native engine during a full
     * scan. The native side unpacks archives (zip/gz/tar/xz/lzma/7z/rar — so a
     * nested APK is reached too) and runs clamav signatures, YARA and the ML
     * model on every extracted buffer.
     */
    private boolean scanGenericFile(java.io.File file, List<ThreatResult> threats) {
        try {
            if (!NativeScanner.isReady()) {
                // Engine may still be loading its signature DBs in the
                // background (up to ~70s, see NativeScanner.init) — wait for
                // it instead of silently reporting "clean" (false negative,
                // e.g. EICAR going undetected on slower real devices).
                Log.i(TAG, "scanGenericFile: native engine not ready yet, waiting for "
                    + file.getAbsolutePath());
                if (!NativeScanner.waitUntilReady(90_000)) {
                    Log.w(TAG, "scanGenericFile: native engine still not ready after wait, "
                        + "skipping " + file.getAbsolutePath());
                    return true;
                }
            }
            if (isOwnAppFile(file)) return true;
            if (!MaxScanFileSize.isWithinLimit(context, file)) {
                Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + file.getAbsolutePath());
                return true;
            }
            if (callback != null)
                callback.onProgress(0, 1, file.getName());
            String path = file.getAbsolutePath();
            long nativeT0 = android.os.SystemClock.elapsedRealtime();
            NativeScanner.Verdict v = runNativeInterruptible(() ->
                NativeScanner.scan(path, null, null, ZeroTrustMode.isEnabled(context)));
            long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
            addTiming("NativeScanner", nativeMs);
            Log.i(TAG, "FILE_ENGINE_TIMING " + file.getName()
                + " NativeScanner=" + nativeMs + "ms slowest=NativeScanner");
            if (v == null) return true; // cancelled (or the native call itself
                                         // failed — either way runNativeInterruptible
                                         // already logged the real cause if it
                                         // wasn't a plain cancellation).
            if (v.isError()) {
                Log.w(TAG, "NATIVE-ERROR " + file.getAbsolutePath() + " " + v.error);
                return true;
            }
            saveGeneratedRule(v);
            // Per-detection whitelist suppression: a hit INSIDE a known-good
            // (whitelisted) APK is a false positive, but a non-APK virus sitting
            // alongside that APK in the same archive is NOT suppressed by the APK's
            // hash. Keep only the detections that survive.
            List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
            boolean malicious = !live.isEmpty();

            if (!malicious && v.permissions < 6) return true;

            ThreatResult.Builder b = new ThreatResult.Builder(path);
            b.setStandaloneFile(true);
            List<String> reasons = new java.util.ArrayList<>();
            int riskScore = 0;
            boolean mlMalicious = false;
            boolean hasRealThreat = false;
            boolean hasEicar = false;
            for (NativeScanner.Verdict.Detection d : live) {
                if ("ML".equals(d.name)) {
                    if (DetectionCategories.isEnabled(context, DetectionCategories.ML)
                            && v.jaccard >= 0.55 && v.anomaly >= 0.33) {
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
            // 13+ => almost certainly a malware (exceeds even heavy carriers
            // like Turkcell ≈ 11), exactly 12 => suspicious. Raised from 9/10
            // so common apps with 9-11 dangerous permissions aren't flagged.
            if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                if (v.permissions >= 13) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                    reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/36)");
                } else if (v.permissions >= 12) {
                    riskScore = Math.max(riskScore, 40);
                    if (!hasRealThreat) {
                        b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                    }
                    reasons.add("🔐 Suspicious permissions (" + v.permissions + "/36)");
                }
            }
            if (mlMalicious) {
                String near = v.nearest != null ? "  ~" + v.nearest : "";
                reasons.add(String.format(java.util.Locale.US,
                    "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
            }
            if (v.md5 != null && !v.md5.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.md5);
            }
            b.setRiskScore(riskScore);
            b.setReasons(reasons);
            b.setAppName(file.getName() + " (FILE)");
            b.setApkPath(path);
            ThreatResult r = b.build();
            if (r.isThreat() && !threats.contains(r)) {
                threats.add(r);
                if (callback != null) callback.onThreatFound(r);
            }
            return true;
        } catch (Throwable t) {
            // Previously: catch (Throwable t) { /* degrade gracefully */ } —
            // swallowed EVERY failure (including a real native-engine crash)
            // with zero trace, and the caller had no way to tell "scanned,
            // found nothing" apart from "never actually scanned". That made
            // scanSingleFile return null either way, which ScanFragment then
            // showed as "System clean" — a file that crashed the scanner
            // reported itself SAFE. Log it and tell the caller this one
            // genuinely failed, instead of silently agreeing it was clean.
            Log.e(TAG, "scanGenericFile: native scan crashed for " + file.getAbsolutePath(), t);
            return false;
        }
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
     *  than a trusted package name. Hash/package whitelist still suppresses FPs.
     *  Reports progress so the user sees which APK is being deep-scanned. */
    private void deepNativeScanInstalledApks(List<ApplicationInfo> apps, PackageManager pm,
                                             List<ThreatResult> threats) {
        if (!NativeScanner.isReady()) return;
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        for (ThreatResult t : threats) if (t.getPackageName() != null) seen.add(t.getPackageName());
        // Use the same continuous counter (appsScannedBase + filesScannedCount)
        // as scanAllStorageRoots so the progress never resets mid-scan.
        for (ApplicationInfo app : apps) {
            if (cancelRequested) return;
            
            // Pause handling
            while (pauseRequested && !cancelRequested) {
                try { Thread.sleep(100); } catch (InterruptedException e) { break; }
            }
            if (cancelRequested) return;
            
            try {
                if (app.sourceDir == null) continue;
                // Never deep-flag system files.
                if ((app.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                        || (app.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        || app.sourceDir.startsWith("/system/") || app.sourceDir.startsWith("/vendor/")
                        || app.sourceDir.startsWith("/product/") || app.sourceDir.startsWith("/apex/")) continue;
                if (app.packageName != null && (app.packageName.equals(context.getPackageName())
                        || seen.contains(app.packageName)
                        || photonCache.containsKey(app.packageName))) continue;
                if (!MaxScanFileSize.isWithinLimit(context, new java.io.File(app.sourceDir))) {
                    Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + app.packageName);
                    continue;
                }
                int n = appsScannedBase + filesScannedCount.incrementAndGet();
                if (callback != null)
                    callback.onProgress(n, n, app.packageName + " [deep]");
                long nativeT0 = android.os.SystemClock.elapsedRealtime();
                NativeScanner.Verdict v = runNativeInterruptible(() ->
                    NativeScanner.scan(app.sourceDir, app.packageName, null, ZeroTrustMode.isEnabled(context)));
                long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
                addTiming("NativeScanner", nativeMs);
                Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                    + " NativeScanner=" + nativeMs + "ms slowest=NativeScanner");
                if (v == null) continue;
                // Per-detection suppression (a hit inside a whitelisted APK is an
                // FP; a non-APK virus alongside it is not). Nothing survives → skip.
                List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
                if (cancelRequested) return;
                if (live.isEmpty()) continue;
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
                if (cancelRequested) return;
                if (!anyEvidence) continue;
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
                if (r.isThreat() && !threats.contains(r)) {
                    threats.add(r);
                    if (app.packageName != null) seen.add(app.packageName);
                    if (callback != null) callback.onThreatFound(r);
                }
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
                    if (r != null && r.isThreat() && !threats.contains(r)) {
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
        if (app.packageName != null && photonCache.containsKey(app.packageName)
                && photonCacheEnabled()) {
            Log.i(TAG, "Photon Cache Hit: " + app.packageName);
            return photonCache.get(app.packageName);
        }

        ThreatResult.Builder builder = new ThreatResult.Builder(app.packageName);
        builder.setStandaloneFile(isApkFile);

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

        // runPkgInfoInterruptible handles Vivo ROM hangs/timeouts internally
        // and sets apkPkgAnalyzerBroken.
        PackageInfo pkgInfo = runPkgInfoInterruptible(() -> {
            if (isApkFile)
                return pm.getPackageArchiveInfo(app.sourceDir, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
            return pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
        });

        try {
        if (pkgInfo != null) {
            if (pkgInfo.requestedPermissions != null) {
                requestedPermissions.addAll(Arrays.asList(pkgInfo.requestedPermissions));
            }
            if (pkgInfo.signatures != null && pkgInfo.signatures.length > 0) {
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

            } else {
                riskScore += 100;
                reasons.add("CRITICAL: Digital signature not found!");
            }

            // Dangerous-permission DETECTION lives in the native (Rust) engine —
            // it counts them from the manifest bytes (works for in-memory/inner
            // APKs too). The 5/6 DECISION is applied below in Java where `v` is in
            // scope, so Java still owns the verdict + whitelist.
        }
        } catch (Throwable e) {
            // See scanSingleFile's matching catch: getPackageArchiveInfo() (and
            // on some ROMs getPackageInfo()) can throw ExceptionInInitializerError
            // — an Error, not an Exception — which catch(Exception) let escape and
            // kill the whole scan thread.
            Log.w(TAG, "analyzeApp: package info lookup failed for " + app.packageName, e);
        }

        // Stealth-rootkit pattern: hidden from the launcher AND requests at
        // least one high-privilege/persistence permission. Neither signal
        // alone is proof (plenty of clean apps hide their icon OR use
        // accessibility/overlay/boot-completed — just not both together).
        if (!isWhitelisted && !isApkFile && app.packageName != null
                && DetectionCategories.isEnabled(context, DetectionCategories.ROOTKIT)
                && hasNoLauncherIcon(pm, app.packageName)) {
            List<String> matchedRootkitPerms = new ArrayList<>();
            for (String suspicious : ROOTKIT_SUSPICIOUS_PERMS) {
                if (requestedPermissions.contains(suspicious)) matchedRootkitPerms.add(suspicious);
            }
            if (!matchedRootkitPerms.isEmpty()) {
                riskScore = Math.max(riskScore, 80);
                builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                reasons.add("🕵️ Rootkit-like behavior: hidden from launcher + suspicious permissions ("
                    + String.join(", ", matchedRootkitPerms) + ")");
            }
        }

        if (!isWhitelisted) {
            try {
                String apkPath;
                if (isApkFile && app.sourceDir != null) {
                    apkPath = app.sourceDir;
                } else {
                    PackageInfo pi = runPkgInfoInterruptible(() ->
                        pm.getPackageInfo(app.packageName, 0));
                    apkPath = pi != null ? pi.applicationInfo.sourceDir : null;
                }
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
                // The native scanner (Rust) reads the file once and computes MD5
                // from bytes already in memory — no need for a separate Java read.
                boolean withinSizeLimit = apkPath != null
                    && MaxScanFileSize.isWithinLimit(context, new java.io.File(apkPath));
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
                }
                if (withinSizeLimit && NativeScanner.isReady()) {
                    long nativeT0 = android.os.SystemClock.elapsedRealtime();
                    NativeScanner.Verdict v = runNativeInterruptible(() ->
                        NativeScanner.scan(apkPath, app.packageName, null, ZeroTrustMode.isEnabled(context)));
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
                    if (v != null && !v.isError()) {
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
                                if (DetectionCategories.isEnabled(context, DetectionCategories.ML)
                                        && v.jaccard >= 0.55 && v.anomaly >= 0.33) {
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
                            // Native DEX static-analysis heuristic: "DEX/High: ..."
                            // (and below) is dropped — a raw code-pattern smell test,
                            // too false-positive-prone to count toward a verdict on
                            // its own. "DEX/Critical: ..." survives and falls through
                            // to the SIGNATURES category below like a real finding.
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
                    // 13+ = almost certainly malware (exceeds heavy carriers like
                    // Turkcell ≈ 11); exactly 12 = suspicious. Raised from 9/10
                    // so common apps with 9-11 dangerous permissions aren't flagged.
                    if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                        if (v.permissions >= 13) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                            reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/36)");
                            nativeCorroborated = true;
                        } else if (v.permissions >= 12) {
                            riskScore = Math.max(riskScore, 40);
                            if (riskScore < 50) builder.setThreatType(
                                com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                            reasons.add("🔐 Suspicious permissions (" + v.permissions + "/36)");
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
        if (!cancelRequested && app.packageName != null) photonCache.put(app.packageName, finalRes);
        return finalRes;
    }
}
