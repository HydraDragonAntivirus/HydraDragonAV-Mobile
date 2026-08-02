package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.util.Log;

import com.hydradragon.antivirus.R;
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

    /** Previously observed default home/launcher package, or null on first check. */
    private static String previousDefaultLauncher = null;

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
    // Thread priority is set at scan-task runtime based on the WakeLock
    // setting (ScanSchedule.isScanWakeLockEnabled): when WakeLock is ON
    // (user wants background scanning) threads use default priority so the
    // OS schedules them even while the app is in the background; when OFF
    // they use THREAD_PRIORITY_BACKGROUND to keep the UI smooth.
    private static volatile boolean backgroundPriority = true;
    public static void setBackgroundPriority(boolean on) { backgroundPriority = on; }
    private static final ExecutorService scanExecutor =
        Executors.newFixedThreadPool(NATIVE_PARALLELISM);
    private static final ExecutorService nativeCallExecutor =
        Executors.newFixedThreadPool(NATIVE_PARALLELISM);
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

    /**
     * Persistent scan cache backed by SQLite + in-memory HashMap.
     * Replaces the old transient ConcurrentHashMap so cached results survive
     * device reboots.  Each ScanEngine instance shares the same DB file
     * (via getNoBackupFilesDir) but keeps its own in-memory snapshot loaded
     * at construction time.
     */
    private static ScanCache scanCache;

    /** Drop a cached scan result so the package is re-scanned fresh (e.g. after
     *  uninstall/update — otherwise a removed virus keeps "coming back"). */
    public static void invalidateCache(String packageName) {
        if (packageName != null && scanCache != null) scanCache.removePhotonCache(packageName);
    }

    /** Clear all scan caches (in-memory + SQLite). */
    public static void clearCache() {
        if (scanCache != null) scanCache.clearAll();
    }

    private boolean photonCacheEnabled() {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("scan_cache_enabled", true);
    }

    private boolean isSystemFileScanningEnabled() {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("scan_system_files_enabled", false);
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
    /** Packages found to be store+NSRL-whitelisted during the current scan run.
     *  Populated by {@link #analyzeApp} and consumed by
     *  {@link #deepNativeScanInstalledApks} to skip the costly native engine
     *  on apps we already trust — their zip-entry hashes are already cached. */
    private final java.util.HashSet<String> whitelistedDuringScan = new java.util.HashSet<>();

    private volatile boolean isBackgroundScan = false;

    public void setBackgroundScan(boolean background) {
        this.isBackgroundScan = background;
    }
    public boolean isBackgroundScan() { return isBackgroundScan; }
    public boolean isScanRunning() { return runningScanType != SCAN_TYPE_NONE; }

    static final int SCAN_TYPE_NONE = 0;
    static final int SCAN_TYPE_QUICK = 1;
    static final int SCAN_TYPE_FULL = 2;
    private volatile int runningScanType = SCAN_TYPE_NONE;
    volatile int pendingScanType = SCAN_TYPE_NONE;

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
        java.util.concurrent.Future<NativeScanner.Verdict> future = nativeCallExecutor.submit(() -> {
            if (backgroundPriority) android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
            return call.call();
        });
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
        if (scanCache == null) scanCache = new ScanCache(context);
        loadPackageWhitelist();
        // Load YARA-X rulesets + ML model into the native engine (non-fatal).
        try { NativeScanner.init(context); } catch (Throwable t) { /* degrade gracefully */ }
    }

    // Screen off / Doze parks the CPU, so a background scan (periodic timer or
    // Downloads-observer triggered) would freeze mid-run until the screen came
    // back on — the reason background scanning "didn't work" while the phone was
    // locked (incl. screen-pinned). A partial wake lock held only for the scan's
    // duration keeps the CPU running; released in finally so it never leaks.
    private android.os.PowerManager.WakeLock scanWakeLock;

    private synchronized android.os.PowerManager.WakeLock acquireScanWakeLock() {
        // Off by user setting (Settings > keep scanning while screen off).
        if (!ScanSchedule.isScanWakeLockEnabled(context)) return null;
        try {
            if (scanWakeLock == null) {
                android.os.PowerManager pm =
                    (android.os.PowerManager) context.getSystemService(Context.POWER_SERVICE);
                if (pm == null) return null;
                scanWakeLock = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "HydraDragon:scan");
                // Reference-counted: overlapping scans (periodic + download) each
                // acquire/release, so one finishing doesn't drop the lock out from
                // under the other still running.
                scanWakeLock.setReferenceCounted(true);
            }
            // 30 min cap so a hung scan can't drain the battery forever.
            scanWakeLock.acquire(30 * 60 * 1000L);
        } catch (Throwable t) {
            Log.w(TAG, "wake lock acquire failed", t);
        }
        return scanWakeLock;
    }

    private synchronized void releaseScanWakeLock() {
        try {
            if (scanWakeLock != null && scanWakeLock.isHeld()) scanWakeLock.release();
        } catch (Throwable t) {
            Log.w(TAG, "wake lock release failed", t);
        }
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

    private static boolean isTlshName(String name) {
        return name != null && name.startsWith("TLSH.");
    }

    /** True for steganography heuristics (appended/hidden data in image or
     *  media files) detected by the Rust native scanner. These are structural
     *  anomalies, not signature matches — ClamAV is not specialised enough to
     *  catch every steganographic payload, so the native scanner emits
     *  HDR.Image.Steganography / HDR.Media.Steganography as a separate signal.
     *  Reported as SUSPICIOUS / MEDIUM risk (score 40) — a stego-only verdict
     *  is below the MALWARE threshold because the actual payload may be benign
     *  (e.g. watermarking tools, album art embedded in metadata padding). */
    private static boolean isStegoName(String name) {
        return name != null && name.contains("Steganography");
    }

    /** " (in /full/outer/path.apk!/classes.dex)" when the detection fired on a
     *  sub-file nested inside the scanned archive rather than the top-level file
     *  itself; "" otherwise. Shows the FULL object_path as-is (not just the inner
     *  entry name), so the outer archive is still visible even for deeply nested
     *  archives (zip inside zip inside apk, etc). */
    private static String subFileSuffix(String outerPath, String objectPath) {
        if (objectPath == null || objectPath.isEmpty() || objectPath.equals(outerPath)) return "";
        return " (in " + objectPath + ")";
    }

    private void loadPackageWhitelist() {
        // Known-good NSRL package keys (whitelist_packages.csv, one "key,md5"
        // per line) into an exact HashSet of the "key" field (package_id^^
        // file_name). Only clears an app WITH a trusted-store install
        // (spoofable alone). The SHA-256 hash whitelist is separate and lives
        // natively (xor filter) — see NativeScanner.isHashWhitelisted.
        // Lives under assets/scan/ (not the assets root) so the same CSV also
        // backs the Rust exact-file skip check in
        // NativeScanner_nativeScanApk.
        try (InputStream in = context.getAssets().open("scan/whitelist_packages.csv")) {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) continue;
                // First comma separates key from md5; the key may itself be
                // quoted (RFC-4180) if it contains a comma — strip the quotes.
                int comma = line.indexOf(',');
                if (comma <= 0) continue;
                String key = line.substring(0, comma);
                if (key.length() >= 2 && key.charAt(0) == '"'
                        && key.charAt(key.length() - 1) == '"') {
                    key = key.substring(1, key.length() - 1).replace("\"\"", "\"");
                }
                whitelistPackages.add(key);
            }
        } catch (Exception e) { /* missing — package whitelist disabled */ }
    }

    /** True if {@code hash} (a whole-APK/file MD5) is a known-good NSRL hash.
     *  Delegates to the native xor filter whitelist (native memory).
     *  ONLY for files already confirmed to be APKs — does NOT check file header. */
    private boolean isHashWhitelisted(String hash) {
        return hash != null && NativeScanner.isHashWhitelisted(hash.toLowerCase(java.util.Locale.US));
    }

    /** Like {@link #isHashWhitelisted} but the Rust side first checks whether
     *  {@code path} begins with ZIP magic bytes (PK\x04\x03) so non-APK files
     *  (EICAR, PDF, etc.) are never whitelisted. */
    private boolean isFileHashWhitelisted(String path, String hash) {
        if (path == null || hash == null) return false;
        return NativeScanner.isHashWhitelistedForFile(path, hash.toLowerCase(java.util.Locale.US));
    }

    /** True if {@code pkg} is an exact known-good NSRL package name. Spoofable on
     *  its own, so callers must combine it with a trusted-store install. */
    private boolean isPackageWhitelisted(String pkg) {
        return pkg != null && whitelistPackages.contains(pkg);
    }

    /**
     * Compute the MD5 hex digest of a file's raw bytes.  Returns the lowercase
     * hex string, or {@code null} if the file can't be read or MD5 fails.
     * Reads the file in 64 KB chunks to keep heap pressure low.
     */
    private static String computeFileMd5(java.io.File file) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = fis.read(buf)) != -1) md.update(buf, 0, n);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder(32);
            for (byte b : digest) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) sb.append('0');
                sb.append(h);
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
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
            // Always hot-load the rule into the live engine so the current session
            // benefits even if disk persistence is disabled by the user.
            if (SaveAutoRules.isEnabled(context)) {
                java.io.File dir = new java.io.File(
                    new java.io.File(context.getFilesDir(), "hydra-scan"), "generated_rules");
                if (!dir.exists() && !dir.mkdirs()) return;
                String name = (v.md5 != null && !v.md5.isEmpty()) ? v.md5 : String.valueOf(System.nanoTime());
                java.io.File out = new java.io.File(dir, "auto_" + name + ".yar");
                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                    fos.write(v.generatedRule.getBytes(StandardCharsets.UTF_8));
                }
                NativeScanner.learnRule(out.getAbsolutePath());
            } else {
                // Disk save disabled — write to a temp file, hot-load it, then delete.
                java.io.File tmp = java.io.File.createTempFile("auto_rule_", ".yar", context.getCacheDir());
                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp)) {
                    fos.write(v.generatedRule.getBytes(StandardCharsets.UTF_8));
                }
                NativeScanner.learnRule(tmp.getAbsolutePath());
                tmp.delete();
            }
        } catch (Exception e) { /* best effort — never block the scan on this */ }
    }

    private List<NativeScanner.Verdict.Detection> survivingDetections(NativeScanner.Verdict v) {
        List<NativeScanner.Verdict.Detection> out = new ArrayList<>();
        for (NativeScanner.Verdict.Detection d : v.detections) {
            if (isDetectionWhitelisted(d)) continue;
            out.add(d);
        }
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

    /** Check whether the default home/launcher has changed since the last scan.
     *  If so, emit a {@code LAUNCHER_CHANGE} behavioral signal so the
     *  YARA-X hydradragon launcher_change rule can fire. */
    private static void checkDefaultLauncher(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            Intent homeIntent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME);
            ResolveInfo ri = pm.resolveActivity(homeIntent, PackageManager.MATCH_DEFAULT_ONLY);
            if (ri == null || ri.activityInfo == null) return;
            String current = ri.activityInfo.packageName;
            String prev = previousDefaultLauncher;
            previousDefaultLauncher = current;
            if (prev == null) return; // first check — no baseline yet
            if (current.equals(prev)) return;
            // The launcher changed. Determine which app caused it: the new one.
            boolean isSystem;
            try {
                isSystem = (pm.getApplicationInfo(current, 0).flags
                    & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0;
            } catch (PackageManager.NameNotFoundException e) {
                isSystem = false;
            }
            HipsMonitor.reportLauncherChange(
                current, true,
                "category_home_resolution",
                !isSystem  // a non-system app replacing the launcher is suspicious
            );
        } catch (Exception e) {
            Log.w(TAG, "checkDefaultLauncher failed", e);
        }
    }

    /** @return true if this call actually started a scan, false if one was
     *  already running (see scanRunning) and this request was skipped. The
     *  caller (e.g. ScanFragment) MUST check this — an isScanRunning() check
     *  done beforehand is not enough, since a background scan can start in
     *  the gap between that check and this call. Checking THIS return value
     *  instead closes that race. */
    public boolean scanAllApps(boolean isFullScan) {
        int reqType = pendingScanType;
        pendingScanType = SCAN_TYPE_NONE;
        if (reqType == SCAN_TYPE_NONE) {
            reqType = isFullScan ? SCAN_TYPE_FULL : SCAN_TYPE_QUICK;
        }
        // Snapshot background flag AND running type BEFORE the CAS to close
        // races where the background scan's finally block clears isBackgroundScan
        // (or the scan thread sets runningScanType) between those reads and the
        // checks below.
        boolean bgScan = isBackgroundScan;
        int currentType = runningScanType;
        if (!scanRunning.compareAndSet(false, true)) {
            if (bgScan && currentType == reqType) {
                isBackgroundScan = false;
                Log.d(TAG, "scanAllApps: adopted background scan for user (type=" + reqType + ")");
                return true;
            }
            Log.w(TAG, "scanAllApps: scan already running (type=" + currentType
                + "), skipping request (type=" + reqType + ")");
            return false;
        }
        runningScanType = reqType;
        cancelRequested = false;
        pauseRequested = false;
        apkPkgAnalyzerBroken = false;
        engineTimingMs.clear();
        filesScannedCount.set(0);
        whitelistedDuringScan.clear();
        acquireScanWakeLock();
        scanExecutor.execute(() -> {
          if (backgroundPriority) android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
          try {
            checkDefaultLauncher(context);

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
                    if (!isBackgroundScan && callback != null) callback.onProgress(i + 1, total, app.packageName);
                    ThreatResult result = analyzeApp(app, pm, false);
                    boolean isThreat = result != null && result.isThreat();
                    if (isThreat && !threats.contains(result)) {
                        threats.add(result);
                        if (callback != null) callback.onThreatFound(result);
                    }
                    String appName = result != null ? result.getAppName() : "";
                    String reason = isThreat
                        ? String.join("; ", result.getReasons() != null ? result.getReasons() : java.util.Collections.emptyList())
                        : "Clean";
                } catch (Exception e) { }
            }

            try {
                if (isFullScan && !cancelRequested) {
                    // Full scan = main installed-app loop PLUS look for
                    // standalone APK files under all storage volumes (SD
                    // card, downloads, etc.) — these are not installed
                    // packages so analyzeApp doesn't see them.
                    java.util.Set<String> installedPackages = new java.util.HashSet<>();
                    for (ApplicationInfo a : apps) if (a.packageName != null) installedPackages.add(a.packageName);
                    long t0 = android.os.SystemClock.elapsedRealtime();
                    scanAllStorageRoots(pm, threats, installedPackages);
                    addTiming("scanAllStorageRoots", android.os.SystemClock.elapsedRealtime() - t0);
                }
            } catch (Exception e) { }

            logEngineTimings();
            NativeScanner.scanAndRespond(context);
            long elapsedMs = android.os.SystemClock.elapsedRealtime() - scanStartMs;
            int scannedTotal = total + filesScannedCount.get() + threats.size();
            if (!isBackgroundScan && callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats, java.util.Collections.emptyList(), elapsedMs));
          } finally {
              isBackgroundScan = false;
              runningScanType = SCAN_TYPE_NONE;
              scanRunning.set(false);
              releaseScanWakeLock();
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
        acquireScanWakeLock();
        scanExecutor.execute(() -> {
          if (backgroundPriority) android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
          try {
            long scanStartMs = android.os.SystemClock.elapsedRealtime();
            PackageManager pm = context.getPackageManager();
            List<ThreatResult> threats = new ArrayList<>();
            scanDirectoryForApks(dir, pm, threats, true);

            logEngineTimings();
            long elapsedMs = android.os.SystemClock.elapsedRealtime() - scanStartMs;
            int scannedTotal = filesScannedCount.get() + threats.size();
            if (callback != null)
                callback.onScanComplete(new ScanResult(scannedTotal, threats.size(), threats, java.util.Collections.emptyList(), elapsedMs));
          } finally {
              scanRunning.set(false);
              releaseScanWakeLock();
          }
        });
        return true;
    }

    private void scanDirectoryForApks(java.io.File dir, PackageManager pm,
                                      List<ThreatResult> threats, boolean fullScan) {
        scanDirectoryForApks(dir, pm, threats, fullScan, (java.util.Set<String>) null);
    }

    /** Bump the storage-file counter and push a live progress update so a full
     *  scan's UI reflects the (potentially huge) storage-root file walk, not
     *  just the up-front installed-apps loop. Adds appsScannedBase so the
     *  displayed count keeps climbing from where the installed-apps loop left
     *  off, instead of resetting back down to 1, 2, 3... current==total on
     *  purpose: the eventual file count isn't known ahead of time, so this
     *  reports "how many scanned so far" rather than a completion percentage. */
    private void reportFileScanned(java.io.File file) {
        reportFileScanned(file, "Scanned", 0, false);
    }

    private void reportFileScanned(java.io.File file, String reason, int riskScore, boolean isThreat) {
        int n = appsScannedBase + filesScannedCount.incrementAndGet();
        if (callback != null) {
            callback.onProgress(n, n, file.getName());
        }
    }

    /**
     * Skip only low-value metadata while system-file scanning is disabled.
     * If system-file scanning is enabled, every file reaches the scanner.
     */
    private boolean shouldSkipNonSystemMetadata(java.io.File file) {
        if (file == null || file.isDirectory()) return false;
        return !isSystemFileScanningEnabled()
                && (file.length() <= 12 || isSafeMetadataMarker(file));
    }

    /**
     * A filename alone is not trusted. A .database_uuid file is safe to skip
     * only when its complete contents are a UUID (optionally followed by one
     * line ending); .nomedia is safe only when empty.
     */
    private static boolean isSafeMetadataMarker(java.io.File file) {
        if (file == null || file.isDirectory()) return false;
        String name = file.getName();
        if (".nomedia".equals(name)) return file.length() == 0;
        if (!".database_uuid".equals(name)) return false;

        long length = file.length();
        if (length < 32 || length > 40) return false;
        try (java.io.FileInputStream input = new java.io.FileInputStream(file)) {
            byte[] bytes = new byte[(int) length];
            int offset = 0;
            while (offset < bytes.length) {
                int read = input.read(bytes, offset, bytes.length - offset);
                if (read < 0) return false;
                offset += read;
            }
            String contents = new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
            return contents.matches("(?i)([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\r?\\n?");
        } catch (java.io.IOException e) {
            return false;
        }
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
            // Generic: skip tiny files (metadata markers like .nomedia,
            // .database_uuid, .staging, temp locks, etc.) that have zero or
            // near-zero scannable content but cost 46-99ms each in native
            // engine overhead.
            if (shouldSkipNonSystemMetadata(file)) continue;
            if (cancelRequested) return;
            if (file.isDirectory()) {
                scanDirectoryForApks(file, pm, threats, fullScan, skipPackages);
            } else if (file.getName().toLowerCase().endsWith(".apk")) {
                // Check if it's a system APK first (getPackageArchiveInfo is
                // lightweight — reads manifest only).  System APKs are already
                // checked by the installed-apps pass — skip MD5 + analyzeApp.
                PackageInfo pkgInfo = runPkgInfoInterruptible(() ->
                    pm.getPackageArchiveInfo(file.getAbsolutePath(),
                        PackageManager.GET_PERMISSIONS));
                if (pkgInfo != null) {
                    String pkgName = pkgInfo.applicationInfo.packageName;
                    if (skipPackages != null && pkgName != null && skipPackages.contains(pkgName)) {
                        if (!cancelRequested) reportFileScanned(file);
                        continue;
                    }
                    // Skip system APKs entirely — no MD5, no analyzeApp.
                    if ((pkgInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                            || (pkgInfo.applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                        if (!cancelRequested) reportFileScanned(file);
                        continue;
                    }

                    // ── MD5 scan-cache check for non-system APKs ──────────
                    // Cache hit avoids the expensive analyzeApp pipeline.
                    String apkMd5 = computeFileMd5(file);
                    if (apkMd5 != null && photonCacheEnabled()) {
                        java.util.Optional<ThreatResult> cachedApk = scanCache != null ? scanCache.getFileCache(apkMd5) : null;
                        if (cachedApk != null) {
                            Log.i(TAG, "File-MD5 cache hit APK (" + apkMd5 + "): " + file.getAbsolutePath());
                            if (cachedApk.isPresent()) {
                                ThreatResult cr = cachedApk.get();
                                if (!threats.contains(cr)) {
                                    threats.add(cr);
                                    if (callback != null) callback.onThreatFound(cr);
                                }
                            }
                            if (!cancelRequested) reportFileScanned(file,
                                cachedApk.isPresent() ? "Cache hit - known threat" : "Cache hit - clean",
                                cachedApk.isPresent() ? 100 : 0, cachedApk.isPresent());
                            continue;
                        }

                        if (isHashWhitelisted(apkMd5)) {
                            Log.i(TAG, "NSRL Whitelist hit APK (MD5 clean): " + file.getAbsolutePath());
                            if (scanCache != null) scanCache.putFileCache(apkMd5, java.util.Optional.empty());
                            if (!cancelRequested) reportFileScanned(file, "NSRL whitelist - clean", 0, false);
                            continue;
                        }
                    }

                    pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                    pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                    ThreatResult result = analyzeApp(pkgInfo.applicationInfo, pm, true);
                    if (result != null && result.isThreat() && !threats.contains(result)) {
                        threats.add(result);
                        if (callback != null) callback.onThreatFound(result);
                    }
                    if (apkMd5 != null && photonCacheEnabled() && !cancelRequested && scanCache != null) {
                        scanCache.putFileCache(apkMd5, (result != null && result.isThreat())
                            ? java.util.Optional.of(result)
                            : java.util.Optional.empty());
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
        // Downloads-observer scans fire while the screen is off — hold the CPU
        // awake for the scan's duration (see acquireScanWakeLock).
        acquireScanWakeLock();
        try {
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
                            PackageManager.GET_PERMISSIONS));
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
        } finally {
            releaseScanWakeLock();
        }
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
        // Skip tiny metadata markers (.nomedia, .database_uuid, .staging,
        // temp locks, etc.) no matter which caller routed here.
        if (shouldSkipNonSystemMetadata(file)) return true;
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

            String path = file.getAbsolutePath();
            long nativeT0 = android.os.SystemClock.elapsedRealtime();
            NativeScanner.Verdict v = runNativeInterruptible(() ->
                NativeScanner.scan(path, null, null, ZeroTrustMode.isEnabled(context)));
            long nativeMs = android.os.SystemClock.elapsedRealtime() - nativeT0;
            addTiming("NativeScanner", nativeMs);
            Log.i(TAG, "FILE_ENGINE_TIMING " + file.getName()
                + " NativeScanner=" + nativeMs + "ms slowest=NativeScanner");
            if (v == null) return true;
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

            if (!malicious && v.permissions < 25) return true;

            ThreatResult.Builder b = new ThreatResult.Builder(path);
            b.setStandaloneFile(true);
            List<String> reasons = new java.util.ArrayList<>();
            int riskScore = 0;
            boolean mlMalicious = false;
            boolean hasRealThreat = false;
            boolean hasEicar = false;
            boolean hasPuaOnly = false;
            boolean hasAutoOnly = false;
            boolean hasTlshOnly = false;
            boolean hasStegoOnly = false;
            for (NativeScanner.Verdict.Detection d : live) {
                if ("ML".equals(d.name)) {
                    if (DetectionCategories.isEnabled(context, DetectionCategories.ML)) {
                        if (v.probability >= 0.95) {
                            mlMalicious = true;
                            hasRealThreat = true;
                        } else if (v.probability >= 0.90) {
                            mlMalicious = true;
                        }
                    }
                    continue;
                }
                if (isEicarName(d.name)) {
                    if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                        hasEicar = true;
                        reasons.add("🧪 [TEST] " + d.name + subFileSuffix(path, d.objectPath));
                    }
                    continue;
                }
                if (isDexHeuristicName(d.name)) continue;

                boolean isPua = isPuaName(d.name);
                boolean isAuto = isAutoGeneratedName(d.name);
                boolean isTlsh = isTlshName(d.name);
                boolean isStego = isStegoName(d.name);
                String category = isPua ? DetectionCategories.PUA
                    : isAuto ? DetectionCategories.AUTO_RULES
                    : DetectionCategories.SIGNATURES;
                if (!DetectionCategories.isEnabled(context, category)) continue;

                if (isPua) hasPuaOnly = true;
                else if (isAuto) hasAutoOnly = true;
                else if (isStego) hasStegoOnly = true;
                else hasRealThreat = true;

                reasons.add((isPua ? "⚠️ [PUA] " : isAuto ? "❔ [AUTO] " : isTlsh ? "🔍 [TLSH] " : isStego ? "📦 [STEGO] " : "🛡️ [SIG] ") + d.name + subFileSuffix(path, d.objectPath));
            }

            if (mlMalicious) {
                String src = "";
                for (NativeScanner.Verdict.Detection d : live) {
                    if ("ML".equals(d.name)) {
                        src = subFileSuffix(path, d.objectPath);
                        break;
                    }
                }
                reasons.add(String.format(java.util.Locale.US, "🤖 [ML] probability=%.2f%s", v.probability, src));
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
                } else if (hasPuaOnly) {
                    riskScore = 50;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                } else if (hasStegoOnly) {
                    riskScore = 40;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                } else if (hasAutoOnly || hasTlshOnly || mlMalicious) {
                    riskScore = mlMalicious ? 70 : 40;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                }
            }
            if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                if (v.permissions >= 30) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                    reasons.add("🔐 Virus permissions (" + v.permissions + "/36)");
                } else if (v.permissions >= 25) {
                    riskScore = Math.max(riskScore, 40);
                    if (!hasRealThreat) {
                        b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                    }
                    reasons.add("🔐 Suspicious permissions (" + v.permissions + "/36)");
                }
            }
            if (mlMalicious) {
                String src = "";
                for (NativeScanner.Verdict.Detection d : v.detections) {
                    if ("ML".equals(d.name)) {
                        src = subFileSuffix(path, d.objectPath);
                        break;
                    }
                }
                reasons.add(String.format(java.util.Locale.US,
                    "🤖 [ML] probability=%.2f%s", v.probability, src));
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
     *  ONLY on NON-whitelisted apps. Whitelisted apps (store+NSRL) were already
     *  processed/cached by {@link #analyzeApp} and tracked in
     *  {@link #whitelistedDuringScan} — skipping them here avoids redundant
     *  native work on apps we already trust.
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
                        || (scanCache != null && scanCache.containsPhotonCache(app.packageName))
                        || whitelistedDuringScan.contains(app.packageName))) continue;
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
                boolean tlshOnly = false;
                boolean mlOnly = false;
                for (NativeScanner.Verdict.Detection d : live) {
                    if ("ML".equals(d.name)) {
                        if (DetectionCategories.isEnabled(context, DetectionCategories.ML)
                                && v.probability >= 0.90) mlOnly = true;
                        continue;
                    }
                    if (isEicarName(d.name)) {
                        if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                            eicar = true; reasons.add("🧪 [TEST] " + d.name + subFileSuffix(app.sourceDir, d.objectPath));
                        }
                        continue;
                    }
                    if (isDexHeuristicName(d.name)) continue;
                    boolean pua = isPuaName(d.name);
                    boolean auto = isAutoGeneratedName(d.name);
                    boolean tlsh = isTlshName(d.name);
                    String category = pua ? DetectionCategories.PUA
                        : auto ? DetectionCategories.AUTO_RULES
                        : DetectionCategories.SIGNATURES;
                    if (!DetectionCategories.isEnabled(context, category)) continue;
                    if (auto) autoOnly = true;
                    if (tlsh) tlshOnly = true;
                    if (!pua && !auto && !tlsh) real = true;
                    reasons.add((pua ? "⚠️ [PUA] " : auto ? "❔ [AUTO] " : tlsh ? "🔍 [TLSH] " : "🛡️ [SIG] ") + d.name + subFileSuffix(app.sourceDir, d.objectPath));
                }
                if (real) {
                    // Auto-signature generation only on an actual confirmed virus,
                    // gated behind the (default-off) Settings toggle.
                    if (AutoRuleGeneration.isEnabled(context)) saveGeneratedRule(v);
                }
                boolean anyEvidence = real || eicar || autoOnly || tlshOnly || mlOnly || !reasons.isEmpty();
                if (cancelRequested) return;
                if (!anyEvidence) {
                    // Cache clean result so subsequent scans skip deep native scan
                    if (app.packageName != null && scanCache != null) {
                        scanCache.putPhotonCache(app.packageName, new ThreatResult.Builder(app.packageName)
                            .setRiskScore(0)
                            .setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN)
                            .build());
                    }
                    continue;
                }
                boolean isSuspicious = autoOnly || tlshOnly || mlOnly;
                b.setThreatType(real
                    ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE
                    : eicar
                        ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.TEST_MALWARE
                        : isSuspicious
                            ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS
                            : com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                b.setRiskScore(real ? 100 : isSuspicious ? (mlOnly ? 70 : 40) : 50);
                if (v.md5 != null && !v.md5.isEmpty())
                    reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.md5);
                b.setReasons(reasons);
                CharSequence label = pm.getApplicationLabel(app);
                b.setAppName((label != null ? label.toString() : app.packageName) + " (DEEP)");
                ThreatResult r = b.build();
                if (app.packageName != null && scanCache != null) {
                    scanCache.putPhotonCache(app.packageName, r);
                }
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
        if (app.packageName != null && photonCacheEnabled() && scanCache != null
                && scanCache.containsPhotonCache(app.packageName)) {
            Log.i(TAG, "Photon Cache Hit: " + app.packageName);
            return scanCache.getPhotonCache(app.packageName);
        }

        ThreatResult.Builder builder = new ThreatResult.Builder(app.packageName);
        builder.setStandaloneFile(isApkFile);

        // Never flag ourselves — exact match against our release + debug package
        // (debug build's packageName has a ".debug" suffix; a scanned own-APK file
        // reports the release id). equals(), not startsWith(), so malware can't
        // self-whitelist with a "com.hydradragon.antivirus.evil" prefix.
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
            if (app.packageName != null) whitelistedDuringScan.add(app.packageName);
            // Skip system apps unless the user explicitly enabled system file
            // scanning (not recommended unless rooted — see Settings toggle).
            if (!context.getSharedPreferences("hydra_prefs", 0)
                    .getBoolean("scan_system_files_enabled", false)) {
                Log.d(TAG, "CLEAR-EXIT[isSystem] " + app.packageName + " sourceDir=" + app.sourceDir);
                builder.setRiskScore(0); return builder.build();
            }
            Log.d(TAG, "SYSTEM-SCAN[enabled] " + app.packageName + " sourceDir=" + app.sourceDir);
        }

        boolean isFromStore = false;
        if (!isApkFile) {
            try {
                String installer;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    installer = pm.getInstallSourceInfo(app.packageName).getInstallingPackageName();
                } else {
                    // No getInstallSourceInfo below API 30 — only path for minSdk 26-29.
                    installer = pm.getInstallerPackageName(app.packageName);
                }
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
            whitelistedDuringScan.add(app.packageName);
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
        // Captured for the Zero Trust "full known details" dump below — only
        // used when NOTHING else flagged this app (riskScore stays 0).
        List<String> requestedPermissions = new ArrayList<>();
        List<String> nativePackages = new ArrayList<>();
        List<String> nativeHashes = new ArrayList<>();
        int dangerousPermCount = -1;
        String mlSummary = null;

        // runPkgInfoInterruptible handles Vivo ROM hangs/timeouts internally
        // and sets apkPkgAnalyzerBroken. GET_SIGNING_CERTIFICATES (API 28+) with
        // a GET_SIGNATURES fallback below it — same dual-path IntegrityCheck.java
        // uses, needed because minSdk 26 predates GET_SIGNING_CERTIFICATES.
        int sigFlag = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P
            ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
        PackageInfo pkgInfo = runPkgInfoInterruptible(() -> {
            if (isApkFile)
                return pm.getPackageArchiveInfo(app.sourceDir, PackageManager.GET_PERMISSIONS | sigFlag);
            return pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS | sigFlag);
        });

        try {
        if (pkgInfo != null) {
            if (pkgInfo.requestedPermissions != null) {
                requestedPermissions.addAll(Arrays.asList(pkgInfo.requestedPermissions));
            }
            Signature[] sigs;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                sigs = (pkgInfo.signingInfo != null)
                    ? (pkgInfo.signingInfo.hasMultipleSigners()
                        ? pkgInfo.signingInfo.getApkContentsSigners()
                        : pkgInfo.signingInfo.getSigningCertificateHistory())
                    : null;
            } else {
                sigs = pkgInfo.signatures;
            }
            if (sigs != null && sigs.length > 0) {
                Signature sig = sigs[0];
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(sig.toByteArray()));
                String subject = cert.getSubjectDN().getName();
                for (String part : subject.split(","))
                    if (part.trim().startsWith("O=")) { companyName = part.trim().substring(2); break; }

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
                boolean withinSizeLimit = apkPath != null
                    && MaxScanFileSize.isWithinLimit(context, new java.io.File(apkPath));
                if (apkPath == null) {
                    Log.d(TAG, "NATIVE-SKIP[apkPath null] " + app.packageName);
                } else if (!withinSizeLimit) {
                    Log.d(TAG, "NATIVE-SKIP[over-size-limit] " + app.packageName + " path=" + apkPath);
                } else if (!NativeScanner.isReady()) {
                    Log.d(TAG, "NATIVE-SKIP[engine not ready] " + app.packageName);
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
                    Log.i(TAG, "FILE_ENGINE_TIMING " + app.packageName
                        + " NativeScanner=" + nativeMs + "ms");
                    Log.d(TAG, "NATIVE-RESULT " + app.packageName + " verdict="
                        + (v == null ? "NULL(cancelled/error)" : ("detections=" + v.detections.size()
                            + " permissions=" + v.permissions + " probability=" + v.probability
                            + " error=" + v.error)));
                    if (v == null) return null;
                    if (!v.isError()) {
                    fileMd5Vt = v.md5;
                    nativePackages.addAll(v.packages);
                    nativeHashes.addAll(v.hashes);
                    dangerousPermCount = v.permissions;
                    mlSummary = String.format(java.util.Locale.US,
                        "probability=%.2f", v.probability);
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
                        boolean hasPuaOnly = false;
                        boolean hasAutoOnly = false;
                        boolean hasTlshOnly = false;
                        boolean hasStegoOnly = false;
                        for (NativeScanner.Verdict.Detection d : live) {
                            if ("ML".equals(d.name)) {
                                if (DetectionCategories.isEnabled(context, DetectionCategories.ML)) {
                                    if (v.probability >= 0.95) {
                                        mlMalicious = true;
                                        hasRealThreat = true;
                                    } else if (v.probability >= 0.90) {
                                        mlMalicious = true;
                                    }
                                }
                                continue;
                            }
                            if (isEicarName(d.name)) {
                                if (DetectionCategories.isEnabled(context, DetectionCategories.EICAR)) {
                                    hasEicar = true; reasons.add("🧪 [TEST] " + d.name + subFileSuffix(apkPath, d.objectPath));
                                }
                                continue;
                            }
                            if (isDexHeuristicName(d.name)) continue;
                            boolean isPua = isPuaName(d.name);
                            boolean isAuto = isAutoGeneratedName(d.name);
                            boolean isTlsh = isTlshName(d.name);
                            boolean isStego = isStegoName(d.name);
                            String category = isPua ? DetectionCategories.PUA
                                : isAuto ? DetectionCategories.AUTO_RULES
                                : DetectionCategories.SIGNATURES;
                            if (!DetectionCategories.isEnabled(context, category)) continue;

                            if (isPua) hasPuaOnly = true;
                            else if (isAuto) hasAutoOnly = true;
                            else if (isStego) hasStegoOnly = true;
                            else hasRealThreat = true;

                            reasons.add((isPua ? "⚠️ [PUA] " : isAuto ? "❔ [AUTO] " : isTlsh ? "🔍 [TLSH] " : isStego ? "📦 [STEGO] " : "🛡️ [SIG] ") + d.name + subFileSuffix(apkPath, d.objectPath));
                        }
                        if (hasRealThreat) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                            if (AutoRuleGeneration.isEnabled(context)) saveGeneratedRule(v);
                        } else if (hasEicar) {
                            riskScore = Math.max(riskScore, 50);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.TEST_MALWARE);
                        } else if (hasPuaOnly) {
                            riskScore = Math.max(riskScore, 50);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                        } else if (hasStegoOnly) {
                            riskScore = Math.max(riskScore, 40);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                        } else if (hasAutoOnly || hasTlshOnly || mlMalicious) {
                            riskScore = Math.max(riskScore, mlMalicious ? 70 : 40);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                        }
                        if (mlMalicious) {
                            String src = "";
                            for (NativeScanner.Verdict.Detection d : v.detections) {
                                if ("ML".equals(d.name)) {
                                    src = subFileSuffix(apkPath, d.objectPath);
                                    break;
                                }
                            }
                            reasons.add(String.format(java.util.Locale.US,
                                "🤖 [ML] probability=%.2f%s", v.probability, src));
                        }
                    } else if (v.isError()) {
                        Log.w(TAG, "native scan error: " + v.error);
                    }

                    if (DetectionCategories.isEnabled(context, DetectionCategories.PERMISSIONS)) {
                        if (v.permissions >= 30) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                            reasons.add("🔐 Virus permissions (" + v.permissions + "/36)");
                        } else if (v.permissions >= 25) {
                            riskScore = Math.max(riskScore, 40);
                            if (riskScore < 50) builder.setThreatType(
                                com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                            reasons.add("🔐 Suspicious permissions (" + v.permissions + "/36)");
                        }
                    }
                    } // end if (v != null)
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
            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.UNKNOWN);
        }
        CharSequence appName = pm.getApplicationLabel(app);
        if (appName == null || appName.toString().contains("com."))
            appName = new java.io.File(app.sourceDir).getName();
        if (isApkFile) appName = appName + " (SD CARD)";
        builder.setAppName(appName.toString());
        if (isApkFile) builder.setApkPath(app.sourceDir);
        
        ThreatResult finalRes = builder.build();
        if (!cancelRequested && app.packageName != null && scanCache != null) scanCache.putPhotonCache(app.packageName, finalRes);
        return finalRes;
    }
}

