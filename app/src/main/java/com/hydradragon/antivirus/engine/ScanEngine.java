package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;
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
        "google", "meta", "facebook", "whatsapp", "microsoft",
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
    /** EXACT whole-APK SHA-256 whitelist (NSRL RDS Android, extension=apk). A
     *  native (clamav/YARA/ML) detection whose whole-APK SHA-256 is in here is a
     *  known false positive and suppressed. Exact membership (not a bloom): the
     *  set is small (~70k) so we get ZERO false positives — i.e. no whitelist
     *  false negative (a malicious hash can never collide into the whitelist). */
    private final java.util.HashSet<String> whitelistHashes = new java.util.HashSet<>();
    /** EXACT known-good package names (NSRL Android, extension=apk). NOT a
     *  standalone clear — a package name is spoofable, so it only clears an app
     *  when combined with a trusted-store install (see analyzeApp). */
    private final java.util.HashSet<String> whitelistPackages = new java.util.HashSet<>();
    /** Set by {@link #cancelScan()} to abort an in-flight scan at the next loop
     *  boundary. Volatile so the UI thread's request is seen by the scan thread. */
    private volatile boolean cancelRequested = false;

    /** Request the running scan to stop as soon as possible (checked between
     *  files/apps, so an already-started native scan of one file still finishes). */
    public void cancelScan() { cancelRequested = true; }

    /** Whether a stop was requested for the current/last scan. */
    public boolean isCancelled() { return cancelRequested; }

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
        loadBloomFilter();
        // Load YARA rulesets + ML model into the native engine (non-fatal).
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

    private void loadBloomFilter() {
        // EXACT whole-APK SHA-256 whitelist (NSRL RDS Android, extension=apk),
        // one lowercase-hex digest per line. Loaded into a HashSet for O(1) exact
        // membership — zero false positives (no whitelist-induced false negative).
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                context.getAssets().open("whitelist_hashes.txt"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.length() == 64) whitelistHashes.add(line);
            }
        } catch (Exception e) { /* missing — whitelist disabled */ }
        // Known-good package names (NSRL). Used only WITH trusted-store origin.
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                context.getAssets().open("whitelist_packages.txt"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) whitelistPackages.add(line);
            }
        } catch (Exception e) { /* missing — package whitelist disabled */ }
    }

    /** True if {@code hash} (a whole-APK/file SHA-256) is an exact known-good
     *  NSRL hash. Exact match — a malicious hash can never falsely land here. */
    private boolean isHashWhitelisted(String hash) {
        return hash != null && whitelistHashes.contains(hash.toLowerCase(java.util.Locale.US));
    }

    /** True if {@code pkg} is an exact known-good NSRL package name. Spoofable on
     *  its own, so callers must combine it with a trusted-store install. */
    private boolean isPackageWhitelisted(String pkg) {
        return pkg != null && whitelistPackages.contains(pkg);
    }

    /** Lowercase-hex SHA-256 of a file's bytes (streamed), or null on error. We
     *  compute it in Java — the native side never sends raw bytes back, only the
     *  hash — so a known-good whole file can be cleared BEFORE the expensive
     *  yara/clamav/ML scan even runs (the "hash first" fast path). */
    private static String fileSha256(java.io.File file) {
        try (java.io.InputStream in = new java.io.FileInputStream(file)) {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : md.digest()) sb.append(Character.forDigit((b >> 4) & 0xF, 16))
                                         .append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    /** Hash-first fast path: if the whole file's SHA-256 is whitelisted it's a
     *  known-good file — skip scanning entirely. Valid for a pure APK (its file
     *  bytes == the APK/zip buffer the whitelist was keyed on). */
    private boolean isFileWhitelisted(String path) {
        return isHashWhitelisted(fileSha256(new java.io.File(path)));
    }

    /** A native detection is a false positive iff one of the APKs in its
     *  extraction lineage is whitelisted (the hit lives inside a known-good APK). */
    private boolean isDetectionWhitelisted(NativeScanner.Verdict.Detection d) {
        for (String h : d.hashes) if (isHashWhitelisted(h)) return true;
        return false;
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

    public void scanAllApps(boolean isFullScan) {
        cancelRequested = false;
        scanExecutor.execute(() -> {
            PackageManager pm = context.getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<ThreatResult> threats = new ArrayList<>();
            int total = apps.size();

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
                    scanAllStorageRoots(pm, threats);
                    deepNativeScanInstalledApks(apps, pm, threats);
                    scanRecentProcesses(pm, threats);
                    scanAccessibleDataDirs(pm, threats);
                } else if (!cancelRequested) {
                    // Quick scan: only APKs in Downloads.
                    scanDirectoryForApks(
                        android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS),
                        pm, threats, false);
                }
            } catch (Exception e) { }

            if (callback != null)
                callback.onScanComplete(new ScanResult(total + threats.size(), threats.size(), threats));
        });
    }

    private void scanDirectoryForApks(java.io.File dir, PackageManager pm,
                                      List<ThreatResult> threats, boolean fullScan) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        java.io.File[] files = dir.listFiles();
        if (files == null) return;
        for (java.io.File file : files) {
            if (cancelRequested) return;
            if (file.isDirectory()) {
                scanDirectoryForApks(file, pm, threats, fullScan);
            } else if (file.getName().toLowerCase().endsWith(".apk")) {
                try {
                    PackageInfo pkgInfo = pm.getPackageArchiveInfo(file.getAbsolutePath(),
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
                    if (pkgInfo != null) {
                        pkgInfo.applicationInfo.sourceDir = file.getAbsolutePath();
                        pkgInfo.applicationInfo.publicSourceDir = file.getAbsolutePath();
                        ThreatResult result = analyzeApp(pkgInfo.applicationInfo, pm, true);
                        if (result != null && result.isThreat()) {
                            threats.add(result);
                            if (callback != null) callback.onThreatFound(result);
                        }
                    }
                } catch (Exception e) { }
            } else if (fullScan) {
                // Non-APK file in a full scan: route through the native engine
                // (hydradragonextractor unpacking + clamav/YARA + ML). Permission
                // analysis doesn't apply — it isn't an installable app.
                scanGenericFile(file, threats);
            }
        }
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
            String path = file.getAbsolutePath();
            // Hash-first fast path: known-good whole file → skip the scan entirely.
            if (isFileWhitelisted(path)) return;
            NativeScanner.Verdict v = NativeScanner.scan(path);
            if (v == null) return;
            // Per-detection whitelist suppression: a hit INSIDE a known-good
            // (whitelisted) APK is a false positive, but a non-APK virus sitting
            // alongside that APK in the same archive is NOT suppressed by the APK's
            // hash. Keep only the detections that survive.
            List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
            boolean malicious = !live.isEmpty();
            // Act on a surviving hit OR a dangerous-permission count.
            if (!malicious && v.permissions < 6) return;

            ThreatResult.Builder b = new ThreatResult.Builder(path);
            List<String> reasons = new java.util.ArrayList<>();
            int riskScore = 0;
            boolean mlMalicious = false;
            boolean hasRealThreat = false;
            for (NativeScanner.Verdict.Detection d : live) {
                if ("ML".equals(d.name)) {
                    mlMalicious = true;
                    hasRealThreat = true;
                } else {
                    boolean isPua = isPuaName(d.name);
                    if (!isPua) hasRealThreat = true;
                    reasons.add((isPua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + d.name);
                }
            }
            if (malicious) {
                if (hasRealThreat) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                } else {
                    riskScore = 50;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                }
            }
            // Two-tier dangerous permissions (same as installed-app analysis):
            // 7+ => certain malware, exactly 6 => suspicious.
            if (v.permissions >= 7) {
                riskScore = 100;
                b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/9)");
            } else if (v.permissions == 6) {
                riskScore = Math.max(riskScore, 30);
                if (!hasRealThreat) {
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                }
                reasons.add("🔐 Suspicious permissions (6/9)");
            }
            if (mlMalicious) {
                String near = v.nearest != null ? "  ~" + v.nearest : "";
                reasons.add(String.format(java.util.Locale.US,
                    "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
            }
            if (v.sha256 != null && !v.sha256.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.sha256);
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

    // ──────────────────────── FULL-SCAN EXTRA PASSES ────────────────────────

    /** 1) Every file under ALL mounted storage volumes, not just primary /sdcard. */
    private void scanAllStorageRoots(PackageManager pm, List<ThreatResult> threats) {
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
            try { scanDirectoryForApks(new java.io.File(r), pm, threats, true); }
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
                // Hash-first fast path: known-good APK (SHA-256 match) → skip.
                // (No package-name skip — a package name is spoofable.)
                if (isFileWhitelisted(app.sourceDir)) continue;
                NativeScanner.Verdict v = NativeScanner.scan(app.sourceDir, app.packageName);
                if (v == null) continue;
                // Per-detection suppression (a hit inside a whitelisted APK is an
                // FP; a non-APK virus alongside it is not). Nothing survives → skip.
                List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
                if (live.isEmpty()) continue;
                ThreatResult.Builder b = new ThreatResult.Builder(
                    app.packageName != null ? app.packageName : app.sourceDir);
                List<String> reasons = new java.util.ArrayList<>();
                boolean real = false;
                for (NativeScanner.Verdict.Detection d : live) {
                    if ("ML".equals(d.name)) { real = true; continue; }
                    boolean pua = isPuaName(d.name);
                    if (!pua) real = true;
                    reasons.add((pua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + d.name);
                }
                b.setThreatType(real
                    ? com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE
                    : com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                b.setRiskScore(real ? 100 : 50);
                if (v.sha256 != null && !v.sha256.isEmpty())
                    reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + v.sha256);
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
        if (isSystem) { builder.setRiskScore(0); return builder.build(); }

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
            builder.setRiskScore(0); return builder.build();
        }

        // User previously marked this app safe ("Safe (ignore)") -> never flag.
        if (app.packageName != null && UserDecisions.isThreatAllowed(context, app.packageName)) {
            builder.setRiskScore(0); return builder.build();
        }

        int riskScore = 0;
        List<String> reasons = new ArrayList<>();
        String fileSha256 = null;   // top-level file hash from the native scan (for the VirusTotal link)
        String companyName = "Unknown Developer";
        String signatureHash = "NONE";

        try {
            PackageInfo pkgInfo = isApkFile
                ? pm.getPackageArchiveInfo(app.sourceDir, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES)
                : pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);

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
                    if (companyName.toLowerCase().contains(trusted)) { isWhitelisted = true; break; }

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
                CodeAnalyzer.AnalysisResult codeResult = codeAnalyzer.analyzeApk(apkPath);
                if (codeResult.isMalicious) {
                    riskScore = Math.min(100, riskScore + codeResult.riskScore);
                    builder.setThreatType(codeResult.threatType);
                    for (String finding : codeResult.findings) {
                        if (!finding.startsWith("✅")) reasons.add("💻 [CODE] " + finding);
                    }
                }

                // Native engine: clamav (type-gated YARA + signatures) + ML model.
                // Hash-first: a known-good (whitelisted) APK skips the whole native
                // block — no scan, no detections, no permission flag.
                if (apkPath != null && NativeScanner.isReady() && !isFileWhitelisted(apkPath)) {
                    NativeScanner.Verdict v = NativeScanner.scan(apkPath, app.packageName);
                    fileSha256 = v.sha256;
                    // Per-detection whitelist suppression (hit inside a whitelisted
                    // APK = FP; non-APK virus alongside it survives).
                    List<NativeScanner.Verdict.Detection> live = survivingDetections(v);
                    boolean mlMalicious = false;
                    if (!live.isEmpty()) {
                        // Split PUA.* / PUA_* hits (potentially-unwanted) from real
                        // malware. Only-PUA (and no ML flag) => PUA, lower risk.
                        boolean hasRealThreat = false;
                        for (NativeScanner.Verdict.Detection d : live) {
                            if ("ML".equals(d.name)) { mlMalicious = true; hasRealThreat = true; continue; }
                            boolean isPua = isPuaName(d.name);
                            if (!isPua) hasRealThreat = true;
                            reasons.add((isPua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + d.name);
                        }
                        if (hasRealThreat) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                        } else {
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
                    // (9 most-dangerous: SMS, call log, contacts, mic, camera,
                    // location, overlay, all-files). 7+ = almost certainly malware;
                    // exactly 6 = suspicious. Legit apps routinely request 3-5.
                    if (v.permissions >= 7) {
                        riskScore = 100;
                        builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                        reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/9)");
                    } else if (v.permissions == 6) {
                        riskScore = Math.max(riskScore, 30);
                        if (riskScore < 50) builder.setThreatType(
                            com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                        reasons.add("🔐 Suspicious permissions (6/9)");
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
            if (fileSha256 != null && !fileSha256.isEmpty()) {
                reasons.add("🔍 VirusTotal: https://www.virustotal.com/gui/file/" + fileSha256);
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
