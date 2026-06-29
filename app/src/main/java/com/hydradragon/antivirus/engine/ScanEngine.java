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
    private BloomFilter<CharSequence> whitelistBloomFilter;

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
        try {
            InputStream is = context.getAssets().open("whitelist.bloom");
            try {
                whitelistBloomFilter = BloomFilter.readFrom(is, Funnels.stringFunnel(StandardCharsets.UTF_8));
            } catch (Exception e) {
                is.close();
                is = context.getAssets().open("whitelist.bloom");
                whitelistBloomFilter = BloomFilter.create(Funnels.stringFunnel(StandardCharsets.UTF_8), 100000, 0.01);
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null)
                    if (!line.trim().isEmpty()) whitelistBloomFilter.put(line.trim());
                reader.close();
            }
            is.close();
        } catch (Exception e) { }
    }

    public void setCallback(ScanCallback callback) { this.callback = callback; }

    public void scanAllApps(boolean isFullScan) {
        scanExecutor.execute(() -> {
            PackageManager pm = context.getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<ThreatResult> threats = new ArrayList<>();
            int total = apps.size();

            for (int i = 0; i < total; i++) {
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
                if (isFullScan) {
                    // Full scan: EVERY file under external storage. APKs get the
                    // full app analysis (permissions + code + native); every other
                    // file type is routed through the native engine, which unpacks
                    // archives via hydradragonextractor and runs clamav/YARA + ML.
                    scanDirectoryForApks(android.os.Environment.getExternalStorageDirectory(), pm, threats, true);
                } else {
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
            NativeScanner.Verdict v = NativeScanner.scan(path);
            // Act on a signature/ML hit OR a dangerous-permission count (an inner
            // APK extracted from this file, detected from the manifest bytes).
            if (v == null || (!v.malicious && v.permissions < 5)) return;

            ThreatResult.Builder b = new ThreatResult.Builder(path);
            List<String> reasons = new java.util.ArrayList<>();
            int riskScore = 0;
            boolean hasRealThreat = v.mlMalicious;
            for (String m : v.matches) {
                boolean isPua = isPuaName(m);
                if (!isPua) hasRealThreat = true;
                reasons.add((isPua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + m);
            }
            if (v.malicious) {
                if (hasRealThreat) {
                    riskScore = 100;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                } else {
                    riskScore = 50;
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                }
            }
            // Two-tier dangerous permissions (same as installed-app analysis):
            // 6+ => certain malware, exactly 5 => suspicious.
            if (v.permissions >= 6) {
                riskScore = 100;
                b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/9)");
            } else if (v.permissions == 5) {
                riskScore = Math.max(riskScore, 30);
                if (!hasRealThreat) {
                    b.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                }
                reasons.add("🔐 Suspicious permissions (5/9)");
            }
            if (v.mlMalicious) {
                String near = v.nearest != null ? "  ~" + v.nearest : "";
                reasons.add(String.format(java.util.Locale.US,
                    "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
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

        boolean isWhitelisted = false;
        if (app.packageName != null) {
            if (whitelistBloomFilter != null && whitelistBloomFilter.mightContain(app.packageName))
                isWhitelisted = true;
            for (String prefix : WHITELIST_PREFIXES)
                if (app.packageName.startsWith(prefix)) { isWhitelisted = true; break; }
        }

        if (isWhitelisted || isFromStore) { builder.setRiskScore(0); return builder.build(); }

        // User previously marked this app safe ("Safe (ignore)") -> never flag.
        if (app.packageName != null && UserDecisions.isThreatAllowed(context, app.packageName)) {
            builder.setRiskScore(0); return builder.build();
        }

        int riskScore = 0;
        List<String> reasons = new ArrayList<>();
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
                if (apkPath != null && NativeScanner.isReady()) {
                    NativeScanner.Verdict v = NativeScanner.scan(apkPath);
                    if (v.malicious) {
                        // Split PUA.* / PUA_* hits (potentially-unwanted) from real
                        // malware. Only-PUA (and no ML flag) => PUA, lower risk.
                        boolean hasRealThreat = v.mlMalicious;
                        for (String m : v.matches) {
                            boolean isPua = isPuaName(m);
                            if (!isPua) hasRealThreat = true;
                            reasons.add((isPua ? "⚠️ [PUA] " : "🛡️ [SIG] ") + m);
                        }
                        if (hasRealThreat) {
                            riskScore = 100;
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                        } else {
                            // Only PUA signatures matched.
                            riskScore = Math.max(riskScore, 50);
                            builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.PUA);
                        }
                        if (v.mlMalicious) {
                            String near = v.nearest != null ? "  ~" + v.nearest : "";
                            reasons.add(String.format(java.util.Locale.US,
                                "🤖 [ML] jaccard=%.2f anomaly=%.4f%s", v.jaccard, v.anomaly, near));
                        }
                    } else if (v.isError()) {
                        Log.w(TAG, "native scan error: " + v.error);
                    }

                    // Two-tier dangerous-permission decision on the native count
                    // (9 most-dangerous: SMS, call log, contacts, mic, camera,
                    // location, overlay, all-files). 6+ = almost certainly malware;
                    // exactly 5 = suspicious. Legit apps routinely request 3-4.
                    if (v.permissions >= 6) {
                        riskScore = 100;
                        builder.setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE);
                        reasons.add("🔐 Excessive dangerous permissions (" + v.permissions + "/9)");
                    } else if (v.permissions == 5) {
                        riskScore = Math.max(riskScore, 30);
                        if (riskScore < 50) builder.setThreatType(
                            com.hydradragon.antivirus.model.ThreatResult.ThreatType.SUSPICIOUS);
                        reasons.add("🔐 Suspicious permissions (5/9)");
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
