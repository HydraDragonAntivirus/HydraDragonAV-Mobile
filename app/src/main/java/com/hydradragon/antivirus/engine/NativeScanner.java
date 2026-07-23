package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Bridge to the native libhydradragonandroid.so scanner.
 *
 * <p>Combines the HydraDragon YARA rulesets (compiled {@code .yrc} bundled as
 * assets) with the one-class MinHash/LSH + Isolation Forest ML model
 * ({@code apk_model.json}) to flag malicious APKs on-device.
 *
 * <p>Usage:
 * <pre>
 *   NativeScanner.init(context);                  // once, e.g. in Application
 *   String json = NativeScanner.scanApk(apkPath); // per APK
 * </pre>
 */
public final class NativeScanner {

    private static final String TAG = "NativeScanner";

    /**
     * Assets sub-folder holding the full scan bundle, read directly from the
     * APK by Rust's AAssetManager — no disk copy needed: compiled {@code .yrc}
     * YARA-X rulesets, the ML model, the clamav signature DBs
     * (.ndb/.ldb/.ldu/.db), the file-type magics (.ftm) needed for the
     * supported-type gate, and the bytecode (.cbc).
     */
    private static final String ASSET_DIR = "scan";

    /** Whether libhydradragonandroid.so loaded. If false, all calls no-op safely. */
    private static final boolean LIB_LOADED;

    /** Guards against firing nativeInit() more than once. isReady() alone isn't
     *  enough: nativeInit() spawns its background Rust thread and returns almost
     *  immediately, staying false for the ~70s the real load takes — so every
     *  call site that races in during that window (HydraDragonApp.onCreate,
     *  MainActivity.onCreate, BootReceiver, GuardService's ScanEngine, and a
     *  fresh ScanEngine per InstallReceiver package-added/replaced event) used
     *  to see isReady()==false and each kick off its own redundant native-init
     *  thread — observed as 6 concurrent native-init threads starving the main
     *  thread into an ANR. */
    private static final java.util.concurrent.atomic.AtomicBoolean INIT_STARTED =
        new java.util.concurrent.atomic.AtomicBoolean(false);

    static {
        boolean loaded;
        try {
            System.loadLibrary("hydradragonandroid");
            loaded = true;
        } catch (Throwable t) {
            // .so missing for this ABI or not built yet — degrade gracefully
            // instead of throwing UnsatisfiedLinkError/ExceptionInInitializerError
            // (which is an Error, not caught by callers' catch(Exception)).
            loaded = false;
            Log.e(TAG, "libhydradragonandroid not loaded; native scan disabled", t);
        }
        LIB_LOADED = loaded;
    }

    private NativeScanner() {
    }

    private static native boolean nativeInit(String assetDir, boolean loadAutoRules, android.content.res.AssetManager assetManager, String filesDir);

    /** True when the async background init has finished populating the native
     *  engine. Replaces the old Java-side {@code ready} flag so the Java layer
     *  is always in sync with the actual Rust engine state. */
    private static native boolean nativeIsReady();

    private static native boolean nativeLearnRule(String yarPath);

    private static native boolean nativeIsEmulationAvailable();

    private static native void nativeSetEmulationEnabled(boolean enabled);

    private static native void nativeSetMaxScanSizeMb(int maxMb);

    private static native void nativeSetDetectZipBomb(boolean enabled);

    private static native void nativeSetScanRelevantOnly(boolean on);

    /** Settings toggle for the Unicorn-based native-code emulation pass (runs
     *  every embedded .so's JNI_OnLoad/entry point in a bounded, syscall-free
     *  sandbox to reveal strings — e.g. a C2 URL — a decode routine only
     *  produces at runtime, never as static plaintext). Applied immediately,
     *  no engine reinit or app restart needed — actually skips the emulation
     *  cost when off, not just its results. */
    public static void setEmulationEnabled(boolean enabled) {
        if (!LIB_LOADED) return;
        try { nativeSetEmulationEnabled(enabled); } catch (Throwable ignore) { }
    }

    /** Called by Rust when the startup probe detects Unicorn's ARM64 JIT
     *  backend is broken on this device.  The app shows a one-time warning
     *  via {@link R.string.unicorn_unsupported}. */
    public static void onEmulationUnavailable(String reason) {
        Log.w(TAG, "Emulation unavailable: " + reason);
    }

    /** Push the user's {@link MaxScanFileSize} preference into the native
     *  engine so extracted archive entries larger than this ceiling are
     *  excluded from ClamAV/YARA/ML scanning. Applied immediately; no
     *  reinit needed. */
    public static void setMaxScanSizeMb(int maxMb) {
        if (!LIB_LOADED) return;
        try { nativeSetMaxScanSizeMb(maxMb); } catch (Throwable ignore) { }
    }

    /** Settings toggle for decompression-bomb rejection during archive
     *  extraction. When on (default), any single decompressed unit past
     *  200 MB, or past a 1000:1 output:input ratio beyond a 10 MB floor, is
     *  rejected and flagged as a detection instead of fully decompressed.
     *  Applied immediately; no reinit needed. */
    public static void setDetectZipBomb(boolean enabled) {
        if (!LIB_LOADED) return;
        try { nativeSetDetectZipBomb(enabled); } catch (Throwable ignore) { }
    }

    /** Settings toggle for relevant-only scanning: when true, only DEX, ELF,
     *  AndroidManifest.xml, and text-like files are scanned inside APKs; all
     *  other assets (images, layouts, resources.arsc, etc.) are skipped.
     *  Applied immediately; no reinit needed. */
    public static void setScanRelevantOnly(boolean on) {
        if (!LIB_LOADED) return;
        try { nativeSetScanRelevantOnly(on); } catch (Throwable ignore) { }
    }

    /** Hot-load a single freshly auto-generated {@code .yar} rule (already written
     *  to disk by ScanEngine.saveGeneratedRule) into the LIVE native engine, so a
     *  family this device just caught is detected by every scan for the rest of
     *  THIS session too — not only after the next app restart (which already
     *  reloads every past generated rule from the init directory). Best-effort:
     *  false just means this session doesn't get the instant benefit; the rule is
     *  still on disk and will load normally next launch. */
    public static boolean learnRule(String yarPath) {
        if (!isReady() || yarPath == null || yarPath.isEmpty()) return false;
        try { return nativeLearnRule(yarPath); } catch (Throwable t) { return false; }
    }

    private static native String nativeScanApk(String path, String hydradragonJson, String fileMd5, boolean zeroTrust);

    /** Diagnostics: what loaded / failed during the last nativeInit. */
    private static native String nativeStatus();

    private static native boolean nativeIsHashWhitelisted(String md5);
    private static native boolean nativeIsHashWhitelistedForFile(String path, String md5);

    private static native String nativeScanUrl(String url);

    /** Malicious category (e.g. "PHISHING") for an http(s) URL, or null if clean
     *  / not a URL. Membership is the native xor filter URL/domain scanner — no
     *  xor filter is held in the Java heap. */
    public static String scanUrl(String url) {
        if (!isReady() || url == null || url.isEmpty()) return null;
        try {
            String c = nativeScanUrl(url);
            return (c == null || c.isEmpty()) ? null : c;
        } catch (Throwable t) { return null; }
    }

    private static native String nativeScanIp(String ip);

    /** Comma-joined matched rule/signature names for OCR'd on-screen text
     *  ("" if clean or engine not ready). Backs {@link #scanText}. */
    private static native String nativeScanText(String text);

    private static native String nativeScanHips(String hipsJson);

    private static native void nativeSetTlshThreshold(int threshold);

    private static native int nativeTlshDiff(String tlsh1, String tlsh2);

    // ── VPN packet scan ─────────────────────────────────────────────────

    private static native void nativeEnableVpnScan(boolean enable);

    private static native String nativeScanPackets(String packetsJson);

    /** Enable VPN packet scanning. Loads emerging-all.yrc rules lazily.
     *  Call from VpnService.onStart(). */
    public static void enableVpnScan(boolean enable) {
        if (!LIB_LOADED) return;
        try { nativeEnableVpnScan(enable); } catch (Throwable ignore) { }
    }

    /** Scan captured VPN packets against emerging-all.yrc (hydradragon
     *  network-threat rules). Returns null if VPN scan is disabled or
     *  engine not ready. */
    public static String scanPackets(String packetsJson) {
        if (!isReady() || packetsJson == null || packetsJson.isEmpty()) return null;
        try {
            String r = nativeScanPackets(packetsJson);
            return (r == null || r.isEmpty()) ? null : r;
        } catch (Throwable t) { return null; }
    }

    /** Push the user's TLSH similarity threshold into the native engine so the
     *  `tlsh_nearest` malware-similarity pass uses it immediately. Clamped
     *  1-200 natively. */
    public static void setTlshThreshold(int threshold) {
        if (!LIB_LOADED) return;
        try { nativeSetTlshThreshold(threshold); } catch (Throwable ignore) { }
    }

    /** TLSH diff distance between two hashes, or -1 on error. */
    public static int tlshDiff(String tlsh1, String tlsh2) {
        if (!LIB_LOADED || tlsh1 == null || tlsh2 == null
                || tlsh1.isEmpty() || tlsh2.isEmpty()) return -1;
        try { return nativeTlshDiff(tlsh1, tlsh2); } catch (Throwable t) { return -1; }
    }

    /** Result of a HIPS behavioral scan. */
    public static final class HipsResult {
        public boolean malicious;
        public final java.util.List<String> matches = new java.util.ArrayList<>();
        /** Suggestion: "uninstall", "warn", or "none". */
        public String suggestion = "none";

        public boolean isMalicious() { return malicious; }
    }

    /** Scan all behavioral HIPS metadata against the YARA-X hydradragon module
     *  HIPS rules. Returns the verdict including matched rules and suggestion. */
    public static HipsResult scanHips(android.content.Context ctx) {
        HipsResult r = new HipsResult();
        if (!isReady()) return r;
        try {
            String json = HipsMonitor.buildReportJson(ctx);
            if (json == null || json.isEmpty()) return r;
            String result = nativeScanHips(json);
            if (result == null || result.isEmpty()) return r;
            org.json.JSONObject o = new org.json.JSONObject(result);
            if (o.has("error")) return r;
            r.malicious = o.optBoolean("malicious", false);
            if (o.has("suggestion")) r.suggestion = o.optString("suggestion", "none");
            org.json.JSONArray arr = o.optJSONArray("matches");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    String m = arr.optString(i, null);
                    if (m != null && !m.isEmpty()) r.matches.add(m);
                }
            }
        } catch (Throwable t) { /* degrade gracefully */ }
        return r;
    }

    /** Convenience: scan HIPS and auto-trigger uninstall if behavioral malware
     *  is detected with "uninstall" suggestion. */
    public static void scanAndRespond(android.content.Context context) {
        HipsResult result = scanHips(context);
        if (result.isMalicious() && "uninstall".equals(result.suggestion)) {
            String flaggedPkg = null;
            for (String match : result.matches) {
                String pkg = extractPackageFromMatch(match);
                if (pkg != null) {
                    flaggedPkg = pkg;
                    break;
                }
            }
            if (flaggedPkg != null) {
                BehaviorResponse.killAndPromptUninstall(context, flaggedPkg);
            }
        }
    }

    /** Extract a package name from a HIPS match identifier.
     *  e.g. "YARA-X.com.evil.app.Ransomware" -> "com.evil.app" */
    private static String extractPackageFromMatch(String match) {
        if (match == null || match.isEmpty()) return null;
        String s = match;
        if (s.startsWith("YARA-X.")) s = s.substring(7);
        else if (s.startsWith("YARA.")) s = s.substring(5);
        else if (s.startsWith("HIPS.")) s = s.substring(5);
        String[] parts = s.split("\\.");
        if (parts.length >= 3) {
            StringBuilder pkg = new StringBuilder();
            for (int i = 0; i < parts.length - 1 && i < 4; i++) {
                if (pkg.length() > 0) pkg.append('.');
                pkg.append(parts[i]);
            }
            return pkg.toString();
        }
        return null;
    }

    /** Malicious category (e.g. "MALWARE_IP") for a resolved IP, or null if clean.
     *  Exact match against the native per-category xor filters (no CIDR/subnet).
     *  Only valid public (non-private, non-loopback, non-link-local, non-multicast)
     *  IPv4 and IPv6 addresses are scanned — domains and private IPs are rejected. */
    public static String scanIp(String ip) {
        if (!isReady() || ip == null || ip.isEmpty()) return null;
        if (!isValidPublicIp(ip)) return null;
        try {
            String c = nativeScanIp(ip);
            return (c == null || c.isEmpty()) ? null : c;
        } catch (Throwable t) { return null; }
    }

    /** Returns true if {@code ip} is a valid public (non-private, non-loopback,
     *  non-link-local, non-multicast) IPv4 address. Rejects domains, hostnames,
     *  malformed strings, and IPv6 (not supported by the native IP xor filters). */
    public static boolean isValidPublicIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        // Reject anything that looks like a domain (contains letters).
        // The IP xor filters only contain canonical IPv4 strings, so any
        // non-digit/dot character means it's not a raw IP literal.
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            int[] octets = new int[4];
            for (int i = 0; i < 4; i++) {
                int val = Integer.parseInt(parts[i]);
                if (val < 0 || val > 255) return false;
                octets[i] = val;
            }
            // Exclude private ranges, loopback, link-local, multicast.
            if (octets[0] == 10) return false;                          // 10.0.0.0/8
            if (octets[0] == 127) return false;                         // 127.0.0.0/8
            if (octets[0] == 169 && octets[1] == 254) return false;     // 169.254.0.0/16
            if (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)) return false; // 172.16.0.0/12
            if (octets[0] == 192 && octets[1] == 168) return false;     // 192.168.0.0/16
            if (octets[0] >= 224 && octets[0] <= 239) return false;     // 224.0.0.0/4 multicast
            if (octets[0] >= 240) return false;                         // 240.0.0.0/4 reserved
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** True if {@code md5} is in the NSRL whitelist (held in NATIVE memory as a
     *  xor filter — never loaded into the Java heap). False if the native
     *  lib/whitelist isn't available. */
    public static boolean isHashWhitelisted(String md5) {
        if (!isReady() || md5 == null || md5.isEmpty()) return false;
        try { return nativeIsHashWhitelisted(md5); } catch (Throwable t) { return false; }
    }

    /** True if the NSRL xor filter contains {@code md5} AND {@code path} is a
     *  ZIP/APK (magic bytes validated in Rust). Non-APK files are rejected. */
    public static boolean isHashWhitelistedForFile(String path, String md5) {
        if (!isReady() || path == null || md5 == null || md5.isEmpty()) return false;
        try { return nativeIsHashWhitelistedForFile(path, md5); } catch (Throwable t) { return false; }
    }

    /** Scan OCR'd on-screen text (from ScreenCaptureService) against the
     *  ClamAV/YARA engine — including {@code hydradragon.screen_text(regexp)}
     *  rules — so wording actually rendered on screen (scam/ransomware/
     *  phishing) is caught even if it never touches the foreground app's own
     *  APK bytes. Returns matched rule/signature names, empty if clean/unready. */
    public static List<String> scanText(String text) {
        List<String> out = new ArrayList<>();
        if (!isReady() || text == null || text.isEmpty()) return out;
        try {
            String joined = nativeScanText(text);
            if (joined != null && !joined.isEmpty()) {
                for (String s : joined.split(",")) if (!s.isEmpty()) out.add(s);
            }
        } catch (Throwable t) { /* degrade gracefully */ }
        return out;
    }

    /** Public: human-readable native engine load report (clamav / yrc / model). */
    public static String status() {
        if (!LIB_LOADED) return "native lib not loaded (.so missing for this ABI)";
        try { return nativeStatus(); } catch (Throwable t) { return "status error: " + t; }
    }

    /**
     * Start the native engine initialisation ASYNCHRONOUSLY with NO asset
     * copy — Rust's AAssetManager reads every scan file directly from the
     * APK (no 330+ MB disk write at launch). The expensive engine loading
     * runs on a background Rust thread. Use {@link #isReady()} to check
     * whether the native engine has finished loading. Safe to call multiple
     * times.
     *
     * @return true when the native engine is already ready; false if init is
     *         still in progress or the library is unavailable.
     */
    public static synchronized boolean init(Context context) {
        if (isReady()) {
            return true;
        }
        if (!LIB_LOADED) {
            return false;
        }
        if (!INIT_STARTED.compareAndSet(false, true)) {
            // Another caller already kicked off nativeInit(); it's still
            // loading in the background. Don't start a second (third, ...)
            // redundant native-init thread — just report not-ready-yet.
            return false;
        }
        // NO asset copy to disk — Rust reads every file directly from the
        // APK assets via AAssetManager. The 70-second init still happens on
        // a background thread but the 330+ MB disk write at launch is gone.
        // The filesDir is still needed for generated_rules/ (auto-learned rules).
        // Best-effort: if mkdirs fails, native init still runs (just no generated
        // rules will be loaded until the next launch after mkdirs succeeds).
        java.io.File dir = new java.io.File(context.getFilesDir(), "hydra-scan");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        boolean loadAutoRules = com.hydradragon.antivirus.engine.DetectionCategories.isEnabled(
            context, com.hydradragon.antivirus.engine.DetectionCategories.AUTO_RULES);
        nativeInit(ASSET_DIR, loadAutoRules, context.getAssets(), dir.getAbsolutePath());
        if (isReady()) {
            // Probe Unicorn at startup — if the ARM64 JIT backend hangs
            // (known bug on real phone hardware), emulation is permanently
            // disabled for this process lifetime.
            if (!nativeIsEmulationAvailable()) {
                onEmulationUnavailable("ARM64 JIT probe failed");
            }
            setEmulationEnabled(com.hydradragon.antivirus.engine.DetectionCategories.isEnabled(
                context, com.hydradragon.antivirus.engine.DetectionCategories.NATIVE_EMULATION));
            setMaxScanSizeMb(com.hydradragon.antivirus.engine.MaxScanFileSize.getMaxMb(context));
            setDetectZipBomb(context.getSharedPreferences("hydra_prefs", 0)
                .getBoolean("detect_zip_bomb_enabled", true));
            setScanRelevantOnly(context.getSharedPreferences("hydra_prefs", 0)
                .getBoolean("scan_relevant_only_enabled", true));
            setTlshThreshold(context.getSharedPreferences("hydra_prefs", 0)
                .getInt("anti_fn_tlsh_threshold", 40));
        }
        Log.i(TAG, "native init " + (isReady() ? "ok" : "background") + " | " + status());
        return isReady();
    }

    /**
     * Scan a single APK file.
     *
     * @return JSON verdict, e.g.
         *         {@code {"malicious":true,"yara":["YARA.Foo"],
     *         "ml":{"malicious":false,"probability":0.61}}
     *         or {@code {"error":"..."}} on failure.
     */
    public static String scanApk(String apkPath) {
        return scanApk(apkPath, null, null, false);
    }

    /** Scan an APK, feeding the {@code hydradragon} module the live-network report
     *  attributed to {@code packageName} (null for an uninstalled APK file).
     *  {@code fileMd5} is the caller's already-computed MD5 of the whole file
     *  (from the hash-first whitelist check), reused natively so the top-level
     *  buffer isn't hashed again; null/"" makes native compute it. */
    public static String scanApk(String apkPath, String packageName, String fileMd5) {
        return scanApk(apkPath, packageName, fileMd5, false);
    }

    /** Same as {@link #scanApk(String, String, String)}, but when
     *  {@code zeroTrust} is true the native side builds the yarGen-style
     *  {@code generated_rule} even for a CLEAN verdict (normally only built
     *  for a malicious one) — Zero Trust Mode never treats "nothing matched"
     *  as "nothing to record". */
    public static String scanApk(String apkPath, String packageName, String fileMd5, boolean zeroTrust) {
        if (!isReady()) {
            return "{\"error\":\"not initialised\"}";
        }
        return nativeScanApk(apkPath, NetworkObservations.buildReportJson(packageName),
                fileMd5 == null ? "" : fileMd5, zeroTrust);
    }

    /** Parsed scan verdict. */
    public static final class Verdict {
        /** Overall: malicious if any clamav/YARA match OR the ML model flagged it. */
        public boolean malicious;
        /** clamav signature + YARA rule names that matched (empty if none). */
        public final List<String> matches = new ArrayList<>();
        /** ML one-class model sub-result. */
        public boolean mlMalicious;
        public double probability;
        /** Distinct dangerous permissions found in the (in-memory) manifest bytes. */
        public int permissions;
        /** Package name(s) of APK(s) reached in-memory (parsed from AndroidManifest.xml). */
        public final List<String> packages = new ArrayList<>();
        /** SHA-256 (lowercase hex) of each APK/zip buffer, for hash-keyed whitelist. */
        public final List<String> hashes = new ArrayList<>();
        /** One entry per malicious hit, each carrying the SHA-256s of the APK(s) in
         *  the buffer's extraction lineage. A detection is a false positive (and
         *  suppressed) iff one of its {@code hashes} is whitelisted — so a hit
         *  inside a known-good APK is cleared while a sibling non-APK virus is not. */
        public final List<Detection> detections = new ArrayList<>();

        public static final class Detection {
            public final String name;
            /** Full in-archive path of the matched sub-file, e.g. {@code app.apk!/classes.dex}. */
            public final String objectPath;
            public final List<String> hashes;
            Detection(String name, String objectPath, List<String> hashes) {
                this.name = name;
                this.objectPath = objectPath;
                this.hashes = hashes;
            }
        }
        /** MD5 (lowercase hex) of the whole scanned file — its "main hash". */
        public String md5;
        /** TLSH of the whole scanned file (its "main hash", mirrors {@link #md5}).
         *  Used by the Anti-FN cache to match a repackaged/renamed variant of a
         *  previously-caught top-level (non-archive) malicious file. */
        public String fileTlsh;
        /** Per-entry MD5 map: entry_name -> md5 (from native verdict entry_md5s).
         *  Used by the Anti-FP cache to check individual zip entry hashes. */
        public final java.util.HashMap<String, String> entryMd5s = new java.util.HashMap<>();
        /** Per-entry TLSH map: entry_name -> tlsh (from native verdict entry_tlshs).
         *  Used by the Anti-FP cache for TLSH similarity matching. */
        public final java.util.HashMap<String, String> entryTlshs = new java.util.HashMap<>();
        /** Non-null ClamAV target number if the file type was skipped (PE/OLE2/…). */
        public Integer skippedTarget;
        /** Non-null if the native scan errored. */
        public String error;
        /** yarGen-style auto-generated YARA rule text for THIS malicious sample
         *  (androguard/hydradragon-aware condition, no whitelist-DB string
         *  filtering), or null for a clean scan / when nothing was extractable. */
        public String generatedRule;
        public String path;

        public boolean isError() { return error != null; }
        public boolean isSkipped() { return skippedTarget != null; }
    }

    public static Verdict scan(String apkPath) {
        return scan(apkPath, null, null);
    }

    public static Verdict scan(String apkPath, String packageName) {
        return scan(apkPath, packageName, null);
    }

    /**
     * Scan an APK and return a fully-parsed {@link Verdict}. {@code packageName}
     * scopes the live-network ({@code hydradragon}) report to that app; pass null
     * for an uninstalled APK file (no runtime activity attributed). {@code fileMd5}
     * is the caller's already-computed MD5 of the file, reused natively.
     */
    public static Verdict scan(String apkPath, String packageName, String fileMd5) {
        return scan(apkPath, packageName, fileMd5, false);
    }

    /** Same as {@link #scan(String, String, String)} but forwards
     *  {@code zeroTrust} to {@link #scanApk(String, String, String, boolean)}. */
    public static Verdict scan(String apkPath, String packageName, String fileMd5, boolean zeroTrust) {
        Verdict v = new Verdict();
        if (!isReady()) {
            v.error = "not initialised";
            return v;
        }
        String json = scanApk(apkPath, packageName, fileMd5, zeroTrust);
        if (json == null) {
            v.error = "null native result";
            return v;
        }
        try {
            JSONObject o = new JSONObject(json);
            return parseVerdictJson(o);
        } catch (Throwable t) {
            v.error = "bad json: " + t.getMessage();
            return v;
        }
    }

    public static Verdict parseVerdictJson(JSONObject o) throws Exception {
        Verdict v = new Verdict();
        if (o.has("error")) {
            v.error = o.optString("error", "unknown");
            return v;
        }
        if (o.has("path")) {
            v.path = o.optString("path", "");
        }
        v.malicious = o.optBoolean("malicious", false);
        v.permissions = o.optInt("permissions", 0);
        JSONArray pkgs = o.optJSONArray("packages");
            if (pkgs != null) {
                for (int i = 0; i < pkgs.length(); i++) {
                    String p = pkgs.optString(i, null);
                    if (p != null && !p.isEmpty()) v.packages.add(p);
                }
            }
            JSONArray hsh = o.optJSONArray("hashes");
            if (hsh != null) {
                for (int i = 0; i < hsh.length(); i++) {
                    String h = hsh.optString(i, null);
                    if (h != null && !h.isEmpty()) v.hashes.add(h);
                }
            }
            if (o.has("md5") && !o.isNull("md5")) {
                v.md5 = o.optString("md5", null);
            }
            if (o.has("file_tlsh") && !o.isNull("file_tlsh")) {
                String ft = o.optString("file_tlsh", null);
                if (ft != null && !ft.isEmpty()) v.fileTlsh = ft;
            }
            if (o.has("skipped") && !o.isNull("skipped")) {
                v.skippedTarget = o.optInt("skipped");
            }
            JSONArray arr = o.optJSONArray("matches");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    String m = arr.optString(i, null);
                    if (m != null && !m.isEmpty()) v.matches.add(m);
                }
            }
            JSONArray dets = o.optJSONArray("detections");
            if (dets != null) {
                for (int i = 0; i < dets.length(); i++) {
                    JSONObject d = dets.optJSONObject(i);
                    if (d == null) continue;
                    String name = d.optString("name", "");
                    String objectPath = d.optString("object_path", "");
                    List<String> dh = new ArrayList<>();
                    JSONArray dhArr = d.optJSONArray("hashes");
                    if (dhArr != null)
                        for (int j = 0; j < dhArr.length(); j++) {
                            String h = dhArr.optString(j, null);
                            if (h != null && !h.isEmpty()) dh.add(h);
                        }
                    v.detections.add(new Verdict.Detection(name, objectPath, dh));
                }
            }
            if (o.has("generated_rule") && !o.isNull("generated_rule")) {
                v.generatedRule = o.optString("generated_rule", null);
            }
            JSONObject em = o.optJSONObject("entry_md5s");
            if (em != null) {
                for (java.util.Iterator<String> it = em.keys(); it.hasNext();) {
                    String key = it.next();
                    String val = em.optString(key, null);
                    if (key != null && val != null && !key.isEmpty() && !val.isEmpty()) {
                        v.entryMd5s.put(key, val);
                    }
                }
            }
            JSONObject et = o.optJSONObject("entry_tlshs");
            if (et != null) {
                for (java.util.Iterator<String> it = et.keys(); it.hasNext();) {
                    String key = it.next();
                    String val = et.optString(key, null);
                    if (key != null && val != null && !key.isEmpty() && !val.isEmpty()) {
                        v.entryTlshs.put(key, val);
                    }
                }
            }
            JSONObject ml = o.optJSONObject("ml");
            if (ml != null) {
                v.mlMalicious = ml.optBoolean("malicious", false);
                v.probability = ml.optDouble("probability", 0.0);
            }
        return v;
    }

    public static boolean isReady() {
        return LIB_LOADED && nativeIsReady();
    }

    /**
     * Block the calling thread (never the UI thread — callers must run this
     * off the main thread) until the native engine finishes loading its
     * signature databases, or until {@code timeoutMs} elapses. On a slow
     * device the ~70s background load (see {@link #init}) can still be
     * running when the user scans a file seconds after launch; without this
     * wait {@code scanGenericFile} used to silently report "clean" instead
     * of actually scanning (false negative — e.g. EICAR going undetected).
     *
     * @return true if the engine became ready within the timeout, false if
     *         it timed out (or the library never loaded at all).
     */
    public static boolean waitUntilReady(long timeoutMs) {
        if (!LIB_LOADED) return false;
        long deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs;
        while (!isReady()) {
            if (android.os.SystemClock.elapsedRealtime() >= deadline) {
                return false;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return true;
    }

}
