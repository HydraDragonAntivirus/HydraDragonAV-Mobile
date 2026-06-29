package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
     * Assets sub-folder holding the full scan bundle (copied flat to internal
     * storage so native code can read it): compiled {@code .yrc} YARA rulesets,
     * the ML model, the clamav signature DBs (.ndb/.ldb/.ldu/.db), the file-type
     * magics (.ftm) needed for the supported-type gate, and the bytecode (.cbc).
     */
    private static final String ASSET_DIR = "scan";

    private static volatile boolean ready = false;
    /** Whether libhydradragonandroid.so loaded. If false, all calls no-op safely. */
    private static final boolean LIB_LOADED;

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

    private static native boolean nativeInit(String dir);

    private static native String nativeScanApk(String path);

    /**
     * Copy bundled assets into internal storage (only if missing or stale) and
     * initialise the native engine. Safe to call multiple times.
     *
     * @return true if at least one ruleset or the ML model loaded.
     */
    public static synchronized boolean init(Context context) {
        if (ready) {
            return true;
        }
        if (!LIB_LOADED) {
            return false;   // native lib unavailable — stay disabled
        }
        File dir = new File(context.getFilesDir(), "hydra-scan");
        if (!dir.exists() && !dir.mkdirs()) {
            Log.e(TAG, "cannot create model dir " + dir);
            return false;
        }
        try {
            String[] names = context.getAssets().list(ASSET_DIR);
            if (names == null || names.length == 0) {
                Log.e(TAG, "no assets under " + ASSET_DIR);
                return false;
            }
            for (String name : names) {
                File out = new File(dir, name);
                if (!out.exists() || out.length() == 0) {
                    copyAsset(context, ASSET_DIR + "/" + name, out);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "asset copy failed", e);
            return false;
        }
        ready = nativeInit(dir.getAbsolutePath());
        Log.i(TAG, "native init " + (ready ? "ok" : "FAILED"));
        return ready;
    }

    /**
     * Scan a single APK file.
     *
     * @return JSON verdict, e.g.
     *         {@code {"malicious":true,"yara":["AndroidOS_filtered.yrc::YARA.Foo"],
     *         "ml":{"malicious":false,"jaccard":0.61,"anomaly":0.42,"nearest":"..."}}}
     *         or {@code {"error":"..."}} on failure.
     */
    public static String scanApk(String apkPath) {
        if (!ready) {
            return "{\"error\":\"not initialised\"}";
        }
        return nativeScanApk(apkPath);
    }

    /** Parsed scan verdict. */
    public static final class Verdict {
        /** Overall: malicious if any clamav/YARA match OR the ML model flagged it. */
        public boolean malicious;
        /** clamav signature + YARA rule names that matched (empty if none). */
        public final List<String> matches = new ArrayList<>();
        /** ML one-class model sub-result. */
        public boolean mlMalicious;
        public double jaccard;
        public double anomaly;
        /** Closest known-malware sample (nullable). */
        public String nearest;
        /** Distinct dangerous permissions found in the (in-memory) manifest bytes. */
        public int permissions;
        /** Package name(s) of APK(s) reached in-memory (parsed from AndroidManifest.xml). */
        public final List<String> packages = new ArrayList<>();
        /** SHA-256 (lowercase hex) of each APK/zip buffer, for hash-keyed whitelist. */
        public final List<String> hashes = new ArrayList<>();
        /** SHA-256 (lowercase hex) of the whole scanned file — its "main hash". */
        public String sha256;
        /** Non-null ClamAV target number if the file type was skipped (PE/OLE2/…). */
        public Integer skippedTarget;
        /** Non-null if the native scan errored. */
        public String error;

        public boolean isError() { return error != null; }
        public boolean isSkipped() { return skippedTarget != null; }
    }

    /**
     * Scan an APK and return a fully-parsed {@link Verdict}.
     */
    public static Verdict scan(String apkPath) {
        Verdict v = new Verdict();
        if (!ready) {
            v.error = "not initialised";
            return v;
        }
        String json = scanApk(apkPath);
        if (json == null) {
            v.error = "null native result";
            return v;
        }
        try {
            JSONObject o = new JSONObject(json);
            if (o.has("error")) {
                v.error = o.optString("error", "unknown");
                return v;
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
            if (o.has("sha256") && !o.isNull("sha256")) {
                v.sha256 = o.optString("sha256", null);
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
            JSONObject ml = o.optJSONObject("ml");
            if (ml != null) {
                v.mlMalicious = ml.optBoolean("malicious", false);
                v.jaccard = ml.optDouble("jaccard", 0.0);
                v.anomaly = ml.optDouble("anomaly", 0.0);
                if (ml.has("nearest") && !ml.isNull("nearest")) {
                    v.nearest = ml.optString("nearest", null);
                }
            }
        } catch (JSONException e) {
            v.error = "parse: " + e.getMessage();
        }
        return v;
    }

    public static boolean isReady() {
        return ready;
    }

    private static void copyAsset(Context context, String name, File out) throws IOException {
        try (InputStream in = context.getAssets().open(name);
             OutputStream os = new FileOutputStream(out)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                os.write(buf, 0, n);
            }
        }
    }
}
