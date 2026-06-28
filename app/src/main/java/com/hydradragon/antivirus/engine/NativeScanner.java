package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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

    static {
        System.loadLibrary("hydradragonandroid");
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
