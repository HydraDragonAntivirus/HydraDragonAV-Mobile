package com.hydradragon.antivirus.engine;

import android.content.Context;

/** User-configurable ceiling on how large a text-like file the native engine
 *  will submit to ClamAV scanning. Text files (HTML, JS, CSS, etc.) beyond
 *  this size are unlikely to contain embedded malware signatures; skipping
 *  them saves ClamAV time with no detection loss. Applied immediately. */
public final class MaxTextScanBytes {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_MAX_BYTES = "max_text_scan_bytes";

    public static final int DEFAULT_BYTES = 10_000_000;
    public static final int MIN_BYTES = 100_000;
    public static final int MAX_BYTES = 650_000_000;

    private MaxTextScanBytes() {}

    public static int getMaxBytes(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_MAX_BYTES, DEFAULT_BYTES);
    }

    public static void setMaxBytes(Context c, int bytes) {
        int clamped = Math.max(MIN_BYTES, Math.min(MAX_BYTES, bytes));
        c.getSharedPreferences(PREFS, 0).edit().putInt(KEY_MAX_BYTES, clamped).apply();
    }
}
