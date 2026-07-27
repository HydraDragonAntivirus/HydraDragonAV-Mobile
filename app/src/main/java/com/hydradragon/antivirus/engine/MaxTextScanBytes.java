package com.hydradragon.antivirus.engine;

import android.content.Context;

/** User-configurable ceiling on how large a text-like file the native engine
 *  will submit to ClamAV scanning. Text files (HTML, JS, CSS, etc.) beyond
 *  this size are unlikely to contain embedded malware signatures; skipping
 *  them saves ClamAV time with no detection loss. Applied immediately. */
public final class MaxTextScanBytes {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_MAX_MB = "max_text_scan_mb";

    public static final int DEFAULT_MB = 10;
    public static final int MIN_MB = 1;
    public static final int MAX_MB = 2048;

    private MaxTextScanBytes() {}

    public static int getMaxMb(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_MAX_MB, DEFAULT_MB);
    }

    public static void setMaxMb(Context c, int mb) {
        int clamped = Math.max(MIN_MB, Math.min(MAX_MB, mb));
        c.getSharedPreferences(PREFS, 0).edit().putInt(KEY_MAX_MB, clamped).apply();
    }

    public static int getMaxBytes(Context c) {
        return getMaxMb(c) * 1024 * 1024;
    }
}
