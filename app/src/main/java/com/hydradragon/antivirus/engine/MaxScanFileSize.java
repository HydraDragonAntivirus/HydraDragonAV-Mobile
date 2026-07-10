package com.hydradragon.antivirus.engine;

import android.content.Context;

/** User-configurable ceiling on how large a file the native engine will scan
 *  (see ScanEngine#scanGenericFile / #analyzeApp / #deepNativeScanInstalledApks) —
 *  a bigger cap means a slower scan (the whole file goes through
 *  hash+ClamAV+YARA+ML), so this trades thoroughness for speed, same tradeoff
 *  as {@link ScanSchedule}'s interval setting. */
public final class MaxScanFileSize {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_MAX_MB = "max_scan_file_size_mb";

    public static final int DEFAULT_MB = 650;
    /** Below this, legitimate APKs/media routinely get skipped entirely —
     *  refuse a tighter cap than this regardless of user input. */
    public static final int MIN_MB = 10;
    /** Hard ceiling the user can't exceed from Settings. */
    public static final int MAX_MB = 2048;

    private MaxScanFileSize() {}

    public static int getMaxMb(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_MAX_MB, DEFAULT_MB);
    }

    public static void setMaxMb(Context c, int mb) {
        int clamped = Math.max(MIN_MB, Math.min(MAX_MB, mb));
        c.getSharedPreferences(PREFS, 0).edit().putInt(KEY_MAX_MB, clamped).apply();
    }

    public static long getMaxBytes(Context c) {
        return getMaxMb(c) * 1024L * 1024L;
    }

    /** True if {@code file} is small enough to actually go through the native
     *  scan — oversized files are skipped entirely rather than truncated (a
     *  truncated scan of, say, a 5GB file would still cost the I/O of hashing
     *  it and give a false sense of having checked it fully). */
    public static boolean isWithinLimit(Context c, java.io.File file) {
        return file != null && file.length() <= getMaxBytes(c);
    }
}
