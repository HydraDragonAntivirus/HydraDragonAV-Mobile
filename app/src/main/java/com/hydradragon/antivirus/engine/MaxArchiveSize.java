package com.hydradragon.antivirus.engine;

import android.content.Context;

/** User-configurable ceiling on how large a NON-zip archive (tar, gz, xz, 7z,
 *  rar, bz2, zst, lz4, cab, iso, etc.) the native engine will extract and scan.
 *  A non-zip archive larger than this is left unextracted — its contents are
 *  skipped entirely. APKs and plain {@code .zip} files are unaffected; they are
 *  governed by {@link MaxScanFileSize} instead. Applied immediately; no engine
 *  reinit needed. */
public final class MaxArchiveSize {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_MAX_MB = "max_archive_size_mb";

    public static final int DEFAULT_MB = 100;
    /** 0 is allowed and means "never extract non-zip archives". */
    public static final int MIN_MB = 0;
    /** Hard ceiling the user can't exceed from Settings. */
    public static final int MAX_MB = 2048;

    private MaxArchiveSize() {}

    public static int getMaxMb(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_MAX_MB, DEFAULT_MB);
    }

    public static void setMaxMb(Context c, int mb) {
        int clamped = Math.max(MIN_MB, Math.min(MAX_MB, mb));
        c.getSharedPreferences(PREFS, 0).edit().putInt(KEY_MAX_MB, clamped).apply();
    }
}
