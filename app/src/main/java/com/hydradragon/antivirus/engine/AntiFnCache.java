package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.io.File;
import java.util.Locale;

/** Anti-FN ("anti false-negative") cache — the mirror image of {@link AntiFpCache}.
 *  Where Anti-FP remembers known-GOOD entries (from whitelisted APKs) to
 *  suppress false positives, Anti-FN remembers known-BAD entries (from
 *  confirmed-malicious scans) so a renamed/repacked/recompiled variant of a
 *  previously-caught sample is still flagged even when the static
 *  YARA/hash signature alone misses it. Matching defaults to TLSH similarity;
 *  MD5 exact match is used instead only if the user picks it in Settings. */
public final class AntiFnCache {

    private static final String TAG = "AntiFnCache";
    private static final String DB_NAME = "anti_fn_cache.db";
    private static final String TABLE = "malicious_entry_cache";

    private static final String SQL_CREATE = "CREATE TABLE IF NOT EXISTS "
        + TABLE + "("
        + "md5 TEXT PRIMARY KEY,"
        + "tlsh TEXT NOT NULL DEFAULT '',"
        + "entry_name TEXT NOT NULL,"
        + "detection_name TEXT NOT NULL DEFAULT '',"
        + "added_at INTEGER NOT NULL"
        + ")";

    private static final String SQL_INDEX_TLSH =
        "CREATE INDEX IF NOT EXISTS idx_tlsh ON " + TABLE + "(tlsh)";

    private final SQLiteDatabase db;
    private final boolean enabled;

    public AntiFnCache(Context context) {
        enabled = context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("anti_fn_enabled", true);
        File dbFile = new File(context.getNoBackupFilesDir(), DB_NAME);
        SQLiteDatabase d;
        try {
            d = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
            d.execSQL(SQL_CREATE);
            d.execSQL(SQL_INDEX_TLSH);
        } catch (Exception e) {
            Log.w(TAG, "Failed to open anti-FN cache DB", e);
            d = null;
        }
        db = d;
    }

    public boolean isEnabled() {
        return enabled && db != null;
    }

    /** Record one confirmed-malicious entry (a nested archive entry, or the
     *  whole top-level file when {@code entryName} is empty). {@code md5}
     *  must be non-empty; {@code tlsh} may be empty if unavailable. */
    public void addEntry(String md5, String tlsh, String entryName, String detectionName) {
        if (!isEnabled() || md5 == null || md5.isEmpty()) return;
        try {
            db.execSQL("INSERT OR IGNORE INTO " + TABLE
                    + "(md5,tlsh,entry_name,detection_name,added_at) VALUES(?,?,?,?,?)",
                new Object[]{
                    md5.toLowerCase(Locale.US),
                    tlsh == null ? "" : tlsh,
                    entryName == null ? "" : entryName,
                    detectionName == null ? "" : detectionName,
                    System.currentTimeMillis()
                });
        } catch (Exception e) {
            Log.w(TAG, "Failed to add anti-FN entry", e);
        }
    }

    /** True if `md5` is a known-malicious entry recorded by a prior scan. */
    public boolean isKnownMd5(String md5) {
        if (!isEnabled() || md5 == null || md5.isEmpty()) return false;
        try (Cursor c = db.rawQuery("SELECT 1 FROM " + TABLE + " WHERE md5=? LIMIT 1",
                new String[]{md5.toLowerCase(Locale.US)})) {
            return c.moveToFirst();
        } catch (Exception e) {
            return false;
        }
    }

    /** Returns the {@code detection_name} of the closest cached malicious
     *  entry within {@code threshold} TLSH distance, or null if none match.
     *  Uses the configured TLSH similarity threshold from settings. */
    public String findSimilarTlsh(String tlsh, int threshold) {
        if (!isEnabled() || tlsh == null || tlsh.isEmpty() || threshold <= 0) return null;
        try (Cursor c = db.rawQuery("SELECT tlsh, detection_name FROM " + TABLE
                + " WHERE tlsh IS NOT NULL AND tlsh != ''", null)) {
            while (c.moveToNext()) {
                String cached = c.getString(0);
                if (cached == null || cached.isEmpty()) continue;
                int dist = NativeScanner.tlshDiff(tlsh, cached);
                if (dist >= 0 && dist <= threshold) {
                    String name = c.getString(1);
                    return (name == null || name.isEmpty()) ? "unknown" : name;
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /** Get the configured TLSH threshold from settings. */
    public static int getTlshThreshold(Context context) {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getInt("anti_fn_tlsh_threshold", 40);
    }

    /** Anti-FN entry match mode: "tlsh" (default) or "md5", set in Settings. */
    public static boolean isMd5MatchMode(Context context) {
        return "md5".equals(context.getSharedPreferences("hydra_prefs", 0)
            .getString("anti_fn_match_mode", "tlsh"));
    }

    /** Remove stale entries older than `maxAgeMs`. */
    public void clean(long maxAgeMs) {
        if (db == null) return;
        long cutoff = System.currentTimeMillis() - maxAgeMs;
        try {
            db.execSQL("DELETE FROM " + TABLE + " WHERE added_at < ?", new Object[]{cutoff});
        } catch (Exception e) {
            Log.w(TAG, "Failed to clean anti-FN cache", e);
        }
    }

    /** Drop everything. Called when the user toggles the setting off. */
    public void clear() {
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + TABLE);
        } catch (Exception e) {
            Log.w(TAG, "Failed to clear anti-FN cache", e);
        }
    }
}
