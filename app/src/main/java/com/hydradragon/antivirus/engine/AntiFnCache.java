package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.io.File;

public final class AntiFnCache {

    private static final String TAG = "AntiFnCache";
    private static final String DB_NAME = "anti_fn_cache.db";
    private static final String TABLE = "malicious_tlsh";

    private static final String SQL_CREATE = "CREATE TABLE IF NOT EXISTS "
        + TABLE + "("
        + "tlsh TEXT NOT NULL,"
        + "file_type TEXT NOT NULL,"
        + "detection_name TEXT NOT NULL DEFAULT '',"
        + "added_at INTEGER NOT NULL,"
        + "PRIMARY KEY(tlsh, file_type)"
        + ")";

    private final SQLiteDatabase db;
    private final boolean enabled;

    public AntiFnCache(Context context) {
        enabled = context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("anti_fn_enabled", true);
        File dbFile = new File(context.getNoBackupFilesDir(), DB_NAME);
        SQLiteDatabase d;
        try {
            d = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
            d.execSQL("PRAGMA cache_size=-2000");
            d.execSQL(SQL_CREATE);
            // Migrate from old schema (tlsh TEXT PRIMARY KEY) to new
            // (PRIMARY KEY(tlsh, file_type)) if file_type column is missing.
            try {
                Cursor c = d.rawQuery("SELECT file_type FROM " + TABLE + " LIMIT 1", null);
                c.close();
            } catch (Exception e) {
                // column does not exist -> old schema, drop and recreate
                d.execSQL("DROP TABLE IF EXISTS " + TABLE);
                d.execSQL(SQL_CREATE);
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to open anti-FN cache DB", e);
            d = null;
        }
        db = d;
    }

    public boolean isEnabled() {
        return enabled && db != null;
    }

    public void addEntry(String tlsh, String detectionName, String fileType) {
        if (!isEnabled() || tlsh == null || tlsh.isEmpty()) return;
        if (fileType == null || fileType.isEmpty()) fileType = "apk";
        try {
            db.execSQL("INSERT OR IGNORE INTO " + TABLE
                    + "(tlsh,file_type,detection_name,added_at) VALUES(?,?,?,?)",
                new Object[]{
                    tlsh,
                    fileType,
                    detectionName == null ? "" : detectionName,
                    System.currentTimeMillis()
                });
        } catch (Exception e) {
            Log.w(TAG, "Failed to add anti-FN entry", e);
        }
    }

    public String findSimilarTlsh(String tlsh, int threshold, String fileType) {
        if (!isEnabled() || tlsh == null || tlsh.isEmpty() || threshold <= 0) return null;
        if (fileType == null || fileType.isEmpty()) fileType = "apk";
        try (Cursor c = db.rawQuery("SELECT tlsh, detection_name FROM " + TABLE
                + " WHERE file_type = ? AND tlsh IS NOT NULL AND tlsh != ''",
                new String[]{fileType})) {
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

    /** Infer file type from entry name for per-type TLSH matching. */
    public static String detectFileType(String entryName) {
        if (entryName == null || entryName.isEmpty()) return "apk";
        String lower = entryName.toLowerCase();
        if (lower.endsWith(".dex") || lower.endsWith(".vdex") || lower.endsWith(".odex")) {
            return "dex";
        }
        if (lower.endsWith(".so")) {
            return "elf";
        }
        // .apk, .zip, or top-level file (no extension) → apk
        return "apk";
    }

    public static int getTlshThreshold(Context context) {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getInt("anti_fn_tlsh_threshold", 40);
    }

    public void clean(long maxAgeMs) {
        if (db == null) return;
        long cutoff = System.currentTimeMillis() - maxAgeMs;
        try {
            db.execSQL("DELETE FROM " + TABLE + " WHERE added_at < ?", new Object[]{cutoff});
            db.execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(TAG, "Failed to clean anti-FN cache", e);
        }
    }

    public void clear() {
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + TABLE);
            db.execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(TAG, "Failed to clear anti-FN cache", e);
        }
    }
}
