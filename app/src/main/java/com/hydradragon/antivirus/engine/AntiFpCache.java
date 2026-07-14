package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;

public final class AntiFpCache {

    private static final String TAG = "AntiFpCache";
    private static final String DB_NAME = "anti_fp_cache.db";
    private static final String TABLE = "entry_cache";

    private static final String SQL_CREATE = "CREATE TABLE IF NOT EXISTS "
        + TABLE + "("
        + "md5 TEXT PRIMARY KEY,"
        + "tlsh TEXT NOT NULL DEFAULT '',"
        + "entry_name TEXT NOT NULL,"
        + "source_apk_pkg TEXT NOT NULL DEFAULT '',"
        + "added_at INTEGER NOT NULL"
        + ")";

    private static final String SQL_INDEX_TLSH =
        "CREATE INDEX IF NOT EXISTS idx_tlsh ON " + TABLE + "(tlsh)";

    private final SQLiteDatabase db;
    private final boolean enabled;

    public AntiFpCache(Context context) {
        enabled = context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("anti_fp_skip_enabled", true);
        File dbFile = new File(context.getNoBackupFilesDir(), DB_NAME);
        SQLiteDatabase d;
        try {
            d = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
            d.execSQL(SQL_CREATE);
            d.execSQL(SQL_INDEX_TLSH);
        } catch (Exception e) {
            Log.w(TAG, "Failed to open anti-FP cache DB", e);
            d = null;
        }
        db = d;
    }

    public boolean isEnabled() {
        return enabled && db != null;
    }

    /** Populate the cache from a JSON array returned by
     *  {@link NativeScanner#computeZipEntryHashes}. */
    public void addEntries(String jsonArray, String sourcePkg) {
        if (!isEnabled() || jsonArray == null || jsonArray.isEmpty()) return;
        long now = System.currentTimeMillis();
        try {
            JSONArray arr = new JSONArray(jsonArray);
            db.beginTransaction();
            try {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.getJSONObject(i);
                    String md5 = o.optString("md5", "");
                    if (md5.isEmpty()) continue;
                    String tlsh = o.optString("tlsh", "");
                    String entry = o.optString("entry", "");
                    db.execSQL("INSERT OR IGNORE INTO " + TABLE
                            + "(md5,tlsh,entry_name,source_apk_pkg,added_at) VALUES(?,?,?,?,?)",
                        new Object[]{md5, tlsh, entry, sourcePkg, now});
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to add anti-FP entries", e);
        }
    }

    /** True if `md5` is a known-good entry from a whitelisted APK. */
    public boolean isKnownMd5(String md5) {
        if (!isEnabled() || md5 == null || md5.isEmpty()) return false;
        try (Cursor c = db.rawQuery("SELECT 1 FROM " + TABLE + " WHERE md5=? LIMIT 1",
                new String[]{md5.toLowerCase(java.util.Locale.US)})) {
            return c.moveToFirst();
        } catch (Exception e) {
            return false;
        }
    }

    /** True if `tlsh` has a close match in the cache (distance <= threshold).
     *  Uses the configured TLSH similarity threshold from settings. */
    public boolean hasSimilarTlsh(String tlsh, int threshold) {
        if (!isEnabled() || tlsh == null || tlsh.isEmpty() || threshold <= 0) return false;
        try (Cursor c = db.rawQuery("SELECT tlsh FROM " + TABLE
                + " WHERE tlsh IS NOT NULL AND tlsh != ''", null)) {
            while (c.moveToNext()) {
                String cached = c.getString(0);
                if (cached == null || cached.isEmpty()) continue;
                int dist = NativeScanner.tlshDiff(tlsh, cached);
                if (dist >= 0 && dist <= threshold) return true;
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /** Get the configured TLSH threshold from settings. */
    public static int getTlshThreshold(Context context) {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getInt("anti_fp_tlsh_threshold", 40);
    }

    /** Anti-FP entry match mode: "tlsh" (default) or "md5", set in Settings. */
    public static boolean isMd5MatchMode(Context context) {
        return "md5".equals(context.getSharedPreferences("hydra_prefs", 0)
            .getString("anti_fp_match_mode", "tlsh"));
    }

    /** Remove stale entries older than `maxAgeMs`. */
    public void clean(long maxAgeMs) {
        if (db == null) return;
        long cutoff = System.currentTimeMillis() - maxAgeMs;
        try {
            db.execSQL("DELETE FROM " + TABLE + " WHERE added_at < ?", new Object[]{cutoff});
        } catch (Exception e) {
            Log.w(TAG, "Failed to clean anti-FP cache", e);
        }
    }

    /** Drop everything. Called when the user toggles the setting off. */
    public void clear() {
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + TABLE);
        } catch (Exception e) {
            Log.w(TAG, "Failed to clear anti-FP cache", e);
        }
    }
}
