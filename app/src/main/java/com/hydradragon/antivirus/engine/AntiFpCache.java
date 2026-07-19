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

    private SQLiteDatabase db;
    private final Context context;

    public AntiFpCache(Context context) {
        this.context = context;
    }

    private boolean isPrefEnabled() {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getBoolean("anti_fp_skip_enabled", true);
    }

    private SQLiteDatabase getDb() {
        if (db != null) return db;
        if (!isPrefEnabled()) return null;
        File dbFile = new File(context.getNoBackupFilesDir(), DB_NAME);
        try {
            db = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
            db.execSQL("PRAGMA cache_size=-2000");
            db.execSQL(SQL_CREATE);
            db.execSQL(SQL_INDEX_TLSH);
        } catch (Exception e) {
            Log.w(TAG, "Failed to open anti-FP cache DB", e);
            db = null;
        }
        return db;
    }

    public boolean isEnabled() {
        return isPrefEnabled() && getDb() != null;
    }

    public void addEntries(String jsonArray, String sourcePkg) {
        if (!isPrefEnabled() || jsonArray == null || jsonArray.isEmpty()) return;
        SQLiteDatabase d = getDb();
        if (d == null) return;
        long now = System.currentTimeMillis();
        try {
            JSONArray arr = new JSONArray(jsonArray);
            d.beginTransaction();
            try {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.getJSONObject(i);
                    String md5 = o.optString("md5", "");
                    if (md5.isEmpty()) continue;
                    String tlsh = o.optString("tlsh", "");
                    String entry = o.optString("entry", "");
                    d.execSQL("INSERT OR IGNORE INTO " + TABLE
                            + "(md5,tlsh,entry_name,source_apk_pkg,added_at) VALUES(?,?,?,?,?)",
                        new Object[]{md5, tlsh, entry, sourcePkg, now});
                }
                d.setTransactionSuccessful();
            } finally {
                d.endTransaction();
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to add anti-FP entries", e);
        }
    }

    public boolean isKnownMd5(String md5) {
        if (!isPrefEnabled() || md5 == null || md5.isEmpty()) return false;
        SQLiteDatabase d = getDb();
        if (d == null) return false;
        try (Cursor c = d.rawQuery("SELECT 1 FROM " + TABLE + " WHERE md5=? LIMIT 1",
                new String[]{md5.toLowerCase(java.util.Locale.US)})) {
            return c.moveToFirst();
        } catch (Exception e) {
            return false;
        }
    }

    public boolean hasSimilarTlsh(String tlsh, int threshold) {
        if (!isPrefEnabled() || tlsh == null || tlsh.isEmpty() || threshold <= 0) return false;
        SQLiteDatabase d = getDb();
        if (d == null) return false;
        try (Cursor c = d.rawQuery("SELECT tlsh FROM " + TABLE
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

    public static int getTlshThreshold(Context context) {
        return context.getSharedPreferences("hydra_prefs", 0)
            .getInt("anti_fp_tlsh_threshold", 40);
    }

    public static boolean isMd5MatchMode(Context context) {
        return "md5".equals(context.getSharedPreferences("hydra_prefs", 0)
            .getString("anti_fp_match_mode", "tlsh"));
    }

    public void clean(long maxAgeMs) {
        SQLiteDatabase d = getDb();
        if (d == null) return;
        long cutoff = System.currentTimeMillis() - maxAgeMs;
        try {
            d.execSQL("DELETE FROM " + TABLE + " WHERE added_at < ?", new Object[]{cutoff});
            d.execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(TAG, "Failed to clean anti-FP cache", e);
        }
    }

    public void clear() {
        SQLiteDatabase d = getDb();
        if (d == null) return;
        try {
            d.execSQL("DELETE FROM " + TABLE);
            d.execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(TAG, "Failed to clear anti-FP cache", e);
        }
    }
}
