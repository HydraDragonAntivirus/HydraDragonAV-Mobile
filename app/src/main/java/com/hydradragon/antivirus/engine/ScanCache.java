package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import com.hydradragon.antivirus.model.ThreatResult;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class ScanCache {

    private static final String TAG = "ScanCache";
    private static final String DB_NAME = "scan_cache.db";
    private static final String FILE_TABLE = "file_scan_cache";
    private static final String PHOTON_TABLE = "photon_cache";

    private static final String SQL_CREATE_FILE =
        "CREATE TABLE IF NOT EXISTS " + FILE_TABLE + "("
        + "md5 TEXT PRIMARY KEY,"
        + "is_clean INTEGER NOT NULL DEFAULT 1,"
        + "json TEXT,"
        + "added_at INTEGER NOT NULL"
        + ")";
    private static final String SQL_CREATE_PHOTON =
        "CREATE TABLE IF NOT EXISTS " + PHOTON_TABLE + "("
        + "package_name TEXT PRIMARY KEY,"
        + "json TEXT NOT NULL,"
        + "added_at INTEGER NOT NULL"
        + ")";

    // In-memory caches for fast per-session access, backed by SQLite for persistence.
    private final ConcurrentHashMap<String, Optional<ThreatResult>> fileCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ThreatResult> photonCache = new ConcurrentHashMap<>();

    private final SQLiteDatabase db;

    public ScanCache(Context context) {
        File dbFile = new File(context.getNoBackupFilesDir(), DB_NAME);
        SQLiteDatabase d;
        try {
            d = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
            d.execSQL("PRAGMA cache_size=-2000");
            d.execSQL(SQL_CREATE_FILE);
            d.execSQL(SQL_CREATE_PHOTON);
        } catch (Exception e) {
            Log.w(TAG, "Failed to open scan cache DB", e);
            d = null;
        }
        db = d;
        if (db != null) loadAllIntoMemory();
    }

    /** Load all cached entries from SQLite into in-memory maps at startup,
     *  so subsequent lookups are fast HashMap hits. */
    private void loadAllIntoMemory() {
        // File cache
        try (Cursor c = db.rawQuery("SELECT md5, is_clean, json FROM " + FILE_TABLE, null)) {
            while (c.moveToNext()) {
                String md5 = c.getString(0);
                boolean clean = c.getInt(1) != 0;
                String json = c.getString(2);
                if (clean || json == null) {
                    fileCache.put(md5, Optional.empty());
                } else {
                    ThreatResult r = deserialize(json);
                    if (r != null) fileCache.put(md5, Optional.of(r));
                }
            }
        } catch (Exception ignored) {}
        // Photon cache
        try (Cursor c = db.rawQuery("SELECT package_name, json FROM " + PHOTON_TABLE, null)) {
            while (c.moveToNext()) {
                String pkg = c.getString(0);
                String json = c.getString(1);
                ThreatResult r = deserialize(json);
                if (r != null) photonCache.put(pkg, r);
            }
        } catch (Exception ignored) {}
    }

    // ── File MD5 cache ────────────────────────────────────────────────────

    /** Returns cached result (empty = clean, non-empty = threat) or null if not cached. */
    public Optional<ThreatResult> getFileCache(String md5) {
        Optional<ThreatResult> mem = fileCache.get(md5);
        if (mem != null) return mem;
        // Miss in memory → try SQLite
        if (db == null) return null;
        try (Cursor c = db.rawQuery("SELECT is_clean, json FROM " + FILE_TABLE + " WHERE md5 = ?",
                new String[]{md5})) {
            if (c.moveToFirst()) {
                boolean clean = c.getInt(0) != 0;
                if (clean || c.isNull(1)) {
                    fileCache.put(md5, Optional.empty());
                    return Optional.empty();
                }
                ThreatResult r = deserialize(c.getString(1));
                if (r != null) {
                    fileCache.put(md5, Optional.of(r));
                    return Optional.of(r);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public void putFileCache(String md5, Optional<ThreatResult> value) {
        fileCache.put(md5, value);
        if (db == null) return;
        try {
            boolean clean = !value.isPresent();
            String json = clean ? null : serialize(value.get());
            db.execSQL("INSERT OR REPLACE INTO " + FILE_TABLE
                    + "(md5,is_clean,json,added_at) VALUES(?,?,?,?)",
                new Object[]{md5, clean ? 1 : 0, json, System.currentTimeMillis()});
        } catch (Exception e) {
            Log.w(TAG, "Failed to write file cache", e);
        }
    }

    public void removeFileCache(String md5) {
        fileCache.remove(md5);
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + FILE_TABLE + " WHERE md5 = ?", new Object[]{md5});
        } catch (Exception ignored) {}
    }

    // ── Photon (package) cache ────────────────────────────────────────────

    public boolean containsPhotonCache(String packageName) {
        if (packageName == null) return false;
        if (photonCache.containsKey(packageName)) return true;
        // Miss → try SQLite
        if (db == null) return false;
        try (Cursor c = db.rawQuery("SELECT json FROM " + PHOTON_TABLE
                + " WHERE package_name = ?", new String[]{packageName})) {
            if (c.moveToFirst()) {
                ThreatResult r = deserialize(c.getString(0));
                if (r != null) {
                    photonCache.put(packageName, r);
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public ThreatResult getPhotonCache(String packageName) {
        if (packageName == null) return null;
        ThreatResult mem = photonCache.get(packageName);
        if (mem != null) return mem;
        // Miss → try SQLite
        if (db == null) return null;
        try (Cursor c = db.rawQuery("SELECT json FROM " + PHOTON_TABLE
                + " WHERE package_name = ?", new String[]{packageName})) {
            if (c.moveToFirst()) {
                ThreatResult r = deserialize(c.getString(0));
                if (r != null) {
                    photonCache.put(packageName, r);
                    return r;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public void putPhotonCache(String packageName, ThreatResult value) {
        if (packageName == null || value == null) return;
        photonCache.put(packageName, value);
        if (db == null) return;
        try {
            db.execSQL("INSERT OR REPLACE INTO " + PHOTON_TABLE
                    + "(package_name,json,added_at) VALUES(?,?,?)",
                new Object[]{packageName, serialize(value), System.currentTimeMillis()});
        } catch (Exception e) {
            Log.w(TAG, "Failed to write photon cache", e);
        }
    }

    public void removePhotonCache(String packageName) {
        if (packageName == null) return;
        photonCache.remove(packageName);
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + PHOTON_TABLE + " WHERE package_name = ?",
                new Object[]{packageName});
        } catch (Exception ignored) {}
    }

    // ── Clear ─────────────────────────────────────────────────────────────

    public void clearAll() {
        fileCache.clear();
        photonCache.clear();
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + FILE_TABLE);
            db.execSQL("DELETE FROM " + PHOTON_TABLE);
        } catch (Exception ignored) {}
    }

    public void clearFileCache() {
        fileCache.clear();
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + FILE_TABLE);
        } catch (Exception ignored) {}
    }

    public void clearPhotonCache() {
        photonCache.clear();
        if (db == null) return;
        try {
            db.execSQL("DELETE FROM " + PHOTON_TABLE);
        } catch (Exception ignored) {}
    }

    // ── Serialization helpers ─────────────────────────────────────────────

    private static String serialize(ThreatResult r) {
        try {
            JSONArray reasons = new JSONArray();
            if (r.getReasons() != null) for (String s : r.getReasons()) reasons.put(s);
            JSONArray perms = new JSONArray();
            if (r.getDangerousPermissions() != null) for (String s : r.getDangerousPermissions()) perms.put(s);
            JSONObject o = new JSONObject();
            o.put("packageName", r.getPackageName() != null ? r.getPackageName() : "");
            o.put("appName", r.getAppName() != null ? r.getAppName() : "");
            o.put("apkPath", r.getApkPath() != null ? r.getApkPath() : "");
            o.put("riskScore", r.getRiskScore());
            o.put("threatType", r.getThreatType().name());
            o.put("reasons", reasons);
            o.put("dangerousPermissions", perms);
            o.put("timestamp", r.getTimestamp());
            o.put("standaloneFile", r.isStandaloneFile());
            return o.toString();
        } catch (Exception e) {
            Log.w(TAG, "Serialize failed", e);
            return "{}";
        }
    }

    private static ThreatResult deserialize(String json) {
        try {
            JSONObject o = new JSONObject(json);
            String packageName = o.optString("packageName", "");
            String appName = o.optString("appName", null);
            String apkPath = o.optString("apkPath", "");
            int riskScore = o.optInt("riskScore", 0);
            ThreatResult.ThreatType threatType;
            try {
                threatType = ThreatResult.ThreatType.valueOf(o.optString("threatType", "CLEAN"));
            } catch (Exception e) {
                threatType = ThreatResult.ThreatType.CLEAN;
            }
            JSONArray jReasons = o.optJSONArray("reasons");
            List<String> reasons = new ArrayList<>();
            if (jReasons != null) for (int i = 0; i < jReasons.length(); i++) reasons.add(jReasons.getString(i));
            JSONArray jPerms = o.optJSONArray("dangerousPermissions");
            List<String> perms = new ArrayList<>();
            if (jPerms != null) for (int i = 0; i < jPerms.length(); i++) perms.add(jPerms.getString(i));
            List<String> dangerousPermissions = perms;
            boolean standaloneFile = o.optBoolean("standaloneFile", false);

            return new ThreatResult.Builder(packageName)
                .setAppName(appName)
                .setApkPath(apkPath)
                .setRiskScore(riskScore)
                .setThreatType(threatType)
                .setReasons(reasons)
                .setDangerousPermissions(dangerousPermissions)
                .setStandaloneFile(standaloneFile)
                .build();
        } catch (Exception e) {
            Log.w(TAG, "Deserialize failed", e);
            return null;
        }
    }
}
