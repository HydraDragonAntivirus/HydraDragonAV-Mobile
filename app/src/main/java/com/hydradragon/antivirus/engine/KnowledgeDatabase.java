package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public final class KnowledgeDatabase {

    private static final String TAG = "KnowledgeDB";
    private static final int FORMAT_VERSION = 1;
    private static final String MIME_TYPE = "application/json";

    private KnowledgeDatabase() {}

    public static void exportCache(Context context, Uri uri) {
        try {
            JSONObject root = new JSONObject();
            root.put("version", FORMAT_VERSION);
            root.put("exported_at", System.currentTimeMillis());

            JSONArray fpArray = new JSONArray();
            JSONArray fnArray = new JSONArray();

            File fpFile = new File(context.getNoBackupFilesDir(), "anti_fp_cache.db");
            if (fpFile.exists()) {
                try (SQLiteDatabase db = SQLiteDatabase.openDatabase(
                        fpFile.getAbsolutePath(), null, SQLiteDatabase.OPEN_READONLY)) {
                    try (Cursor c = db.rawQuery(
                            "SELECT md5,tlsh,entry_name,source_apk_pkg,added_at FROM entry_cache", null)) {
                        while (c.moveToNext()) {
                            JSONObject o = new JSONObject();
                            o.put("md5", c.getString(0));
                            o.put("tlsh", c.getString(1));
                            o.put("entry_name", c.getString(2));
                            o.put("source_apk_pkg", c.getString(3));
                            o.put("added_at", c.getLong(4));
                            fpArray.put(o);
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to read anti-FP cache", e);
                }
            }

            File fnFile = new File(context.getNoBackupFilesDir(), "anti_fn_cache.db");
            if (fnFile.exists()) {
                try (SQLiteDatabase db = SQLiteDatabase.openDatabase(
                        fnFile.getAbsolutePath(), null, SQLiteDatabase.OPEN_READONLY)) {
                    try (Cursor c = db.rawQuery(
                            "SELECT md5,tlsh,entry_name,detection_name,added_at FROM malicious_entry_cache", null)) {
                        while (c.moveToNext()) {
                            JSONObject o = new JSONObject();
                            o.put("md5", c.getString(0));
                            o.put("tlsh", c.getString(1));
                            o.put("entry_name", c.getString(2));
                            o.put("detection_name", c.getString(3));
                            o.put("added_at", c.getLong(4));
                            fnArray.put(o);
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to read anti-FN cache", e);
                }
            }

            root.put("anti_fp", fpArray);
            root.put("anti_fn", fnArray);

            try (OutputStream out = context.getContentResolver().openOutputStream(uri)) {
                if (out != null) {
                    out.write(root.toString(2).getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to export knowledge database", e);
            throw new RuntimeException(e);
        }
    }

    public static int importCache(Context context, Uri uri) {
        int importedCount = 0;
        try {
            StringBuilder sb = new StringBuilder();
            try (InputStream in = context.getContentResolver().openInputStream(uri);
                 BufferedReader br = new BufferedReader(
                         new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());
            int version = root.optInt("version", 0);
            if (version < 1) return 0;

            long now = System.currentTimeMillis();

            JSONArray fpArray = root.optJSONArray("anti_fp");
            if (fpArray != null) {
                SQLiteDatabase fpDb = null;
                try {
                    fpDb = SQLiteDatabase.openOrCreateDatabase(
                            new File(context.getNoBackupFilesDir(), "anti_fp_cache.db"), null);
                    fpDb.execSQL("CREATE TABLE IF NOT EXISTS entry_cache("
                            + "md5 TEXT PRIMARY KEY,"
                            + "tlsh TEXT NOT NULL DEFAULT '',"
                            + "entry_name TEXT NOT NULL,"
                            + "source_apk_pkg TEXT NOT NULL DEFAULT '',"
                            + "added_at INTEGER NOT NULL)");
                    fpDb.execSQL("CREATE INDEX IF NOT EXISTS idx_tlsh ON entry_cache(tlsh)");
                    fpDb.beginTransaction();
                    try {
                        for (int i = 0; i < fpArray.length(); i++) {
                            JSONObject o = fpArray.getJSONObject(i);
                            String md5 = o.optString("md5", "");
                            if (md5.isEmpty()) continue;
                            fpDb.execSQL(
                                "INSERT OR IGNORE INTO entry_cache(md5,tlsh,entry_name,source_apk_pkg,added_at) VALUES(?,?,?,?,?)",
                                new Object[]{
                                    md5.toLowerCase(Locale.US),
                                    o.optString("tlsh", ""),
                                    o.optString("entry_name", ""),
                                    o.optString("source_apk_pkg", ""),
                                    now
                                });
                            importedCount++;
                        }
                        fpDb.setTransactionSuccessful();
                    } finally {
                        fpDb.endTransaction();
                    }
                } finally {
                    if (fpDb != null) fpDb.close();
                }
            }

            JSONArray fnArray = root.optJSONArray("anti_fn");
            if (fnArray != null) {
                SQLiteDatabase fnDb = null;
                try {
                    fnDb = SQLiteDatabase.openOrCreateDatabase(
                            new File(context.getNoBackupFilesDir(), "anti_fn_cache.db"), null);
                    fnDb.execSQL("CREATE TABLE IF NOT EXISTS malicious_entry_cache("
                            + "md5 TEXT PRIMARY KEY,"
                            + "tlsh TEXT NOT NULL DEFAULT '',"
                            + "entry_name TEXT NOT NULL,"
                            + "detection_name TEXT NOT NULL DEFAULT '',"
                            + "added_at INTEGER NOT NULL)");
                    fnDb.execSQL("CREATE INDEX IF NOT EXISTS idx_tlsh ON malicious_entry_cache(tlsh)");
                    fnDb.beginTransaction();
                    try {
                        for (int i = 0; i < fnArray.length(); i++) {
                            JSONObject o = fnArray.getJSONObject(i);
                            String md5 = o.optString("md5", "");
                            if (md5.isEmpty()) continue;
                            fnDb.execSQL(
                                "INSERT OR IGNORE INTO malicious_entry_cache(md5,tlsh,entry_name,detection_name,added_at) VALUES(?,?,?,?,?)",
                                new Object[]{
                                    md5.toLowerCase(Locale.US),
                                    o.optString("tlsh", ""),
                                    o.optString("entry_name", ""),
                                    o.optString("detection_name", ""),
                                    now
                                });
                            importedCount++;
                        }
                        fnDb.setTransactionSuccessful();
                    } finally {
                        fnDb.endTransaction();
                    }
                } finally {
                    if (fnDb != null) fnDb.close();
                }
            }

        } catch (Exception e) {
            Log.w(TAG, "Failed to import knowledge database", e);
            throw new RuntimeException(e);
        }
        return importedCount;
    }
}
