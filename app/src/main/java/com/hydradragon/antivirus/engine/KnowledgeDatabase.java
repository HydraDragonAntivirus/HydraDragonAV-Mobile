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

            JSONArray fnArray = new JSONArray();

            File fnFile = new File(context.getNoBackupFilesDir(), "anti_fn_cache.db");
            if (fnFile.exists()) {
                try (SQLiteDatabase db = SQLiteDatabase.openDatabase(
                        fnFile.getAbsolutePath(), null, SQLiteDatabase.OPEN_READONLY)) {
                    try (Cursor c = db.rawQuery(
                            "SELECT tlsh,detection_name,added_at FROM malicious_tlsh", null)) {
                        while (c.moveToNext()) {
                            JSONObject o = new JSONObject();
                            o.put("tlsh", c.getString(0));
                            o.put("detection_name", c.getString(1));
                            o.put("added_at", c.getLong(2));
                            fnArray.put(o);
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to read anti-FN cache", e);
                }
            }

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

            JSONArray fnArray = root.optJSONArray("anti_fn");
            if (fnArray != null) {
                SQLiteDatabase fnDb = null;
                try {
                    fnDb = SQLiteDatabase.openOrCreateDatabase(
                            new File(context.getNoBackupFilesDir(), "anti_fn_cache.db"), null);
                    fnDb.execSQL("CREATE TABLE IF NOT EXISTS malicious_tlsh("
                            + "tlsh TEXT PRIMARY KEY,"
                            + "detection_name TEXT NOT NULL DEFAULT '',"
                            + "added_at INTEGER NOT NULL)");
                    fnDb.beginTransaction();
                    try {
                        for (int i = 0; i < fnArray.length(); i++) {
                            JSONObject o = fnArray.getJSONObject(i);
                            String tlsh = o.optString("tlsh", "");
                            if (tlsh.isEmpty()) continue;
                            fnDb.execSQL(
                                "INSERT OR IGNORE INTO malicious_tlsh(tlsh,detection_name,added_at) VALUES(?,?,?)",
                                new Object[]{
                                    tlsh,
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
