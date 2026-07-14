package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class NetworkTrafficDB {

    private static final String TAG = "NetworkTrafficDB";
    private static final int FORMAT_VERSION = 1;

    private NetworkTrafficDB() {}

    public static void exportTraffic(Context context, Uri uri) {
        try {
            JSONObject root = new JSONObject();
            root.put("version", FORMAT_VERSION);
            root.put("exported_at", System.currentTimeMillis());

            JSONArray events = new JSONArray();
            List<NetworkMonitor.NetworkEvent> log = NetworkMonitor.getEventLogStatic();
            for (NetworkMonitor.NetworkEvent e : log) {
                JSONObject o = new JSONObject();
                o.put("timestamp", e.timestamp);
                o.put("sourceIp", e.sourceIp);
                o.put("destIp", e.destIp);
                o.put("destPort", e.destPort);
                o.put("protocol", e.protocol);
                o.put("blocked", e.blocked);
                o.put("reason", e.reason);
                o.put("pid", e.pid);
                events.put(o);
            }
            root.put("events", events);

            try (OutputStream out = context.getContentResolver().openOutputStream(uri)) {
                if (out != null) {
                    out.write(root.toString(2).getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to export network traffic", e);
            throw new RuntimeException(e);
        }
    }

    public static int importTraffic(Context context, Uri uri) {
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

            JSONArray events = root.optJSONArray("events");
            if (events == null) return 0;

            CopyOnWriteArrayList<NetworkMonitor.NetworkEvent> log = NetworkMonitor.getEventLogStaticRef();
            for (int i = 0; i < events.length(); i++) {
                JSONObject o = events.getJSONObject(i);
                NetworkMonitor.NetworkEvent event = new NetworkMonitor.NetworkEvent(
                    o.optString("sourceIp", "local"),
                    o.optString("destIp", "unknown"),
                    o.optInt("destPort", 0),
                    o.optString("protocol", "TCP"),
                    o.optBoolean("blocked", false),
                    o.optString("reason", "Imported"),
                    o.optInt("pid", 0)
                );
                log.add(0, event);
                importedCount++;
                if (event.blocked) {
                    NetworkMonitor.recordBlocked();
                } else {
                    NetworkMonitor.recordAllowed();
                }
            }

            while (log.size() > 1000) {
                log.remove(log.size() - 1);
            }

        } catch (Exception e) {
            Log.w(TAG, "Failed to import network traffic", e);
            throw new RuntimeException(e);
        }
        return importedCount;
    }
}
