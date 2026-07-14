package com.hydradragon.antivirus.service;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import com.hydradragon.antivirus.model.ThreatResult;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ThreatLogger {
    private static final String PREF_NAME = "HydraDragon_ThreatLogs";

    public static void logThreat(Context context, String packageName, String appName, String action) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String currentLogs = prefs.getString("logs", "");

        String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());
        String newLog = "[" + time + "] " + appName + " (" + packageName + ") -> " + action + "\n";

        prefs.edit().putString("logs", newLog + currentLogs).apply();
    }

    /** Same log entry as {@link #logThreat(Context, String, String, String)}, plus every
     *  detection reason (virus/rule name, hash, VirusTotal link, etc.) and dangerous
     *  permission carried by the full {@link ThreatResult} — the plain-string overload
     *  above only ever stored whatever single summary line the caller synthesized,
     *  discarding the actual detection detail that ThreatResult already has. */
    public static void logThreat(Context context, ThreatResult threat, String action) {
        if (threat == null) return;
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String currentLogs = prefs.getString("logs", "");

        String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(time).append("] ")
          .append(threat.getAppName()).append(" (").append(threat.getPackageName()).append(") -> ")
          .append(action).append("\n");
        sb.append("    type=").append(threat.getThreatType())
          .append(" level=").append(threat.getThreatLevel())
          .append(" risk=").append(threat.getRiskScore())
          .append("\n");
        List<String> reasons = threat.getReasons();
        if (reasons != null) {
            for (String r : reasons) sb.append("    ► ").append(r).append("\n");
        }
        List<String> perms = threat.getDangerousPermissions();
        if (perms != null && !perms.isEmpty()) {
            sb.append("    permissions: ").append(String.join(", ", perms)).append("\n");
        }

        prefs.edit().putString("logs", sb.toString() + currentLogs).apply();
    }
    
    public static String getLogs(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString("logs", context.getString(com.hydradragon.antivirus.R.string.no_threat_logs));
    }

    public static void exportLogs(Context context, Uri uri) {
        String logs = getLogs(context);
        try (OutputStream out = context.getContentResolver().openOutputStream(uri)) {
            if (out != null) {
                out.write(logs.getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {}
    }

    public static void importLogs(Context context, Uri uri) {
        StringBuilder sb = new StringBuilder();
        try (InputStream in = context.getContentResolver().openInputStream(uri);
             BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } catch (Exception ignored) {}
        if (sb.length() > 0) {
            SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            prefs.edit().putString("logs", sb.toString()).apply();
        }
    }
}
