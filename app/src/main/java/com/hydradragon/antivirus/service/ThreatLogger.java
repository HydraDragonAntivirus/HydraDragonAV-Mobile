package com.hydradragon.antivirus.service;

import android.content.Context;
import android.content.SharedPreferences;
import java.text.SimpleDateFormat;
import java.util.Date;
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
    
    public static String getLogs(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString("logs", context.getString(com.hydradragon.antivirus.R.string.no_threat_logs));
    }
}
