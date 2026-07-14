package com.hydradragon.antivirus.engine;

import android.content.Context;

public final class FastScanMode {

    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "fast_scan_mode_enabled";

    private FastScanMode() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, false);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
