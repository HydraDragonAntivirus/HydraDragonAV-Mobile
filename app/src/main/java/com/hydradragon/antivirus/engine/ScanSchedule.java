package com.hydradragon.antivirus.engine;

import android.content.Context;

/** User-configurable periodic-scan intervals (see GuardService#startPeriodicScans).
 *  Defaults match what was previously hardcoded: quick scan every 30 minutes,
 *  full scan every 180 minutes (3 hours). */
public final class ScanSchedule {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_QUICK = "scan_interval_quick_min";
    private static final String KEY_FULL = "scan_interval_full_min";
    private static final String KEY_ENABLED = "periodic_scan_enabled";

    public static final int DEFAULT_QUICK_MIN = 30;
    public static final int DEFAULT_FULL_MIN = 180;
    /** Below this, the periodic scan would thrash the device (battery/CPU) —
     *  refuse to schedule tighter than this regardless of user input. */
    public static final int MIN_INTERVAL_MIN = 5;

    private ScanSchedule() {}

    /** Whether GuardService should schedule the periodic Quick/Full scans at
     *  all (see GuardService#startPeriodicScans). On by default; real-time
     *  protection (Downloads watcher, on-install scan) keeps running either
     *  way — this only turns off the background timer-driven re-scans. */
    public static boolean isPeriodicScanEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY_ENABLED, true);
    }

    public static void setPeriodicScanEnabled(Context c, boolean enabled) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY_ENABLED, enabled).apply();
    }

    public static int getQuickScanIntervalMinutes(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_QUICK, DEFAULT_QUICK_MIN);
    }

    public static int getFullScanIntervalMinutes(Context c) {
        return c.getSharedPreferences(PREFS, 0).getInt(KEY_FULL, DEFAULT_FULL_MIN);
    }

    public static void setQuickScanIntervalMinutes(Context c, int minutes) {
        c.getSharedPreferences(PREFS, 0).edit()
            .putInt(KEY_QUICK, Math.max(MIN_INTERVAL_MIN, minutes)).apply();
    }

    public static void setFullScanIntervalMinutes(Context c, int minutes) {
        c.getSharedPreferences(PREFS, 0).edit()
            .putInt(KEY_FULL, Math.max(MIN_INTERVAL_MIN, minutes)).apply();
    }
}
