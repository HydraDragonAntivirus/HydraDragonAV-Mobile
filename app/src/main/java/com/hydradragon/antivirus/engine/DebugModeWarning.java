package com.hydradragon.antivirus.engine;

import android.content.Context;

/** Whether MainActivity should warn the user when USB/wireless debugging
 *  (ADB) is on (see DebugModeCheck). On by default; the user can turn the
 *  warning off from Settings (or from the warning dialog itself) if they're a
 *  developer who always has debugging on. */
public final class DebugModeWarning {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "debug_mode_warning_enabled";

    private DebugModeWarning() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
