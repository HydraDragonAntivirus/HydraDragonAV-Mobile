package com.hydradragon.antivirus.engine;

import android.content.Context;

/** Whether MainActivity should warn the user when the device is rooted
 *  (see RootCheck). On by default; the user can turn the warning off from
 *  Settings (or from the warning dialog itself) if they understand the risk. */
public final class RootWarning {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "root_warning_enabled";

    private RootWarning() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
