package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Whether GuardService should silently start itself when the device boots
 * (see BootReceiver). On by default, matching other antivirus apps — the
 * user can turn it off from Settings if they'd rather start protection
 * manually.
 */
public final class BootAutoStart {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "boot_auto_start";

    private BootAutoStart() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
