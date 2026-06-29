package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Global on/off switch for real-time protection. When disabled, the antivirus
 * is "paused": no alerts, redirects or block pages are raised even if a threat
 * is seen. The user controls it from Settings. Defaults to ON.
 */
public final class ProtectionState {

    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "protection_enabled";

    private ProtectionState() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
