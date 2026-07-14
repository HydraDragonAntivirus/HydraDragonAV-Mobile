package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Controls whether auto-generated YARA rules (produced by the native engine
 * when AutoRuleGeneration is ON) are persisted to the device's
 * generated_rules/ directory so they survive app restarts.
 *
 * When this is OFF the rule is still generated in memory and used for the
 * CURRENT scan session (via NativeScanner.learnRule), but it is NOT
 * written to disk and therefore NOT reloaded on the next launch.
 *
 * Default: ON (same behaviour as before this setting was introduced).
 */
public final class SaveAutoRules {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY   = "save_auto_rules";

    private SaveAutoRules() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}