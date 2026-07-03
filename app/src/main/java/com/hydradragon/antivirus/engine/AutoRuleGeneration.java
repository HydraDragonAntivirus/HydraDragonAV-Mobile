package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Controls whether a confirmed-malware hit gets turned into a self-learned
 * "YARA-X.auto_*" rule (see ScanEngine#saveGeneratedRule). NOT RECOMMENDED
 * (high FP risk): a rule generated from one sample's raw strings can later
 * match unrelated clean apps that happen to share those strings. Off by
 * default — the user must opt in from Settings.
 */
public final class AutoRuleGeneration {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "auto_rule_generation";

    private AutoRuleGeneration() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, false);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
