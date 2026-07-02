package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Zero Trust companion setting: when an app whose verdict is UNKNOWN (Zero
 * Trust — no detector matched, NOT verified clean) is about to be uninstalled
 * from within the app's own threat/scan UI, ask the user whether to generate
 * a signature from it first (its APK is still on disk at that point; once the
 * system uninstall completes it's gone). Off by default — the user must opt
 * in from Settings, and only has an effect while Zero Trust Mode is also on.
 */
public final class AskSignatureOnRemove {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "ask_signature_on_remove";

    private AskSignatureOnRemove() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, false);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
