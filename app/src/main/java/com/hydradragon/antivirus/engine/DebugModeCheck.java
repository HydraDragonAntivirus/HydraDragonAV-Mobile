package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.provider.Settings;

/** Detects whether USB/wireless debugging (ADB) is enabled on the device.
 *  Unlike root (RootCheck, which blocks launch outright), this is common for
 *  developers and power users, so it's a WARNING, not a hard block — ADB
 *  access lets another app/PC push input events, pull app data, or sideload,
 *  which is a real attack surface but not proof of compromise on its own. */
public final class DebugModeCheck {

    private DebugModeCheck() {}

    public static boolean isEnabled(Context context) {
        try {
            return Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.ADB_ENABLED, 0) == 1;
        } catch (Throwable t) {
            return false;
        }
    }
}
