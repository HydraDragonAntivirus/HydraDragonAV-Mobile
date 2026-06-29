package com.hydradragon.antivirus.engine;

import android.os.Build;

import java.io.File;

/** Detects whether the device is rooted. The app refuses to run on rooted
 *  devices (and therefore never scans / false-flags system files). */
public final class RootCheck {

    private RootCheck() {}

    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk", "/data/adb/ksu",
        "/data/adb/ap", "/system/bin/magisk"
    };

    public static boolean isRooted() {
        for (String p : SU_PATHS) {
            try { if (new File(p).exists()) return true; } catch (Throwable ignore) {}
        }
        String tags = Build.TAGS;
        return tags != null && tags.contains("test-keys");
    }
}
