package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.ApplicationInfo;

/**
 * Whitelist of trusted packages so legitimate apps (Google, OEM, big-vendor and
 * system apps) are never flagged by behavioural detection (e.g. notification /
 * UI-event spam). Keeps "Google" from being called a virus.
 */
public final class TrustedPackages {

    /** Trusted publisher / OEM / system package prefixes. */
    private static final String[] PREFIXES = {
        "com.google.", "com.android.", "android", "com.whatsapp",
        "com.facebook.", "com.instagram.", "com.twitter", "com.spotify",
        "com.microsoft.", "org.telegram.", "com.discord", "org.mozilla.",
        "com.opera.", "com.brave.", "com.duckduckgo.",
        "com.miui.", "com.samsung.", "com.sec.", "com.oppo.", "com.vivo.",
        "com.motorola.", "com.huawei.", "com.hihonor.", "com.oneplus.",
        "com.realme.", "com.asus.", "com.sony.", "com.coloros.", "com.heytap.",
        "com.qualcomm.", "com.mediatek.", "com.lge.", "com.transsion.",
        "com.termux", "io.github.", "com.github.", "org.fdroid.",
    };

    private TrustedPackages() {}

    public static boolean isTrusted(Context c, String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        for (String p : PREFIXES) {
            if (pkg.equals(p) || pkg.startsWith(p)) return true;
        }
        // System / updated-system apps are trusted too.
        try {
            ApplicationInfo ai = c.getPackageManager().getApplicationInfo(pkg, 0);
            if ((ai.flags & (ApplicationInfo.FLAG_SYSTEM
                    | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) {
                return true;
            }
        } catch (Exception ignore) {
        }
        return false;
    }
}
