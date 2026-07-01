package com.hydradragon.antivirus.engine;

import android.content.Context;

/**
 * Default-deny posture: when NONE of the detectors (ClamAV/YARA signatures,
 * the ML model, TLSH fuzzy-malware matching, DEX static analysis, dangerous
 * permissions, behaviour, screen-text/OCR) flag anything, a normal scan
 * reports the app as clean. With Zero Trust Mode on, an unmatched app is
 * instead reported SUSPICIOUS ("unverified", not "safe") with a full dump of
 * everything the engine knows about it, so the user judges for themselves
 * instead of the app being silently trusted.
 *
 * <p>NOT RECOMMENDED for most users: legitimate apps routinely hit zero
 * detections (that's the common case, not the exception), so this trades a
 * high false-positive rate for maximum visibility. Off by default.
 */
public final class ZeroTrustMode {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "zero_trust_mode";

    private ZeroTrustMode() {}

    public static boolean isEnabled(Context c) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY, false);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY, on).apply();
    }
}
