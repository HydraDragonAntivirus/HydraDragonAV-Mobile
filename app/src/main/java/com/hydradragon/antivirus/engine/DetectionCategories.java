package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * User-configurable per-category detection toggles (Settings). Each category
 * maps to one kind of evidence the engine can act on — turning one off means
 * a hit of THAT kind alone no longer counts toward a threat verdict (other
 * enabled categories still do). All on by default; this is about letting the
 * user tune false-positive-prone categories down, not a security hole — the
 * signature/ClamAV category is the core detector and should stay on for most
 * users.
 */
public final class DetectionCategories {
    private static final String PREFS = "hydra_prefs";

    public static final String SIGNATURES = "detect_cat_signatures";
    public static final String ML = "detect_cat_ml";
    public static final String PUA = "detect_cat_pua";
    public static final String AUTO_RULES = "detect_cat_auto_rules";
    public static final String PERMISSIONS = "detect_cat_permissions";
    public static final String EICAR = "detect_cat_eicar";
    /** Embedded malicious/phishing URL strings inside an APK (ScanEngine's
     *  reinstated {@code UrlThreatScanner.scanApk()} call — see its javadoc
     *  for why this is far less false-positive-prone than a bare-domain
     *  check: a full URL (with path) is much more specific than a domain
     *  alone, so a bloom hit here means much more). */
    public static final String URL_STRINGS = "detect_cat_url_strings";
    /** Unicorn-based native-code (.so/ELF) emulation to reveal runtime-only
     *  decoded strings (see NativeScanner.setEmulationEnabled / emulate.rs).
     *  Applied to the native engine immediately on toggle, actually skipping
     *  the emulation cost when off — not just suppressing its results. */
    public static final String NATIVE_EMULATION = "detect_cat_native_emulation";

    private DetectionCategories() {}

    public static boolean isEnabled(Context c, String category) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(category, true);
    }

    public static void setEnabled(Context c, String category, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(category, on).apply();
    }
}
