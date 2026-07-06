package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

/** User-configurable on/off switches for every DYNAMIC (runtime-behavior)
 *  detector — as opposed to {@link DetectionCategories}, which gates the
 *  STATIC scan-time engines (signatures/ML/PUA/etc). All default to
 *  {@code true}; each detector's entry point checks {@link #isEnabled} for
 *  its own key before doing any work, so turning one off is a genuine no-op,
 *  not just a suppressed notification. */
public final class BehaviorDetectionSettings {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_PREFIX = "behavior_detect_";

    /** UI event spam / notification-flood detection (DynamicAnalysisService). */
    public static final String UI_SPAM = "ui_spam";
    /** Device-became-rooted-mid-session detection (GuardService#checkRootTransition). */
    public static final String ROOT_EXPLOIT = "root_exploit";
    /** Permission-combo + suspicious-DNS dynamic risk score (DynamicRiskEngine). */
    public static final String DYNAMIC_RISK = "dynamic_risk";
    /** Mass file-rename-after-permission-grant ransomware behaviour (RansomwareBehaviorGuard). */
    public static final String RANSOMWARE = "ransomware";
    /** Task-hijacking / StrandHogg activities-count check (StrandHoggGuard, MainActivity). */
    public static final String TASK_HIJACK = "task_hijack";
    /** FLAG_SECURE + "Show Taps" screen-capture defense (SecureWindowGuard, MainActivity). */
    public static final String SCREEN_SECURITY = "screen_security";
    /** Temporary decoy "file trap" deployment for freshly-installed, unknown
     *  apps that just got All Files Access (FileCanaryGuard). */
    public static final String FILE_CANARY = "file_canary";
    /** Malware kicking the user off its own uninstall/device-admin-deactivation
     *  screen, repeatedly (RemovalResistanceGuard). */
    public static final String REMOVAL_RESISTANCE = "removal_resistance";

    private BehaviorDetectionSettings() {}

    public static boolean isEnabled(Context c, String key) {
        return c.getSharedPreferences(PREFS, 0).getBoolean(KEY_PREFIX + key, true);
    }

    public static void setEnabled(Context c, String key, boolean on) {
        c.getSharedPreferences(PREFS, 0).edit().putBoolean(KEY_PREFIX + key, on).apply();
    }
}
