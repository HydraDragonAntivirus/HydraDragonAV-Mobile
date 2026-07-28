package com.hydradragon.antivirus.ui;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.MotionEvent;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.CleanupEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SettingsFragment extends Fragment {

    private LinearLayout container;
    private final List<CleanupEngine.BloatwareApp> foundBloatware = new ArrayList<>();
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_THEME = "theme_mode";
    private static final String KEY_SHIELD = "web_shield_enabled";
    private static final String KEY_SCREEN_OCR = "screen_ocr_enabled";
    private static final int REQ_VPN = 1201;
    private static final int REQ_SCREEN_CAPTURE = 1202;
    private static final int REQ_SMS = 1203;
    private static final int REQ_NOTIFICATION = 1204;

    // Self-protection: only the real user should be able to change settings.
    // A transparent tapjacking overlay is detected by FLAG_WINDOW_IS_OBSCURED
    // (applyObscuredTouchWarning shows a Toast instead of blocking — PiP
    // windows must not break toggles) — but a malicious accessibility service calling
    // AccessibilityNodeInfo.performAction(ACTION_CLICK) directly never
    // generates a MotionEvent at all, so obscure-touch filtering can't see
    // it. The only thing that technique CAN'T fake convincingly is HUMAN
    // TIMING: no one deliberately flips several unrelated toggles within a
    // fraction of a second. RECENT_TOGGLE_WINDOW_MS / RECENT_TOGGLE_BURST is
    // that rate limit — a burst reverts itself and blocks with a warning.
    private static final long RECENT_TOGGLE_WINDOW_MS = 1200;
    private static final int RECENT_TOGGLE_BURST = 3;
    private final java.util.ArrayDeque<Long> recentToggleTimes = new java.util.ArrayDeque<>();

    // Set right before launching exportRuleLauncher so the callback (which
    // gets only the destination Uri back) knows WHICH .yar file's content to
    // write there.
    private java.io.File pendingExportRuleFile;
    private final androidx.activity.result.ActivityResultLauncher<String> exportRuleLauncher =
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.CreateDocument("application/octet-stream"),
            uri -> {
                if (uri == null || pendingExportRuleFile == null) return;
                try (java.io.InputStream in = new java.io.FileInputStream(pendingExportRuleFile);
                     java.io.OutputStream out = requireContext().getContentResolver().openOutputStream(uri)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    Toast.makeText(getContext(), getString(R.string.auto_rule_exported), Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(getContext(), getString(R.string.auto_rule_export_failed), Toast.LENGTH_SHORT).show();
                }
                pendingExportRuleFile = null;
            });

    private final androidx.activity.result.ActivityResultLauncher<String> knowledgeExportLauncher =
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.CreateDocument("application/json"),
            uri -> {
                if (uri == null) return;
                try {
                    com.hydradragon.antivirus.engine.KnowledgeDatabase.exportCache(requireContext(), uri);
                    Toast.makeText(getContext(), getString(R.string.knowledge_db_exported, 0), Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(getContext(), getString(R.string.knowledge_db_export_failed), Toast.LENGTH_SHORT).show();
                }
            });

    private final androidx.activity.result.ActivityResultLauncher<String> knowledgeImportLauncher =
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.GetContent(),
            uri -> {
                if (uri == null) return;
                try {
                    int count = com.hydradragon.antivirus.engine.KnowledgeDatabase.importCache(requireContext(), uri);
                    Toast.makeText(getContext(),
                        getString(R.string.knowledge_db_imported, count), Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(getContext(), getString(R.string.knowledge_db_import_failed), Toast.LENGTH_SHORT).show();
                }
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inf, @Nullable ViewGroup p, @Nullable Bundle s) {
        ScrollView scroll = new ScrollView(getContext());
        scroll.setBackgroundColor(color(R.color.bg_primary));
        container = new LinearLayout(getContext());
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(40, 56, 40, 56);
        scroll.addView(container);
        buildUI();
        return scroll;
    }

    @Override
    public void onResume() {
        super.onResume();
        // Rebuild so toggles reflect state changed by a system screen this
        // fragment doesn't get a direct callback for (Accessibility settings,
        // Device Admin consent) — the fragment itself isn't recreated when
        // the user comes back from those, only the Activity resumes.
        if (container != null) buildUI();
    }

    private void buildUI() {
        container.removeAllViews();
        addTitle(getString(R.string.settings_title));
        addBtn("🌍 " + getString(R.string.language_settings), color(R.color.bg_secondary), v -> selectLanguage());

        addHeader(getString(R.string.appearance));
        String currentTheme = prefs().getString(KEY_THEME, null);
        if (currentTheme == null) {
            // Migrate from old boolean preference
            boolean dark = prefs().getBoolean("dark_mode", true);
            currentTheme = dark ? "dark" : "light";
            prefs().edit().putString(KEY_THEME, currentTheme).apply();
        }
        String themeLabel;
        switch (currentTheme) {
            case "system": themeLabel = getString(R.string.theme_system); break;
            case "light":  themeLabel = getString(R.string.theme_light);  break;
            default:       themeLabel = getString(R.string.theme_dark);   break;
        }
        addThemeSelector(themeLabel, v -> showThemeModeDialog());

        addHeader(getString(R.string.protection_header));
        boolean prot = com.hydradragon.antivirus.engine.ProtectionState.isEnabled(requireContext());
        addToggle(getString(R.string.realtime_protection), prot, (btn, on) -> {
            com.hydradragon.antivirus.engine.ProtectionState.setEnabled(requireContext(), on);
            Intent svc = new Intent(requireContext(),
                com.hydradragon.antivirus.service.GuardService.class);
            if (on) {
                ContextCompat.startForegroundService(requireContext(), svc);
                Toast.makeText(getContext(), getString(R.string.protection_enabled), Toast.LENGTH_SHORT).show();
            } else {
                requireContext().stopService(svc);
                Toast.makeText(getContext(), getString(R.string.protection_paused), Toast.LENGTH_SHORT).show();
            }
        });

        boolean bootAutoStart = com.hydradragon.antivirus.engine.BootAutoStart.isEnabled(requireContext());
        addToggle(getString(R.string.boot_auto_start_toggle), bootAutoStart, (btn, on) -> {
            com.hydradragon.antivirus.engine.BootAutoStart.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.boot_auto_start_on_toast)
                : getString(R.string.boot_auto_start_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean debugWarn = com.hydradragon.antivirus.engine.DebugModeWarning.isEnabled(requireContext());
        addToggle(getString(R.string.debug_mode_warning_toggle), debugWarn, (btn, on) ->
            com.hydradragon.antivirus.engine.DebugModeWarning.setEnabled(requireContext(), on));

        boolean rootWarn = com.hydradragon.antivirus.engine.RootWarning.isEnabled(requireContext());
        addToggle(getString(R.string.root_warning_toggle), rootWarn, (btn, on) ->
            com.hydradragon.antivirus.engine.RootWarning.setEnabled(requireContext(), on));

        boolean uninstallWarn = prefs().getBoolean("uninstall_warning_enabled", true);
        addToggle(getString(R.string.uninstall_warning_toggle), uninstallWarn, (btn, on) ->
            prefs().edit().putBoolean("uninstall_warning_enabled", on).apply());

        // Device Admin self-protection (SelfProtection/AdminReceiver) existed
        // in the codebase but was never actually wired up anywhere — this is
        // the first place the user can turn it on/off. Turning ON opens the
        // system consent screen (async — the switch's true state is re-read
        // next time this screen builds, same as the Accessibility toggle).
        // Turning OFF is synchronous (removeActiveAdmin).
        boolean selfProtectionActive = com.hydradragon.antivirus.engine.SelfProtection.isActive(requireContext());
        addToggle(getString(R.string.self_protection_toggle), selfProtectionActive, (btn, on) -> {
            if (on) {
                startActivity(com.hydradragon.antivirus.engine.SelfProtection.activationIntent(requireContext()));
            } else {
                com.hydradragon.antivirus.engine.SelfProtection.deactivate(requireContext());
                Toast.makeText(getContext(), getString(R.string.self_protection_off_toast), Toast.LENGTH_SHORT).show();
            }
        });

        boolean periodicScanOn = com.hydradragon.antivirus.engine.ScanSchedule.isPeriodicScanEnabled(requireContext());
        addToggle(getString(R.string.periodic_scan_toggle), periodicScanOn, (btn, on) -> {
            com.hydradragon.antivirus.engine.ScanSchedule.setPeriodicScanEnabled(requireContext(), on);
            // Only startPeriodicScans() reads this, at GuardService startup —
            // restart it so the change takes effect right away, same as the
            // interval dialog below.
            Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.GuardService.class);
            requireContext().stopService(svc);
            ContextCompat.startForegroundService(requireContext(), svc);
            Toast.makeText(getContext(), on
                ? getString(R.string.periodic_scan_on_toast)
                : getString(R.string.periodic_scan_off_toast), Toast.LENGTH_SHORT).show();
        });

        boolean wakeLockOn = com.hydradragon.antivirus.engine.ScanSchedule.isScanWakeLockEnabled(requireContext());
        com.hydradragon.antivirus.engine.ScanEngine.setBackgroundPriority(!wakeLockOn);
        addToggle(getString(R.string.scan_wakelock_toggle), wakeLockOn, (btn, on) -> {
            com.hydradragon.antivirus.engine.ScanSchedule.setScanWakeLockEnabled(requireContext(), on);
            com.hydradragon.antivirus.engine.ScanEngine.setBackgroundPriority(!on);
            // Read fresh at the start of each scan (acquireScanWakeLock), so no
            // service restart needed — takes effect on the next scan.
            Toast.makeText(getContext(), on
                ? getString(R.string.scan_wakelock_on_toast)
                : getString(R.string.scan_wakelock_off_toast), Toast.LENGTH_SHORT).show();
        });

        addBtn("⏱ " + getString(R.string.scan_interval_btn), color(R.color.bg_secondary),
            v -> showScanIntervalDialog());
        addBtn("📦 " + getString(R.string.max_scan_file_size_btn), color(R.color.bg_secondary),
            v -> showMaxScanFileSizeDialog());
        addBtn("📄 " + getString(R.string.max_text_scan_bytes_btn), color(R.color.bg_secondary),
            v -> showMaxTextScanBytesDialog());

        addHeader(getString(R.string.detection_categories_header));
        addCategoryToggle(R.string.detect_cat_signatures, com.hydradragon.antivirus.engine.DetectionCategories.SIGNATURES);
        addCategoryToggle(R.string.detect_cat_ml, com.hydradragon.antivirus.engine.DetectionCategories.ML);
        addCategoryToggle(R.string.detect_cat_pua, com.hydradragon.antivirus.engine.DetectionCategories.PUA);
        addCategoryToggle(R.string.detect_cat_auto_rules, com.hydradragon.antivirus.engine.DetectionCategories.AUTO_RULES);
        addCategoryToggle(R.string.detect_cat_permissions, com.hydradragon.antivirus.engine.DetectionCategories.PERMISSIONS);
        addCategoryToggle(R.string.detect_cat_eicar, com.hydradragon.antivirus.engine.DetectionCategories.EICAR);
        addCategoryToggle(R.string.detect_cat_url_strings, com.hydradragon.antivirus.engine.DetectionCategories.URL_STRINGS);
        addCategoryToggle(R.string.detect_cat_rootkit, com.hydradragon.antivirus.engine.DetectionCategories.ROOTKIT);
        boolean nativeEmuOn = com.hydradragon.antivirus.engine.DetectionCategories.isEnabled(
            requireContext(), com.hydradragon.antivirus.engine.DetectionCategories.NATIVE_EMULATION);
        addToggle(getString(R.string.detect_cat_native_emulation), nativeEmuOn, (btn, checked) -> {
            com.hydradragon.antivirus.engine.DetectionCategories.setEnabled(requireContext(),
                com.hydradragon.antivirus.engine.DetectionCategories.NATIVE_EMULATION, checked);
            com.hydradragon.antivirus.engine.NativeScanner.setEmulationEnabled(checked);
        });

        boolean testKeyOn = requireContext().getSharedPreferences("hydra_prefs", 0)
            .getBoolean(com.hydradragon.antivirus.engine.DetectionCategories.RISKWARE_TESTKEY, false);
        addToggle(getString(R.string.detect_cat_riskware_testkey), testKeyOn, (btn, checked) -> {
            com.hydradragon.antivirus.engine.DetectionCategories.setEnabled(requireContext(),
                com.hydradragon.antivirus.engine.DetectionCategories.RISKWARE_TESTKEY, checked);
            com.hydradragon.antivirus.engine.NativeScanner.setRiskwareTestKeyEnabled(checked);
        });

        addHeader(getString(R.string.behavior_detection_header));
        addBehaviorToggle(R.string.behavior_ui_spam, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.UI_SPAM);
        addBehaviorToggle(R.string.behavior_root_exploit, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.ROOT_EXPLOIT);
        addBehaviorToggle(R.string.behavior_dynamic_risk, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.DYNAMIC_RISK);
        addBehaviorToggle(R.string.behavior_ransomware, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.RANSOMWARE);
        addBehaviorToggle(R.string.behavior_file_canary, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.FILE_CANARY);
        addBehaviorToggle(R.string.behavior_task_hijack, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.TASK_HIJACK);
        addBehaviorToggle(R.string.behavior_screen_security, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCREEN_SECURITY);
        addBehaviorToggle(R.string.behavior_crypto_miner, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.CRYPTO_MINER);
        addBehaviorToggle(R.string.behavior_file_read_estimator, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.FILE_READ_ESTIMATOR);
        addBehaviorToggle(R.string.behavior_wiper, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.WIPER);

        // Web Shield is core protection (malicious-domain/IP DNS filtering),
        // not an extra — it lives in Protection, not Premium Features.
        boolean shield = prefs().getBoolean(KEY_SHIELD, false);
        addToggle(getString(R.string.web_shield), shield, (btn, on) -> {
            prefs().edit().putBoolean("web_shield_decided", true)
                          .putBoolean(KEY_SHIELD, on).apply();
            if (on) enableWebShield(btn);
            else disableWebShield();
        });

        boolean suricataScan = prefs().getBoolean("suricata_rule_scan_enabled", true);
        addToggle(getString(R.string.suricata_rule_scan), suricataScan, (btn, on) -> {
            prefs().edit().putBoolean("suricata_rule_scan_enabled", on).apply();
            Toast.makeText(getContext(), on
                ? getString(R.string.suricata_rule_scan_on_toast)
                : getString(R.string.suricata_rule_scan_off_toast), Toast.LENGTH_SHORT).show();
        });

        addHeader(getString(R.string.premium_features_header));
        boolean zeroTrust = com.hydradragon.antivirus.engine.ZeroTrustMode.isEnabled(requireContext());
        addToggle(getString(R.string.zero_trust_toggle), zeroTrust, (btn, on) -> {
            com.hydradragon.antivirus.engine.ZeroTrustMode.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.zero_trust_on_toast)
                : getString(R.string.zero_trust_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean autoRuleGen = com.hydradragon.antivirus.engine.AutoRuleGeneration.isEnabled(requireContext());
        addToggle(getString(R.string.auto_rule_gen_toggle), autoRuleGen, (btn, on) -> {
            com.hydradragon.antivirus.engine.AutoRuleGeneration.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.auto_rule_gen_on_toast)
                : getString(R.string.auto_rule_gen_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean saveAutoRules = com.hydradragon.antivirus.engine.SaveAutoRules.isEnabled(requireContext());
        addToggle(getString(R.string.save_auto_rules_toggle), saveAutoRules, (btn, on) -> {
            com.hydradragon.antivirus.engine.SaveAutoRules.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.save_auto_rules_on_toast)
                : getString(R.string.save_auto_rules_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean askSigOnRemove = com.hydradragon.antivirus.engine.AskSignatureOnRemove.isEnabled(requireContext());
        addToggle(getString(R.string.ask_sig_on_remove_toggle), askSigOnRemove, (btn, on) -> {
            com.hydradragon.antivirus.engine.AskSignatureOnRemove.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.ask_sig_on_remove_on_toast)
                : getString(R.string.ask_sig_on_remove_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean autoDeleteMalware = com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(requireContext());
        addToggle(getString(R.string.auto_delete_malware_toggle), autoDeleteMalware, (btn, on) -> {
            com.hydradragon.antivirus.engine.AutoDeleteMalware.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? getString(R.string.auto_delete_malware_on_toast)
                : getString(R.string.auto_delete_malware_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean scanCache = prefs().getBoolean("scan_cache_enabled", true);
        addToggle(getString(R.string.scan_cache_toggle), scanCache, (btn, on) -> {
            prefs().edit().putBoolean("scan_cache_enabled", on).apply();
            if (!on) com.hydradragon.antivirus.engine.ScanEngine.clearCache(requireContext());
            Toast.makeText(getContext(), on
                ? getString(R.string.scan_cache_on_toast)
                : getString(R.string.scan_cache_off_toast), Toast.LENGTH_SHORT).show();
        });

        boolean detectZipBomb = prefs().getBoolean("detect_zip_bomb_enabled", true);
        addToggle(getString(R.string.detect_zip_bomb_toggle), detectZipBomb, (btn, on) -> {
            prefs().edit().putBoolean("detect_zip_bomb_enabled", on).apply();
            com.hydradragon.antivirus.engine.NativeScanner.setDetectZipBomb(on);
            Toast.makeText(getContext(), on
                ? getString(R.string.detect_zip_bomb_on_toast)
                : getString(R.string.detect_zip_bomb_off_toast), Toast.LENGTH_SHORT).show();
        });

        boolean systemScan = prefs().getBoolean("scan_system_files_enabled", false);
        addToggle(getString(R.string.scan_system_toggle), systemScan, (btn, on) -> {
            prefs().edit().putBoolean("scan_system_files_enabled", on).apply();
            Toast.makeText(getContext(), on
                ? getString(R.string.scan_system_on_toast)
                : getString(R.string.scan_system_off_toast), Toast.LENGTH_LONG).show();
        });

        boolean antiFn = prefs().getBoolean("anti_fn_enabled", true);
        addToggle(getString(R.string.anti_fn_enabled_toggle), antiFn, (btn, on) -> {
            prefs().edit().putBoolean("anti_fn_enabled", on).apply();
            if (!on) {
                // Clear the cache when disabled
                com.hydradragon.antivirus.engine.AntiFnCache cache =
                    new com.hydradragon.antivirus.engine.AntiFnCache(requireContext());
                cache.clear();
            }
            Toast.makeText(getContext(), on
                ? getString(R.string.anti_fn_on_toast)
                : getString(R.string.anti_fn_off_toast), Toast.LENGTH_SHORT).show();
        });

        int antiFnTlshThresh = prefs().getInt("anti_fn_tlsh_threshold", 30);
        addBtn("🔀 " + getString(R.string.anti_fn_tlsh_threshold_btn) + " (" + antiFnTlshThresh + ")", color(R.color.bg_secondary),
            v -> showAntiFnTlshThresholdDialog());


        boolean relevantOnly = prefs().getBoolean("scan_relevant_only_enabled", true);
        addToggle(getString(R.string.scan_relevant_only_toggle), relevantOnly, (btn, on) -> {
            prefs().edit().putBoolean("scan_relevant_only_enabled", on).apply();
            com.hydradragon.antivirus.engine.NativeScanner.setScanRelevantOnly(on);
        });

        boolean screenOcr = prefs().getBoolean(KEY_SCREEN_OCR, false);
        addToggle(getString(R.string.screen_ocr_toggle), screenOcr, (btn, on) -> {
            if (on) requestScreenCapture(btn);
            else stopScreenCapture();
        });

        boolean smsGranted = ContextCompat.checkSelfPermission(requireContext(),
            android.Manifest.permission.RECEIVE_SMS) == android.content.pm.PackageManager.PERMISSION_GRANTED;
        addToggle(getString(R.string.sms_scan_toggle), smsGranted, (btn, on) -> {
            if (on) requestSmsPermission(btn);
            else openAppSettingsToRevokeSms();
        });

        // Silent Mode — when ON, no notification permission is requested
        // and the app runs without any notification popups.
        boolean silentMode = prefs().getBoolean("silent_mode", false);
        addToggle(getString(R.string.silent_mode_toggle), silentMode, (btn, on) -> {
            prefs().edit().putBoolean("silent_mode", on).apply();
            if (!on && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && ContextCompat.checkSelfPermission(requireContext(),
                        android.Manifest.permission.POST_NOTIFICATIONS)
                        != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFICATION);
            }
        });

        // All Files Access — required to scan installed APKs on Android 11+.
        // Only MANAGE_EXTERNAL_STORAGE is MANDATORY — all other permissions
        // are optional (notifications, accessibility, etc.).
        boolean allFilesGranted = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
            || Environment.isExternalStorageManager();
        addToggle(getString(R.string.all_files_access_title), allFilesGranted, (btn, on) -> {
            if (on && !allFilesGranted) {
                try {
                    startActivity(new Intent(
                        android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + requireContext().getPackageName())));
                } catch (Throwable ignore) { }
                buildUI();
            } else {
                Toast.makeText(getContext(), "Open App Info > Permissions to revoke",
                    Toast.LENGTH_LONG).show();
                try {
                    startActivity(new Intent(
                        android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:" + requireContext().getPackageName())));
                } catch (Throwable ignore) { }
                buildUI();
            }
        });

        // Draw Over Other Apps — SYSTEM_ALERT_WINDOW is already declared in the
        // manifest as the documented background-activity-start exemption (see
        // AndroidManifest.xml). This toggle lets the user grant/revoke it via
        // the system's special-access screen.
        boolean overlayGranted = Build.VERSION.SDK_INT < Build.VERSION_CODES.M
            || android.provider.Settings.canDrawOverlays(requireContext());
        addToggle(getString(R.string.draw_overlay_toggle), overlayGranted, (btn, on) -> {
            if (on && !overlayGranted) {
                try {
                    startActivity(new Intent(
                        android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:" + requireContext().getPackageName())));
                } catch (Throwable ignore) { }
                buildUI();
            } else {
                Toast.makeText(getContext(), getString(R.string.draw_overlay_off_toast),
                    Toast.LENGTH_LONG).show();
                try {
                    startActivity(new Intent(
                        android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:" + requireContext().getPackageName())));
                } catch (Throwable ignore) { }
                buildUI();
            }
        });

        // Off by default: one FileObserver thread per storage root, plus files
        // dropped outside Downloads are also already caught (just not instantly)
        // by GuardService's periodic Full Scan. See GuardService.KEY_REALTIME_STORAGE_WATCH.
        boolean storageWatch = prefs().getBoolean(
            com.hydradragon.antivirus.service.GuardService.KEY_REALTIME_STORAGE_WATCH, true);
        addToggle(getString(R.string.storage_watch_toggle), storageWatch, (btn, on) -> {
            prefs().edit().putBoolean(
                com.hydradragon.antivirus.service.GuardService.KEY_REALTIME_STORAGE_WATCH, on).apply();
            // GuardService only sets up the extra watchers in onCreate() — restart
            // it so the new setting takes effect immediately instead of on next
            // device reboot / app relaunch.
            Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.GuardService.class);
            requireContext().stopService(svc);
            ContextCompat.startForegroundService(requireContext(), svc);
        });

        // Allow screen recording — removes FLAG_SECURE so other apps
        // (screen recorders, remote-support tools) can see this app's UI.
        boolean allowRecording = prefs().getBoolean("disable_secure_flag", true);
        addToggle(getString(R.string.disable_secure_flag_toggle), allowRecording, (btn, on) -> {
            prefs().edit().putBoolean("disable_secure_flag", on).apply();
            android.app.Activity a = getActivity();
            if (a != null) {
                if (on) {
                    a.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
                } else if (com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(a,
                        com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCREEN_SECURITY)) {
                    a.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
                }
            }
        });

        addHeader(getString(R.string.whitelists_header));
        addBtn("🚫 " + getString(R.string.ignored_signatures_btn), color(R.color.bg_secondary),
            v -> showManagedListDialog(
                getString(R.string.ignored_signatures_btn),
                getString(R.string.ignored_signatures_hint),
                com.hydradragon.antivirus.engine.IgnoredSignatures.getAll(requireContext()),
                com.hydradragon.antivirus.engine.IgnoredSignatures::add,
                com.hydradragon.antivirus.engine.IgnoredSignatures::remove));
        addBtn("🌐 " + getString(R.string.website_whitelist_btn), color(R.color.bg_secondary),
            v -> showManagedListDialog(
                getString(R.string.website_whitelist_btn),
                getString(R.string.website_whitelist_hint),
                com.hydradragon.antivirus.engine.WebsiteWhitelist.getAll(requireContext()),
                com.hydradragon.antivirus.engine.WebsiteWhitelist::add,
                com.hydradragon.antivirus.engine.WebsiteWhitelist::remove));
        addBtn("📜 " + getString(R.string.auto_rules_manager_btn), color(R.color.bg_secondary),
            v -> showAutoRulesManagerDialog());
        addBtn("🗑 " + getString(R.string.clear_scan_cache_btn), color(R.color.bg_secondary),
            v -> showClearCacheDialog());

        addHeader(getString(R.string.knowledge_db_header));
        addBtn("📤 " + getString(R.string.knowledge_db_export_btn), color(R.color.bg_secondary),
            v -> exportKnowledgeDatabase());
        addBtn("📥 " + getString(R.string.knowledge_db_import_btn), color(R.color.bg_secondary),
            v -> importKnowledgeDatabase());

        addHeader(getString(R.string.system));
        addBtn(getString(R.string.bloatware_cleaner), color(R.color.neon_cyan), v -> runCleanup());
        addBtn("⟲ " + getString(R.string.reset_settings_btn), 0xFFFF0040, v -> confirmResetSettings());

        addHeader(getString(R.string.about));
        addAbout();
    }

    // ─── RESET SETTINGS ─────────────────────────────────────────────
    /** One row of the category picker: a label + the raw hydra_prefs keys that
     *  category owns. Reset removes those keys (not put-defaults) so every
     *  reader's own getX(ctx, DEFAULT) fallback is what decides the restored
     *  value — one source of truth instead of duplicating defaults here. */
    private static final class ResetCategory {
        final int labelRes;
        final String[] keys;
        ResetCategory(int labelRes, String... keys) { this.labelRes = labelRes; this.keys = keys; }
    }
    private static final int CAT_APPEARANCE = 0;
    private static final int CAT_PROTECTION = 1;
    private static final int CAT_DETECTION = 2;
    private static final int CAT_BEHAVIOR = 3;
    private static final int CAT_PRIVACY = 4;
    private static final int CAT_PREMIUM = 5;
    private static final int CAT_WHITELISTS = 6;
    private final ResetCategory[] resetCategories = {
        new ResetCategory(R.string.reset_cat_appearance, "theme_mode", "dark_mode", "language"),
        new ResetCategory(R.string.reset_cat_protection, "protection_enabled", "boot_auto_start",
            "debug_mode_warning_enabled", "root_warning_enabled", "uninstall_warning_enabled",
            "periodic_scan_enabled", "scan_interval_quick_min", "scan_interval_full_min",
            "max_scan_file_size_mb"),
        new ResetCategory(R.string.reset_cat_detection, "detect_cat_signatures", "detect_cat_ml",
            "detect_cat_pua", "detect_cat_auto_rules", "detect_cat_permissions", "detect_cat_eicar",
            "detect_cat_url_strings", "detect_cat_rootkit", "detect_cat_native_emulation",
            "detect_cat_riskware_testkey"),
        new ResetCategory(R.string.reset_cat_behavior, "ui_spam", "root_exploit", "dynamic_risk",
            "ransomware", "task_hijack", "screen_security", "file_canary"),
        new ResetCategory(R.string.reset_cat_privacy, KEY_SHIELD, "web_shield_decided", KEY_SCREEN_OCR,
            "silent_mode", com.hydradragon.antivirus.service.GuardService.KEY_REALTIME_STORAGE_WATCH,
            "disable_secure_flag", "scan_cache_enabled", "detect_zip_bomb_enabled", "scan_relevant_only_enabled",
            "anti_fn_enabled", "anti_fn_tlsh_threshold",
            "suricata_rule_scan_enabled", "max_text_scan_bytes"),
        new ResetCategory(R.string.reset_cat_premium, "zero_trust_mode", "auto_rule_generation",
            "ask_signature_on_remove", "auto_delete_malware_enabled"),
        new ResetCategory(R.string.reset_cat_whitelists, "ignored_signatures", "website_whitelist"),
    };

    private void confirmResetSettings() {
        String[] labels = new String[resetCategories.length];
        boolean[] checked = new boolean[resetCategories.length];
        for (int i = 0; i < resetCategories.length; i++) {
            labels[i] = getString(resetCategories[i].labelRes);
            checked[i] = true;
        }
        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.reset_settings_btn))
            .setMultiChoiceItems(labels, checked, (d, which, isChecked) -> checked[which] = isChecked)
            .setPositiveButton(getString(R.string.reset_settings_btn), (d, w) -> resetSelectedSettings(checked))
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    private void resetSelectedSettings(boolean[] checked) {
        boolean any = false;
        for (boolean b : checked) if (b) { any = true; break; }
        if (!any) return;

        SharedPreferences.Editor editor = prefs().edit();
        for (int i = 0; i < resetCategories.length; i++) {
            if (!checked[i]) continue;
            for (String key : resetCategories[i].keys) editor.remove(key);
        }
        editor.apply();

        if (checked[CAT_APPEARANCE]) {
            AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.getEmptyLocaleList());
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
        }
        if (checked[CAT_PRIVACY]) {
            disableWebShield();
            stopScreenCapture();
        }
        if (checked[CAT_PROTECTION] || checked[CAT_DETECTION] || checked[CAT_PRIVACY]) {
            Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.GuardService.class);
            requireContext().stopService(svc);
            ContextCompat.startForegroundService(requireContext(), svc);
        }
        Toast.makeText(getContext(), getString(R.string.reset_settings_done), Toast.LENGTH_LONG).show();
        if (checked[CAT_APPEARANCE] && getActivity() != null) getActivity().recreate();
        else buildUI();
    }

    // ─── BLOATWARE ─────────────────────────────────────────────────
    private void runCleanup() {
        foundBloatware.clear();
        AlertDialog dlg = new AlertDialog.Builder(requireContext(),
            android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.scanning_bloatware))
            .setMessage(getString(R.string.scanning_bloatware_msg))
            .setCancelable(false).create();
        dlg.show();

        new CleanupEngine(requireContext()).scan(new CleanupEngine.Callback() {
            @Override public void onFound(CleanupEngine.BloatwareApp a) { foundBloatware.add(a); }
            @Override public void onDone(int n) {
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    dlg.dismiss();
                    if (n == 0) Toast.makeText(getContext(), getString(R.string.clean_no_bloatware), Toast.LENGTH_LONG).show();
                    else showNext();
                });
            }
        });
    }

    private void showNext() {
        if (foundBloatware.isEmpty()) {
            Toast.makeText(getContext(), getString(R.string.all_apps_processed), Toast.LENGTH_SHORT).show();
            return;
        }
        CleanupEngine.BloatwareApp a = foundBloatware.get(0);
        LinearLayout lay = new LinearLayout(getContext());
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setPadding(32, 24, 32, 24);

        if (a.icon != null) {
            ImageView iv = new ImageView(getContext());
            iv.setImageDrawable(a.icon);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(96, 96);
            lp.gravity = Gravity.CENTER_HORIZONTAL; lp.bottomMargin = 16;
            lay.addView(iv, lp);
        }
        TextView tv = new TextView(getContext());
        tv.setText(a.reason + "\n\n📱 " + a.name + "\n📦 " + a.pkg
            + "\n💾 " + (a.memKb / 1024) + " MB RAM\n\n⏳ Kalan: " + foundBloatware.size());
        tv.setTextColor(color(R.color.text_primary));
        tv.setTypeface(Typeface.MONOSPACE);
        lay.addView(tv);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.bg_app_found))
            .setView(lay)
            .setPositiveButton(getString(R.string.btn_uninstall_disable), (d, w) -> {
                if (!CleanupEngine.disableWithRoot(a.pkg)) {
                    startActivity(new Intent(Intent.ACTION_DELETE)
                        .setData(Uri.parse("package:" + a.pkg)));
                } else {
                    Toast.makeText(getContext(), getString(R.string.disabled_success), Toast.LENGTH_SHORT).show();
                }
                foundBloatware.remove(0); showNext();
            })
            .setNegativeButton(getString(R.string.btn_skip), (d, w) -> { foundBloatware.remove(0); showNext(); })
            .setNeutralButton(getString(R.string.btn_close), null).show();
    }

    // ─── WEB SHIELD (DNS VPN) ─────────────────────────────────────
    private void enableWebShield(CompoundButton btn) {
        Intent prep;
        try {
            prep = VpnService.prepare(requireContext());
        } catch (Throwable t) {
            Toast.makeText(getContext(), getString(R.string.vpn_unavailable), Toast.LENGTH_LONG).show();
            prefs().edit().putBoolean(KEY_SHIELD, false).apply();
            if (btn != null) btn.setChecked(false);
            return;
        }
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);   // system consent dialog
        } else {
            startShieldService();                    // already authorised
        }
    }

    private void startShieldService() {
        ContextCompat.startForegroundService(requireContext(),
            new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class));
        Toast.makeText(getContext(), getString(R.string.web_shield_enabled), Toast.LENGTH_SHORT).show();
    }

    private void disableWebShield() {
        // Deliver an explicit STOP action so the running service tears the tunnel
        // down deterministically, then also stopService as a belt-and-braces.
        Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class);
        svc.setAction(com.hydradragon.antivirus.service.DnsVpnService.ACTION_STOP);
        try { requireContext().startService(svc); } catch (Throwable ignore) {}
        requireContext().stopService(
            new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class));
        Toast.makeText(getContext(), getString(R.string.web_shield_disabled), Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == android.app.Activity.RESULT_OK) {
                startShieldService();
            } else {
                // Consent denied — revert the toggle.
                prefs().edit().putBoolean(KEY_SHIELD, false).apply();
                Toast.makeText(getContext(), getString(R.string.vpn_consent_denied), Toast.LENGTH_LONG).show();
                buildUI();
            }
        } else if (requestCode == REQ_SCREEN_CAPTURE) {
            if (resultCode == android.app.Activity.RESULT_OK && data != null) {
                prefs().edit().putBoolean(KEY_SCREEN_OCR, true).apply();
                Intent svc = new Intent(requireContext(),
                    com.hydradragon.antivirus.service.ScreenCaptureService.class);
                svc.putExtra(com.hydradragon.antivirus.service.ScreenCaptureService.EXTRA_RESULT_CODE, resultCode);
                svc.putExtra(com.hydradragon.antivirus.service.ScreenCaptureService.EXTRA_RESULT_DATA, data);
                ContextCompat.startForegroundService(requireContext(), svc);
                Toast.makeText(getContext(), getString(R.string.screen_ocr_on_toast), Toast.LENGTH_SHORT).show();
            } else {
                prefs().edit().putBoolean(KEY_SCREEN_OCR, false).apply();
                Toast.makeText(getContext(), getString(R.string.screen_capture_consent_denied), Toast.LENGTH_LONG).show();
                buildUI();
            }
        }
    }

    // ─── SCREEN OCR (Zero Trust) ───────────────────────────────────
    private void requestScreenCapture(CompoundButton btn) {
        android.media.projection.MediaProjectionManager mgr =
            (android.media.projection.MediaProjectionManager)
                requireContext().getSystemService(Context.MEDIA_PROJECTION_SERVICE);
        if (mgr == null) {
            Toast.makeText(getContext(), getString(R.string.screen_capture_unavailable), Toast.LENGTH_LONG).show();
            if (btn != null) btn.setChecked(false);
            return;
        }
        startActivityForResult(mgr.createScreenCaptureIntent(), REQ_SCREEN_CAPTURE);
    }

    private void stopScreenCapture() {
        prefs().edit().putBoolean(KEY_SCREEN_OCR, false).apply();
        requireContext().stopService(new Intent(requireContext(),
            com.hydradragon.antivirus.service.ScreenCaptureService.class));
        Toast.makeText(getContext(), getString(R.string.screen_ocr_off_toast), Toast.LENGTH_SHORT).show();
    }

    // ─── SMS PROTECTION ─────────────────────────────────────────────
    /** RECEIVE_SMS is dangerous + Play Console "Restricted Permission" — it's
     *  opt-in from Settings, never requested at app launch (see MainActivity),
     *  so declining or never touching this toggle simply leaves SMS scanning
     *  off; the rest of the suite is unaffected. */
    private void requestSmsPermission(CompoundButton btn) {
        if (ContextCompat.checkSelfPermission(requireContext(), android.Manifest.permission.RECEIVE_SMS)
                == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return; // already granted (toggle just reflected stale state)
        }
        requestPermissions(new String[]{android.Manifest.permission.RECEIVE_SMS}, REQ_SMS);
    }

    /** Android has no API to revoke a permission from within the app — send the
     *  user to this app's system App Info > Permissions screen to turn it off. */
    private void openAppSettingsToRevokeSms() {
        Toast.makeText(getContext(), getString(R.string.sms_open_permissions_toast), Toast.LENGTH_LONG).show();
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:" + requireContext().getPackageName())));
        } catch (Throwable ignore) { }
        buildUI(); // revert the toggle visually — permission is still granted until the user acts
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_SMS) {
            boolean granted = grantResults.length > 0
                && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED;
            Toast.makeText(getContext(), granted ? getString(R.string.sms_scanning_enabled) : getString(R.string.sms_permission_denied),
                granted ? Toast.LENGTH_SHORT : Toast.LENGTH_LONG).show();
            buildUI();
        } else if (requestCode == REQ_NOTIFICATION) {
            boolean granted = grantResults.length > 0
                && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED;
            if (!granted) {
                Toast.makeText(getContext(), "Notification permission denied — enable Silent Mode or grant from Settings",
                    Toast.LENGTH_LONG).show();
            }
            buildUI();
        }
    }

    // ─── UI YARDIMCILARI ──────────────────────────────────────────
    private int color(int rid) { return ContextCompat.getColor(requireContext(), rid); }
    private SharedPreferences prefs() { return requireContext().getSharedPreferences(PREFS, 0); }

    private void addTitle(String t) {
        TextView v = new TextView(getContext());
        v.setText(t); v.setTextColor(color(R.color.neon_green));
        v.setTextSize(22); v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        v.setPadding(0,0,0,32); container.addView(v);
    }
    private void addHeader(String t) {
        TextView v = new TextView(getContext());
        v.setText("── " + t + " ──"); v.setTextColor(color(R.color.text_secondary));
        v.setTextSize(11); v.setTypeface(Typeface.MONOSPACE);
        v.setPadding(0,32,0,12); container.addView(v);
    }
    private LinearLayout row() {
        LinearLayout r = new LinearLayout(getContext());
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setBackgroundColor(color(R.color.bg_secondary));
        r.setPadding(24,20,24,20); r.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = 8; r.setLayoutParams(lp); return r;
    }
    private void applyObscuredTouchWarning(View v) {
        v.setOnTouchListener((view, event) -> {
            if ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
                    && event.getAction() == MotionEvent.ACTION_DOWN) {
                Toast.makeText(getContext(), R.string.obscured_touch_warning, Toast.LENGTH_SHORT).show();
            }
            return false;
        });
    }
    private void addInfo(String em, String label, String val) {
        LinearLayout r = row();
        TextView l = new TextView(getContext()); l.setText(em + "  " + label);
        l.setTextColor(color(R.color.text_primary)); l.setTypeface(Typeface.MONOSPACE);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(l);
        TextView v = new TextView(getContext()); v.setText(val);
        v.setTextColor(color(R.color.neon_green)); v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        r.addView(v); container.addView(r);
    }
    private void addToggle(String label, boolean state, CompoundButton.OnCheckedChangeListener cb) {
        LinearLayout r = row();
        TextView l = new TextView(getContext()); l.setText(label);
        l.setTextColor(color(R.color.text_primary)); l.setTypeface(Typeface.MONOSPACE);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(l);
        Switch sw = new Switch(getContext()); sw.setChecked(state);
        // Overlay warning instead of blocking — PiP windows (YouTube, etc.)
        // would otherwise make toggles unresponsive.
        applyObscuredTouchWarning(sw);
        sw.setOnCheckedChangeListener(guardedToggleListener(cb));
        r.addView(sw); container.addView(r);
    }

    /** Wraps a toggle's real listener with the rate-limit described above the
     *  RECENT_TOGGLE_* constants. Reverts (without re-invoking the real
     *  listener) and warns instead of applying the change when a burst is
     *  detected. */
    private CompoundButton.OnCheckedChangeListener guardedToggleListener(
            CompoundButton.OnCheckedChangeListener real) {
        return (btn, checked) -> {
            long now = System.currentTimeMillis();
            recentToggleTimes.addLast(now);
            while (!recentToggleTimes.isEmpty()
                    && now - recentToggleTimes.peekFirst() > RECENT_TOGGLE_WINDOW_MS) {
                recentToggleTimes.removeFirst();
            }
            if (recentToggleTimes.size() >= RECENT_TOGGLE_BURST) {
                recentToggleTimes.clear();
                btn.setOnCheckedChangeListener(null);
                btn.setChecked(!checked); // revert
                btn.setOnCheckedChangeListener(guardedToggleListener(real));
                Toast.makeText(getContext(), getString(R.string.settings_automation_blocked),
                    Toast.LENGTH_LONG).show();
                return;
            }
            real.onCheckedChanged(btn, checked);
        };
    }
    private void addThemeSelector(String currentLabel, View.OnClickListener cl) {
        LinearLayout r = row();
        TextView l = new TextView(getContext()); l.setText(getString(R.string.theme_mode_label));
        l.setTextColor(color(R.color.text_primary)); l.setTypeface(Typeface.MONOSPACE);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(l);
        TextView v = new TextView(getContext()); v.setText(currentLabel);
        v.setTextColor(color(R.color.neon_green)); v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        v.setPadding(16, 0, 0, 0);
        r.addView(v);
        r.setOnClickListener(cl);
        r.setClickable(true);
        r.setFocusable(true);
        applyObscuredTouchWarning(r);
        container.addView(r);
    }

    private void showThemeModeDialog() {
        String[] modes = {
            getString(R.string.theme_system),
            getString(R.string.theme_dark),
            getString(R.string.theme_light)
        };
        String[] values = {"system", "dark", "light"};
        String current = prefs().getString(KEY_THEME, "dark");
        int checked = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i].equals(current)) { checked = i; break; }
        }
        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.theme_mode_label))
            .setSingleChoiceItems(modes, checked, (dialog, which) -> {
                String chosen = values[which];
                prefs().edit().putString(KEY_THEME, chosen).apply();
                dialog.dismiss();
                int mode;
                switch (chosen) {
                    case "light":  mode = AppCompatDelegate.MODE_NIGHT_NO;  break;
                    case "system": mode = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM; break;
                    default:       mode = AppCompatDelegate.MODE_NIGHT_YES; break;
                }
                AppCompatDelegate.setDefaultNightMode(mode);
                if (getActivity() != null) {
                    getActivity().recreate();
                }
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    private void addBtn(String label, int bgColor, View.OnClickListener cl) {
        TextView b = new TextView(getContext()); b.setText(label);
        // Was hardcoded pure black regardless of theme — invisible on a dark
        // mode button whose background is bg_secondary (dark navy in night
        // mode). text_primary tracks day/night correctly (dark text on the
        // light backgrounds, light text on the dark ones).
        b.setTextColor(color(R.color.text_primary)); b.setBackgroundColor(bgColor);
        b.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        b.setPadding(32,28,32,28); b.setTextSize(14); b.setGravity(Gravity.CENTER);
        applyObscuredTouchWarning(b); // warn instead of blocking (PiP-friendly)
        b.setOnClickListener(cl);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = 12; b.setLayoutParams(lp); container.addView(b);
    }
    private void addAbout() {
        TextView v = new TextView(getContext());
        v.setText("HydraDragon Antivirus v" + com.hydradragon.antivirus.BuildConfig.VERSION_NAME
            + "\n━━━━━━━━━━━━━━━━━━━━━━\n\n" +
            "[ GELİŞTİRİCİLER ]\n\n  ◈  Musayev Yusif\n  ◈  Emirhan Uçan\n\n" +
            "━━━━━━━━━━━━━━━━━━━━━━\n" +
            "https://github.com/HydraDragonAntivirus/HydraDragonAV-Mobile");
        v.setTextColor(color(R.color.text_secondary));
        v.setTypeface(Typeface.MONOSPACE); v.setLineSpacing(6,1); v.setPadding(16,24,16,0);
        v.setAutoLinkMask(Linkify.WEB_URLS);
        v.setMovementMethod(LinkMovementMethod.getInstance());
        container.addView(v);
    }

    // Display name (native script) <-> BCP-47 tag, in the same order/set as the
    // 20 localized app/src/main/res/values-XX resource folders.
    private static final String[] LANGUAGE_NAMES = {
        "English", "Türkçe", "Español", "Deutsch", "Français", "Русский",
        "Português", "العربية", "Italiano", "Nederlands", "Polski", "Українська",
        "中文", "日本語", "한국어", "हिन्दी", "Bahasa Indonesia", "Tiếng Việt",
        "فارسی", "ไทย",
    };
    private static final String[] LANGUAGE_CODES = {
        "en", "tr", "es", "de", "fr", "ru",
        "pt", "ar", "it", "nl", "pl", "uk",
        "zh", "ja", "ko", "hi", "in", "vi",
        "fa", "th",
    };

    private void selectLanguage() {
        new android.app.AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.language_settings))
            .setItems(LANGUAGE_NAMES, (dialog, which) -> {
                String code = LANGUAGE_CODES[which];
                prefs().edit().putString("language", code).apply();
                // Per-app language override (AndroidX AppCompat) — this is what
                // actually switches the UI's resource-qualifier locale; the
                // previous version only saved the preference and restarted the
                // activity, which did nothing because no locale was ever applied.
                // AppCompat persists this across process restarts on its own.
                // "en" maps to the default locale (no override) so Android
                // resolves to values/strings.xml instead of values-en/.
                if ("en".equals(code)) {
                    AppCompatDelegate.setApplicationLocales(
                        androidx.core.os.LocaleListCompat.getEmptyLocaleList());
                } else {
                    AppCompatDelegate.setApplicationLocales(
                        androidx.core.os.LocaleListCompat.forLanguageTags(code));
                }
            }).show();
    }

    /** Lets the user configure how often GuardService's periodic background
     *  scans run (see ScanSchedule / GuardService#startPeriodicScans). Applies
     *  immediately by restarting GuardService, same as the storage-watch toggle. */
    private void showScanIntervalDialog() {
        LinearLayout box = new LinearLayout(requireContext());
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 24, 48, 0);

        TextView quickLabel = new TextView(requireContext());
        quickLabel.setText(getString(R.string.scan_interval_quick_label));
        quickLabel.setTextColor(color(R.color.text_primary));
        box.addView(quickLabel);
        android.widget.EditText quickInput = new android.widget.EditText(requireContext());
        quickInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        quickInput.setText(String.valueOf(
            com.hydradragon.antivirus.engine.ScanSchedule.getQuickScanIntervalMinutes(requireContext())));
        box.addView(quickInput);

        TextView fullLabel = new TextView(requireContext());
        fullLabel.setText(getString(R.string.scan_interval_full_label));
        fullLabel.setTextColor(color(R.color.text_primary));
        fullLabel.setPadding(0, 32, 0, 0);
        box.addView(fullLabel);
        android.widget.EditText fullInput = new android.widget.EditText(requireContext());
        fullInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        fullInput.setText(String.valueOf(
            com.hydradragon.antivirus.engine.ScanSchedule.getFullScanIntervalMinutes(requireContext())));
        box.addView(fullInput);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.scan_interval_btn))
            .setMessage(getString(R.string.scan_interval_hint,
                com.hydradragon.antivirus.engine.ScanSchedule.MIN_INTERVAL_MIN))
            .setView(box)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                int quick = parseMinutesOrDefault(quickInput.getText().toString(),
                    com.hydradragon.antivirus.engine.ScanSchedule.DEFAULT_QUICK_MIN);
                int full = parseMinutesOrDefault(fullInput.getText().toString(),
                    com.hydradragon.antivirus.engine.ScanSchedule.DEFAULT_FULL_MIN);
                com.hydradragon.antivirus.engine.ScanSchedule.setQuickScanIntervalMinutes(requireContext(), quick);
                com.hydradragon.antivirus.engine.ScanSchedule.setFullScanIntervalMinutes(requireContext(), full);
                // GuardService only reads these at startPeriodicScans() (onCreate)
                // — restart it so the new interval takes effect right away.
                Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.GuardService.class);
                requireContext().stopService(svc);
                ContextCompat.startForegroundService(requireContext(), svc);
                Toast.makeText(getContext(), getString(R.string.scan_interval_saved), Toast.LENGTH_SHORT).show();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    /** One row for a single DetectionCategories toggle — same on/off contract
     *  as every other category, just parameterized by string res + pref key.
     *  AUTO_RULES is special: it also gates what the NATIVE engine loads at
     *  init (see NativeScanner.init), so toggling it restarts GuardService —
     *  same pattern as the storage-watch toggle — instead of only taking
     *  effect on the next full app restart. */
    private void addCategoryToggle(int labelRes, String category) {
        boolean on = com.hydradragon.antivirus.engine.DetectionCategories.isEnabled(requireContext(), category);
        addToggle(getString(labelRes), on, (btn, checked) -> {
            com.hydradragon.antivirus.engine.DetectionCategories.setEnabled(requireContext(), category, checked);
            if (com.hydradragon.antivirus.engine.DetectionCategories.AUTO_RULES.equals(category)) {
                Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.GuardService.class);
                requireContext().stopService(svc);
                ContextCompat.startForegroundService(requireContext(), svc);
            }
        });
    }

    /** One row for a single BehaviorDetectionSettings toggle — a dynamic
     *  (runtime-behavior) detector, as opposed to addCategoryToggle's
     *  static scan-time engines. Turning one off is read by that detector's
     *  own entry point, so it's a genuine no-op, not just a silenced alert;
     *  see BehaviorDetectionSettings' javadoc for which detector each key
     *  maps to. */
    private void addBehaviorToggle(int labelRes, String key) {
        boolean on = com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(requireContext(), key);
        addToggle(getString(labelRes), on, (btn, checked) ->
            com.hydradragon.antivirus.engine.BehaviorDetectionSettings.setEnabled(requireContext(), key, checked));
    }

    private int parseMinutesOrDefault(String text, int def) {
        try {
            int v = Integer.parseInt(text.trim());
            return Math.max(com.hydradragon.antivirus.engine.ScanSchedule.MIN_INTERVAL_MIN, v);
        } catch (Exception e) {
            return def;
        }
    }

    /** TLSH similarity threshold for the Anti-FP cache (1-200, default 40).
     *  Lower = stricter (only very close matches are suppressed); higher =
     *  more aggressive (more similar-looking entries are treated as known-good). */
    /** TLSH similarity threshold for the Anti-FN cache and native scanner (1-200, default 40). */
    private void showAntiFnTlshThresholdDialog() {
        LinearLayout box = new LinearLayout(requireContext());
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 24, 48, 0);

        TextView label = new TextView(requireContext());
        label.setText(getString(R.string.anti_fn_tlsh_threshold_hint));
        label.setTextColor(color(R.color.text_primary));
        label.setPadding(0, 0, 0, 16);
        box.addView(label);
        android.widget.EditText input = new android.widget.EditText(requireContext());
        input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        input.setText(String.valueOf(prefs().getInt("anti_fn_tlsh_threshold", 30)));
        box.addView(input);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.anti_fn_tlsh_threshold_btn))
            .setView(box)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                int val;
                try {
                    val = Integer.parseInt(input.getText().toString().trim());
                } catch (Exception e) {
                    val = 40;
                }
                val = Math.max(1, Math.min(200, val));
                prefs().edit().putInt("anti_fn_tlsh_threshold", val).apply();
                com.hydradragon.antivirus.engine.NativeScanner.setTlshThreshold(val);
                Toast.makeText(getContext(),
                    getString(R.string.anti_fn_tlsh_threshold_saved, val),
                    Toast.LENGTH_SHORT).show();
                buildUI();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    /** Max-file-size-to-scan config (see MaxScanFileSize) — same
     *  EditText-in-AlertDialog pattern as showScanIntervalDialog(). Takes
     *  effect on the NEXT scan (each ScanEngine call site reads it live, no
     *  service restart needed, unlike the interval setting). */
    private void showMaxScanFileSizeDialog() {
        LinearLayout box = new LinearLayout(requireContext());
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 24, 48, 0);

        TextView label = new TextView(requireContext());
        label.setText(getString(R.string.max_scan_file_size_label));
        label.setTextColor(color(R.color.text_primary));
        box.addView(label);
        android.widget.EditText input = new android.widget.EditText(requireContext());
        input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        input.setText(String.valueOf(
            com.hydradragon.antivirus.engine.MaxScanFileSize.getMaxMb(requireContext())));
        box.addView(input);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.max_scan_file_size_btn))
            .setMessage(getString(R.string.max_scan_file_size_hint,
                com.hydradragon.antivirus.engine.MaxScanFileSize.MIN_MB,
                com.hydradragon.antivirus.engine.MaxScanFileSize.MAX_MB))
            .setView(box)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                int mb;
                try {
                    mb = Integer.parseInt(input.getText().toString().trim());
                } catch (Exception e) {
                    mb = com.hydradragon.antivirus.engine.MaxScanFileSize.DEFAULT_MB;
                }
                com.hydradragon.antivirus.engine.MaxScanFileSize.setMaxMb(requireContext(), mb);
                Toast.makeText(getContext(), getString(R.string.max_scan_file_size_saved), Toast.LENGTH_SHORT).show();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    /** Max-text-file-bytes-to-scan config (see MaxTextScanBytes) — same
     *  EditText-in-AlertDialog pattern as showMaxScanFileSizeDialog(). Takes
     *  effect on the NEXT scan (each ScanEngine call site reads it live, no
     *  service restart needed). */
    private void showMaxTextScanBytesDialog() {
        LinearLayout box = new LinearLayout(requireContext());
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 24, 48, 0);

        TextView label = new TextView(requireContext());
        label.setText(getString(R.string.max_text_scan_bytes_label));
        label.setTextColor(color(R.color.text_primary));
        box.addView(label);
        android.widget.EditText input = new android.widget.EditText(requireContext());
        input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        int curMb = com.hydradragon.antivirus.engine.MaxTextScanBytes.getMaxMb(requireContext());
        input.setText(String.valueOf(curMb));
        box.addView(input);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.max_text_scan_bytes_btn))
            .setMessage(getString(R.string.max_text_scan_bytes_hint,
                com.hydradragon.antivirus.engine.MaxTextScanBytes.MIN_MB,
                com.hydradragon.antivirus.engine.MaxTextScanBytes.MAX_MB))
            .setView(box)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                int mb;
                try {
                    mb = Integer.parseInt(input.getText().toString().trim());
                } catch (Exception e) {
                    mb = com.hydradragon.antivirus.engine.MaxTextScanBytes.DEFAULT_MB;
                }
                com.hydradragon.antivirus.engine.MaxTextScanBytes.setMaxMb(requireContext(), mb);
                com.hydradragon.antivirus.engine.NativeScanner.setMaxTextScanBytes(
                    com.hydradragon.antivirus.engine.MaxTextScanBytes.getMaxBytes(requireContext()));
                Toast.makeText(getContext(), getString(R.string.max_text_scan_bytes_saved), Toast.LENGTH_SHORT).show();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    private void showClearCacheDialog() {
        String[] items = {
            getString(R.string.cache_session),
            getString(R.string.cache_anti_fn),
        };
        boolean[] checked = {true, true};
        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.clear_scan_cache_btn))
            .setMultiChoiceItems(items, checked, (d, which, isChecked) -> checked[which] = isChecked)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                boolean any = false;
                if (checked[0]) {
                    com.hydradragon.antivirus.engine.ScanEngine.clearCache();
                    any = true;
                }
                if (checked[1]) {
                    try { new com.hydradragon.antivirus.engine.AntiFnCache(requireContext()).clear(); }
                    catch (Exception ignore) {}
                    any = true;
                }
                if (any) Toast.makeText(getContext(), getString(R.string.cache_cleared), Toast.LENGTH_SHORT).show();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    /** Lists every self-learned "generated_rules/*.yar" file (see
     *  ScanEngine#saveGeneratedRule) this device has ever auto-produced from a
     *  confirmed detection — same directory the native engine reloads at
     *  every init (NativeScanner.init / DetectionCategories.AUTO_RULES).
     *  Each row: tap to view the raw YARA source, ✎ to export it via SAF
     *  (Storage Access Framework — user picks the destination), ✕ to delete
     *  it from disk (also means the native engine stops matching it on the
     *  NEXT init/restart, not retroactively for the current session). */
    private void showAutoRulesManagerDialog() {
        java.io.File dir = new java.io.File(new java.io.File(requireContext().getFilesDir(), "hydra-scan"), "generated_rules");
        java.io.File[] files = dir.exists() ? dir.listFiles((d, name) -> name.endsWith(".yar")) : null;
        java.util.List<java.io.File> rules = new java.util.ArrayList<>();
        if (files != null) rules.addAll(java.util.Arrays.asList(files));
        rules.sort((a, b) -> b.lastModified() > a.lastModified() ? 1 : -1);

        LinearLayout listBox = new LinearLayout(requireContext());
        listBox.setOrientation(LinearLayout.VERTICAL);

        AlertDialog dlg = new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.auto_rules_manager_btn))
            .setView(listBox)
            .setNegativeButton(getString(R.string.btn_close), null)
            .create();

        Runnable[] refresh = new Runnable[1];
        refresh[0] = () -> {
            listBox.removeAllViews();
            if (rules.isEmpty()) {
                TextView empty = new TextView(requireContext());
                empty.setText(getString(R.string.auto_rules_empty));
                empty.setTextColor(color(R.color.text_secondary));
                empty.setPadding(0, 16, 0, 16);
                listBox.addView(empty);
            }
            for (java.io.File f : rules) {
                LinearLayout r = row();
                TextView name = new TextView(requireContext());
                name.setText(f.getName());
                name.setTextColor(color(R.color.text_primary));
                name.setTypeface(Typeface.MONOSPACE);
                name.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
                name.setOnClickListener(v -> showAutoRuleContentDialog(f));
                r.addView(name);

                TextView exportBtn = new TextView(requireContext());
                exportBtn.setText("⭳");
                exportBtn.setTextColor(color(R.color.neon_cyan));
                exportBtn.setPadding(24, 0, 24, 0);
                exportBtn.setOnClickListener(v -> {
                    pendingExportRuleFile = f;
                    exportRuleLauncher.launch(f.getName());
                });
                r.addView(exportBtn);

                TextView deleteBtn = new TextView(requireContext());
                deleteBtn.setText("✕");
                deleteBtn.setTextColor(0xFFFF0040);
                deleteBtn.setPadding(0, 0, 8, 0);
                deleteBtn.setOnClickListener(v -> {
                    if (f.delete()) {
                        rules.remove(f);
                        refresh[0].run();
                    } else {
                        Toast.makeText(getContext(), getString(R.string.auto_rule_delete_failed), Toast.LENGTH_SHORT).show();
                    }
                });
                r.addView(deleteBtn);
                listBox.addView(r);
            }
        };
        refresh[0].run();
        dlg.show();
    }

    /** Read-only view of one .yar file's raw source — tapped from the Auto
     *  Rules manager list. */
    private void showAutoRuleContentDialog(java.io.File file) {
        String content;
        try {
            content = new String(java.nio.file.Files.readAllBytes(file.toPath()), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            content = getString(R.string.auto_rule_read_failed);
        }
        TextView tv = new TextView(requireContext());
        tv.setText(content);
        tv.setTextColor(color(R.color.text_primary));
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        tv.setPadding(24, 16, 24, 16);
        ScrollView scroll = new ScrollView(requireContext());
        scroll.addView(tv);
        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(file.getName())
            .setView(scroll)
            .setPositiveButton(getString(R.string.btn_close), null)
            .show();
    }

    private void exportKnowledgeDatabase() {
        knowledgeExportLauncher.launch("hydradragon_knowledge_db.json");
    }

    private void importKnowledgeDatabase() {
        knowledgeImportLauncher.launch("application/json");
    }

    /** Generic "type to add / tap to remove" manager, shared by Ignored
     *  Signatures and Website Whitelist — both are just a small user-edited
     *  string set with an add(Context,String) + remove(Context,String) API. */
    private void showManagedListDialog(String title, String hint, java.util.List<String> current,
                                        java.util.function.BiConsumer<Context, String> adder,
                                        java.util.function.BiConsumer<Context, String> remover) {
        LinearLayout box = new LinearLayout(requireContext());
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(48, 8, 48, 0);

        TextView hintView = new TextView(requireContext());
        hintView.setText(hint);
        hintView.setTextColor(color(R.color.text_secondary));
        hintView.setTextSize(12);
        hintView.setPadding(0, 0, 0, 16);
        box.addView(hintView);

        LinearLayout listBox = new LinearLayout(requireContext());
        listBox.setOrientation(LinearLayout.VERTICAL);
        box.addView(listBox);

        android.widget.EditText input = new android.widget.EditText(requireContext());
        input.setHint(title);
        box.addView(input);

        AlertDialog dlg = new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(title)
            .setView(box)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                String v = input.getText().toString().trim();
                if (!v.isEmpty()) adder.accept(requireContext(), v);
            })
            .setNegativeButton(getString(R.string.btn_close), null)
            .create();

        Runnable[] refresh = new Runnable[1];
        refresh[0] = () -> {
            listBox.removeAllViews();
            java.util.List<String> items = current;
            for (String item : items) {
                LinearLayout r = new LinearLayout(requireContext());
                r.setOrientation(LinearLayout.HORIZONTAL);
                r.setGravity(Gravity.CENTER_VERTICAL);
                TextView t = new TextView(requireContext());
                t.setText(item);
                t.setTextColor(color(R.color.text_primary));
                t.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
                r.addView(t);
                TextView removeBtn = new TextView(requireContext());
                removeBtn.setText("✕");
                removeBtn.setTextColor(0xFFFF0040);
                removeBtn.setPadding(24, 0, 8, 0);
                removeBtn.setOnClickListener(rv -> {
                    remover.accept(requireContext(), item);
                    items.remove(item);
                    refresh[0].run();
                });
                r.addView(removeBtn);
                listBox.addView(r);
            }
        };
        refresh[0].run();
        dlg.show();

        // Re-add immediately re-renders the list without closing the dialog —
        // override the positive button's default (dismissing) click after show().
        dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String val = input.getText().toString().trim();
            if (!val.isEmpty()) {
                adder.accept(requireContext(), val);
                current.add(val);
                input.setText("");
                refresh[0].run();
            }
        });
    }

}
