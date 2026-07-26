package com.hydradragon.antivirus;

import android.content.ComponentName;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.bottomnavigation.BottomNavigationView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.ui.DashboardFragment;
import com.hydradragon.antivirus.ui.NetworkFragment;
import com.hydradragon.antivirus.ui.ScanFragment;
import com.hydradragon.antivirus.ui.SettingsFragment;
import com.hydradragon.antivirus.ui.ThreatLogFragment;

public class MainActivity extends AppCompatActivity {

    private static final int REQ_VPN = 102;
    private static final int REQ_OVERLAY = 103;

    private com.hydradragon.antivirus.security.StrandHoggGuard strandHoggGuard;
    private com.hydradragon.antivirus.security.SecureWindowGuard windowGuard;
    private BottomNavigationView bottomNav;
    // checkMandatoryPermissions() can be re-entered from more than one
    // lifecycle path in quick succession — onResume() (fired whenever a
    // system permission/settings screen closes and this Activity resumes)
    // AND onRequestPermissionsResult()/onActivityResult() (fired for the same
    // event) both call it. Without this guard, each re-entry created a BRAND
    // NEW AlertDialog for the same still-pending permission, stacking
    // duplicates — the user saw the same permission asked several times in a
    // row even though they'd already answered it once.
    private boolean permissionDialogShowing = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        String theme = prefs.getString("theme_mode", null);
        if (theme == null) {
            // Migrate from old boolean preference
            boolean dark = prefs.getBoolean("dark_mode", true);
            theme = dark ? "dark" : "light";
            prefs.edit().putString("theme_mode", theme).apply();
        }
        switch (theme) {
            case "light":  AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);  break;
            case "system": AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM); break;
            default:       AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES); break;
        }

        // FLAG_SECURE (screenshot/screen-recording + Recents-thumbnail block)
        // must be set before super.onCreate()/setContentView() — scan results,
        // threat details and network activity shown in this app are sensitive.
        // Check the user's "Allow screen recording" toggle first — when ON,
        // FLAG_SECURE is intentionally omitted regardless of SCREEN_SECURITY.
        windowGuard = new com.hydradragon.antivirus.security.SecureWindowGuard(this);
        boolean disableSecure = getSharedPreferences("hydra_prefs", 0)
            .getBoolean("disable_secure_flag", true);
        if (!disableSecure && com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCREEN_SECURITY)) {
            windowGuard.applyFlagSecure();
        }

        super.onCreate(savedInstanceState);

        com.hydradragon.antivirus.engine.AppLifecycleTracker.register(getApplication());
        // Fire the native engine init as early as possible: the ~70s ClamAV/YARA
        // load runs in a background thread so it's ready before the first scan
        // hits ScanEngine (which also calls init — it's idempotent).
        com.hydradragon.antivirus.engine.NativeScanner.init(this);
        strandHoggGuard = new com.hydradragon.antivirus.security.StrandHoggGuard(this);

        // Refuse to run a repackaged/re-signed copy of this APK (see
        // IntegrityCheck — signing certificate no longer matches the one this
        // build was compiled with).
        if (com.hydradragon.antivirus.engine.IntegrityCheck.isTampered(this)) {
            new AlertDialog.Builder(this)
                .setTitle(R.string.integrity_blocked_title)
                .setMessage(R.string.integrity_blocked_msg)
                .setCancelable(false)
                .setPositiveButton(R.string.integrity_blocked_exit, (d, w) -> finish())
                .setOnDismissListener(d -> finish())
                .show();
            return;
        }

        // The app warns on rooted devices but lets the user continue if they
        // understand the risks — the antivirus does not support root-level
        // features and ADB is not supported for production use.
        if (com.hydradragon.antivirus.engine.RootCheck.isRooted()) {
            if (com.hydradragon.antivirus.engine.RootWarning.isEnabled(this)) {
                new AlertDialog.Builder(this)
                    .setTitle(R.string.root_warning_title)
                    .setMessage(R.string.root_warning_msg)
                    .setCancelable(false)
                    .setPositiveButton(R.string.root_warning_continue, null)
                    .setNegativeButton(R.string.root_warning_exit, (d, w) -> finish())
                    .setNeutralButton(R.string.root_warning_dont_ask, (d, w) ->
                        com.hydradragon.antivirus.engine.RootWarning.setEnabled(this, false))
                    .show();
            }
            // If the warning has been previously dismissed (isEnabled == false),
            // or the user clicked "Continue" / "Don't ask again", proceed normally.
        }

        setContentView(R.layout.activity_main);

        // Version shown in the header always tracks BuildConfig (build.gradle
        // versionName) — never hardcode it in strings.xml again, it silently
        // goes stale every release (was stuck at "v1.0.3" for several bumps).
        TextView tvAppTitle = findViewById(R.id.tv_app_title);
        if (tvAppTitle != null) {
            tvAppTitle.setText(getString(R.string.app_title, BuildConfig.VERSION_NAME));
        }

        // USB/wireless debugging is a real attack surface (another device can
        // push input, pull app data, sideload) but common for developers, so
        // this WARNS instead of blocking launch like root/tampering do above.
        if (com.hydradragon.antivirus.engine.DebugModeWarning.isEnabled(this)
                && com.hydradragon.antivirus.engine.DebugModeCheck.isEnabled(this)) {
            new AlertDialog.Builder(this)
                .setTitle(R.string.debug_mode_warning_title)
                .setMessage(R.string.debug_mode_warning_msg)
                .setCancelable(true)
                .setPositiveButton(R.string.debug_mode_warning_open_settings, (d, w) ->
                    startActivity(new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)))
                .setNegativeButton(R.string.debug_mode_warning_dont_ask, (d, w) ->
                    com.hydradragon.antivirus.engine.DebugModeWarning.setEnabled(this, false))
                .setNeutralButton(R.string.btn_close, null)
                .show();
        }

        bottomNav = findViewById(R.id.bottom_navigation);

        overridePendingTransition(R.anim.theme_fade_in, 0);

        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                .putInt("last_nav_item", id).apply();
            if (id == R.id.nav_dashboard) {
                showFragment(new DashboardFragment());
                return true;
            } else if (id == R.id.nav_scan) {
                showFragment(new ScanFragment());
                return true;
            } else if (id == R.id.nav_network) {
                showFragment(new NetworkFragment());
                return true;
            } else if (id == R.id.nav_threats) {
                showFragment(new ThreatLogFragment());
                return true;
            } else if (id == R.id.nav_settings) {
                showFragment(new SettingsFragment());
                return true;
            }
            return false;
        });

        // UI gizle
        findViewById(R.id.content_frame).setVisibility(View.GONE);
        bottomNav.setVisibility(View.GONE);

        // Only auto-start the guard if the user hasn't paused protection.
        if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(this)) {
            ContextCompat.startForegroundService(this, new Intent(this, com.hydradragon.antivirus.service.GuardService.class));
        }

        // Biometric prompt removed — go straight to permission checks
        checkMandatoryPermissions();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.TASK_HIJACK)) {
            strandHoggGuard.startWatching(this::onTaskHijackDetected, 1500);
        }
        if (com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCREEN_SECURITY)) {
            windowGuard.startWatching(this::onSecureFlagLost, 2000);
        }
        if (findViewById(R.id.content_frame).getVisibility() != View.VISIBLE) {
            checkMandatoryPermissions();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        strandHoggGuard.stopWatching();
        windowGuard.stopWatching();
    }

    // Overriding every startActivity/startActivityForResult entry point (this
    // catches Fragment.startActivity() too — it delegates to the host
    // Activity's own methods) closes a real race: our own navigation calls
    // (Accessibility Settings, Play Protect, Developer Options, VPN/screen-
    // capture consent...) return immediately, but onPause() — which stops
    // the watchers above — only fires once Android actually processes the
    // activity transition a moment later. If a watcher's already-scheduled
    // tick lands in that gap, it sees the system screen we JUST launched
    // sitting in our own task (bumping its activity count) while our own
    // createdCount never incremented for it (ActivityLifecycleCallbacks only
    // ever fires for OUR OWN activities) — a guaranteed false "task hijack"
    // that kicked the user straight out of the app. Stopping both watchers
    // before every intentional navigation removes that window entirely;
    // onResume() restarts them once we're actually back.
    @Override
    public void startActivity(Intent intent) {
        stopSecurityWatchers();
        super.startActivity(intent);
    }

    @Override
    public void startActivity(Intent intent, android.os.Bundle options) {
        stopSecurityWatchers();
        super.startActivity(intent, options);
    }

    @Override
    public void startActivityForResult(Intent intent, int requestCode) {
        stopSecurityWatchers();
        super.startActivityForResult(intent, requestCode);
    }

    @Override
    public void startActivityForResult(Intent intent, int requestCode, android.os.Bundle options) {
        stopSecurityWatchers();
        super.startActivityForResult(intent, requestCode, options);
    }

    private void stopSecurityWatchers() {
        if (strandHoggGuard != null) strandHoggGuard.stopWatching();
        if (windowGuard != null) windowGuard.stopWatching();
    }

    @Override
    public void onConfigurationChanged(@NonNull Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        overridePendingTransition(R.anim.theme_fade_in, R.anim.theme_fade_out);
    }

    /** See StrandHoggGuard's javadoc — something other than HydraDragon itself
     *  is present in this activity's task. Fail closed: don't keep showing
     *  the app's UI once this is possible. */
    private void onTaskHijackDetected(int expected, int actual) {
        android.util.Log.e("HydraDragon-MainActivity", "Task hijack suspected: expected "
            + expected + " activities in our task, found " + actual);
        Toast.makeText(this, getString(R.string.task_hijack_detected), Toast.LENGTH_LONG).show();
        finishAndRemoveTask();
    }

    /** See SecureWindowGuard's javadoc — a runtime hook stripped FLAG_SECURE
     *  from our own window after we set it. Fail closed the same way. */
    private void onSecureFlagLost() {
        android.util.Log.e("HydraDragon-MainActivity", "FLAG_SECURE lost on live window");
        Toast.makeText(this, getString(R.string.security_flag_lost), Toast.LENGTH_LONG).show();
        finishAndRemoveTask();
    }

    private void checkMandatoryPermissions() {
        // Already have a dialog up from a previous (overlapping) call — don't
        // stack a duplicate on top of it. It clears itself (see
        // showMandatoryPermissionDialog / showOptionalAccessibilityDialog /
        // showOptionalPlayProtectDialog / showOptionalWebShieldDialog) once
        // the user answers, and the SAME re-entrant call that would have
        // fired again gets a fresh chance next lifecycle event anyway.
        if (permissionDialogShowing) return;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            showMandatoryPermissionDialog(
                getString(R.string.all_files_access_title),
                getString(R.string.all_files_access_msg),
                new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + getPackageName()))
            );
            return;
        }

        // POST_NOTIFICATIONS is optional (not blocking) — user can enable via
        // Settings > Notifications or turn on Silent Mode to skip entirely.
        SharedPreferences notifPrefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && !notifPrefs.getBoolean("notifications_decided", false)
                && !notifPrefs.getBoolean("silent_mode", false)) {
            notifPrefs.edit().putBoolean("notifications_decided", true).apply();
            ActivityCompat.requestPermissions(this, new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 101);
            // Don't return — non-blocking, continue the startup flow
        }

        // SMS virus/scam detection (SmsReceiver) is opt-in from Settings, not
        // asked here at launch — see SettingsFragment's SMS scan toggle.

        SharedPreferences accessibilityPrefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        if (!isAccessibilityServiceEnabled() && !accessibilityPrefs.getBoolean("accessibility_decided", false)) {
            showOptionalAccessibilityDialog();
            return;
        }

        // Google Play Protect works alongside (not instead of) HydraDragon — it
        // vets apps at install time via Google's server-side scan. If the user
        // turned it off we recommend re-enabling it, but never block on it.
        if (!isPlayProtectEnabled()) {
            showOptionalPlayProtectDialog();
            return;
        }

        // Self-Protection (Device Admin) — see SelfProtection. Asked once at
        // first launch, same "decided" pattern as Web Shield below, instead
        // of only being reachable if the user happens to find it in Settings
        // (it existed in the codebase but was never surfaced anywhere before).
        SharedPreferences selfProtPrefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        if (!selfProtPrefs.getBoolean("self_protection_decided", false)) {
            showOptionalSelfProtectionDialog();
            return;
        }

        // Draw Over Other Apps (overlay) — optional, asked once at first launch.
        // Without this permission, the MalwareFoundActivity dialog overlay won't
        // show when the user is in another app; the alert still arrives as a
        // notification instead. MUST be checked BEFORE Web Shield, because both
        // Web Shield buttons (Skip / Grant) bypass checkMandatoryPermissions()
        // and go straight to startAppUI().
        SharedPreferences prefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !android.provider.Settings.canDrawOverlays(this)) {
            if (!prefs.getBoolean("overlay_decided", false)) {
                showOptionalOverlayDialog();
                return;
            }
        }

        // Optional local DNS-filtering VPN (Web Shield). The system VPN/key icon
        // only appears once VpnService.prepare() consent is granted AND the
        // service establishes the tunnel — so we must request consent here.
        if (!prefs.getBoolean("web_shield_decided", false)) {
            showOptionalWebShieldDialog();
            return;
        }
        if (prefs.getBoolean("web_shield_enabled", false)) {
            startWebShield();   // re-arms the tunnel; drives startAppUI()
            return;
        }

        startAppUI();
    }

    private void showOptionalSelfProtectionDialog() {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.self_protection_dialog_title))
            .setMessage(getString(R.string.self_protection_dialog_msg))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.enable), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("self_protection_decided", true).apply();
                startActivity(com.hydradragon.antivirus.engine.SelfProtection.activationIntent(this));
            })
            .setNegativeButton(getString(R.string.skip), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("self_protection_decided", true).apply();
                checkMandatoryPermissions();
            })
            .show();
    }

    private void showOptionalWebShieldDialog() {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.web_shield_vpn_title))
            .setMessage(getString(R.string.web_shield_vpn_msg))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.enable), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("web_shield_decided", true)
                    .putBoolean("web_shield_enabled", true).apply();
                startWebShield();
            })
            .setNegativeButton(getString(R.string.skip), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("web_shield_decided", true)
                    .putBoolean("web_shield_enabled", false).apply();
                checkMandatoryPermissions();
            })
            .show();
    }

    private void showOptionalOverlayDialog() {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.overlay_request_title))
            .setMessage(getString(R.string.overlay_request_msg))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.btn_grant_now), (dialog, which) -> {
                permissionDialogShowing = false;
                Intent intent = new Intent(android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
                startActivityForResult(intent, REQ_OVERLAY);
            })
            .setNegativeButton(getString(R.string.skip), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("overlay_decided", true).apply();
                checkMandatoryPermissions();
            })
            .show();
    }

    /** Request VPN consent if needed, then start the service. */
    private void startWebShield() {
        Intent prep;
        try {
            prep = VpnService.prepare(this);
        } catch (Throwable t) {
            // Some devices/another always-on VPN can throw — degrade gracefully.
            Toast.makeText(this, getString(R.string.vpn_unavailable), Toast.LENGTH_LONG).show();
            getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                .putBoolean("web_shield_enabled", false).apply();
            startAppUIIfHidden();
            return;
        }
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);   // consent dialog -> onActivityResult
        } else {
            onVpnReady();                            // already authorised
        }
    }

    private void onVpnReady() {
        ContextCompat.startForegroundService(this,
            new Intent(this, com.hydradragon.antivirus.service.DnsVpnService.class));
        startAppUIIfHidden();
    }

    private void startAppUIIfHidden() {
        if (findViewById(R.id.content_frame).getVisibility() != View.VISIBLE) {
            startAppUI();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                onVpnReady();
            } else {
                // User declined consent — remember it, don't nag every launch.
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("web_shield_enabled", false).apply();
                startAppUIIfHidden();
            }
        } else if (requestCode == REQ_OVERLAY) {
            getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                .putBoolean("overlay_decided", true).apply();
            String toastMsg = android.provider.Settings.canDrawOverlays(this)
                ? getString(R.string.overlay_granted_toast)
                : getString(R.string.draw_overlay_off_toast);
            Toast.makeText(this, toastMsg, Toast.LENGTH_LONG).show();
            checkMandatoryPermissions();
        }
    }

    private void showMandatoryPermissionDialog(String title, String message, Intent intent) {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message + getString(R.string.mandatory_permission_suffix))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.btn_grant_now), (dialog, which) -> {
                permissionDialogShowing = false;
                startActivity(intent);
            })
            .setNegativeButton(getString(R.string.btn_exit_app), (dialog, which) -> finish())
            .show();
    }

    private void showOptionalAccessibilityDialog() {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.accessibility_optional_title))
            .setMessage(getString(R.string.accessibility_optional_msg))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.btn_grant_now), (dialog, which) -> {
                permissionDialogShowing = false;
                startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS));
            })
            .setNegativeButton(getString(R.string.skip), (dialog, which) -> {
                permissionDialogShowing = false;
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("accessibility_decided", true).apply();
                checkMandatoryPermissions();
            })
            .show();
    }

    private void startAppUI() {
        findViewById(R.id.content_frame).setVisibility(View.VISIBLE);
        bottomNav.setVisibility(View.VISIBLE);
        int lastNav = getSharedPreferences("hydra_prefs", MODE_PRIVATE)
            .getInt("last_nav_item", R.id.nav_dashboard);
        if (getIntent() != null && getIntent().getBooleanExtra("open_scan_tab", false)) {
            lastNav = R.id.nav_scan;
        }
        bottomNav.setSelectedItemId(lastNav);
        Fragment f;
        if (lastNav == R.id.nav_scan) f = new ScanFragment();
        else if (lastNav == R.id.nav_network) f = new NetworkFragment();
        else if (lastNav == R.id.nav_threats) f = new ThreatLogFragment();
        else if (lastNav == R.id.nav_settings) f = new SettingsFragment();
        else f = new DashboardFragment();
        showFragment(f);
        checkAndShowThreatDialog(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent != null && intent.getBooleanExtra("open_scan_tab", false)) {
            if (bottomNav != null) {
                bottomNav.setSelectedItemId(R.id.nav_scan);
            }
        }
        checkAndShowThreatDialog(intent);
    }

    private void checkAndShowThreatDialog(Intent intent) {
        if (intent == null || !intent.hasExtra("alert_threat_name")) return;
        String name = intent.getStringExtra("alert_threat_name");
        String pkg = intent.getStringExtra("alert_threat_pkg");
        String reason = intent.getStringExtra("alert_threat_reason");
        int risk = intent.getIntExtra("alert_threat_risk", 0);
        boolean isFile = intent.getBooleanExtra("alert_threat_is_file", false);
        String path = intent.getStringExtra("alert_threat_path");

        if (name == null || name.isEmpty()) name = pkg != null ? pkg : "Malware";
        if (reason == null) reason = "-";

        final String finalPkg = pkg;
        final String finalPath = path;

        new AlertDialog.Builder(this)
            .setTitle("⚠️ " + getString(R.string.malware_found_heading))
            .setMessage(name + "\n\n" + getString(R.string.malware_found_risk_score, risk)
                    + "\nReason: " + reason)
            .setCancelable(false)
            .setPositiveButton(isFile ? R.string.btn_delete_file : R.string.btn_uninstall, (d, w) -> {
                if (isFile) {
                    if (finalPath != null && !finalPath.isEmpty()) {
                        java.io.File f = new java.io.File(finalPath);
                        if (f.exists()) f.delete();
                    }
                } else {
                    if (finalPkg != null && !finalPkg.isEmpty()) {
                        Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + finalPkg));
                        del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        startActivity(del);
                    }
                }
            })
            .setNegativeButton(R.string.btn_dismiss, null)
            .show();

        intent.removeExtra("alert_threat_name");
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 101) {
            permissionDialogShowing = false;
            getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                .putBoolean("notifications_decided", true).apply();
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                checkMandatoryPermissions();
            } else {
                Toast.makeText(this, getString(R.string.notification_permission_required), Toast.LENGTH_LONG).show();
                checkMandatoryPermissions();
            }
        }
    }

    /**
     * Google Play Protect's on/off state isn't exposed by any public API — this
     * reads the same {@code package_verifier_user_consent} Settings.Global key
     * the Play Store's own Play Protect toggle writes to (1 = enabled/consented,
     * -1 = disabled; other/missing values are treated as enabled so we never
     * nag a device where the key doesn't apply, e.g. no Play Services).
     */
    private boolean isPlayProtectEnabled() {
        int consent = Settings.Global.getInt(getContentResolver(), "package_verifier_user_consent", 1);
        return consent != -1;
    }

    private void showOptionalPlayProtectDialog() {
        permissionDialogShowing = true;
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.play_protect_off_title))
            .setMessage(getString(R.string.play_protect_off_msg))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.enable), (dialog, which) -> {
                permissionDialogShowing = false;
                openPlayProtectSettings();
                // Don't call startAppUI() — onResume will re-enter
                // checkMandatoryPermissions() for the remaining dialog chain.
            })
            .setNegativeButton(getString(R.string.skip), (dialog, which) -> {
                permissionDialogShowing = false;
                checkMandatoryPermissions();
            })
            .show();
    }

    private void openPlayProtectSettings() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("market://settings/play_protect"))
                .setPackage("com.android.vending"));
        } catch (Throwable t) {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/settings/play_protect")));
            } catch (Throwable t2) {
                Toast.makeText(this, getString(R.string.play_protect_open_failed), Toast.LENGTH_LONG).show();
            }
        }
    }

    private boolean isAccessibilityServiceEnabled() {
        ComponentName expectedComponentName = new ComponentName(this, com.hydradragon.antivirus.service.DynamicAnalysisService.class);
        String enabledServicesSetting = Settings.Secure.getString(getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        if (enabledServicesSetting == null) return false;
        TextUtils.SimpleStringSplitter colonSplitter = new TextUtils.SimpleStringSplitter(':');
        colonSplitter.setString(enabledServicesSetting);
        while (colonSplitter.hasNext()) {
            String componentNameString = colonSplitter.next();
            ComponentName enabledService = ComponentName.unflattenFromString(componentNameString);
            if (enabledService != null && enabledService.equals(expectedComponentName)) return true;
        }
        return false;
    }

    public void showFragment(Fragment fragment) {
        getSupportFragmentManager()
            .beginTransaction()
            .replace(R.id.content_frame, fragment)
            .commit();
    }
}