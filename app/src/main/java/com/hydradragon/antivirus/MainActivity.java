package com.hydradragon.antivirus;

import android.content.ComponentName;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
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

    private BottomNavigationView bottomNav;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        boolean dark = prefs.getBoolean("dark_mode", true);
        AppCompatDelegate.setDefaultNightMode(dark ? AppCompatDelegate.MODE_NIGHT_YES : AppCompatDelegate.MODE_NIGHT_NO);

        super.onCreate(savedInstanceState);

        // The app refuses to run on rooted devices (and so never scans/false-flags
        // system files).
        if (com.hydradragon.antivirus.engine.RootCheck.isRooted()) {
            new AlertDialog.Builder(this)
                .setTitle(R.string.root_blocked_title)
                .setMessage(R.string.root_blocked_msg)
                .setCancelable(false)
                .setPositiveButton(R.string.root_blocked_exit, (d, w) -> finish())
                .setOnDismissListener(d -> finish())
                .show();
            return;
        }

        setContentView(R.layout.activity_main);

        bottomNav = findViewById(R.id.bottom_navigation);

        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
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

        // Biyometrik kaldırıldı, direkt izinlere geç
        checkMandatoryPermissions();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (findViewById(R.id.content_frame).getVisibility() != View.VISIBLE) {
            checkMandatoryPermissions();
        }
    }

    private void checkMandatoryPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            showMandatoryPermissionDialog(
                "All Files Access Required", 
                "HydraDragon needs full file access to scan for malware.", 
                new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + getPackageName()))
            );
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 101);
            return;
        }

        if (!isAccessibilityServiceEnabled()) {
            showOptionalAccessibilityDialog();
            return;
        }

        // Optional local DNS-filtering VPN (Web Shield). The system VPN/key icon
        // only appears once VpnService.prepare() consent is granted AND the
        // service establishes the tunnel — so we must request consent here.
        SharedPreferences prefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
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

    private void showOptionalWebShieldDialog() {
        new AlertDialog.Builder(this)
            .setTitle("Web Shield (VPN)")
            .setMessage("HydraDragon can run a LOCAL DNS-filtering VPN to block malicious / phishing sites. "
                + "It does NOT proxy, decrypt or inspect your traffic — only DNS lookups are filtered, on-device. "
                + "Android shows a key icon while it's active.")
            .setCancelable(false)
            .setPositiveButton("Enable", (dialog, which) -> {
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("web_shield_decided", true)
                    .putBoolean("web_shield_enabled", true).apply();
                startWebShield();
            })
            .setNegativeButton("Skip", (dialog, which) -> {
                getSharedPreferences("hydra_prefs", MODE_PRIVATE).edit()
                    .putBoolean("web_shield_decided", true)
                    .putBoolean("web_shield_enabled", false).apply();
                startAppUI();
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
            Toast.makeText(this, "VPN unavailable on this device", Toast.LENGTH_LONG).show();
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
        }
    }

    private void showMandatoryPermissionDialog(String title, String message, Intent intent) {
        new AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message + "\n\nIf you don't grant this permission, the app will close.")
            .setCancelable(false)
            .setPositiveButton("Grant Now", (dialog, which) -> startActivity(intent))
            .setNegativeButton("Exit App", (dialog, which) -> finish())
            .show();
    }

    private void showOptionalAccessibilityDialog() {
        new AlertDialog.Builder(this)
            .setTitle("Accessibility Service (Optional)")
            .setMessage("HydraDragon Dynamic Behavior Analysis needs Accessibility Service to actively monitor apps and stop ransomware in real-time.\n\nHowever, some devices restrict this. You can skip this if your device doesn't allow it, but Advanced Dynamic Protection will be disabled.")
            .setCancelable(false)
            .setPositiveButton("Grant Now", (dialog, which) -> startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)))
            .setNegativeButton("Skip", (dialog, which) -> startAppUI())
            .show();
    }

    private void startAppUI() {
        findViewById(R.id.content_frame).setVisibility(View.VISIBLE);
        bottomNav.setVisibility(View.VISIBLE);
        showFragment(new DashboardFragment());
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 101) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                checkMandatoryPermissions(); 
            } else {
                Toast.makeText(this, "Notification permission is required!", Toast.LENGTH_LONG).show();
                finish();
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

    private void showFragment(Fragment fragment) {
        getSupportFragmentManager()
            .beginTransaction()
            .replace(R.id.content_frame, fragment)
            .commit();
    }
}