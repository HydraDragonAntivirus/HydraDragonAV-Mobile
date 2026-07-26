package com.hydradragon.antivirus.ui;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.adapter.ThreatAdapter;
import com.hydradragon.antivirus.model.ScanResult;
import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.service.GuardService;
import com.hydradragon.antivirus.service.ThreatLogger;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ScanFragment extends Fragment {

    private Button btnScan;
    private Button btnPauseResume;
    private ProgressBar progressBar;
    private TextView tvProgress, tvCurrentApp, tvScanStatus, tvScanned, tvThreats, tvActiveThreats, tvThreatLabel, tvEngineWarning;
    private ImageView ivScannerIcon;
    private RecyclerView rvThreats;

    private GuardService guardService;
    private boolean serviceBound = false;
    private android.net.Uri pendingCustomScanUri = null;
    private String pendingUninstallPkg = null;
    private File pendingCustomScanDir = null;

    // STATIC MEMORY: survives switching between tabs — this data stays put.
    private static boolean isScanning = false;
    private static boolean hasScanned = false;
    private static String lastScanStatus = null;
    private static int lastScannedCount = 0;
    private static List<ThreatResult> foundThreats = new ArrayList<>();
    private static int hiddenThreatCount = 0;
    // Latest onProgress() values — restored in onViewCreated so switching away
    // from this tab mid-scan and back doesn't show a stale/blank progress bar
    // until the NEXT progress tick happens to arrive (could be a noticeable
    // delay, looked like the scan was "broken" until it moved to another file).
    private static int lastProgressCurrent = 0;
    private static int lastProgressTotal = 0;
    private static String lastProgressName = "";

    private static final String TAG = "HydraDragon-Scan";

    private static final int MAX_DISPLAYED_THREATS = 50;

    private ThreatAdapter threatAdapter;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(android.content.ComponentName name, android.os.IBinder service) {
            guardService = ((com.hydradragon.antivirus.service.GuardService.GuardBinder) service).getService();
            serviceBound = true;
            // Run the merged status check immediately so the scan page shows the
            // correct text (engine loading / background scan / scan prompt)
            // right when the service connects, not 2s later on the next poll.
            statusPollCheck.run();
            if (isScanning && pendingCustomScanUri == null && pendingCustomScanDir == null) {
                startScanTimer();
                attachScanCallback();
                // Sync pause button with engine state — view is recreated
                // fresh after rotation, static fields don't cover pause.
                if (guardService != null && guardService.getScanEngine() != null) {
                    btnPauseResume.setVisibility(View.VISIBLE);
                    if (guardService.getScanEngine().isPaused()) {
                        btnPauseResume.setText("▶");
                        tvCurrentApp.setText(getString(R.string.scan_paused));
                    } else {
                        btnPauseResume.setText("⏸");
                    }
                }
            }

            // A file or folder was picked while the engine was still asleep —
            // scan it now that the service is awake.
            if (pendingCustomScanUri != null) {
                scanCustomFile(pendingCustomScanUri);
                pendingCustomScanUri = null;
            }
            if (pendingCustomScanDir != null) {
                startCustomFolderScan(pendingCustomScanDir);
                pendingCustomScanDir = null;
            }
        }
        @Override
        public void onServiceDisconnected(android.content.ComponentName name) { serviceBound = false; }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_scan, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        if (lastScanStatus == null) lastScanStatus = getString(R.string.scan_system);

        btnScan = view.findViewById(R.id.btn_start_scan);
        btnPauseResume = view.findViewById(R.id.btn_pause_resume);
        progressBar = view.findViewById(R.id.scan_progress);
        tvProgress = view.findViewById(R.id.tv_progress_text);
        tvCurrentApp = view.findViewById(R.id.tv_current_app);
        tvScanStatus = view.findViewById(R.id.tv_scan_status);
        tvScanned = view.findViewById(R.id.tv_scanned_count);
        tvThreats = view.findViewById(R.id.tv_threat_count);
        tvActiveThreats = view.findViewById(R.id.tv_active_threats);
        tvThreatLabel = view.findViewById(R.id.tv_threat_label);
        tvEngineWarning = view.findViewById(R.id.tv_engine_warning);
        ivScannerIcon = view.findViewById(R.id.iv_scanner_icon);
        rvThreats = view.findViewById(R.id.rv_threats);
        threatAdapter = new ThreatAdapter(foundThreats);
        rvThreats.setLayoutManager(new LinearLayoutManager(getContext()));
        rvThreats.setAdapter(threatAdapter);

        // Switched tabs and came back — restore the last known state on screen
        if (hasScanned) {
            tvScanned.setText(String.valueOf(lastScannedCount));
            tvThreats.setText(String.valueOf(foundThreats.size()));
                    tvActiveThreats.setText(String.valueOf(foundThreats.size()));
            tvScanStatus.setText(lastScanStatus);
            tvCurrentApp.setText("");
            btnScan.setText(getString(R.string.rescan));
            if (foundThreats.size() > 0) {
                tvThreats.setTextColor(0xFFFF0040);
                tvThreatLabel.setVisibility(View.VISIBLE);
            }
        }

        // Engine loading check — run on a delay to give onServiceConnected time
        // to fire if the service is still binding.
        view.postDelayed(this::checkEngineLoading, 300);
        pollEngineLoading();

        if (isScanning) {
            boolean cancelling = serviceBound && guardService != null
                && guardService.getScanEngine() != null
                && guardService.getScanEngine().isCancelled();
            if (cancelling) {
                btnScan.setText(getString(R.string.scan_stopping));
                btnScan.setEnabled(false);
                tvCurrentApp.setText(getString(R.string.scan_stopping));
            } else {
                btnScan.setText(getString(R.string.scan_stop));
                btnScan.setEnabled(true);
                startScannerAnimation();
            }
            // Restore the last known progress immediately instead of leaving
            // the bar/labels at their fresh-inflated (0/blank) state until the
            // engine's next onProgress() call happens to arrive.
            if (lastProgressTotal > 0) {
                progressBar.setMax(lastProgressTotal);
                progressBar.setProgress(lastProgressCurrent);
                tvProgress.setText(lastProgressCurrent + "/" + lastProgressTotal);
                tvCurrentApp.setText("► " + lastProgressName);
            }
        }

        // SMART REMOVAL (distinguishes a standalone APK file from an installed app)
        threatAdapter.setOnThreatClickListener(new com.hydradragon.antivirus.adapter.ThreatAdapter.OnThreatClickListener() {
            @Override
            public void onThreatDeleteClick(ThreatResult threat) {
                // One-tap delete button on the row: a lightweight yes/no
                // confirmation (not the full Destroy/Ignore/Ignore-signature
                // dialog below) since an unconfirmed bare button risks
                // accidental taps, then reuses the exact same destroy logic.
                StringBuilder delMsg = new StringBuilder();
                delMsg.append(getString(R.string.threat_found_dialog_msg, threat.getAppName(), threat.getRiskScore()));
                if (!threat.getReasons().isEmpty()) {
                    delMsg.append("\n\n");
                    for (String r : threat.getReasons()) {
                        delMsg.append("▸ ").append(r).append("\n");
                    }
                }
                android.widget.TextView delTv = new android.widget.TextView(getContext());
                delTv.setText(delMsg.toString().trim());
                delTv.setTextSize(14);
                delTv.setPadding(48, 24, 48, 24);
                delTv.setAutoLinkMask(android.text.util.Linkify.WEB_URLS);
                delTv.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
                delTv.setTextColor(0xFFE6EDF3);
                new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle(getString(R.string.btn_destroy))
                    .setView(delTv)
                    .setPositiveButton(getString(R.string.btn_destroy), (dialog, which) -> destroyThreat(threat))
                    .setNegativeButton(getString(R.string.btn_cancel), null)
                    .show();
            }

            @Override
            public void onThreatClick(ThreatResult threat) {
                StringBuilder msg = new StringBuilder();
                msg.append(getString(R.string.threat_found_dialog_msg, threat.getAppName(), threat.getRiskScore()));
                if (!threat.getReasons().isEmpty()) {
                    msg.append("\n\n");
                    for (String r : threat.getReasons()) {
                        msg.append("▸ ").append(r).append("\n");
                    }
                }
                android.widget.TextView tv = new android.widget.TextView(getContext());
                tv.setText(msg.toString().trim());
                tv.setTextSize(14);
                tv.setPadding(48, 24, 48, 24);
                tv.setAutoLinkMask(android.text.util.Linkify.WEB_URLS);
                tv.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
                tv.setTextColor(0xFFE6EDF3);
            new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(getString(R.string.threat_found_dialog_title))
                .setView(tv)
                .setPositiveButton(getString(R.string.btn_destroy), (dialog, which) -> destroyThreat(threat))
                .setNegativeButton(getString(R.string.btn_ignore), (dialog, which) -> {
                    // Whitelist this package/file so it is never flagged again.
                    String id = (threat.getPackageName() != null && !threat.getPackageName().isEmpty())
                        ? threat.getPackageName() : threat.getApkPath();
                    com.hydradragon.antivirus.engine.UserDecisions.allowThreat(getContext(), id);
                    ThreatLogger.logThreat(getContext(), threat, "WHITELISTED (ignored)");
                    foundThreats.remove(threat);
                    threatAdapter.notifyDataSetChanged();
                    tvThreats.setText(String.valueOf(foundThreats.size()));
                    tvActiveThreats.setText(String.valueOf(foundThreats.size()));
                    if (foundThreats.isEmpty()) tvThreatLabel.setVisibility(View.GONE);
                })
                .setNeutralButton(getString(R.string.btn_ignore_signature), (dialog, which) ->
                    showIgnoreSignatureDialog(threat))
                .show();
            }
        });

        btnScan.setOnClickListener(v -> {
            if (!isScanning) showScanTypeDialog();
            else stopScan();
        });

        btnPauseResume.setOnClickListener(v -> {
            if (!serviceBound || guardService == null || guardService.getScanEngine() == null) return;
            com.hydradragon.antivirus.engine.ScanEngine engine = guardService.getScanEngine();
            if (engine.isPaused()) {
                engine.resumeScan();
                btnPauseResume.setText("⏸");
                tvCurrentApp.setText(getString(R.string.scan_resuming));
            } else {
                engine.pauseScan();
                btnPauseResume.setText("▶");
                tvCurrentApp.setText(getString(R.string.scan_paused));
            }
        });
    }

    /** Removes a flagged threat right now: deletes it directly if it's a
     *  standalone file, or uninstalls it (with the same Zero Trust
     *  ask-for-signature-first detour) if it's an installed app. Shared by
     *  the row-tap "SMART REMOVAL" dialog's Destroy button and the per-item
     *  delete button's confirmation. */
    private void destroyThreat(ThreatResult threat) {
        String path = threat.getApkPath();

        // CASE 1: a standalone file (loose APK or generic file) not
        // actually installed as an app — delete it directly instead
        // of firing ACTION_UNINSTALL, which would silently do
        // nothing for a non-package path.
        if (threat.isStandaloneFile() && path != null) {
            File file = new File(path);
            if (file.exists() && file.delete()) {
                Toast.makeText(getContext(), getString(R.string.threat_destroyed), Toast.LENGTH_LONG).show();
                // Write to the history log
                ThreatLogger.logThreat(getContext(), threat, getString(R.string.file_deleted_safe));
                // Remove it from the on-screen list immediately
                foundThreats.remove(threat);
                threatAdapter.notifyDataSetChanged();
                tvThreats.setText(String.valueOf(foundThreats.size()));
                    tvActiveThreats.setText(String.valueOf(foundThreats.size()));
                if (foundThreats.isEmpty()) tvThreatLabel.setVisibility(View.GONE);
            } else {
                Toast.makeText(getContext(), getString(R.string.file_delete_failed), Toast.LENGTH_SHORT).show();
            }
        } else {
            // CASE 2: an app already INSTALLED on this phone
            boolean isZeroTrustUnknown = threat.getThreatType() == ThreatResult.ThreatType.UNKNOWN
                && com.hydradragon.antivirus.engine.ZeroTrustMode.isEnabled(requireContext())
                && com.hydradragon.antivirus.engine.AskSignatureOnRemove.isEnabled(requireContext());
            if (isZeroTrustUnknown) {
                new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle(getString(R.string.gen_sig_on_remove_title))
                    .setMessage(getString(R.string.gen_sig_on_remove_msg, threat.getAppName()))
                    .setPositiveButton(getString(R.string.gen_sig_on_remove_yes), (d2, w2) -> {
                        boolean generated = guardService != null
                            && guardService.getScanEngine().generateRuleForApp(
                                threat.getApkPath(), threat.getPackageName());
                        Toast.makeText(getContext(), generated
                            ? getString(R.string.gen_sig_on_remove_done)
                            : getString(R.string.gen_sig_on_remove_failed), Toast.LENGTH_SHORT).show();
                        uninstallInstalledThreat(threat);
                    })
                    .setNegativeButton(getString(R.string.gen_sig_on_remove_no), (d2, w2) -> uninstallInstalledThreat(threat))
                    .show();
            } else {
                uninstallInstalledThreat(threat);
            }
        }
    }

    /** Lets the user pick which of THIS threat's specific detection/signature
     *  names (parsed from its reasons — "EMOJI [TAG] name") to suppress
     *  engine-wide from now on (see IgnoredSignatures), instead of only
     *  whitelisting this one app/file (that's the "IGNORE" button above). */
    private void showIgnoreSignatureDialog(ThreatResult threat) {
        java.util.List<String> names = new java.util.ArrayList<>();
        for (String reason : threat.getReasons()) {
            int close = reason.indexOf("] ");
            if (close >= 0 && close + 2 < reason.length()) {
                names.add(reason.substring(close + 2));
            }
        }
        if (names.isEmpty()) {
            Toast.makeText(getContext(), getString(R.string.no_signature_to_ignore), Toast.LENGTH_SHORT).show();
            return;
        }
        boolean[] checked = new boolean[names.size()];
        new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.btn_ignore_signature))
            .setMultiChoiceItems(names.toArray(new String[0]), checked, (d, which, isChecked) -> checked[which] = isChecked)
            .setPositiveButton(getString(R.string.lock_save), (d, w) -> {
                int count = 0;
                for (int i = 0; i < names.size(); i++) {
                    if (checked[i]) {
                        com.hydradragon.antivirus.engine.IgnoredSignatures.add(requireContext(), names.get(i));
                        count++;
                    }
                }
                if (count > 0) {
                    Toast.makeText(getContext(), getString(R.string.signature_ignored_toast, count), Toast.LENGTH_SHORT).show();
                }
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }

    /** Fires the system uninstall UI for an installed-app threat, then hides it
     *  from this screen's list (same behavior for both the direct-delete path
     *  and the "ask to generate a signature first" path above). */
    private void uninstallInstalledThreat(ThreatResult threat) {
        String pkg = threat.getPackageName();

        // Kill any running (background) process of the malware FIRST, before
        // asking the system to uninstall it — a still-running process can
        // otherwise keep re-spawning a service/receiver during the brief
        // window the uninstall confirmation UI is up. KILL_BACKGROUND_PROCESSES
        // is a normal (auto-granted) permission; there's no stronger
        // "force-stop any app" API available to a regular (non-system) app.
        if (pkg != null && !pkg.isEmpty()) {
            try {
                android.app.ActivityManager am =
                    (android.app.ActivityManager) requireContext().getSystemService(Context.ACTIVITY_SERVICE);
                if (am != null) am.killBackgroundProcesses(pkg);
            } catch (Exception ignore) { }
        }

        // Some malware self-grants Device Admin specifically to resist
        // uninstallation (Android blocks uninstalling an active admin app
        // until it's deactivated). There's no API for a regular app to revoke
        // ANOTHER app's admin status — only the user, from the system's
        // "Device admin apps" screen — so detect it and send them straight
        // there instead of letting the uninstall silently fail.
        if (isActiveDeviceAdmin(pkg)) {
            new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(getString(R.string.malware_has_admin_title))
                .setMessage(getString(R.string.malware_has_admin_msg, threat.getAppName()))
                .setCancelable(false)
                .setPositiveButton(getString(R.string.malware_has_admin_open_settings), (d, w) -> {
                    // There's no public constant for the exact "Device admin
                    // apps" screen (it's an internal Settings activity that
                    // varies by OEM) — Security settings is the reliable,
                    // documented entry point every device has, and the
                    // device-admin list is always reachable from there.
                    try {
                        startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS));
                    } catch (Exception ignore) { }
                    proceedWithUninstall(threat);
                })
                .setNegativeButton(getString(R.string.btn_cancel), null)
                .show();
            return;
        }

        proceedWithUninstall(threat);
    }

    private boolean isActiveDeviceAdmin(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                requireContext().getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm == null) return false;
            for (android.content.ComponentName admin : dpm.getActiveAdmins()) {
                if (admin != null && pkg.equals(admin.getPackageName())) return true;
            }
        } catch (Exception ignore) { }
        return false;
    }

    private void proceedWithUninstall(ThreatResult threat) {
        String pkg = threat.getPackageName();
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + pkg));
        startActivity(intent);

        // Stay on the list until onResume() confirms the package is actually
        // gone — removing it here was optimistic and could hide a threat that
        // was never really uninstalled (user cancelled the system dialog, or
        // it silently failed).
        pendingUninstallPkg = pkg;
    }

    @Override
    public void onResume() {
        super.onResume();
        // User returned to our app after the system uninstall dialog.
        // Only now do we know whether the uninstall actually went through.
        if (pendingUninstallPkg != null) {
            if (!isPackageInstalled(pendingUninstallPkg)) {
                // Confirmed gone — safe to drop it from the list now.
                for (ThreatResult t : foundThreats) {
                    if (pendingUninstallPkg.equals(t.getPackageName())) {
                        foundThreats.remove(t);
                        threatAdapter.notifyDataSetChanged();
                        tvThreats.setText(String.valueOf(foundThreats.size()));
                    tvActiveThreats.setText(String.valueOf(foundThreats.size()));
                        if (foundThreats.isEmpty()) tvThreatLabel.setVisibility(View.GONE);
                        break;
                    }
                }
            } else if (isProcessRunning(pendingUninstallPkg)
                    && requireContext().getSharedPreferences("hydra_prefs", 0)
                        .getBoolean("uninstall_warning_enabled", true)) {
                for (ThreatResult t : foundThreats) {
                    if (pendingUninstallPkg.equals(t.getPackageName())) {
                        showUninstallFailedDialog(t);
                        break;
                    }
                }
            }
            // Still installed but no longer running (e.g. user cancelled the
            // system dialog) — leave it in the list untouched, no dialog.
            pendingUninstallPkg = null;
        }
    }

    private boolean isPackageInstalled(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        try {
            requireContext().getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private boolean isProcessRunning(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                requireContext().getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) return false;
            for (android.app.ActivityManager.RunningAppProcessInfo p : am.getRunningAppProcesses()) {
                if (p != null && pkg.equals(p.processName)) return true;
            }
        } catch (Exception ignore) { }
        return false;
    }

    private void showUninstallFailedDialog(ThreatResult threat) {
        if (!isAdded()) return;
        new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.uninstall_failed_title))
            .setMessage(getString(R.string.uninstall_failed_msg, threat.getAppName()))
            .setCancelable(false)
            .setPositiveButton(getString(R.string.uninstall_failed_safe_mode), (d, w) -> {
                Intent intent = new Intent(android.provider.Settings.ACTION_SETTINGS);
                startActivity(intent);
                Toast.makeText(getContext(), getString(R.string.uninstall_failed_safe_mode_toast), Toast.LENGTH_LONG).show();
            })
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show();
    }
    private void showScanTypeDialog() {
        if (guardService != null && guardService.isEngineLoading()) {
            Toast.makeText(getContext(), getString(R.string.engine_loading_warning), Toast.LENGTH_SHORT).show();
            return;
        }
        String[] options = {
            getString(R.string.btn_quick_scan),
            getString(R.string.btn_full_scan),
            getString(R.string.scan_custom),
            getString(R.string.scan_custom_folder)
        };
        new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.scan_type_title))
            .setItems(options, (dialog, which) -> {
                if (which == 0) startScan(false);
                else if (which == 1) startScan(true);
                else if (which == 2) pickFileLauncher.launch("*/*");
                else if (which == 3) pickFolderLauncher.launch(null);
            })
            .show();
    }


    private void startScan(boolean isFullScan) {
        Log.d(TAG, "startScan: isFullScan=" + isFullScan);
        if (!serviceBound || guardService == null) { Log.w(TAG, "startScan: service not bound"); return; }
        if (guardService.isEngineLoading()) {
            Log.w(TAG, "startScan: engine still loading");
            Toast.makeText(getContext(), getString(R.string.engine_loading_warning), Toast.LENGTH_SHORT).show();
            return;
        }
        // GuardService's own periodic background scan (see startPeriodicScans)
        // shares this same ScanEngine. A pre-check here alone isn't race-free
        // — a background scan can start in the gap between it and the actual
        // scanAllApps() call below — so set up the UI optimistically, THEN
        // check scanAllApps()'s own return value (the real, atomic answer)
        // and roll the UI back if it turns out a scan was already running.
        resetScanUI();
        attachScanCallback();
        Log.d(TAG, "startScan: calling scanAllApps(isFullScan=" + isFullScan + ")");
        if (guardService.getScanEngine() == null || !guardService.getScanEngine().scanAllApps(isFullScan)) {
            // Lost the race to a background scan — undo the optimistic UI
            // state instead of leaving this screen stuck on "SCANNING..."
            // forever with nothing to ever complete it.
            Log.w(TAG, "startScan: scanAllApps returned false (race lost to background scan)");
            isScanning = false;
            stopScannerAnimation();
            btnScan.setText(getString(R.string.rescan));
            btnPauseResume.setVisibility(View.INVISIBLE);
            Toast.makeText(getContext(), getString(R.string.scan_already_running), Toast.LENGTH_SHORT).show();
            return;
        }

        // Surface the native (Rust) engine status so a silent init failure
        // (clamav DB / model / .yrc) is visible without adb.
        String engineStatus = com.hydradragon.antivirus.engine.NativeScanner.status();
        Log.d(TAG, "Scan started successfully. Engine status: " + engineStatus);
        android.widget.Toast.makeText(getContext(),
            getString(R.string.engine_status_format, engineStatus),
            android.widget.Toast.LENGTH_LONG).show();
    }

    /** Start an Anti-FP scan: runs a full scan WITH anti-FP cache population
     *  and detection suppression. This is the only scan type that uses the
     *  anti-FP cache. */
    /** Stop button: request the engine to abort. The in-flight scan ends at its
     *  next file/app boundary and fires onScanComplete with what was found. */
    private void stopScan() {
        Log.d(TAG, "stopScan: user requested cancel");
        if (!serviceBound || guardService == null || guardService.getScanEngine() == null) {
            Log.w(TAG, "stopScan: service not available");
            return;
        }
        guardService.getScanEngine().cancelScan();
        btnScan.setText(getString(R.string.scan_stopping));
        btnScan.setEnabled(false);
        tvCurrentApp.setText(getString(R.string.scan_stopping));
    }

    /** Registers this screen's UI updates as GuardService's "UI" callback —
     *  NOT scanEngine.setCallback() directly. GuardService keeps permanent
     *  ownership of the engine's actual callback (notifications + history
     *  logging) and forwards every event here too; calling
     *  scanEngine.setCallback() from here would silently replace that
     *  permanent callback and kill all future threat notifications/logging,
     *  including for this very scan. */
    private void attachScanCallback() {
        guardService.setUiScanCallback(new com.hydradragon.antivirus.engine.ScanEngine.ScanCallback() {
            @Override
            public void onProgress(int current, int total, String packageName) {
                lastProgressCurrent = current;
                lastProgressTotal = total;
                lastProgressName = packageName != null ? packageName : "";
                lastScannedCount = current;
                if (current % 50 == 0 || current == total || packageName != null) {
                    Log.d(TAG, "onProgress: " + current + "/" + total + " — " + packageName);
                }
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    progressBar.setMax(total);
                    progressBar.setProgress(current);
                    tvProgress.setText(current + "/" + total);
                    tvCurrentApp.setText("► " + packageName);
                    tvScanned.setText(String.valueOf(current));
                });
            }

            @Override
            public void onThreatFound(ThreatResult threat) {
                Log.w(TAG, "onThreatFound: " + threat.getAppName()
                    + " pkg=" + threat.getPackageName()
                    + " path=" + threat.getApkPath()
                    + " type=" + threat.getThreatType()
                    + " risk=" + threat.getRiskScore()
                    + " reasons=" + threat.getReasons()
                    + " standalone=" + threat.isStandaloneFile());
                if (getActivity() == null) return;
                if (!threat.isThreat()) return;
                getActivity().runOnUiThread(() -> {
                    if (foundThreats.contains(threat)) return;
                    if (foundThreats.size() < MAX_DISPLAYED_THREATS) {
                        foundThreats.add(threat);
                        threatAdapter.notifyItemInserted(foundThreats.size() - 1);
                    } else {
                        hiddenThreatCount++;
                    }
                    int total = foundThreats.size() + hiddenThreatCount;
                    tvThreats.setText(String.valueOf(total));
                    tvActiveThreats.setText(String.valueOf(total));
                    tvThreats.setTextColor(0xFFFF0040);
                    tvThreatLabel.setVisibility(View.VISIBLE);
                });
            }

            @Override
            public void onScanComplete(ScanResult result) {
                stopScanTimer();
                Log.d(TAG, "onScanComplete: totalScanned=" + result.getTotalScanned()
                    + " threatsFound=" + result.getThreatsFound()
                    + " durationMs=" + result.getScanDurationMs()
                    + " clean=" + result.isClean());
                boolean wasCancelled = serviceBound && guardService != null
                    && guardService.getScanEngine().isCancelled();
                Log.d(TAG, "onScanComplete: wasCancelled=" + wasCancelled);
                long secs = result.getScanDurationMs() / 1000;
                long millis = result.getScanDurationMs() % 1000;
                String duration = String.format(java.util.Locale.US, "%d.%03ds", secs, millis);
                int totalThreats = result.getThreats().size();
                isScanning = false;
                if (getActivity() != null) {
                    getActivity().getSharedPreferences("hydra_prefs", 0)
                        .edit().putBoolean("first_scan_completed", true).apply();
                }
                if (!isAdded()) {
                    lastScanStatus = result.isClean() ? "System clean" : totalThreats + " threats";
                    if (wasCancelled) lastScanStatus = "Scan stopped";
                    lastScanStatus += " (" + duration + ")";
                    lastProgressName = "";
                    lastProgressCurrent = 0;
                    lastProgressTotal = 0;
                    Log.d(TAG, "onScanComplete: fragment detached, status saved");
                    return;
                }
                if (wasCancelled) {
                    lastScanStatus = getString(R.string.scan_stopped) + " (" + duration + ")";
                } else if (result.isClean()) {
                    lastScanStatus = getString(R.string.scan_clean_system) + " (" + duration + ")";
                } else {
                    lastScanStatus = getString(R.string.threats_found_count, totalThreats) + " (" + duration + ")";
                }
                if (hiddenThreatCount > 0) {
                    lastScanStatus += " (" + getString(R.string.threats_hidden_count, hiddenThreatCount) + ")";
                }
                getActivity().runOnUiThread(() -> {
                    stopScannerAnimation();
                    btnScan.setText(getString(R.string.rescan));
                    btnScan.setEnabled(true);
                    btnPauseResume.setVisibility(View.INVISIBLE);
                    tvCurrentApp.setText("");
                    if (progressBar.getMax() > 0) progressBar.setProgress(progressBar.getMax());
                    lastProgressCurrent = 0;
                    lastProgressTotal = 0;
                    lastProgressName = "";
                    threatAdapter.notifyDataSetChanged();
                    tvThreats.setText(String.valueOf(totalThreats));
                    tvActiveThreats.setText(String.valueOf(totalThreats));
                    tvScanStatus.setText(lastScanStatus);
                    if (wasCancelled) {
                        tvScanStatus.setTextColor(0xFFFFAA00);
                        tvCurrentApp.setText(lastScanStatus);
                        tvThreatLabel.setVisibility(foundThreats.isEmpty() ? View.GONE : View.VISIBLE);
                    } else if (result.isClean()) {
                        tvScanStatus.setTextColor(0xFF00FF88);
                        tvThreatLabel.setVisibility(View.GONE);
                    } else {
                        tvScanStatus.setTextColor(0xFFFF0040);
                        tvThreatLabel.setVisibility(foundThreats.isEmpty() ? View.GONE : View.VISIBLE);
                    }
                });
            }

            @Override
            public void onError(String error) {
                stopScanTimer();
                Log.e(TAG, "onError: " + error);
                // Same fix as onScanComplete just above: clear the static flag
                // even if the fragment is gone, or a background/engine error
                // firing while this screen isn't visible leaves isScanning
                // stuck true forever — every future scan attempt then silently
                // refuses to start.
                isScanning = false;
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    stopScannerAnimation();
                    btnScan.setText(getString(R.string.rescan));
                    btnScan.setEnabled(true);
                    lastScanStatus = getString(R.string.scan_error, error);
                    tvScanStatus.setText(lastScanStatus);
                });
            }
        });
    }

    private void startScannerAnimation() {
        RotateAnimation rotate = new RotateAnimation(0f, 360f, Animation.RELATIVE_TO_SELF, 0.5f, Animation.RELATIVE_TO_SELF, 0.5f);
        rotate.setDuration(1000);
        rotate.setRepeatCount(Animation.INFINITE);
        rotate.setInterpolator(new LinearInterpolator());
        ivScannerIcon.startAnimation(rotate);
    }

    private void stopScannerAnimation() { ivScannerIcon.clearAnimation(); }

    /** Clears all scan result UI so a new scan starts from a blank state. */
    private void resetScanUI() {
        isScanning = true;
        hasScanned = true;
        foundThreats.clear();
        hiddenThreatCount = 0;
        threatAdapter.notifyDataSetChanged();
        lastProgressCurrent = 0;
        lastProgressTotal = 0;
        lastProgressName = "";
        lastScannedCount = 0;

        btnScan.setText(getString(R.string.scan_stop));
        btnScan.setEnabled(true);
        btnPauseResume.setVisibility(View.VISIBLE);
        btnPauseResume.setText("⏸");
        startScannerAnimation();
        startScanTimer();

        lastScanStatus = getString(R.string.scan_scanning_btn);
        tvScanStatus.setText(lastScanStatus);
        tvScanStatus.setTextColor(0xFF00D9FF);
        tvThreats.setText("0");
        tvActiveThreats.setText("0");
        tvThreatLabel.setVisibility(View.GONE);
        tvScanned.setText("0");
        tvProgress.setText("0/0");
        tvCurrentApp.setText("");
        progressBar.setProgress(0);
        progressBar.setMax(0);
    }

    private void checkEngineLoading() {
        if (!isAdded()) return;
        boolean loading = guardService != null && guardService.isEngineLoading();
        if (loading) {
            tvEngineWarning.setVisibility(View.VISIBLE);
            btnScan.setEnabled(false);
            tvScanStatus.setText(getString(R.string.engine_loading_status));
            tvScanStatus.setTextColor(0xFFFFAA00);
        } else {
            tvEngineWarning.setVisibility(View.GONE);
            if (!isScanning) {
                btnScan.setEnabled(true);
                if (!hasScanned) {
                    tvScanStatus.setText(getString(R.string.scan_prompt));
                    tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.text_secondary));
                }
            }
        }
    }

    // Live scan timer: updates status text every second with elapsed time.
    private long scanStartTime = 0;
    private final android.os.Handler scanTimerHandler = new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable scanTimerTick = new Runnable() {
        @Override
        public void run() {
            if (!isAdded() || !isScanning) return;
            long elapsed = System.currentTimeMillis() - scanStartTime;
            long secs = elapsed / 1000;
            long mins = secs / 60;
            secs %= 60;
            String timeStr = String.format(java.util.Locale.US, "%02d:%02d", mins, secs);
            tvScanStatus.setText(getString(R.string.scan_scanning_btn) + " " + timeStr);
            scanTimerHandler.postDelayed(this, 1000);
        }
    };

    private void startScanTimer() {
        scanStartTime = System.currentTimeMillis();
        scanTimerHandler.removeCallbacks(scanTimerTick);
        scanTimerHandler.post(scanTimerTick);
    }

    private void stopScanTimer() {
        scanTimerHandler.removeCallbacks(scanTimerTick);
    }

    // Single poller that checks engine loading state only.
    private final android.os.Handler statusPoller = new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable statusPollCheck = new Runnable() {
        @Override
        public void run() {
            if (!isAdded()) return;
            if (serviceBound && guardService != null) {
                if (guardService.isEngineLoading()) {
                    tvEngineWarning.setVisibility(View.VISIBLE);
                    btnScan.setEnabled(false);
                    tvScanStatus.setText(getString(R.string.engine_loading_status));
                    tvScanStatus.setTextColor(0xFFFFAA00);
                } else {
                    tvEngineWarning.setVisibility(View.GONE);
                    if (!isScanning) {
                        btnScan.setEnabled(true);
                        if (!hasScanned) {
                            tvScanStatus.setText(getString(R.string.scan_prompt));
                            tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.text_secondary));
                        }
                    }
                }
            }
            statusPoller.postDelayed(this, 2000);
        }
    };
    private void pollEngineLoading() { statusPoller.post(statusPollCheck); }

    @Override
    public void onStart() {
        super.onStart();
        requireContext().bindService(new Intent(getContext(), GuardService.class), serviceConnection, Context.BIND_AUTO_CREATE);
        pollEngineLoading();
    }

    @Override
    public void onStop() {
        super.onStop();
        stopScanTimer();
        statusPoller.removeCallbacks(statusPollCheck);
        if (serviceBound) {
            // GuardService keeps scanning/notifying/logging on its own even
            // with no UI attached — just drop this screen's reference so it's
            // not held past the fragment's lifecycle (see setUiScanCallback).
            if (guardService != null) guardService.setUiScanCallback(null);
            requireContext().unbindService(serviceConnection);
            serviceBound = false;
        }
    }

    
    private final androidx.activity.result.ActivityResultLauncher<String> pickFileLauncher =
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.GetContent(), uri -> {
            if (uri != null) {
                if (serviceBound && guardService != null) {
                    scanCustomFile(uri); // Scan immediately if the engine is already awake
                } else {
                    pendingCustomScanUri = uri; // Engine asleep — remember it, scan in onStart
                }
            }
        });

    /** Folder picker for Custom Scan's "pick a folder" option. Returns a SAF
     *  tree Uri, not a filesystem path — converted best-effort via
     *  uriTreeToFile() (works for local device storage, the common case;
     *  falls back to a toast if the volume can't be resolved to a real path,
     *  e.g. a cloud-backed document provider). */
    private final androidx.activity.result.ActivityResultLauncher<Uri> pickFolderLauncher =
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.OpenDocumentTree(), treeUri -> {
            if (treeUri == null) return;
            File dir = uriTreeToFile(treeUri);
            if (dir == null || !dir.isDirectory()) {
                Toast.makeText(getContext(), getString(R.string.scan_custom_folder_unsupported), Toast.LENGTH_LONG).show();
                return;
            }
            if (serviceBound && guardService != null) {
                startCustomFolderScan(dir);
            } else {
                pendingCustomScanDir = dir;
            }
        });

    /** Resolves a SAF tree Uri to a real filesystem File, for the common case
     *  of a LOCAL storage volume (primary or an SD card) — the document ID for
     *  those is "<volume>:<relative/path>" (e.g. "primary:Download"), which
     *  maps directly onto Environment's storage roots. Returns null for
     *  anything that isn't a local storage document tree (e.g. a cloud
     *  provider), since there's no real filesystem path to scan there. */
    private File uriTreeToFile(Uri treeUri) {
        try {
            String docId = android.provider.DocumentsContract.getTreeDocumentId(treeUri);
            return resolveDocumentId(docId);
        } catch (Exception e) {
            return null;
        }
    }

    /** Resolves a single-document content URI (e.g. from GetContent) to a real
     *  filesystem File. Works for local storage volumes (primary + SD card)
     *  and file:// URIs. Returns null for cloud providers or unresolvable URIs. */
    private File uriToRealFile(Uri uri) {
        if ("file".equals(uri.getScheme())) {
            return new File(uri.getPath());
        }
        if (!"content".equals(uri.getScheme())) return null;
        try {
            String docId = android.provider.DocumentsContract.getDocumentId(uri);
            return resolveDocumentId(docId);
        } catch (Exception e) {
            return null;
        }
    }

    /** Shared resolver: given a document ID like "primary:Download/file.apk"
     *  or "XXXX-XXXX:some/path", return the real File or null. */
    private File resolveDocumentId(String docId) {
        try {
            String[] split = docId.split(":", 2);
            String volume = split[0];
            String relative = split.length > 1 ? split[1] : "";
            File root;
            if ("primary".equalsIgnoreCase(volume)) {
                root = android.os.Environment.getExternalStorageDirectory();
            } else {
                // Non-primary volume (SD card) — look it up among the
                // app-scoped external file dirs' volume roots.
                root = null;
                for (File f : requireContext().getExternalFilesDirs(null)) {
                    if (f == null) continue;
                    String path = f.getAbsolutePath();
                    int idx = path.indexOf("/Android/");
                    if (idx > 0 && path.contains(volume)) {
                        root = new File(path.substring(0, idx));
                        break;
                    }
                }
                if (root == null) return null;
            }
            return relative.isEmpty() ? root : new File(root, relative);
        } catch (Exception e) {
            return null;
        }
    }

    /** Custom Scan's folder option — reuses the exact same UI plumbing as a
     *  normal quick/full scan (attachScanCallback + the ScanCallback contract)
     *  since ScanEngine.scanCustomFolder() reports through it identically. */
    private void startCustomFolderScan(File dir) {
        Log.d(TAG, "startCustomFolderScan: dir=" + dir.getAbsolutePath());
        if (!serviceBound || guardService == null) { Log.w(TAG, "startCustomFolderScan: service not bound"); return; }
        if (guardService.isEngineLoading()) {
            Toast.makeText(getContext(), getString(R.string.engine_loading_warning), Toast.LENGTH_SHORT).show();
            return;
        }
        resetScanUI();
        attachScanCallback();
        Log.d(TAG, "startCustomFolderScan: calling scanCustomFolder");
        if (!guardService.getScanEngine().scanCustomFolder(dir)) {
            Log.w(TAG, "startCustomFolderScan: scanCustomFolder returned false");
            // Same race-free check as startScan() — see its comment.
            isScanning = false;
            stopScannerAnimation();
            btnScan.setText(getString(R.string.rescan));
            btnPauseResume.setVisibility(View.INVISIBLE);
            Toast.makeText(getContext(), getString(R.string.scan_already_running), Toast.LENGTH_SHORT).show();
        }
    }

private void scanCustomFile(android.net.Uri uri) {
        Log.d(TAG, "scanCustomFile: uri=" + uri);
        if (!serviceBound || guardService == null) { Log.w(TAG, "scanCustomFile: service not bound"); return; }
        if (guardService.isEngineLoading()) {
            Toast.makeText(getContext(), getString(R.string.engine_loading_warning), Toast.LENGTH_SHORT).show();
            return;
        }
        resetScanUI();
        // Single-file scan doesn't support pause/resume.
        btnPauseResume.setVisibility(View.INVISIBLE);
        // Keep the button enabled (unlike other transient states here) so its
        // onClickListener's `else stopScan()` branch (line ~221) can actually
        // fire — disabling it during a manual single-file scan meant Stop was
        // never clickable for this flow, even though stopScan()/cancelScan()
        // already works fine here (scanSingleFile polls cancelRequested the
        // same way scanAllApps/scanCustomFolder do).

        new Thread(() -> {
            // Try to resolve the URI to a real filesystem path so the scan
            // result shows the original file location instead of a cache copy.
            java.io.File realFile = uriToRealFile(uri);
            java.io.File scanFile;
            if (realFile != null && realFile.isFile() && realFile.canRead()) {
                scanFile = realFile;
                Log.d(TAG, "scanCustomFile: using real path " + scanFile.getAbsolutePath()
                    + " (" + scanFile.length() + " bytes)");
            } else {
                // Fall back to copying to cache (cloud provider, etc.)
                String originalName = uri.getLastPathSegment();
                if (originalName == null || originalName.isEmpty()) originalName = "custom_scan_file";
                int slash = originalName.lastIndexOf('/');
                if (slash >= 0) originalName = originalName.substring(slash + 1);
                originalName = originalName.replaceAll("[^a-zA-Z0-9._-]", "_");
                try {
                    java.io.File tempFile = new java.io.File(getContext().getCacheDir(), originalName);
                    java.io.InputStream is = getContext().getContentResolver().openInputStream(uri);
                    if (is == null) throw new java.io.IOException("openInputStream returned null for " + uri);
                    java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile);
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = is.read(buffer)) != -1) fos.write(buffer, 0, read);
                    fos.flush(); fos.close(); is.close();
                    scanFile = tempFile;
                    Log.d(TAG, "scanCustomFile: using cache copy " + scanFile.getAbsolutePath()
                        + " (" + scanFile.length() + " bytes)");
                } catch (Exception e) {
                    Log.e("ScanFragment", "scanCustomFile: failed copying uri=" + uri, e);
                    isScanning = false;
                    if (getActivity() != null) {
                        getActivity().runOnUiThread(() -> {
                            stopScannerAnimation();
                            btnScan.setText(getString(R.string.rescan));
                            btnScan.setEnabled(true);
                            tvScanStatus.setText(getString(R.string.error_reading_file));
                        });
                    }
                    return;
                }
            }

            try {
                Log.d(TAG, "scanCustomFile: running scanSingleFile on " + scanFile.getAbsolutePath()
                    + " (" + scanFile.length() + " bytes)");
                final com.hydradragon.antivirus.model.ThreatResult result;
                com.hydradragon.antivirus.engine.ScanEngine engine = guardService.getScanEngine();
                if (engine != null) {
                    result = engine.scanSingleFile(scanFile);
                } else {
                    result = null;
                }

                // Same reasoning as the copy-failure catch above: clear the
                // static flag first, unconditionally, THEN update views only
                // if the fragment is still around to show them.
                isScanning = false;
                Log.d(TAG, "scanCustomFile: result=" + (result != null ? result.getAppName() + " isThreat=" + result.isThreat() : "null"));
                if (getActivity() != null) {
                    getActivity().runOnUiThread(() -> {
                        stopScannerAnimation();
                        btnScan.setText(getString(R.string.rescan));
                        btnScan.setEnabled(true);

                        if (result != null && result.isThreat()) {
                            foundThreats.add(result);
                            threatAdapter.notifyItemInserted(0);
                            tvThreats.setText("1");
                            tvActiveThreats.setText("1");
                            tvThreats.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.threat_red));
                            tvScanStatus.setText(getString(R.string.threats_found_count, 1));
                            tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.threat_red));
                            tvThreatLabel.setVisibility(View.VISIBLE);
                        } else {
                            tvScanStatus.setText(getString(R.string.system_clean));
                            tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.neon_green));
                        }
                    });
                }
            } catch (Exception e) {
                Log.e("ScanFragment", "scanCustomFile: scanSingleFile failed for uri=" + uri, e);
                isScanning = false;
                if (getActivity() != null) {
                    getActivity().runOnUiThread(() -> {
                        stopScannerAnimation();
                        btnScan.setText(getString(R.string.rescan));
                        btnScan.setEnabled(true);
                        tvScanStatus.setText(getString(R.string.error_scanning_file));
                    });
                }
            }
        }).start();
    }

}
