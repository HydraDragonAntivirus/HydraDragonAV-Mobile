package com.hydradragon.antivirus.ui;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
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
    private ProgressBar progressBar;
    private TextView tvProgress, tvCurrentApp, tvScanStatus, tvScanned, tvThreats;
    private ImageView ivScannerIcon;
    private RecyclerView rvThreats;

    private GuardService guardService;
    private boolean serviceBound = false;
    private android.net.Uri pendingCustomScanUri = null;
    
    // STATİK HAFIZA: Sen sekmeler arası gezsen bile bu veriler silinmez, orada kalır!
    private static boolean isScanning = false;
    private static boolean hasScanned = false;
    private static String lastScanStatus = null;
    private static int lastScannedCount = 0;
    private static List<ThreatResult> foundThreats = new ArrayList<>();

    private ThreatAdapter threatAdapter;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(android.content.ComponentName name, android.os.IBinder service) {
            guardService = ((com.hydradragon.antivirus.service.GuardService.GuardBinder) service).getService();
            serviceBound = true;
            if (isScanning && pendingCustomScanUri == null) attachScanCallback();
            
            // Eğer uykuya dalarken seçilmiş bir dosya varsa, uyanır uyanmaz tara!
            if (pendingCustomScanUri != null) {
                scanCustomFile(pendingCustomScanUri);
                pendingCustomScanUri = null;
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
        progressBar = view.findViewById(R.id.scan_progress);
        tvProgress = view.findViewById(R.id.tv_progress_text);
        tvCurrentApp = view.findViewById(R.id.tv_current_app);
        tvScanStatus = view.findViewById(R.id.tv_scan_status);
        tvScanned = view.findViewById(R.id.tv_scanned_count);
        tvThreats = view.findViewById(R.id.tv_threat_count);
        ivScannerIcon = view.findViewById(R.id.iv_scanner_icon);
        rvThreats = view.findViewById(R.id.rv_threats);

        threatAdapter = new ThreatAdapter(foundThreats);
        rvThreats.setLayoutManager(new LinearLayoutManager(getContext()));
        rvThreats.setAdapter(threatAdapter);

        // Sekme değiştirip geri geldiysen, son durumu ekrana yükle
        if (hasScanned) {
            tvScanned.setText(String.valueOf(lastScannedCount));
            tvThreats.setText(String.valueOf(foundThreats.size()));
            tvScanStatus.setText(lastScanStatus);
            btnScan.setText(getString(R.string.rescan));
            if (foundThreats.size() > 0) tvThreats.setTextColor(0xFFFF0040);
        }

        if (isScanning) {
            btnScan.setText(getString(R.string.scan_stop));
            btnScan.setEnabled(true);
            startScannerAnimation();
        }

        // AKILLI SİLME İŞLEMİ (APK Dosyası vs Kurulu Uygulama Ayırımı)
        threatAdapter.setOnThreatClickListener(threat -> {
            new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(getString(R.string.threat_found_dialog_title))
                .setMessage(getString(R.string.threat_found_dialog_msg, threat.getAppName(), threat.getRiskScore()))
                .setPositiveButton(getString(R.string.btn_destroy), (dialog, which) -> {
                    String path = threat.getApkPath();
                    
                    // DURUM 1: Eğer bu SD Karttaki gizli bir .apk dosyasıysa
                    if (path != null && path.contains("/storage/")) {
                        File file = new File(path);
                        if (file.exists() && file.delete()) {
                            Toast.makeText(getContext(), getString(R.string.threat_destroyed), Toast.LENGTH_LONG).show();
                            // Günlüklere yaz
                            ThreatLogger.logThreat(getContext(), threat.getPackageName(), threat.getAppName(), getString(R.string.file_deleted_safe));
                            // Ekranda listeden anında kaldır!
                            foundThreats.remove(threat);
                            threatAdapter.notifyDataSetChanged();
                            tvThreats.setText(String.valueOf(foundThreats.size()));
                        } else {
                            Toast.makeText(getContext(), getString(R.string.file_delete_failed), Toast.LENGTH_SHORT).show();
                        }
                    } else {
                        // DURUM 2: Eğer bu telefona hali hazırda KURULMUŞ bir uygulamaysa
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
                })
                .setNegativeButton(getString(R.string.btn_ignore), (dialog, which) -> {
                    // Whitelist this package/file so it is never flagged again.
                    String id = (threat.getPackageName() != null && !threat.getPackageName().isEmpty())
                        ? threat.getPackageName() : threat.getApkPath();
                    com.hydradragon.antivirus.engine.UserDecisions.allowThreat(getContext(), id);
                    ThreatLogger.logThreat(getContext(), threat.getPackageName(), threat.getAppName(), "WHITELISTED (ignored)");
                    foundThreats.remove(threat);
                    threatAdapter.notifyDataSetChanged();
                    tvThreats.setText(String.valueOf(foundThreats.size()));
                })
                .setNeutralButton(getString(R.string.btn_ignore_signature), (dialog, which) ->
                    showIgnoreSignatureDialog(threat))
                .show();
        });

        btnScan.setOnClickListener(v -> {
            if (!isScanning) showScanTypeDialog();
            else stopScan();
        });
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
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + threat.getPackageName()));
        startActivity(intent);

        // Ekrandan direkt gizleyelim ki silinmiş hissiyatı versin
        foundThreats.remove(threat);
        threatAdapter.notifyDataSetChanged();
        tvThreats.setText(String.valueOf(foundThreats.size()));
    }

    private void showScanTypeDialog() {
        String[] options = {
            getString(R.string.btn_quick_scan),
            getString(R.string.btn_full_scan),
            getString(R.string.scan_custom)
        };
        new AlertDialog.Builder(getContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.scan_type_title))
            .setItems(options, (dialog, which) -> {
                if (which == 0) startScan(false);
                else if (which == 1) startScan(true);
                else if (which == 2) pickFileLauncher.launch("*/*");
            })
            .show();
    }


    private void startScan(boolean isFullScan) {
        if (!serviceBound || guardService == null) return;
        // GuardService's own periodic background scan (see startPeriodicScans)
        // shares this same ScanEngine — if it's mid-run, scanAllApps() below
        // would silently no-op (see ScanEngine.scanAllApps's overlap guard),
        // leaving this screen stuck on "SCANNING..." forever with nothing to
        // complete it. Tell the user instead of starting an animation that
        // will never finish.
        if (guardService.getScanEngine().isScanRunning()) {
            android.widget.Toast.makeText(getContext(),
                getString(R.string.scan_already_running), android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        isScanning = true;
        hasScanned = true;
        foundThreats.clear();
        threatAdapter.notifyDataSetChanged();

        btnScan.setText(getString(R.string.scan_stop));
        btnScan.setEnabled(true);
        startScannerAnimation();

        // Clear the PREVIOUS scan's final status ("System clean" / "N threats
        // found") right away — otherwise it stays on screen, looking like a
        // stale/wrong result, for this whole new scan until it finishes.
        lastScanStatus = getString(R.string.scan_scanning_btn);
        tvScanStatus.setText(lastScanStatus);
        tvScanStatus.setTextColor(0xFF00D9FF);
        tvThreats.setText("0");

        // Surface the native (Rust) engine status so a silent init failure
        // (clamav DB / model / .yrc) is visible without adb.
        android.widget.Toast.makeText(getContext(),
            getString(R.string.engine_status_format, com.hydradragon.antivirus.engine.NativeScanner.status()),
            android.widget.Toast.LENGTH_LONG).show();

        attachScanCallback();
        guardService.getScanEngine().scanAllApps(isFullScan);
    }

    /** Stop button: request the engine to abort. The in-flight scan ends at its
     *  next file/app boundary and fires onScanComplete with what was found. */
    private void stopScan() {
        if (!serviceBound || guardService == null) return;
        guardService.getScanEngine().cancelScan();
        btnScan.setText(getString(R.string.scan_stopping));
        btnScan.setEnabled(false);
        tvCurrentApp.setText(getString(R.string.scan_stopping));
    }

    private void attachScanCallback() {
        guardService.getScanEngine().setCallback(new com.hydradragon.antivirus.engine.ScanEngine.ScanCallback() {
            @Override
            public void onProgress(int current, int total, String packageName) {
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    progressBar.setMax(total);
                    progressBar.setProgress(current);
                    tvProgress.setText(current + "/" + total);
                    tvCurrentApp.setText("► " + packageName);
                    lastScannedCount = current;
                    tvScanned.setText(String.valueOf(current));
                });
            }

            @Override
            public void onThreatFound(ThreatResult threat) {
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    if (!foundThreats.contains(threat)) {
                        foundThreats.add(threat);
                        threatAdapter.notifyItemInserted(foundThreats.size() - 1);
                        tvThreats.setText(String.valueOf(foundThreats.size()));
                        tvThreats.setTextColor(0xFFFF0040);
                    }
                });
            }

            @Override
            public void onScanComplete(ScanResult result) {
                if (getActivity() == null) {
                    isScanning = false;
                    return;
                }
                boolean wasCancelled = serviceBound && guardService != null
                    && guardService.getScanEngine().isCancelled();
                getActivity().runOnUiThread(() -> {
                    isScanning = false;
                    stopScannerAnimation();
                    btnScan.setText(getString(R.string.rescan));
                    btnScan.setEnabled(true);
                    if (wasCancelled) {
                        lastScanStatus = getString(R.string.scan_stopped);
                        tvScanStatus.setText(lastScanStatus);
                        tvScanStatus.setTextColor(0xFFFFAA00);
                    } else if (result.isClean()) {
                        lastScanStatus = getString(R.string.scan_clean_system);
                        tvScanStatus.setText(lastScanStatus);
                        tvScanStatus.setTextColor(0xFF00FF88);
                    } else {
                        lastScanStatus = getString(R.string.threats_found_count, foundThreats.size());
                        tvScanStatus.setText(lastScanStatus);
                        tvScanStatus.setTextColor(0xFFFF0040);
                    }
                });
            }

            @Override
            public void onError(String error) {
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    isScanning = false;
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

    @Override
    public void onStart() {
        super.onStart();
        requireContext().bindService(new Intent(getContext(), GuardService.class), serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onStop() {
        super.onStop();
        if (serviceBound) {
            requireContext().unbindService(serviceConnection);
            serviceBound = false;
        }
    }

    
    private final androidx.activity.result.ActivityResultLauncher<String> pickFileLauncher = 
        registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.GetContent(), uri -> {
            if (uri != null) {
                if (serviceBound && guardService != null) {
                    scanCustomFile(uri); // Motor uyanıksa direkt tara
                } else {
                    pendingCustomScanUri = uri; // Motor uykudaysa hafızaya al, onStart'ta taranacak
                }
            }
        });

private void scanCustomFile(android.net.Uri uri) {
        if (!serviceBound || guardService == null) return;
        isScanning = true;
        hasScanned = true;
        foundThreats.clear();
        threatAdapter.notifyDataSetChanged();

        btnScan.setText(getString(R.string.scanning));
        btnScan.setEnabled(false);
        startScannerAnimation();

        lastScanStatus = getString(R.string.scan_scanning_btn);
        tvScanStatus.setText(lastScanStatus);
        tvScanStatus.setTextColor(0xFF00D9FF);

        new Thread(() -> {
            try {
                // Seçilen dosyayı geçici belleğe al ve ScanEngine'e sok
                java.io.File tempFile = new java.io.File(getContext().getCacheDir(), "custom_scan.apk");
                java.io.InputStream is = getContext().getContentResolver().openInputStream(uri);
                java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile);
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1) fos.write(buffer, 0, read);
                fos.flush(); fos.close(); is.close();

                android.content.pm.PackageManager pm = getContext().getPackageManager();
                android.content.pm.PackageInfo pkgInfo = pm.getPackageArchiveInfo(tempFile.getAbsolutePath(), android.content.pm.PackageManager.GET_PERMISSIONS | android.content.pm.PackageManager.GET_SIGNATURES);
                
                final com.hydradragon.antivirus.model.ThreatResult result;
                if (pkgInfo != null) {
                    pkgInfo.applicationInfo.sourceDir = tempFile.getAbsolutePath();
                    pkgInfo.applicationInfo.publicSourceDir = tempFile.getAbsolutePath();
                    result = guardService.getScanEngine().analyzeSingleApp(pkgInfo.applicationInfo, pm, true);
                } else {
                    // APK olmayan tehlikeli uzantılar (.exe, .sh) için manuel risk kontrolü
                    com.hydradragon.antivirus.model.ThreatResult.Builder tb = new com.hydradragon.antivirus.model.ThreatResult.Builder(uri.getLastPathSegment());
                    tb.setAppName(uri.getLastPathSegment() + " (Custom File)");
                    tb.setApkPath(tempFile.getAbsolutePath());
                    String name = uri.getLastPathSegment().toLowerCase();
                    if (name.endsWith(".exe") || name.endsWith(".bat") || name.endsWith(".sh") || name.endsWith(".apk")) {
                        tb.setRiskScore(85);
                        tb.setReasons(java.util.Arrays.asList(getString(R.string.suspicious_apk_file), "Unknown Source"));
                    } else {
                        tb.setRiskScore(0);
                    }
                    result = tb.build();
                }

                if (getActivity() != null) {
                    getActivity().runOnUiThread(() -> {
                        isScanning = false;
                        stopScannerAnimation();
                        btnScan.setText(getString(R.string.rescan));
                        btnScan.setEnabled(true);
                        
                        if (result != null && result.isThreat()) {
                            foundThreats.add(result);
                            threatAdapter.notifyItemInserted(0);
                            tvThreats.setText("1");
                            tvThreats.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.threat_red));
                            tvScanStatus.setText(getString(R.string.threats_found_count, 1));
                            tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.threat_red));
                        } else {
                            tvThreats.setText("0");
                            tvThreats.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.neon_green));
                            tvScanStatus.setText(getString(R.string.system_clean));
                            tvScanStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.neon_green));
                        }
                    });
                }
            } catch(Exception e) {
                if (getActivity() != null) {
                    getActivity().runOnUiThread(() -> {
                        isScanning = false;
                        stopScannerAnimation();
                        btnScan.setText(getString(R.string.rescan));
                        btnScan.setEnabled(true);
                        tvScanStatus.setText(getString(R.string.error_reading_file));
                    });
                }
            }
        }).start();
    }

}
