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
            btnScan.setText(getString(R.string.scanning));
            btnScan.setEnabled(false);
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
                        Intent intent = new Intent(Intent.ACTION_DELETE);
                        intent.setData(Uri.parse("package:" + threat.getPackageName()));
                        startActivity(intent);
                        
                        // Ekrandan direkt gizleyelim ki silinmiş hissiyatı versin
                        foundThreats.remove(threat);
                        threatAdapter.notifyDataSetChanged();
                        tvThreats.setText(String.valueOf(foundThreats.size()));
                    }
                })
                .setNegativeButton(getString(R.string.btn_ignore), null)
                .show();
        });

        btnScan.setOnClickListener(v -> { if (!isScanning) showScanTypeDialog(); });
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
        isScanning = true;
        hasScanned = true;
        foundThreats.clear();
        threatAdapter.notifyDataSetChanged();

        btnScan.setText(getString(R.string.scanning));
        btnScan.setEnabled(false);
        startScannerAnimation();

        attachScanCallback();
        guardService.getScanEngine().scanAllApps(isFullScan);
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
                getActivity().runOnUiThread(() -> {
                    isScanning = false;
                    stopScannerAnimation();
                    btnScan.setText(getString(R.string.rescan));
                    btnScan.setEnabled(true);
                    if (result.isClean()) {
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
                        tvScanStatus.setText("Error reading file");
                    });
                }
            }
        }).start();
    }

}
