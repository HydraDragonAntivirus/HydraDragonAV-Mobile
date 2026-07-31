// DOSYA: app/src/main/java/com/hydradragon/antivirus/ui/DashboardFragment.java
package com.hydradragon.antivirus.ui;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.NetworkMonitor;
import com.hydradragon.antivirus.model.ProcessInfo;
import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.service.GuardService;
import com.hydradragon.antivirus.views.HexagonStatusView;
import com.hydradragon.antivirus.views.LiveNetworkChart;

import java.util.Locale;

/**
 * Dashboard Fragment - Main screen
 * Cyberpunk dashboard mimicking the Windows version.
 *
 * Indicators:
 * - Hexagon security status (green/yellow/red)
 * - Live network activity chart
 * - Total traffic / Blocked / Allowed counters
 * - Real-time threat feed
 */
public class DashboardFragment extends Fragment {

    private HexagonStatusView hexagonView;
    private LiveNetworkChart networkChart;
    private TextView tvStatus;
    private TextView tvStatusDesc;
    private TextView tvTotalTraffic;
    private TextView tvBlocked;
    private TextView tvAllowed;
    private TextView tvLiveActivityRate;
    private View threatIntelPanel;
    private TextView tvThreatFeed;
    private TextView tvEngineStatus;
    private TextView tvMemoryInfo;
    private View layoutScanReminder;
    private TextView tvChartLabel;

    private GuardService guardService;
    private boolean serviceBound = false;
    private Handler uiHandler;
    private Runnable statsUpdater;
    private Runnable engineStatusPoller;
    private long lastTotalBytes = 0;
    private long lastTimeMs = 0;

    private String selectedPkg = null;
    private final java.util.LinkedHashMap<String, int[]> pkgTraffic = new java.util.LinkedHashMap<>();
    private final java.util.List<String> pkgOrder = new java.util.ArrayList<>();



    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            GuardService.GuardBinder binder = (GuardService.GuardBinder) service;
            guardService = binder.getService();
            serviceBound = true;

            guardService.setCallback(new GuardService.GuardCallback() {
                @Override
                public void onThreatDetected(ThreatResult threat) {
                    if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() -> showThreatAlert(threat));
                }

                @Override
                public void onSuspiciousProcess(ProcessInfo process) {
                    if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() ->
                        appendThreatFeed("⚠ Şüpheli Process: " + process.getProcessName()));
                }

                @Override
                public void onNetworkAlert(NetworkMonitor.NetworkEvent event) {
                    if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() ->
                        appendThreatFeed("🛡 Engellendi: " + event.destIp + ":" + event.destPort));
                }

                @Override
                public void onStatusUpdate(String status) {
                    if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() -> updateStatus(status));
                }
            });

            startStatsUpdater();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            serviceBound = false;
            guardService = null;
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_dashboard, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        uiHandler = new Handler(Looper.getMainLooper());

        hexagonView = view.findViewById(R.id.hexagon_status);
        networkChart = view.findViewById(R.id.network_chart);
        tvStatus = view.findViewById(R.id.tv_security_status);
        tvStatusDesc = view.findViewById(R.id.tv_status_desc);
        tvTotalTraffic = view.findViewById(R.id.tv_total_traffic);
        tvBlocked = view.findViewById(R.id.tv_blocked);
        tvAllowed = view.findViewById(R.id.tv_allowed);
        tvLiveActivityRate = view.findViewById(R.id.tv_live_rate);
        tvThreatFeed = view.findViewById(R.id.tv_threat_feed);
        tvEngineStatus = view.findViewById(R.id.tv_engine_status);
        tvMemoryInfo = view.findViewById(R.id.tv_memory_info);
        tvChartLabel = view.findViewById(R.id.tv_chart_label);
        layoutScanReminder = view.findViewById(R.id.layout_scan_reminder);

        View btnGraph = view.findViewById(R.id.btn_behavior_graph);
        if (btnGraph != null) {
            btnGraph.setOnClickListener(v -> {
                if (getActivity() instanceof com.hydradragon.antivirus.MainActivity) {
                    ((com.hydradragon.antivirus.MainActivity) getActivity())
                        .showFragment(BehaviorGraphFragment.newInstance(""));
                }
            });
        }

        if (networkChart != null) {
            networkChart.setOnClickListener(v -> cycleChartPackage());
        }
        Log.d("HydraDragon-Dash", "layoutScanReminder=" + layoutScanReminder);

        // First-scan reminder banner
        SharedPreferences prefs = requireContext().getSharedPreferences("hydra_prefs", 0);
        boolean firstScanCompleted = prefs.getBoolean("first_scan_completed", false);
        Log.d("HydraDragon-Dash", "firstScanCompleted=" + firstScanCompleted);
        if (!firstScanCompleted) {
            Log.d("HydraDragon-Dash", "showing scan reminder banner");
            layoutScanReminder.setVisibility(View.VISIBLE);
            layoutScanReminder.setOnClickListener(v -> {
                if (getActivity() != null) {
                    BottomNavigationView nav = getActivity().findViewById(R.id.bottom_navigation);
                    if (nav != null) nav.setSelectedItemId(R.id.nav_scan);
                }
            });
        }

        // Initial state
        setSecureState();
        tvEngineStatus.setText(getString(R.string.dashboard_firewall_active));

        // Startup animation
        startStartupAnimation();
        startEngineStatusPoller();
    }

    private void startStartupAnimation() {
        // Hexagon pulse animation
        if (hexagonView != null) hexagonView.startPulseAnimation();

        tvTotalTraffic.setText("0");
        tvBlocked.setText("0");
        tvAllowed.setText("0");
    }

    private void startStatsUpdater() {
        statsUpdater = new Runnable() {
            private int lastTotal = 0;
            private java.util.HashMap<Integer, String> pidCache = new java.util.HashMap<>();
            @Override
            public void run() {
                if (!isAdded()) { uiHandler.removeCallbacks(this); return; }
                if (!serviceBound || guardService == null) {
                    uiHandler.postDelayed(this, 1000);
                    return;
                }
                NetworkMonitor nm = guardService.getNetworkMonitor();
                if (nm == null) {
                    uiHandler.postDelayed(this, 1000);
                    return;
                }

                int blocked = nm.getBlockedCount();
                int allowed = nm.getAllowedCount();
                int total = blocked + allowed;

                tvTotalTraffic.setText(String.valueOf(total));
                tvBlocked.setText(String.valueOf(blocked));
                tvAllowed.setText(String.valueOf(allowed));

                long totalIn = nm.getBytesReceived();
                long totalOut = nm.getBytesSent();
                long now = System.currentTimeMillis();
                long totalBytes = totalIn + totalOut;
                float speedKbps = 0f;

                if (lastTimeMs > 0 && now > lastTimeMs) {
                    long deltaBytes = totalBytes - lastTotalBytes;
                    long deltaTimeMs = now - lastTimeMs;
                    if (deltaBytes < 0) deltaBytes = 0;
                    speedKbps = (deltaBytes / 1024f) / (deltaTimeMs / 1000f);
                }
                lastTotalBytes = totalBytes;
                lastTimeMs = now;

                if (tvLiveActivityRate != null) {
                    if (speedKbps < 1024f) {
                        tvLiveActivityRate.setText(String.format(java.util.Locale.US, "%.1f KB/s", speedKbps));
                    } else {
                        tvLiveActivityRate.setText(String.format(java.util.Locale.US, "%.2f MB/s", speedKbps / 1024f));
                    }
                }

                for (NetworkMonitor.NetworkEvent ev : nm.getEventLog()) {
                    String pkg = resolvePidToPackage(ev.pid, pidCache);
                    if (pkg == null) continue;
                    if (!pkgTraffic.containsKey(pkg)) {
                        pkgTraffic.put(pkg, new int[]{0});
                        pkgOrder.add(pkg);
                    }
                    pkgTraffic.get(pkg)[0]++;
                }

                if (networkChart != null) {
                    float displayRate = speedKbps;
                    if (selectedPkg != null) {
                        int[] cnt = pkgTraffic.get(selectedPkg);
                        displayRate = cnt != null ? cnt[0] : 0f;
                    }
                    networkChart.addDataPoint(displayRate > 0 ? displayRate : 0f);
                }

                if (tvChartLabel != null) {
                    tvChartLabel.setText(selectedPkg != null ? selectedPkg : getString(R.string.live_network_activity));
                }

                if (tvMemoryInfo != null) {
                    try {
                        int pid = android.os.Process.myPid();
                        android.app.ActivityManager am = (android.app.ActivityManager)
                            requireContext().getSystemService(Context.ACTIVITY_SERVICE);
                        if (am == null) throw new Exception();
                        android.os.Debug.MemoryInfo mi = am.getProcessMemoryInfo(new int[]{pid})[0];
                        int pssKb = mi.getTotalPss();
                        tvMemoryInfo.setText(pssKb / 1024 + " MB PSS");
                    } catch (Throwable ignored) {
                        tvMemoryInfo.setText("—");
                    }
                }

                uiHandler.postDelayed(this, 2000);
            }
        };
        uiHandler.post(statsUpdater);
    }

    private void cycleChartPackage() {
        if (!isAdded()) return;
        if (selectedPkg == null) {
            if (pkgOrder.isEmpty()) return;
            selectedPkg = pkgOrder.get(0);
        } else {
            int idx = pkgOrder.indexOf(selectedPkg);
            if (idx < 0 || idx >= pkgOrder.size() - 1) {
                selectedPkg = null;
            } else {
                selectedPkg = pkgOrder.get(idx + 1);
            }
        }
        if (tvChartLabel != null) {
            tvChartLabel.setText(selectedPkg != null ? selectedPkg : getString(R.string.live_network_activity));
        }
    }

    private String resolvePidToPackage(int pid, java.util.HashMap<Integer, String> cache) {
        if (pid <= 0) return null;
        String cached = cache.get(pid);
        if (cached != null) return cached;
        if (cache.size() > 200) cache.clear();
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                requireContext().getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) return null;
            for (android.app.ActivityManager.RunningAppProcessInfo p : am.getRunningAppProcesses()) {
                if (p != null && p.pid == pid) {
                    cache.put(pid, p.processName);
                    return p.processName;
                }
            }
        } catch (Throwable ignored) {}
        cache.put(pid, "");
        return null;
    }

        private void setSecureState() {
        tvStatus.setText(getString(R.string.dashboard_system_secure));
        tvStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), com.hydradragon.antivirus.R.color.neon_green));
        
        com.hydradragon.antivirus.engine.NetworkSecurityScanner scanner = new com.hydradragon.antivirus.engine.NetworkSecurityScanner(getContext());
        com.hydradragon.antivirus.engine.NetworkSecurityScanner.SecurityReport report = scanner.scanCurrentNetwork();

        if (!report.isSecure) {
            tvStatusDesc.setText(getString(R.string.dashboard_status_alert_desc, report.statusMessage));
            if (report.isArpSpoofing) {
                setAlertState();
                appendThreatFeed("🚨 " + report.statusMessage);
            } else {
                tvStatus.setTextColor(android.graphics.Color.parseColor("#FFD700"));
                if (hexagonView != null) hexagonView.setLoadingState();
            }
        } else {
            tvStatusDesc.setText(getString(R.string.dashboard_status_secure_desc, report.statusMessage));
        }
        
        if (hexagonView != null && report.isSecure) hexagonView.setSecureState(true);
    }

    private void setAlertState() {
        tvStatus.setText(getString(R.string.threat_detected));
        tvStatus.setTextColor(0xFFFF0040);
        if (hexagonView != null) hexagonView.setSecureState(false);
    }

    private void showThreatAlert(ThreatResult threat) {
        setAlertState();
        appendThreatFeed("🚨 MALWARE: " + threat.getAppName()
            + " [Risk:" + threat.getRiskScore() + "]");
    }

    private void appendThreatFeed(String line) {
        String current = tvThreatFeed.getText().toString();
        String timestamp = String.format(Locale.getDefault(), "[%tT] ", System.currentTimeMillis());
        tvThreatFeed.setText(timestamp + line + "\n" + current);
    }

    private void updateStatus(String status) {
        tvStatusDesc.setText(status);
    }

    private void startEngineStatusPoller() {
        engineStatusPoller = new Runnable() {
            @Override
            public void run() {
                if (!isAdded()) return;
                if (serviceBound && guardService != null) {
                    if (guardService.isEngineLoading()) {
                        tvEngineStatus.setText(getString(R.string.engine_loading_status));
                        tvEngineStatus.setTextColor(0xFFFFAA00);
                        tvStatus.setText(getString(R.string.dashboard_engine_loading));
                        tvStatus.setTextColor(0xFFFFAA00);
                        tvStatusDesc.setText(getString(R.string.dashboard_status_loading_desc));
                        if (hexagonView != null) hexagonView.setLoadingState();
                    } else {
                        tvEngineStatus.setText(getString(R.string.dashboard_system_secure));
                        tvEngineStatus.setTextColor(androidx.core.content.ContextCompat.getColor(
                            requireContext(), com.hydradragon.antivirus.R.color.neon_green));
                        setSecureState();
                    }
                }
                uiHandler.postDelayed(this, 2000);
            }
        };
        uiHandler.post(engineStatusPoller);
    }

    @Override
    public void onStart() {
        super.onStart();
        Intent intent = new Intent(getContext(), GuardService.class);
        requireContext().bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onStop() {
        super.onStop();
        if (serviceBound) {
            if (statsUpdater != null) uiHandler.removeCallbacks(statsUpdater);
            if (engineStatusPoller != null) uiHandler.removeCallbacks(engineStatusPoller);
            requireContext().unbindService(serviceConnection);
            serviceBound = false;
        }
    }
}
