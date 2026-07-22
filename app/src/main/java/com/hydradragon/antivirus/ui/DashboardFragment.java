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
    private View layoutScanReminder;

    private GuardService guardService;
    private boolean serviceBound = false;
    private Handler uiHandler;
    private Runnable statsUpdater;
    private Runnable engineStatusPoller;



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
        layoutScanReminder = view.findViewById(R.id.layout_scan_reminder);

        // First-scan reminder banner
        SharedPreferences prefs = requireContext().getSharedPreferences("hydra_prefs", 0);
        if (!prefs.getBoolean("first_scan_completed", false)) {
            view.post(() -> {
                layoutScanReminder.setVisibility(View.VISIBLE);
                layoutScanReminder.setOnClickListener(v -> {
                    if (getActivity() != null) {
                        BottomNavigationView nav = getActivity().findViewById(R.id.bottom_navigation);
                        if (nav != null) nav.setSelectedItemId(R.id.nav_scan);
                    }
                });
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
            @Override
            public void run() {
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

                uiHandler.postDelayed(this, 2000);
            }
        };
        uiHandler.post(statsUpdater);
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
