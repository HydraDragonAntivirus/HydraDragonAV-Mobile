// DOSYA: app/src/main/java/com/hydradragon/antivirus/ui/DashboardFragment.java
package com.hydradragon.antivirus.ui;

import android.animation.ValueAnimator;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.NetworkMonitor;
import com.hydradragon.antivirus.model.ProcessInfo;
import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.service.GuardService;
import com.hydradragon.antivirus.views.HexagonStatusView;
import com.hydradragon.antivirus.views.LiveNetworkChart;

import java.util.Locale;

/**
 * Dashboard Fragment - Ana ekran
 * Windows versiyonunu taklit eden cyberpunk dashboard.
 *
 * Göstergeler:
 * - Hexagon güvenlik durumu (yeşil/sarı/kırmızı)
 * - Canlı ağ aktivite grafiği
 * - Toplam trafik / Engellenen / İzin verilen sayaçları
 * - Gerçek zamanlı tehdit akışı
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

    private GuardService guardService;
    private boolean serviceBound = false;
    private Handler uiHandler;
    private Runnable statsUpdater;

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

        // İlk durum
        setSecureState();
        tvEngineStatus.setText("Firewall Engine ACTIVE");

        // Başlangıç animasyonu
        startStartupAnimation();
    }

    private void startStartupAnimation() {
        // Hexagon pulse animasyonu
        if (hexagonView != null) hexagonView.startPulseAnimation();

        // Counter animasyonu
        animateCounter(tvTotalTraffic, 0, 0);
        animateCounter(tvBlocked, 0, 0);
        animateCounter(tvAllowed, 0, 0);
    }

    private void animateCounter(TextView tv, int from, int to) {
        ValueAnimator animator = ValueAnimator.ofInt(from, to);
        animator.setDuration(1000);
        animator.setInterpolator(new AccelerateDecelerateInterpolator());
        animator.addUpdateListener(a -> tv.setText(String.valueOf(a.getAnimatedValue())));
        animator.start();
    }

    private void startStatsUpdater() {
        statsUpdater = new Runnable() {
            @Override
            public void run() {
                if (!serviceBound || guardService == null) return;
                NetworkMonitor nm = guardService.getNetworkMonitor();

                int blocked = nm.getBlockedCount();
                int allowed = nm.getAllowedCount();
                int total = blocked + allowed;

                animateCounter(tvTotalTraffic, 0, total);
                animateCounter(tvBlocked, 0, blocked);
                animateCounter(tvAllowed, 0, allowed);

                uiHandler.postDelayed(this, 1000);
            }
        };
        uiHandler.post(statsUpdater);
    }

        private void setSecureState() {
        tvStatus.setText("System Secure");
        tvStatus.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), com.hydradragon.antivirus.R.color.neon_green));
        
        com.hydradragon.antivirus.engine.NetworkSecurityScanner scanner = new com.hydradragon.antivirus.engine.NetworkSecurityScanner(getContext());
        com.hydradragon.antivirus.engine.NetworkSecurityScanner.SecurityReport report = scanner.scanCurrentNetwork();

        if (!report.isSecure) {
            tvStatusDesc.setText("• Monitoring active\n• Network rules enforced\n" + report.statusMessage);
            if (report.isArpSpoofing) {
                setAlertState();
                appendThreatFeed("🚨 " + report.statusMessage);
            } else tvStatus.setTextColor(android.graphics.Color.parseColor("#FFD700"));
        } else {
            tvStatusDesc.setText("• Monitoring active\n• Network rules enforced\n• " + report.statusMessage);
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
            requireContext().unbindService(serviceConnection);
            serviceBound = false;
        }
    }
}
