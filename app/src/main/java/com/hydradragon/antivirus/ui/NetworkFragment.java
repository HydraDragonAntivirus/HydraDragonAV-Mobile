package com.hydradragon.antivirus.ui;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.adapter.NetworkEventAdapter;
import com.hydradragon.antivirus.engine.NetworkMonitor;
import com.hydradragon.antivirus.engine.NetworkTrafficDB;
import com.hydradragon.antivirus.service.GuardService;
import com.hydradragon.antivirus.views.LiveNetworkChart;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class NetworkFragment extends Fragment {

    private LiveNetworkChart liveChart;
    private TextView tvBytesIn;
    private TextView tvBytesOut;
    private TextView tvBlockedCount;
    private TextView tvAllowedCount;
    private TextView tvNetworkType;
    private RecyclerView rvNetworkEvents;
    private NetworkEventAdapter eventAdapter;
    private List<NetworkMonitor.NetworkEvent> events = new ArrayList<>();

    private GuardService guardService;
    private boolean serviceBound = false;
    private Handler handler;
    private Runnable statsUpdater;
    private long lastTotalBytes = 0;
    private long lastTimeMs = 0;

    private final ActivityResultLauncher<String> exportLauncher =
        registerForActivityResult(new ActivityResultContracts.CreateDocument("application/json"),
            uri -> {
                if (uri == null) return;
                try {
                    NetworkTrafficDB.exportTraffic(requireContext(), uri);
                    int count = NetworkMonitor.getEventLogStatic().size();
                    Toast.makeText(getContext(),
                        getString(R.string.net_traffic_exported, count), Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(getContext(), getString(R.string.net_traffic_export_failed), Toast.LENGTH_SHORT).show();
                }
            });

    private final ActivityResultLauncher<String> importLauncher =
        registerForActivityResult(new ActivityResultContracts.GetContent(),
            uri -> {
                if (uri == null) return;
                try {
                    int count = NetworkTrafficDB.importTraffic(requireContext(), uri);
                    Toast.makeText(getContext(),
                        getString(R.string.net_traffic_imported, count), Toast.LENGTH_SHORT).show();
                    refreshEventList();
                } catch (Exception e) {
                    Toast.makeText(getContext(), getString(R.string.net_traffic_import_failed), Toast.LENGTH_SHORT).show();
                }
            });

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            guardService = ((GuardService.GuardBinder) service).getService();
            serviceBound = true;
            setupNetworkCallback();
            startUpdater();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            serviceBound = false;
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_network, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        handler = new Handler(Looper.getMainLooper());

        liveChart = view.findViewById(R.id.live_network_chart);
        tvBytesIn = view.findViewById(R.id.tv_bytes_in);
        tvBytesOut = view.findViewById(R.id.tv_bytes_out);
        tvBlockedCount = view.findViewById(R.id.tv_blocked_count);
        tvAllowedCount = view.findViewById(R.id.tv_allowed_count);
        tvNetworkType = view.findViewById(R.id.tv_network_type);
        rvNetworkEvents = view.findViewById(R.id.rv_network_events);

        eventAdapter = new NetworkEventAdapter(events);
        rvNetworkEvents.setLayoutManager(new LinearLayoutManager(getContext()));
        rvNetworkEvents.setAdapter(eventAdapter);

        view.findViewById(R.id.btn_export_traffic).setOnClickListener(v ->
            exportLauncher.launch("hydradragon_traffic_log.json"));
        view.findViewById(R.id.btn_import_traffic).setOnClickListener(v ->
            importLauncher.launch("application/json"));
    }

    private void refreshEventList() {
        List<NetworkMonitor.NetworkEvent> currentEvents = NetworkMonitor.getEventLogStatic();
        events.clear();
        events.addAll(currentEvents.subList(0, Math.min(100, currentEvents.size())));
        eventAdapter.notifyDataSetChanged();
        rvNetworkEvents.scrollToPosition(0);
    }

    private void setupNetworkCallback() {
        if (guardService.getNetworkMonitor() == null) {
            handler.postDelayed(this::setupNetworkCallback, 500);
            return;
        }
        guardService.getNetworkMonitor().setCallback(new NetworkMonitor.NetworkCallback() {
            @Override
            public void onSuspiciousActivity(NetworkMonitor.NetworkEvent event) {
                if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() -> {
                    events.add(0, event);
                    if (events.size() > 100) events.remove(events.size() - 1);
                    eventAdapter.notifyItemInserted(0);
                    rvNetworkEvents.scrollToPosition(0);
                });
            }

            @Override
            public void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed) {}

            @Override
            public void onNetworkChange(boolean isConnected, String networkType) {
                if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() -> {
                    tvNetworkType.setText(networkType);
                    tvNetworkType.setTextColor(isConnected ? 0xFF00FF88 : 0xFFFF0040);
                });
            }
        });
    }

    private void startUpdater() {
        statsUpdater = new Runnable() {
            @Override
            public void run() {
                if (!serviceBound || guardService == null || guardService.getNetworkMonitor() == null) return;
                NetworkMonitor nm = guardService.getNetworkMonitor();
                List<NetworkMonitor.NetworkEvent> currentEvents = nm.getEventLog();
                if (events.isEmpty() && !currentEvents.isEmpty()) {
                    events.addAll(currentEvents.subList(0, Math.min(50, currentEvents.size())));
                    eventAdapter.notifyDataSetChanged();
                }
                long totalIn = nm.getBytesReceived();
                long totalOut = nm.getBytesSent();
                tvBytesIn.setText(formatBytes(totalIn));
                tvBytesOut.setText(formatBytes(totalOut));
                tvBlockedCount.setText(String.valueOf(nm.getBlockedCount()));
                tvAllowedCount.setText(String.valueOf(nm.getAllowedCount()));

                long now = System.currentTimeMillis();
                long totalBytes = totalIn + totalOut;
                if (lastTimeMs > 0 && now > lastTimeMs) {
                    long deltaBytes = totalBytes - lastTotalBytes;
                    long deltaTimeMs = now - lastTimeMs;
                    if (deltaBytes < 0) deltaBytes = 0;
                    float speedKbps = (deltaBytes / 1024f) / (deltaTimeMs / 1000f);
                    if (liveChart != null) liveChart.addDataPoint(speedKbps);
                } else if (liveChart != null) {
                    liveChart.addDataPoint(0f);
                }
                lastTotalBytes = totalBytes;
                lastTimeMs = now;

                handler.postDelayed(this, 1000);
            }
        };
        handler.post(statsUpdater);
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.getDefault(), "%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format(Locale.getDefault(), "%.1f MB", bytes / (1024.0 * 1024));
        return String.format(Locale.getDefault(), "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    @Override
    public void onStart() {
        super.onStart();
        requireContext().bindService(
            new Intent(getContext(), GuardService.class),
            serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onStop() {
        super.onStop();
        if (statsUpdater != null) handler.removeCallbacks(statsUpdater);
        if (serviceBound) {
            requireContext().unbindService(serviceConnection);
            serviceBound = false;
        }
    }
}
