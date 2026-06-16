// DOSYA: app/src/main/java/com/hydradragon/antivirus/ui/NetworkFragment.java
package com.hydradragon.antivirus.ui;

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
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.adapter.NetworkEventAdapter;
import com.hydradragon.antivirus.engine.NetworkMonitor;
import com.hydradragon.antivirus.service.GuardService;
import com.hydradragon.antivirus.views.LiveNetworkChart;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Network Fragment
 * Canlı ağ trafiği izleme ekranı.
 */
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
    }

    private void setupNetworkCallback() {
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
            public void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed) {
                if(isAdded() && getActivity() != null) getActivity().runOnUiThread(() -> {
                    tvBytesIn.setText(formatBytes(bytesIn) + "/s");
                    tvBytesOut.setText(formatBytes(bytesOut) + "/s");
                    tvBlockedCount.setText(String.valueOf(blocked));
                    tvAllowedCount.setText(String.valueOf(allowed));
                    if (liveChart != null) liveChart.addDataPoint(bytesIn + bytesOut);
                });
            }

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
                if (!serviceBound) return;
                // Mevcut event listesini güncelle
                List<NetworkMonitor.NetworkEvent> currentEvents =
                    guardService.getNetworkMonitor().getEventLog();
                if (events.isEmpty() && !currentEvents.isEmpty()) {
                    events.addAll(currentEvents.subList(0, Math.min(50, currentEvents.size())));
                    eventAdapter.notifyDataSetChanged();
                }
                handler.postDelayed(this, 2000);
            }
        };
        handler.post(statsUpdater);
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.getDefault(), "%.1f KB", bytes / 1024.0);
        return String.format(Locale.getDefault(), "%.1f MB", bytes / (1024.0 * 1024));
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
