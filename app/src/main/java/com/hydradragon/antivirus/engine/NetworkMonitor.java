// DOSYA: app/src/main/java/com/hydradragon/antivirus/engine/NetworkMonitor.java
package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * HydraDragon Network Monitor
 * Ağ trafiğini izler, şüpheli bağlantıları tespit eder.
 *
 * Özellikler:
 * - Şüpheli IP/domain tespiti
 * - C2 (Command & Control) server bağlantısı tespiti
 * - Tor/VPN kullanım tespiti
 * - DNS leak tespiti
 * - Canlı trafik istatistikleri
 */
public class NetworkMonitor {

    private static final String TAG = "HydraDragon-NetMon";

    // Bilinen kötü amaçlı IP aralıkları / C2 sunucuları
    private static final Set<String> BLACKLISTED_IPS = new HashSet<>(Arrays.asList(
        "185.220.101.", // Tor exit nodes
        "198.96.155.",
        "45.142.212.",
        "91.108.4.",    // Telegram (bazı malwareler kullanır)
        "176.31.208."
    ));

    // Şüpheli portlar
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
        4444, 4445, 5555, 6666, 7777, // Metasploit default portları
        8080, 8443, 9999, 1337,
        31337, 12345, 54321           // Bilinen backdoor portları
    ));

    // Şüpheli domain kalıpları
    private static final List<String> SUSPICIOUS_DOMAINS = Arrays.asList(
        ".onion", "tor2web", "i2p",
        "ngrok.io", "serveo.net",    // Tünel servisleri - malware sıkça kullanır
        "dyndns", "no-ip", "ddns"    // Dynamic DNS - C2 sıkça kullanır
    );

    private final Context context;
    private final ConnectivityManager connectivityManager;
    private final ScheduledExecutorService scheduler;
    private final ExecutorService executor;
    private final CopyOnWriteArrayList<NetworkEvent> eventLog;
    private NetworkCallback networkCallback;
    private boolean isMonitoring = false;

    private long bytesReceived = 0;
    private long bytesSent = 0;
    private int blockedConnections = 0;
    private int allowedConnections = 0;

    public static class NetworkEvent {
        public final long timestamp;
        public final String sourceIp;
        public final String destIp;
        public final int destPort;
        public final String protocol;
        public final boolean blocked;
        public final String reason;
        public final int pid;

        public NetworkEvent(String sourceIp, String destIp, int destPort,
                          String protocol, boolean blocked, String reason, int pid) {
            this.timestamp = System.currentTimeMillis();
            this.sourceIp = sourceIp;
            this.destIp = destIp;
            this.destPort = destPort;
            this.protocol = protocol;
            this.blocked = blocked;
            this.reason = reason;
            this.pid = pid;
        }
    }

    public interface NetworkCallback {
        void onSuspiciousActivity(NetworkEvent event);
        void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed);
        void onNetworkChange(boolean isConnected, String networkType);
    }

    public NetworkMonitor(Context context) {
        this.context = context;
        this.connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.executor = Executors.newFixedThreadPool(3);
        this.eventLog = new CopyOnWriteArrayList<>();
    }

    public void setCallback(NetworkCallback callback) {
        this.networkCallback = callback;
    }

    /**
     * Ağ izlemesini başlat
     */
    public void startMonitoring() {
        if (isMonitoring) return;
        isMonitoring = true;

        // Ağ değişikliklerini izle
        NetworkRequest networkRequest = new NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build();

        ConnectivityManager.NetworkCallback cmCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                String netType = getNetworkType();
                if (networkCallback != null) networkCallback.onNetworkChange(true, netType);
                Log.i(TAG, "Network connection: " + netType);
            }

            @Override
            public void onLost(Network network) {
                if (networkCallback != null) networkCallback.onNetworkChange(false, "DISCONNECTED");
            }
        };

        connectivityManager.registerNetworkCallback(networkRequest, cmCallback);

        // Periyodik istatistik güncelleme (her 1 saniye)
        scheduler.scheduleAtFixedRate(() -> {
            updateTrafficStats();
            checkThreatIntelligence();
        }, 0, 1, TimeUnit.SECONDS);

        // DNS leak testi (her 5 dakika)
        scheduler.scheduleAtFixedRate(this::checkDnsLeak, 0, 5, TimeUnit.MINUTES);

        Log.i(TAG, "✓ Network monitoring started");
    }

    /**
     * Gerçek zamanlı trafik istatistikleri güncelle
     */
    private void updateTrafficStats() {
        try {
            // Android TrafficStats API kullan
            long rxBytes = android.net.TrafficStats.getTotalRxBytes();
            long txBytes = android.net.TrafficStats.getTotalTxBytes();

            long deltaRx = rxBytes - bytesReceived;
            long deltaTx = txBytes - bytesSent;
            bytesReceived = rxBytes;
            bytesSent = txBytes;

            if (networkCallback != null) {
                networkCallback.onStatsUpdate(deltaRx, deltaTx, blockedConnections, allowedConnections);
            }
        } catch (Exception e) {
            Log.e(TAG, "Traffic statistics error", e);
        }
    }

    /**
     * Bağlantı güvenlik kontrolü
     * @return true: güvenli, false: şüpheli/engellendi
     */
    public boolean checkConnection(String destIp, int destPort, String packageName) {
        // Blacklist IP kontrolü
        for (String blacklistedPrefix : BLACKLISTED_IPS) {
            if (destIp.startsWith(blacklistedPrefix)) {
                logEvent(destIp, destPort, "TCP", true, "Blacklisted IP: " + blacklistedPrefix, 0);
                blockedConnections++;
                return false;
            }
        }

        // Şüpheli port kontrolü
        if (SUSPICIOUS_PORTS.contains(destPort)) {
            logEvent(destIp, destPort, "TCP", true,
                "Suspicious port: " + destPort + " (" + packageName + ")", 0);
            blockedConnections++;
            return false;
        }

        allowedConnections++;
        logEvent(destIp, destPort, "TCP", false, "Allowed", 0);
        return true;
    }

    /**
     * Domain şüpheli mi kontrol et
     */
    public boolean isSuspiciousDomain(String domain) {
        for (String pattern : SUSPICIOUS_DOMAINS) {
            if (domain.toLowerCase().contains(pattern)) return true;
        }
        return false;
    }

    /**
     * DNS leak testi
     */
    private void checkDnsLeak() {
        executor.execute(() -> {
            try {
                InetAddress addr = InetAddress.getByName("dnsleaktest.com");
                Log.d(TAG, "DNS: " + addr.getHostAddress());
                // Eğer DNS sunucusu şüpheliyse uyar
            } catch (Exception e) {
                Log.e(TAG, "DNS leak test error", e);
            }
        });
    }

    /**
     * Threat Intelligence feed kontrolü
     */
    private void checkThreatIntelligence() {
        // TODO: HydraDragon cloud threat feed'den güncelleme al
        // Şimdilik local blacklist kullanıyor
    }

    private void logEvent(String destIp, int port, String protocol,
                          boolean blocked, String reason, int pid) {
        NetworkEvent event = new NetworkEvent("local", destIp, port, protocol, blocked, reason, pid);
        eventLog.add(event);

        // Max 1000 kayıt tut
        while (eventLog.size() > 1000) eventLog.remove(0);

        if (blocked && networkCallback != null) {
            networkCallback.onSuspiciousActivity(event);
        }
    }

    private String getNetworkType() {
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) return "NONE";
        NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
        if (caps == null) return "UNKNOWN";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "WiFi";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "Mobile";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
        return "Other";
    }

    public List<NetworkEvent> getEventLog() { return new ArrayList<>(eventLog); }
    public long getBytesReceived() { return bytesReceived; }
    public long getBytesSent() { return bytesSent; }
    public int getBlockedCount() { return blockedConnections; }
    public int getAllowedCount() { return allowedConnections; }

    public void stopMonitoring() {
        isMonitoring = false;
        scheduler.shutdown();
        executor.shutdown();
        Log.i(TAG, "Network monitoring stopped");
    }
}

