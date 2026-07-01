// DOSYA: app/src/main/java/com/hydradragon/antivirus/engine/NetworkMonitor.java
package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.util.Log;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
 * - Şüpheli IP/domain tespiti (bloom filter + hardcoded rules)
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

    // Şüpheli domain anahtar kelimeleri (bloom filter yedeği)
    private static final List<String> SUSPICIOUS_DOMAIN_PATTERNS = Arrays.asList(
        ".onion", "tor2web", "i2p",
        "ngrok.io", "serveo.net",    // Tünel servisleri - malware sıkça kullanır
        "dyndns", "no-ip", "ddns"    // Dynamic DNS - C2 sıkça kullanır
    );

    // Bloom filter asset

    private final Context context;
    private final ConnectivityManager connectivityManager;
    private final ScheduledExecutorService scheduler;
    private final ExecutorService executor;
    // Static: the REAL blocking/allowing happens in DnsVpnService (separate
    // Service instance, same process) — see recordEvent(). A per-instance log
    // would sit empty forever since DnsVpnService has no reference to whichever
    // NetworkMonitor instance the UI happens to be bound to.
    private static final CopyOnWriteArrayList<NetworkEvent> eventLog = new CopyOnWriteArrayList<>();
    private NetworkCallback networkCallback;
    /** Same instance as {@link #networkCallback} in practice (one NetworkMonitor
     *  is ever bound to the UI at a time) — kept static too so recordEvent(),
     *  called from DnsVpnService's own instance, can still push a LIVE update to
     *  whichever screen is currently listening. */
    private static volatile NetworkCallback staticCallback;
    private boolean isMonitoring = false;

    // Domain bloom filter

    private long bytesReceived = 0;
    private long bytesSent = 0;
    // Static (process-wide): the ACTUAL blocking/allowing of DNS queries happens
    // in DnsVpnService — a separate Service instance from whichever NetworkMonitor
    // the UI is bound to (via GuardService). Both run in the same app process (no
    // android:process split in the manifest), so a static counter is what lets
    // DnsVpnService's notifyBlocked()/pass-through calls actually reach the
    // Dashboard/Network screens instead of updating a NetworkMonitor instance
    // nothing reads from.
    private static final java.util.concurrent.atomic.AtomicInteger blockedConnections =
        new java.util.concurrent.atomic.AtomicInteger(0);
    private static final java.util.concurrent.atomic.AtomicInteger allowedConnections =
        new java.util.concurrent.atomic.AtomicInteger(0);

    /** Called by DnsVpnService when it sinkholes a malicious/blacklisted query. */
    public static void recordBlocked() { blockedConnections.incrementAndGet(); }

    /** Called by DnsVpnService when a DNS query is forwarded through cleanly. */
    public static void recordAllowed() { allowedConnections.incrementAndGet(); }

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
        loadDomainFilters();
    }

    /** Domain bloom lookups now run natively (fastbloom) via
     *  {@link UrlThreatScanner#scanUrl}, so there's nothing to load here. */
    private void loadDomainFilters() {
        // no-op — domain/URL blooms live on the native side.
    }

    public void setCallback(NetworkCallback callback) {
        this.networkCallback = callback;
        staticCallback = callback;
    }

    /** Called by DnsVpnService for every DNS query it actually blocks or allows
     *  — the real traffic path, separate from this class's own (dead)
     *  checkConnection()/logEvent() pair. Feeds both getEventLog() (so the
     *  Network screen's list isn't empty/stale on next backfill) and the live
     *  callback (so an already-open Network screen sees it immediately, not just
     *  after leaving and re-entering the tab). */
    public static void recordEvent(String destIp, int port, String protocol,
                                    boolean blocked, String reason) {
        NetworkEvent event = new NetworkEvent("local", destIp, port, protocol, blocked, reason, 0);
        eventLog.add(0, event);
        while (eventLog.size() > 1000) eventLog.remove(eventLog.size() - 1);
        if (blocked) recordBlocked(); else recordAllowed();
        NetworkCallback cb = staticCallback;
        if (cb != null) cb.onSuspiciousActivity(event);
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
    // Previous cumulative sample for computing the per-tick rate. -1 = no sample
    // yet, so the first tick doesn't emit a huge bogus spike.
    private long lastRx = -1, lastTx = -1;

    private void updateTrafficStats() {
        try {
            long[] tot = deviceBytes();      // cumulative {rx, tx}
            long rx = tot[0], tx = tot[1];
            bytesReceived = rx;              // exposed via getBytesReceived() (total)
            bytesSent = tx;

            long deltaRx = 0, deltaTx = 0;
            if (lastRx >= 0) {
                deltaRx = Math.max(0, rx - lastRx);   // bytes since last tick (rate)
                deltaTx = Math.max(0, tx - lastTx);
            }
            lastRx = rx;
            lastTx = tx;

            if (networkCallback != null) {
                networkCallback.onStatsUpdate(deltaRx, deltaTx, blockedConnections.get(), allowedConnections.get());
            }
        } catch (Exception e) {
            Log.e(TAG, "Traffic statistics error", e);
        }
    }

    /**
     * Cumulative device {rx, tx} in bytes. Prefers {@code TrafficStats}; when the
     * device reports {@code UNSUPPORTED} (-1, common on Android 12+/some OEMs)
     * falls back to {@code NetworkStatsManager} (needs Usage Access). Returns the
     * last-known totals if both fail, so traffic never falsely reads 0.
     */
    private long[] deviceBytes() {
        long rx = android.net.TrafficStats.getTotalRxBytes();
        long tx = android.net.TrafficStats.getTotalTxBytes();
        if (rx != android.net.TrafficStats.UNSUPPORTED
            && tx != android.net.TrafficStats.UNSUPPORTED
            && rx >= 0 && tx >= 0) {
            return new long[]{rx, tx};
        }
        try {
            android.app.usage.NetworkStatsManager nsm =
                (android.app.usage.NetworkStatsManager)
                    context.getSystemService(Context.NETWORK_STATS_SERVICE);
            long now = System.currentTimeMillis();
            long r = 0, t = 0;
            int[] types = { ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE };
            for (int type : types) {
                android.app.usage.NetworkStats.Bucket b =
                    nsm.querySummaryForDevice(type, null, 0, now);
                if (b != null) { r += b.getRxBytes(); t += b.getTxBytes(); }
            }
            return new long[]{r, t};
        } catch (Throwable ignore) {
            // Usage Access not granted or query failed — keep last-known totals.
            return new long[]{ Math.max(0, bytesReceived), Math.max(0, bytesSent) };
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
                recordBlocked();
                return false;
            }
        }

        // Şüpheli port kontrolü
        if (SUSPICIOUS_PORTS.contains(destPort)) {
            logEvent(destIp, destPort, "TCP", true,
                "Suspicious port: " + destPort + " (" + packageName + ")", 0);
            recordBlocked();
            return false;
        }

        recordAllowed();
        logEvent(destIp, destPort, "TCP", false, "Allowed", 0);
        return true;
    }

    /**
     * Domain'i bloom filter + pattern listesine karşı kontrol et.
     * @return true: şüpheli/zararlı domain
     */
    public boolean isSuspiciousDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();

        // İlk olarak hardcoded pattern'leri kontrol et (hızlı)
        for (String pattern : SUSPICIOUS_DOMAIN_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }

        // Native fastbloom domain/URL kontrolü — domain'i http:// formuna çevirip
        // (URL bloom'ları http:// string'lerinden üretildi) tüm kategorilere bak.
        try {
            if (UrlThreatScanner.get(context).scanUrl("http://" + lower) != null) {
                return true;
            }
        } catch (Throwable ignore) {
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
        // Şimdilik local bloom filter + blacklist kullanıyor
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
    public int getBlockedCount() { return blockedConnections.get(); }
    public int getAllowedCount() { return allowedConnections.get(); }

    public void stopMonitoring() {
        isMonitoring = false;
        scheduler.shutdown();
        executor.shutdown();
        Log.i(TAG, "Network monitoring stopped");
    }
}

