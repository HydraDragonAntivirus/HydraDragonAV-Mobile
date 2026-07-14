// FILE: app/src/main/java/com/hydradragon/antivirus/engine/NetworkMonitor.java
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
 * Monitors network traffic, detects suspicious connections.
 *
 * Features:
 * - Suspicious IP/domain detection (xor filter + hardcoded rules)
 * - C2 (Command & Control) server connection detection
 * - Tor/VPN usage detection
 * - DNS leak detection
 * - Live traffic statistics
 */
public class NetworkMonitor {

    private static final String TAG = "HydraDragon-NetMon";

    // Known malicious IP ranges / C2 servers
    private static final Set<String> BLACKLISTED_IPS = new HashSet<>(Arrays.asList(
        "185.220.101.", // Tor exit nodes
        "198.96.155.",
        "45.142.212.",
        "91.108.4.",    // Telegram (some malware use it)
        "176.31.208."
    ));

    // Suspicious ports
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
        4444, 4445, 5555, 6666, 7777, // Metasploit default ports
        8080, 8443, 9999, 1337,
        31337, 12345, 54321           // Known backdoor ports
    ));

    // Suspicious domain keywords (xor filter backup)
    private static final List<String> SUSPICIOUS_DOMAIN_PATTERNS = Arrays.asList(
        ".onion", "tor2web", "i2p",
        "ngrok.io", "serveo.net",    // Tunnel services - malware frequently uses
        "dyndns", "no-ip", "ddns"    // Dynamic DNS - C2 frequently uses
    );

    // Xor filter asset

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

    // Domain xor filter

    private long bytesReceived = 0;
    private long bytesSent = 0;
    private long statsLastFetchMs = 0;
    private static final long STATS_CACHE_TTL_MS = 5_000;
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

    /** Domain xor filter lookups now run natively via
     *  {@link UrlThreatScanner#scanUrl}, so there's nothing to load here. */
    private void loadDomainFilters() {
        // no-op — domain/URL xor filters live on the native side.
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
        // onSuspiciousActivity is BLOCKED-only by contract (GuardService turns it
        // straight into a "🛡 ... Engellendi" push notification + threat-log entry
        // + Dashboard feed line, unconditionally). Firing it for an ALLOWED query
        // too — e.g. gstatic.com, completely normal Google-CDN traffic — showed
        // it in the live feed labelled "Engellendi" even though nothing was
        // blocked. Allowed events still land in getEventLog() for the Network
        // screen's full list (allowed rows render green there), just not as a
        // "suspicious" push alert.
        if (blocked) {
            NetworkCallback cb = staticCallback;
            if (cb != null) cb.onSuspiciousActivity(event);
        }
    }

    /**
     * Start network monitoring
     */
    public void startMonitoring() {
        if (isMonitoring) return;
        isMonitoring = true;

        // Monitor network changes
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

        // DNS leak test (every 5 minutes — ONLY background periodic task that
        // remains; stats are pulled on-demand by the UI's own timers so there
        // is ZERO periodic allocation when no screen is visible)
        scheduler.scheduleAtFixedRate(this::checkDnsLeak, 0, 5, TimeUnit.MINUTES);

        Log.i(TAG, "✓ Network monitoring started");
    }

    /**
     * Lazily refresh cached TrafficStats values. Called on-demand from
     * getBytesReceived/getBytesSent; never runs from a background timer.
     */
    private void refreshStats() {
        long now = System.currentTimeMillis();
        if (now - statsLastFetchMs < STATS_CACHE_TTL_MS) return;
        statsLastFetchMs = now;
        long rx = android.net.TrafficStats.getTotalRxBytes();
        long tx = android.net.TrafficStats.getTotalTxBytes();
        if (rx != android.net.TrafficStats.UNSUPPORTED && rx >= 0
            && tx != android.net.TrafficStats.UNSUPPORTED && tx >= 0) {
            bytesReceived = rx;
            bytesSent = tx;
            return;
        }
        try {
            android.app.usage.NetworkStatsManager nsm =
                (android.app.usage.NetworkStatsManager)
                    context.getSystemService(Context.NETWORK_STATS_SERVICE);
            long now2 = System.currentTimeMillis();
            android.app.usage.NetworkStats.Bucket b =
                nsm.querySummaryForDevice(ConnectivityManager.TYPE_WIFI, null, 0, now2);
            long r = (b != null) ? b.getRxBytes() : 0;
            long t = (b != null) ? b.getTxBytes() : 0;
            b = nsm.querySummaryForDevice(ConnectivityManager.TYPE_MOBILE, null, 0, now2);
            if (b != null) { r += b.getRxBytes(); t += b.getTxBytes(); }
            bytesReceived = r;
            bytesSent = t;
        } catch (Throwable ignored) {}
    }

    /**
     * Connection security check
     * @return true: safe, false: suspicious/blocked
     */
    public boolean checkConnection(String destIp, int destPort, String packageName) {
        // Blacklist IP check
        for (String blacklistedPrefix : BLACKLISTED_IPS) {
            if (destIp.startsWith(blacklistedPrefix)) {
                logEvent(destIp, destPort, "TCP", true, "Blacklisted IP: " + blacklistedPrefix, 0);
                recordBlocked();
                return false;
            }
        }

        // Suspicious port check
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
     * Check domain against xor filter + pattern list.
     * @return true: suspicious/malicious domain
     */
    public boolean isSuspiciousDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();

        // First check hardcoded patterns (fast)
        for (String pattern : SUSPICIOUS_DOMAIN_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }

        // Native xor filter domain/URL check — convert domain to http:// form
        // (URL xor filters were generated from http:// strings) check all categories.
        try {
            if (UrlThreatScanner.get(context).scanUrl("http://" + lower) != null) {
                return true;
            }
        } catch (Throwable ignore) {
        }

        return false;
    }

    /**
     * DNS leak test
     */
    private void checkDnsLeak() {
        executor.execute(() -> {
            try {
                InetAddress addr = InetAddress.getByName("dnsleaktest.com");
                Log.d(TAG, "DNS: " + addr.getHostAddress());
                // Alert if DNS server is suspicious
            } catch (Exception e) {
                Log.e(TAG, "DNS leak test error", e);
            }
        });
    }

    private void logEvent(String destIp, int port, String protocol,
                          boolean blocked, String reason, int pid) {
        NetworkEvent event = new NetworkEvent("local", destIp, port, protocol, blocked, reason, pid);
        eventLog.add(event);

        // Keep max 1000 records
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

    /** Direct access to the static event log for export. */
    public static List<NetworkEvent> getEventLogStatic() { return new ArrayList<>(eventLog); }

    /** Direct reference to the static event log for import. */
    public static CopyOnWriteArrayList<NetworkEvent> getEventLogStaticRef() { return eventLog; }

    /** Fetch received bytes, lazily refreshed from TrafficStats (cached 5s). */
    public long getBytesReceived() { refreshStats(); return bytesReceived; }

    /** Fetch sent bytes, lazily refreshed from TrafficStats (cached 5s). */
    public long getBytesSent() { refreshStats(); return bytesSent; }
    public int getBlockedCount() { return blockedConnections.get(); }
    public int getAllowedCount() { return allowedConnections.get(); }

    public void stopMonitoring() {
        isMonitoring = false;
        scheduler.shutdown();
        executor.shutdown();
        Log.i(TAG, "Network monitoring stopped");
    }
}

