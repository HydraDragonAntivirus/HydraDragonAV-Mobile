package com.hydradragon.antivirus.engine;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * Live network activity observed on the device (continuously, by the DNS
 * Web-Shield VPN), attributed to the app that made each request and fed to the
 * YARA-X {@code hydradragon} module as a JSON report when THAT app is scanned.
 * This is the dynamic-analysis counterpart to the static androguard report:
 * rules can match what a specific app actually connects to, e.g.
 * {@code hydradragon.network.dns_lookup(/evil\.com/)} or
 * {@code hydradragon.url(/badpath/)}.
 *
 * <p>Per-package: the VPN resolves each DNS query's owner UID
 * ({@code ConnectivityManager.getConnectionOwnerUid}, API 29+) → package name,
 * so the report fed when scanning {@code com.foo} contains only what
 * {@code com.foo} contacted.
 *
 * <p>JSON shape mirrors the cuckoo schema the module was cloned from:
 * <pre>{@code
 *   {"network":{"domains":[{"domain":"x.com"}],"hosts":["1.2.3.4"]},
 *    "urls":["http://x.com/path"]}
 * }</pre>
 *
 * Bounded per app (oldest evicted) so long uptime can't grow it unbounded.
 */
public final class NetworkObservations {

    private static final int MAX_PER_APP = 2048;
    private static final int MAX_APPS = 1024;

    private static final class Buckets {
        final LinkedHashSet<String> domains = new LinkedHashSet<>();
        final LinkedHashSet<String> hosts = new LinkedHashSet<>();
        final LinkedHashSet<String> urls = new LinkedHashSet<>();

        boolean isEmpty() { return domains.isEmpty() && hosts.isEmpty() && urls.isEmpty(); }
    }

    /** package name → observations. */
    private static final Map<String, Buckets> byPkg = new HashMap<>();

    private NetworkObservations() {}

    public static synchronized void addDomain(String pkg, String domain) { add(pkg, 0, domain); }
    public static synchronized void addHost(String pkg, String host)     { add(pkg, 1, host); }
    public static synchronized void addUrl(String pkg, String url)       { add(pkg, 2, url); }

    private static void add(String pkg, int kind, String v) {
        if (pkg == null || pkg.isEmpty() || v == null) return;
        v = v.trim();
        if (v.isEmpty()) return;
        Buckets b = byPkg.get(pkg);
        if (b == null) {
            if (byPkg.size() >= MAX_APPS) return; // cap distinct apps tracked
            b = new Buckets();
            byPkg.put(pkg, b);
        }
        LinkedHashSet<String> set = (kind == 0) ? b.domains : (kind == 1) ? b.hosts : b.urls;
        if (set.size() >= MAX_PER_APP && !set.contains(v)) {
            Iterator<String> it = set.iterator();
            if (it.hasNext()) { it.next(); it.remove(); }
        }
        set.add(v);
    }

    /** Build the hydradragon JSON report for {@code pkg}, or "" if nothing was
     *  observed for it (or {@code pkg} is null — e.g. an uninstalled APK file). */
    public static synchronized String buildReportJson(String pkg) {
        if (pkg == null) return "";
        Buckets b = byPkg.get(pkg);
        if (b == null || b.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"network\":{\"domains\":[");
        boolean first = true;
        for (String d : b.domains) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"domain\":\"").append(esc(d)).append("\"}");
        }
        sb.append("],\"hosts\":[");
        appendArray(sb, b.hosts);
        sb.append("]},\"urls\":[");
        appendArray(sb, b.urls);
        sb.append("]}");
        return sb.toString();
    }

    private static void appendArray(StringBuilder sb, LinkedHashSet<String> set) {
        boolean first = true;
        for (String s : set) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(esc(s)).append('"');
        }
    }

    private static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
}
